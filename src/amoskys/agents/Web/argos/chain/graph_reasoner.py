"""Graph-based attack-chain reasoner.

Takes findings + profile, activates matching edges in the WordPress
attack graph, searches all simple paths from UNAUTHENTICATED to
terminal goal states, scores each path by expected value, applies
defense-aware pruning, and surfaces:

  - ranked exploit paths (real chains)
  - near-miss paths       (1 missing edge from a winning path)
  - defensive posture     (edges pruned by detected defenses)

Output shape: ExploitPath objects compatible with the existing
ExploitChain dataclass so downstream reporters don't care whether
a chain came from the legacy rule engine or the graph reasoner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from amoskys.agents.Web.argos.chain.graph import (
    AttackEdge, AttackGraph, AttackState,
    _TERMINAL_GOALS, build_wordpress_graph, state_impact,
)

logger = logging.getLogger("amoskys.argos.chain.graph_reasoner")


# ── Data model ────────────────────────────────────────────────────


@dataclass
class ExploitPath:
    """A concrete attack path through the graph."""
    name: str                            # e.g. "Credential spray → admin → RCE"
    goal_state: str
    edges: List[AttackEdge] = field(default_factory=list)
    triggering_findings: List[Any] = field(default_factory=list)
    cost_minutes: int = 0
    success_prob: float = 1.0
    detectability: float = 0.0
    impact: float = 0.0
    expected_value: float = 0.0

    severity: str = "medium"
    cvss_estimate: float = 5.0
    confidence: int = 50

    narrative: str = ""
    business_impact: str = ""
    mitre_chain: List[str] = field(default_factory=list)
    defense_notes: List[str] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)
    replay_commands: List[str] = field(default_factory=list)
    is_near_miss: bool = False
    missing_for_completion: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        # Emit in the same shape as legacy ExploitChain so the HTML/PDF
        # renderers don't need to know the difference.
        return {
            "name":             self.name,
            "goal_state":       self.goal_state,
            "severity":         self.severity,
            "cvss_estimate":    self.cvss_estimate,
            "confidence":       self.confidence,
            "narrative":        self.narrative,
            "business_impact":  self.business_impact,
            "evidence_trail":   [e.name for e in self.edges],
            "links":            [],
            # Graph-specific extras (HTML/PDF render these richer)
            "cost_minutes":     self.cost_minutes,
            "success_prob":     round(self.success_prob, 3),
            "detectability":    round(self.detectability, 3),
            "impact":           round(self.impact, 2),
            "expected_value":   round(self.expected_value, 3),
            "mitre_chain":      list(self.mitre_chain),
            "defense_notes":    list(self.defense_notes),
            "assumptions":      list(self.assumptions),
            "replay_commands":  list(self.replay_commands),
            "is_near_miss":     self.is_near_miss,
            "missing_for_completion": list(self.missing_for_completion),
        }


@dataclass
class GraphReport:
    """Full output of the graph reasoner."""
    paths:         List[ExploitPath] = field(default_factory=list)
    near_misses:   List[ExploitPath] = field(default_factory=list)
    defenses_detected: List[str] = field(default_factory=list)
    pruned_edges:  List[str] = field(default_factory=list)
    activated_edges: int = 0
    total_edges:   int = 0
    goals_reached: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "paths":              [p.to_dict() for p in self.paths],
            "near_misses":        [p.to_dict() for p in self.near_misses],
            "defenses_detected":  list(self.defenses_detected),
            "pruned_edges":       list(self.pruned_edges),
            "activated_edges":    self.activated_edges,
            "total_edges":        self.total_edges,
            "goals_reached":      sorted(self.goals_reached),
            "notes":              list(self.notes),
        }


# ── Defense detection ─────────────────────────────────────────────


_DEFENSE_PENALTY = 0.25   # edges pruned by a present defense have prob ×= 0.25


def _detect_defenses(profile) -> List[str]:
    """Return a list of defense family tags active on the target."""
    if profile is None:
        return []
    tags: List[str] = []
    waf = getattr(profile, "waf_names", None) or []
    for w in waf:
        wl = str(w).lower()
        if "wordfence" in wl:
            tags.append("wordfence")
        if "cloudflare" in wl:
            tags.append("cloudflare")
        if "sucuri" in wl:
            tags.append("sucuri")
        if "modsec" in wl:
            tags.append("modsecurity")
        if "imperva" in wl or "incapsula" in wl:
            tags.append("imperva")
        if "aws" in wl:
            tags.append("aws")
    cdn = (getattr(profile, "cdn_name", None) or "").lower()
    if "cloudflare" in cdn and "cloudflare" not in tags:
        tags.append("cloudflare")
    if "sucuri" in cdn and "sucuri" not in tags:
        tags.append("sucuri")
    # Aegis plugin is one of OUR own customer sensors; detected via
    # body signature by wp_probe if installed. Not currently fingerprinted
    # in ArchitectureProfile, but reserved here for future use.
    return sorted(set(tags))


# ── Edge activation ───────────────────────────────────────────────


def _activate(graph: AttackGraph, findings: List, profile
              ) -> Tuple[List[AttackEdge], List[AttackEdge], Dict[str, Any]]:
    """Return (active_edges, pruned_edges, per-edge finding map).

    An edge is active if:
      - It has no trigger_kinds (state-transition edge), OR
      - At least one finding matches its kinds + predicate.

    Defense pruning: if ANY of the edge's defense_pruned_by families
    is active, the edge's success_prob is multiplied by 0.25 rather
    than wholly removed (defenses aren't perfect).
    """
    defenses = _detect_defenses(profile)
    edge_to_finding: Dict[str, Any] = {}
    active: List[AttackEdge] = []
    pruned: List[AttackEdge] = []

    for e in graph.all_edges():
        matched_finding = None
        if e.trigger_kinds:
            matched_finding = e.activated_by(findings, profile)
            if matched_finding is None:
                continue
        # Clone so we don't mutate the catalog
        cloned = AttackEdge(
            name=e.name, from_state=e.from_state, to_state=e.to_state,
            trigger_kinds=e.trigger_kinds, trigger_predicate=e.trigger_predicate,
            cost_minutes=e.cost_minutes, success_prob=e.success_prob,
            detectability=e.detectability,
            mitre_technique=e.mitre_technique,
            defense_pruned_by=e.defense_pruned_by,
            attacker_action=e.attacker_action,
            defender_should_see=e.defender_should_see,
            replay_command=e.replay_command,
        )
        # Defense-aware pruning
        overlap = set(cloned.defense_pruned_by) & set(defenses)
        if overlap:
            cloned.success_prob = round(cloned.success_prob * _DEFENSE_PENALTY, 3)
            pruned.append(cloned)
        if matched_finding is not None:
            edge_to_finding[cloned.name] = matched_finding
        active.append(cloned)
    return active, pruned, edge_to_finding


# ── Path scoring ──────────────────────────────────────────────────


def _score_path(edges: List[AttackEdge], goal: str) -> Dict[str, float]:
    cost = sum(e.cost_minutes for e in edges)
    prob = 1.0
    not_detected = 1.0
    for e in edges:
        prob *= e.success_prob
        not_detected *= (1.0 - e.detectability)
    detectability = 1.0 - not_detected
    impact = state_impact(goal)
    stealth = not_detected
    ev = prob * impact * stealth
    return {
        "cost": cost, "prob": prob,
        "detectability": detectability,
        "impact": impact, "expected_value": ev,
    }


def _severity_from_ev(ev: float, impact: float) -> Tuple[str, float]:
    """Map an expected-value score to a severity label + CVSS estimate.

    Tuned so that:
      - chains with impact ≥ 9.0 and EV ≥ 5.0 → critical (9.0+)
      - chains with impact ≥ 8.0 and EV ≥ 3.0 → high    (7.0-8.9)
      - chains with impact ≥ 5.0 and EV ≥ 1.0 → medium  (4.0-6.9)
      - else → low / info
    """
    if impact >= 9.0 and ev >= 5.0:
        return "critical", min(10.0, 9.0 + ev * 0.1)
    if impact >= 8.0 and ev >= 3.0:
        return "high", min(8.9, 7.0 + ev * 0.2)
    if impact >= 5.0 and ev >= 1.0:
        return "medium", min(6.9, 4.0 + ev * 0.3)
    if impact >= 3.0:
        return "low", min(3.9, 2.0 + ev * 0.5)
    return "info", 2.0


# ── Narrative composition ─────────────────────────────────────────


def _compose_narrative(path: List[AttackEdge],
                        edge_to_finding: Dict[str, Any],
                        goal_state: str) -> Tuple[str, str, List[str], List[str], List[str]]:
    """Build (narrative, business_impact, mitre_chain, assumptions,
    defense_notes) for a path. Narrative is multi-step attacker POV."""
    lines: List[str] = []
    mitre: List[str] = []
    assumptions: List[str] = []
    defense_notes: List[str] = []

    lines.append(f"Goal: reach state `{goal_state}` from public internet.")
    lines.append("")
    for i, e in enumerate(path, 1):
        step_hdr = f"{i}. [{e.mitre_technique or 'T-?'}] {e.name}"
        lines.append(step_hdr)
        if e.attacker_action:
            lines.append(f"     Attacker: {e.attacker_action}")
        if e.defender_should_see:
            lines.append(f"     Blue team should see: {e.defender_should_see}")
        f = edge_to_finding.get(e.name)
        if f is not None:
            ev = getattr(f, "evidence", "") or ""
            if ev:
                lines.append(f"     Anchored by finding: {ev[:140]}")
        # collect
        if e.mitre_technique:
            mitre.append(e.mitre_technique)
        if e.defense_pruned_by:
            defense_notes.append(
                f"Step {i} may be dampened by: {', '.join(e.defense_pruned_by)}."
            )
        # implicit assumptions
        if e.success_prob < 0.7:
            assumptions.append(
                f"Step {i} assumes attacker is willing to accept "
                f"~{int((1 - e.success_prob) * 100)}% failure rate on this edge."
            )
        if e.cost_minutes >= 30:
            assumptions.append(
                f"Step {i} budgets ~{e.cost_minutes} min of attacker time; "
                "not viable for drive-by opportunists."
            )

    # Business impact
    impact_by_goal = {
        AttackState.CODE_EXECUTION:
            "Remote code execution as the web user — attacker can read "
            "wp-config.php, modify any file in the webroot, install persistent "
            "backdoors. Full application compromise.",
        AttackState.ACCOUNT_ADMIN:
            "WordPress administrator access. Attacker can install plugins, "
            "modify theme files, export user data, and pivot to RCE within "
            "minutes.",
        AttackState.DATABASE_WRITE:
            "Attacker can modify stored data — user accounts, content, "
            "commerce records. Downstream: forge admin user, inject stored "
            "XSS into every post, drain WooCommerce balances.",
        AttackState.DATABASE_READ:
            "Customer data readable — email lists, hashed passwords (which "
            "crack for ~30% of users), PII, commerce records. Regulatory "
            "exposure under GDPR/CCPA.",
        AttackState.FILE_WRITE:
            "Attacker can drop files in the webroot. One step from RCE.",
        AttackState.PERSISTENCE:
            "Attacker survives reboots, credential rotations, plugin "
            "updates. Removal requires forensic cleanup of mu-plugins, "
            "wp_options, cron tasks, and file-integrity restoration.",
        AttackState.LATERAL:
            "Compromise spreads to neighbouring sites on shared hosting.",
        AttackState.DATA_EXFIL:
            "Customer data leaving the network. Regulatory disclosure "
            "triggers (72-hour GDPR, state-level notifications).",
        AttackState.FULL_COMPROMISE:
            "Full compromise.",
    }
    business_impact = impact_by_goal.get(
        goal_state,
        f"Attacker reaches {goal_state} — remediation required."
    )

    return (
        "\n".join(lines),
        business_impact,
        mitre,
        list(dict.fromkeys(assumptions)),     # dedupe preserving order
        list(dict.fromkeys(defense_notes)),
    )


# ── Public entry point ────────────────────────────────────────────


def reason_graph(findings: List, profile=None,
                 max_depth: int = 6, top_k: int = 8) -> GraphReport:
    """Given findings + profile, enumerate + score + rank exploit paths."""
    graph = build_wordpress_graph()
    total = len(graph.all_edges())
    defenses = _detect_defenses(profile)

    active, pruned, edge_to_finding = _activate(graph, findings, profile)
    active_graph = AttackGraph()
    active_graph.extend(active)

    report = GraphReport(
        defenses_detected=defenses,
        pruned_edges=[e.name for e in pruned],
        activated_edges=len(active),
        total_edges=total,
    )
    report.notes.append(
        f"{len(active)}/{total} edges activated by findings; "
        f"{len(pruned)} edges dampened by detected defenses {defenses or '(none)'}."
    )

    # Enumerate paths to each terminal goal
    seen_path_keys: Set[Tuple[str, ...]] = set()
    for goal in _TERMINAL_GOALS:
        paths = active_graph.paths(AttackState.UNAUTHENTICATED, goal, max_depth=max_depth)
        if not paths:
            continue
        report.goals_reached.add(goal)
        for path in paths:
            key = tuple(e.name for e in path)
            if key in seen_path_keys:
                continue
            seen_path_keys.add(key)
            scores = _score_path(path, goal)
            sev, cvss = _severity_from_ev(scores["expected_value"], scores["impact"])
            narrative, biz, mitre, assumptions, defense_notes = _compose_narrative(
                path, edge_to_finding, goal)
            # Anchor findings for the path
            trig = [edge_to_finding[e.name] for e in path
                    if e.name in edge_to_finding]
            # Path name — first and last edge
            pname = (f"{path[0].name}"
                     f"{' → ' + path[-1].name if len(path) > 1 else ''}  "
                     f"(goal: {goal})")
            replay = [e.replay_command for e in path if e.replay_command]
            ep = ExploitPath(
                name=pname, goal_state=goal, edges=path,
                triggering_findings=trig,
                cost_minutes=scores["cost"], success_prob=scores["prob"],
                detectability=scores["detectability"],
                impact=scores["impact"], expected_value=scores["expected_value"],
                severity=sev, cvss_estimate=cvss,
                confidence=max(20, min(95, int(scores["prob"] * 100))),
                narrative=narrative, business_impact=biz,
                mitre_chain=mitre,
                assumptions=assumptions,
                defense_notes=defense_notes,
                replay_commands=replay,
            )
            report.paths.append(ep)

    # Rank by expected value descending, then by severity level
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    report.paths.sort(
        key=lambda p: (sev_rank.get(p.severity, 0), p.expected_value),
        reverse=True,
    )
    report.paths = report.paths[:top_k]

    # ── Near-miss detection ──
    # For each INACTIVE edge whose from_state is reachable with active edges,
    # ask: would activating this edge unlock a NEW path to a terminal goal?
    # If yes → near-miss path. Reports "what's missing".
    inactive_edges = [e for e in graph.all_edges()
                      if e.trigger_kinds and e.activated_by(findings, profile) is None]
    # Compute what states are reachable with active edges
    reachable = {AttackState.UNAUTHENTICATED}
    changed = True
    while changed:
        changed = False
        for e in active:
            if e.from_state in reachable and e.to_state not in reachable:
                reachable.add(e.to_state)
                changed = True
    for inactive in inactive_edges:
        if inactive.from_state not in reachable:
            continue
        # Simulate activating this edge: could new paths emerge?
        sim_graph = AttackGraph()
        sim_graph.extend(active + [inactive])
        for goal in _TERMINAL_GOALS:
            if goal in report.goals_reached:
                continue  # already covered by a real path
            paths = sim_graph.paths(AttackState.UNAUTHENTICATED, goal, max_depth=max_depth)
            if not paths:
                continue
            path = min(paths, key=lambda p: len(p))
            scores = _score_path(path, goal)
            sev, cvss = _severity_from_ev(scores["expected_value"], scores["impact"])
            narrative, biz, mitre, assumptions, defense_notes = _compose_narrative(
                path, edge_to_finding, goal)
            missing_kinds = sorted(set(inactive.trigger_kinds))
            name = (f"NEAR-MISS: {inactive.name}  (unlocks goal: {goal}) — "
                    f"missing finding kind{'s' if len(missing_kinds)>1 else ''}: "
                    f"{'|'.join(missing_kinds)}")
            near = ExploitPath(
                name=name, goal_state=goal, edges=path,
                cost_minutes=scores["cost"], success_prob=scores["prob"],
                detectability=scores["detectability"],
                impact=scores["impact"], expected_value=scores["expected_value"],
                severity=sev, cvss_estimate=cvss,
                confidence=max(10, int(scores["prob"] * 60)),  # lower confidence: hypothetical
                narrative=(
                    "This path would be REAL if a finding matching "
                    f"`{'|'.join(missing_kinds)}` were observed. The graph "
                    f"currently lacks that activation.\n\n" + narrative
                ),
                business_impact=biz,
                mitre_chain=mitre,
                assumptions=assumptions + [
                    f"Hypothetical — requires a `{missing_kinds[0]}` finding "
                    "to become real."
                ],
                defense_notes=defense_notes,
                replay_commands=[],
                is_near_miss=True,
                missing_for_completion=missing_kinds,
            )
            # Dedupe by goal state + missing kind
            already = any(
                n.goal_state == goal and
                n.missing_for_completion == missing_kinds
                for n in report.near_misses
            )
            if not already:
                report.near_misses.append(near)
            break  # one near-miss per inactive edge

    # Rank near-misses by impact
    report.near_misses.sort(key=lambda p: (p.expected_value, p.impact), reverse=True)
    report.near_misses = report.near_misses[:5]

    return report


__all__ = [
    "ExploitPath", "GraphReport", "reason_graph",
]
