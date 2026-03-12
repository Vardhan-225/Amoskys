"""
AMOSKYS Platform Capabilities Introspection

Produces static capability data from AGENT_REGISTRY + probe definitions.
Always available regardless of whether telemetry.db has event data.

Used by:
  - /dashboard/api/mitre/coverage (declared coverage baseline)
  - /dashboard/api/agents/deep-overview (fallback when no events)
  - /dashboard/api/platform-capabilities (full static catalog)
"""

from __future__ import annotations

import importlib
import time
from typing import Any, Dict, List, Tuple

# ── Cache ─────────────────────────────────────────────────────────
_capabilities_cache: Dict[str, Any] = {}
_CACHE_TTL = 300  # 5 minutes — probe defs don't change at runtime


def _is_cached(key: str) -> bool:
    entry = _capabilities_cache.get(key)
    if entry and (time.time() - entry["ts"]) < _CACHE_TTL:
        return True
    return False


def _get_cached(key: str) -> Any:
    return _capabilities_cache[key]["data"]


def _set_cached(key: str, data: Any) -> None:
    _capabilities_cache[key] = {"data": data, "ts": time.time()}


# ── Core Functions ────────────────────────────────────────────────


def get_platform_capabilities(platform: str) -> Dict[str, Any]:
    """Return full probe metadata for all agents available on the given platform.

    Args:
        platform: "darwin", "linux", or "windows"

    Returns:
        Dict keyed by agent_id, each containing:
            name, description, category, icon, platforms,
            probes: [{name, description, mitre_techniques, mitre_tactics}]
    """
    cache_key = f"caps_{platform}"
    if _is_cached(cache_key):
        return _get_cached(cache_key)

    from amoskys.agents import AGENT_REGISTRY
    from amoskys.observability.probe_audit import AGENT_PROBE_MAP

    result: Dict[str, Any] = {}

    for agent_id, reg in AGENT_REGISTRY.items():
        if platform not in reg.get("platforms", []):
            continue

        agent_data: Dict[str, Any] = {
            "name": reg["name"],
            "description": reg["description"],
            "category": reg.get("category", "endpoint"),
            "icon": reg.get("icon", agent_id),
            "platforms": reg["platforms"],
            "declared_probes": reg.get("probes", 0),
            "probes": [],
            "mitre_techniques": [],
            "mitre_tactics": [],
        }

        # Try to import and instantiate probes for MITRE extraction
        probe_info = AGENT_PROBE_MAP.get(agent_id)
        if probe_info:
            try:
                mod = importlib.import_module(probe_info["module"])
                factory = getattr(mod, probe_info["factory"])
                probes = factory()
                agent_techniques = set()
                agent_tactics = set()

                for p in probes:
                    techs = list(getattr(p, "mitre_techniques", []))
                    tacts = list(getattr(p, "mitre_tactics", []))
                    agent_techniques.update(techs)
                    agent_tactics.update(tacts)
                    agent_data["probes"].append(
                        {
                            "name": getattr(p, "name", "unknown"),
                            "description": getattr(p, "description", ""),
                            "mitre_techniques": techs,
                            "mitre_tactics": tacts,
                        }
                    )

                agent_data["mitre_techniques"] = sorted(agent_techniques)
                agent_data["mitre_tactics"] = sorted(agent_tactics)
            except Exception:
                pass

        result[agent_id] = agent_data

    _set_cached(cache_key, result)
    return result


def get_declared_mitre_coverage(platform: str) -> Dict[str, Any]:
    """Aggregate all MITRE technique/tactic declarations from probes on this platform.

    Returns:
        {
            "by_tactic": {"execution": ["T1059", "T1204"], ...},
            "by_technique": {"T1059": [("proc", "process_spawn"), ...], ...},
            "technique_count": int,
            "tactic_count": int,
        }
    """
    cache_key = f"mitre_{platform}"
    if _is_cached(cache_key):
        return _get_cached(cache_key)

    caps = get_platform_capabilities(platform)

    by_tactic: Dict[str, List[str]] = {}
    by_technique: Dict[str, List[Tuple[str, str]]] = {}

    for agent_id, agent_data in caps.items():
        for probe in agent_data.get("probes", []):
            probe_name = probe.get("name", "unknown")
            for tech in probe.get("mitre_techniques", []):
                if tech not in by_technique:
                    by_technique[tech] = []
                by_technique[tech].append((agent_id, probe_name))

            for tactic in probe.get("mitre_tactics", []):
                # Normalize tactic name for consistent keying
                tactic_key = tactic.lower().replace(" ", "_").replace("-", "_")
                if tactic_key not in by_tactic:
                    by_tactic[tactic_key] = []
                # Add techniques from this probe to this tactic
                for tech in probe.get("mitre_techniques", []):
                    if tech not in by_tactic[tactic_key]:
                        by_tactic[tactic_key].append(tech)

    result = {
        "by_tactic": by_tactic,
        "by_technique": {
            t: [(a, p) for a, p in sources] for t, sources in by_technique.items()
        },
        "technique_count": len(by_technique),
        "tactic_count": len(by_tactic),
    }

    _set_cached(cache_key, result)
    return result


def get_agent_capabilities_summary(platform: str) -> List[Dict[str, Any]]:
    """Return a summary list of all agents on this platform with capability counts.

    Returns:
        List of dicts: agent_id, name, description, category, icon,
                       probe_count, mitre_technique_count, mitre_techniques, platforms
    """
    caps = get_platform_capabilities(platform)
    summary = []

    for agent_id, data in caps.items():
        summary.append(
            {
                "agent_id": agent_id,
                "name": data["name"],
                "description": data["description"],
                "category": data["category"],
                "icon": data["icon"],
                "platforms": data["platforms"],
                "probe_count": len(data["probes"]) or data.get("declared_probes", 0),
                "mitre_technique_count": len(data["mitre_techniques"]),
                "mitre_techniques": data["mitre_techniques"],
                "mitre_tactics": data["mitre_tactics"],
            }
        )

    return summary
