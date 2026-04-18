# Argos

Autonomous offensive agent for AMOSKYS Web. Pairs with Aegis (defensive)
under IGRIS (brain).

## What it does

Given an authorized target, Argos runs a structured pentest engagement:

1. **Consent** — verifies DNS TXT ownership proof on the target
2. **Recon** — enumerates subdomains, IPs, exposed services
3. **Fingerprint** — identifies WP version, installed plugins/themes, server stack
4. **Probe** — runs selected vulnerability tools (nuclei, wpscan, etc.)
5. **Triage** — dedups + re-scores findings
6. **Report** — emits a JSON + (v1) human-readable PDF report

Every phase writes a signed event to the Proof Spine (v1).

## Quickstart

```bash
# Install nuclei and wpscan first (required for real probes)
brew install nuclei
gem install wpscan

# Scan the lab WordPress site
cd /Volumes/Akash_Lab/Amoskys
PYTHONPATH=src python -m amoskys.agents.Web.argos scan lab.amoskys.com \
    --tools nuclei-cves,wpscan \
    --max-rps 5 \
    --max-duration 1800 \
    --report-dir ./argos-reports
```

Output:
```
[argos] engagement 2f... -> lab.amoskys.com
[argos] tools: ['nuclei-cves', 'wpscan']
[argos] scope: rps=5 duration=1800s
...
[argos] summary
  phases complete: ['consent', 'recon', 'fingerprint', 'probe', 'triage', 'report']
  duration: 127.4s
  findings: {'info': 4, 'low': 0, 'medium': 2, 'high': 1, 'critical': 0}

[argos] report written to: ./argos-reports/argos-2f...json
```

## Scope enforcement

Argos refuses to probe without a `Scope` object that includes:
- `target` — the exact domain authorized
- `txt_token` — DNS TXT ownership proof (verified against `amoskys-verify.<target>`)
- `window_start_ns` / `window_end_ns` — engagement time box
- `max_rps` / `max_duration_s` — rate + duration caps
- `allowed_probe_classes` — whitelist of tool probe classes

Tool probe classes are namespaced (e.g., `nuclei.cves`, `wpscan.plugins`).
A permanent denylist blocks anything in `nuclei.dos`, `*.destructive`, etc.
These are hard-coded in `engine.Scope.DENIED_PROBE_CLASSES` and cannot be
overridden at runtime.

## Roadmap

| Version | Capability |
|---------|------------|
| v0.1 (now) | CLI scaffold, nuclei + wpscan drivers, JSON report, in-memory Proof Spine |
| v0.2 | Real DNS TXT consent verification, Proof Spine POST, encrypted report store |
| v0.3 | PDF report renderer, MITRE-classified findings, AMRDR posterior feedback hook |
| v1.0 | PentAGI-style LLM reasoning loop for manual PoC construction, HackerOne submission flow |
| v1.5 | OOB Collaborator integration, blind-vuln detection |
| v2.0 | Grey-box fuzzing with LLM-guided payload mutation |
| v3.0 | Source-level static analysis of downloadable plugins |

## Architecture notes

- **Tool drivers are narrow.** A driver wraps ONE tool invocation style,
  not the entire tool's CLI surface. `NucleiTool(category="cves")` and
  `NucleiTool(category="exposures")` are separate instances.
- **Scope is the safety boundary.** Every `run()` call gets the Scope;
  the Engagement validates `tool.probe_class` against the allowlist
  before invoking. `DENIED_PROBE_CLASSES` is a hard constant.
- **No destructive probes ever.** `*.dos`, `*.destructive`, `*.intrusive`
  are permanently denied. Extending the denylist is a code change, not
  a config change.
- **Every probe is auditable.** `ToolResult.command` stores the exact argv
  executed. `Engagement._emit_phase` chain-hashes phase events. A
  customer can demand the full log at any time.
