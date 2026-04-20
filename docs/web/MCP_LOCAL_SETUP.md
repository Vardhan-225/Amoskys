# Running the AMOSKYS MCP server locally for web engagements

**Status:** verified 2026-04-20. All 11 `web_*` tools registered and
functional. 44 endpoint-fleet tools also available from the same server
(they target a fleet DB that may not exist on your Mac — those will
error until you point `FLEET_DB` at a real one or simply ignore them).

## Why local, not lab

The `web_*` tools do not need to run on `lab.amoskys.com`:
- 9 tools make HTTP requests to arbitrary targets on the public
  internet (wp.org SVN, crt.sh, prospect domains).
- 2 tools (`web_aegis_event_counts`, `web_aegis_recent_critical`) read
  the Aegis event log; either SSH to the lab to tail it, or point
  `AMOSKYS_AEGIS_LOG` at a local copy.

Running the MCP server on your Mac keeps latency low for Claude Code
and avoids the "deploy Python + mcp SDK on the WP-hosting box" tax.

## One-time setup (already done on this Mac)

```bash
cd /Volumes/Akash_Lab/Amoskys
.venv/bin/python -m pip install mcp
```

The `mcp` SDK (version 1.27.0 as of writing) pulls in `sse-starlette`,
`uvicorn`, `pydantic-2.x`, and `python-multipart` — ~40 MB of deps.

## Launch command (copy-paste)

```bash
cd /Volumes/Akash_Lab/Amoskys
PYTHONPATH=src \
  AMOSKYS_WEB_ATLAS_PATH=$(pwd)/docs/web/WP_ATTACK_ATLAS.md \
  MCP_AUTH_ENABLED=false \
  MCP_BRAIN_ENABLED=false \
  MCP_HOST=127.0.0.1 \
  MCP_PORT=8445 \
  .venv/bin/python -m amoskys.mcp.server
```

Leave it running in a terminal. The server emits one startup log line
per connected client and per tool call.

If you prefer a background service on macOS: create a LaunchAgent at
`~/Library/LaunchAgents/com.amoskys.mcp.plist` with the same command.

## Claude Code configuration

Add this block to `~/.claude/settings.json` (or the equivalent per-
project `.claude/settings.json`):

```json
{
  "mcpServers": {
    "amoskys-web": {
      "type": "sse",
      "url": "http://127.0.0.1:8445/sse"
    }
  }
}
```

Restart Claude Code. You should now have 55 new tools available,
prefixed `mcp__amoskys-web__`.

## The 11 web tools

| Tool | Purpose | External HTTP? |
|---|---|---|
| `web_operator_playbook` | Ranked next-moves for an engagement | no |
| `web_run_stage1` | Full OSINT sweep + pitch dossier | yes (target) |
| `web_pitch_email` | Ready-to-send first-touch email | yes (target) |
| `web_analyze_plugin` | AST scan one plugin at a wp.org version | yes (wp.org) |
| `web_hunt_top_plugins` | Sweep top-N wp.org plugins for CVEs | yes (wp.org) |
| `web_atlas_coverage` | Live coverage count from the atlas | no |
| `web_list_blind_spots` | Entries with no Aegis or Argos coverage | no |
| `web_list_ast_scanners` | Inventory of 6 AST scanner families | no |
| `web_legitimacy_profile` | Traffic-legitimacy audit view | no |
| `web_aegis_event_counts` | Aegis events by type (last N hours) | optional |
| `web_aegis_recent_critical` | Most recent critical/high events | optional |

For the Aegis-reading tools to work, either set:
```bash
export AMOSKYS_AEGIS_LOG=/path/to/local/events.jsonl
```
or mount `/var/www/html/wp-content/uploads/amoskys-aegis/events.jsonl`
from the lab over SSHFS.

## Security

With `MCP_AUTH_ENABLED=false` the server accepts any connection on
127.0.0.1. This is safe for a local-only Mac. If you expose the server
publicly (behind nginx, over a VPN, etc.) flip `MCP_AUTH_ENABLED=true`
and set `MCP_API_KEYS=k1,k2,...` — see `src/amoskys/mcp/config.py` for
all env vars.

## Tips

- Start with `web_operator_playbook(target_host="<domain>", stage=1)`
  in a Claude Code session. It returns the ordered moves; your agent
  executes each, updates state, and calls again.
- `web_run_stage1` is the "one-shot" equivalent — runs the first four
  moves in sequence and hands back the PitchDossier.
- For prospect discovery, the `prospecting/` module is not yet surfaced
  via MCP. Call it directly from a Python script (see
  `/tmp/run_prospector_from_list.py` for shape) until we add
  `web_find_wp_prospects` to the MCP tool list.
