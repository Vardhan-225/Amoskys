# Monorepo Discipline

AMOSKYS Web lives in the same repository as AMOSKYS endpoint (the macOS agent
platform). This document spells out the rules that keep the two products from
contaminating each other.

## The decision

Keep one repository until one of the following happens:

1. Team grows past 4 engineers and onboarding friction from a shared repo
   becomes a real cost.
2. We open-source one product and keep the other proprietary.
3. A shared abstraction (Proof Spine, IGRIS kernel) stabilizes enough that
   extracting it as a standalone library has a clear win.

Until then: monorepo, with the discipline below.

## Directory contract

```
/
├── src/amoskys/
│   ├── agents/
│   │   ├── common/          # SHARED — base classes, no OS or web knowledge
│   │   ├── os/              # ENDPOINT only — macOS, Linux, Windows agents
│   │   └── Web/             # WEB only — Argos, Aegis source, web sensors
│   ├── core/                # SHARED — protobuf, Proof Spine, eventbus, WAL
│   ├── intel/               # SHARED — scoring, AMRDR skeleton, fusion engine
│   ├── igris/               # SHARED — brain kernel (supervisor, signals)
│   │   ├── endpoint/        # endpoint-specific signals and collectors
│   │   └── web/             # web-specific signals and collectors
│   ├── storage/             # SHARED — TelemetryStore, with per-product tables
│   └── mcp/                 # SHARED — MCP infrastructure
│       ├── endpoint_server.py
│       └── web_server.py
├── web/                     # SHARED — Flask dashboard, extended per product
├── scripts/
│   └── lab/                 # WEB — lab infrastructure scripts
├── deploy/
│   ├── endpoint/            # ENDPOINT deployment (pkg, pkgbuild)
│   └── web/                 # WEB deployment (FastAPI ingest, WP plugin zip)
└── docs/
    ├── endpoint/            # ENDPOINT product docs (if any)
    └── web/                 # WEB product docs (this directory)
```

## Import rules (enforceable in CI)

**Rule 1**: `src/amoskys/agents/os/*` MUST NOT import `src/amoskys/agents/Web/*`.
**Rule 2**: `src/amoskys/agents/Web/*` MUST NOT import `src/amoskys/agents/os/*`.

**Rule 3**: `src/amoskys/core/*`, `src/amoskys/intel/*`, `src/amoskys/igris/*`
(excluding the `endpoint/` and `web/` subpackages) MUST NOT import ANY
`src/amoskys/agents/*`.

**Rule 4**: `src/amoskys/igris/endpoint/*` MUST NOT import
`src/amoskys/igris/web/*` and vice versa.

**Rule 5**: `src/amoskys/agents/common/*` MUST NOT import from os/ or Web/.

Implementing rule enforcement is straightforward:

```python
# scripts/check-import-contract.py
# Parses AST of every .py file in src/amoskys, builds import graph,
# fails CI if any forbidden edge exists.
```

Wire this into pre-commit and CI. It's a one-time cost.

## Storage rules

- Endpoint and web MUST NOT share a database. Endpoint uses its existing
  `fleet.db` (SQLite). Web will use its own Postgres database.
- They MAY share table schemas conceptually (e.g., both have a `devices` /
  `sites` concept) but the physical storage is separate.
- A tool that reads both is a future concern; today neither product reads the
  other's data.

## Configuration rules

- Each product has its own config namespace.
  - Endpoint config: `config/endpoint/` (existing `amoskys.yaml` moves here
    in the next refactor)
  - Web config: `config/web/` (new)
- The CLI dispatches to the right namespace based on subcommand:
  - `amoskys endpoint-agent` → endpoint config
  - `amoskys web-argos` → web config

## Dependency rules

One `pyproject.toml`, two optional-dependency extras:

```
[project.optional-dependencies]
endpoint = [...]  # macOS-specific packages
web = [...]       # Argos + ingest + dashboard packages
all = [...]       # union
```

CI installs both and runs both test suites on every PR, so breaking one is
caught immediately.

## CI rules

Matrix pipeline:
- `test-endpoint`: installs `[endpoint]`, runs `tests/endpoint/`
- `test-web`: installs `[web]`, runs `tests/web/`
- `test-core`: installs neither extra (only core deps), runs `tests/core/`
  (ensures core has no accidental OS or web deps)
- `import-contract`: runs the import-graph checker
- `lint-all`: flake8/black/isort over the whole tree

Any PR that touches `src/amoskys/agents/os/` runs `test-endpoint` as required.
Any PR that touches `src/amoskys/agents/Web/` runs `test-web` as required.
Any PR touching `src/amoskys/core/|intel/|igris/` runs all three.

## Git branching

Long-lived branches:
- `main` — both products deployable from here
- `amoskys-web/*` — web-product feature branches
- `endpoint/*` — endpoint-product feature branches

Short-lived branches as needed.

**Release tags** are per product:
- `web-v1.0.0` — a tagged release of AMOSKYS Web
- `endpoint-v2.1.3` — a tagged release of AMOSKYS endpoint
- Both products can be released from the same `main` commit at different
  times with different tags.

## CODEOWNERS (future)

When team grows past one person:

```
# .github/CODEOWNERS
src/amoskys/agents/os/             @endpoint-team
src/amoskys/agents/Web/            @web-team
src/amoskys/core/                  @platform-team
src/amoskys/igris/                 @platform-team
docs/web/                          @web-team
docs/endpoint/                     @endpoint-team
```

Until there's more than one person, this file is noise.

## Refactoring protocol

When shared code needs a breaking change:
1. Open an issue describing the change.
2. Get explicit sign-off from the "other" product's owner.
3. Bump shared-module version in a minor release.
4. Both products test against the bump in the same PR.
5. Merge only if both products' test suites pass.

Nothing fancy. Just the equivalent of library versioning, inside one repo.

## When to split (exit criteria)

Signals that it's time to split:

- Shared-code changes regularly break the "other" product's tests.
- Engineers are regularly rewriting parts of the wrong product by accident.
- Customer questions start with "is this an AMOSKYS Web issue or an endpoint
  issue?" more than 10% of the time (the products have bled together).
- Open-source strategy diverges (one becomes OSS, the other stays proprietary).
- Hiring: candidates who would be great at one product are turned off by the
  size of the repo.

If any of those triggers, split. Extract `amoskys-core` as a package, create
`amoskys-endpoint` and `amoskys-web` repos, publish `amoskys-core` to PyPI
(or private index). The split is mechanical if the import rules have been
obeyed throughout the monorepo's life.
