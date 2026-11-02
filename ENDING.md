# The end of AMOSKYS

AMOSKYS started on July 28, 2025 with one question: *what is my Mac actually talking to?*

It ended on November 2, 2026.

In between it grew into much more than an answer to that question: endpoint agents for macOS and Linux, a signed Endpoint Security sentinel running as root, a signed telemetry format, a fleet server, an autonomous analysis loop called IGRIS, a live dashboard with a globe, and a WordPress attack lab with its own sensor. That came to 639 commits, about 38,000 lines of code and more than 4,000 tests, almost all of it built by one person.

It never became a product. It had no users. It cost money every month, and the scope kept growing faster than it could be finished. Late on, its own audit showed the brain measuring its own output. That's a sign of a system nobody was depending on, including me.

So I shut it down. The servers are terminated, the data is gone, and the bill is zero. The code, the docs and the record of how it ended stay here.

## What I'm keeping

- How macOS really works underneath: Endpoint Security, unified logs, launchd, code signing, notarization.
- How detection is actually built: telemetry, correlation, scoring, and how easily scoring fools itself.
- Running real infrastructure: TLS, nginx, systemd, DNS, and what it all costs each month.
- One lesson: **pick one user and one problem, and ship to them before building the next thing.**

## If you're reading this

The code is MIT-licensed and free to learn from or take apart. Start with the [architecture audit](docs/architecture/AMOSKYS_ARCHITECTURE_AUDIT_2026-06-17.md). It's honest about what worked and what didn't. [docs/DISMANTLE.md](docs/DISMANTLE.md) records exactly how the project was shut down and how to rebuild it.

Thanks to everyone who looked at it, tested it or asked hard questions about it.

— Akash Thanneeru, November 2, 2026
