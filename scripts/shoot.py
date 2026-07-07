#!/usr/bin/env python3
"""Screenshot AMOSKYS dashboard pages from the local preview server."""
import os
import sys
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8890"
OUT = os.environ.get(
    "SHOT_DIR",
    "/private/tmp/claude-501/-Users-athanneeru-Desktop/bc389485-63ba-4d3e-a3cc-505af1bd8278/scratchpad/shots",
)

pages = sys.argv[1:] or ["/dashboard/"]

os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 900})
    for path in pages:
        name = path.strip("/").replace("/", "_") or "home"
        try:
            pg.goto(BASE + path, wait_until="domcontentloaded", timeout=20000)
            pg.wait_for_timeout(4500)  # let JS-fetched data render
            f = f"{OUT}/{name}.png"
            pg.screenshot(path=f, full_page=False)
            print(f"OK  {path} -> {f}")
        except Exception as e:
            print(f"ERR {path}: {type(e).__name__}: {str(e)[:80]}")
    b.close()
