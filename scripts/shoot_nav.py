#!/usr/bin/env python3
"""Screenshot the header nav with a dropdown group hovered open."""
import os
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8890"
OUT = "/private/tmp/claude-501/-Users-athanneeru-Desktop/0840796b-3999-4596-8533-dd66c22a5833/scratchpad/shots"
os.makedirs(OUT, exist_ok=True)

with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1440, "height": 640})
    pg.goto(BASE + "/dashboard/threats", wait_until="domcontentloaded", timeout=20000)
    pg.wait_for_timeout(1500)
    # hover the Detection group to open its dropdown
    try:
        pg.hover('[data-nav-group="detection"]')
        pg.wait_for_timeout(600)
    except Exception as e:
        print("hover detection failed:", e)
    pg.screenshot(path=f"{OUT}/nav_detection_open.png", full_page=False)
    print(f"OK nav_detection_open -> {OUT}/nav_detection_open.png")
    # hover Telemetry
    try:
        pg.hover('[data-nav-group="telemetry"]')
        pg.wait_for_timeout(600)
    except Exception as e:
        print("hover telemetry failed:", e)
    pg.screenshot(path=f"{OUT}/nav_telemetry_open.png", full_page=False)
    print(f"OK nav_telemetry_open -> {OUT}/nav_telemetry_open.png")
    b.close()
