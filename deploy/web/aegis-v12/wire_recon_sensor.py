#!/usr/bin/env python3
"""Wire v1.2 Recon-campaign sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-recon-sensor.php"
DST = f"{INC}/class-aegis-recon-sensor.php"


def _read(p): return open(p).read()
def _write(p, s):
    t = p + ".tmp"; open(t, "w").write(s); os.chmod(t, 0o644); shutil.move(t, p)


def main():
    if os.geteuid() != 0: sys.exit("run as root")
    if not os.path.exists(SRC): sys.exit(f"missing {SRC}")
    shutil.copy2(SRC, DST)
    st = os.stat(BLOCK); os.chown(DST, st.st_uid, st.st_gid); os.chmod(DST, 0o644)
    print(f"  ✓ copied → {DST}")

    s = _read(MAIN)
    add_require = ("require_once AMOSKYS_AEGIS_PLUGIN_DIR . "
                   "'includes/class-aegis-recon-sensor.php';")
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-ssrf-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require); break
        s = "\n".join(lines); print("  ✓ required")
    if "private $recon_sensor;" not in s:
        s = s.replace("private $ssrf_sensor;",
                      "private $ssrf_sensor;\n\t/** @var Amoskys_Aegis_Recon_Sensor */\n\tprivate $recon_sensor;", 1)
        print("  ✓ property")
    if "$this->recon_sensor" not in s:
        s = s.replace(
            "$this->ssrf_sensor   = new Amoskys_Aegis_Ssrf_Sensor( $this->emitter );",
            "$this->ssrf_sensor   = new Amoskys_Aegis_Ssrf_Sensor( $this->emitter );\n"
            "\t\t$this->recon_sensor  = new Amoskys_Aegis_Recon_Sensor( $this->emitter );", 1)
        print("  ✓ instantiated")
    if "$this->recon_sensor->register()" not in s:
        s = s.replace("$this->ssrf_sensor->register();",
                      "$this->ssrf_sensor->register();\n\t\t$this->recon_sensor->register();", 1)
        print("  ✓ registered")
    _write(MAIN, s)

    b = _read(BLOCK)
    if "RECON_CAMPAIGN_LIMIT" not in b:
        b = b.replace(
            "const SSRF_ATTEMPT_LIMIT  = 1;",
            "const SSRF_ATTEMPT_LIMIT  = 1;\n"
            "\tconst RECON_CAMPAIGN_LIMIT = 1; // 5 categories in 10m → instant block", 1)
        print("  ✓ added RECON_CAMPAIGN_LIMIT")
    if "'recon_campaign'" not in b:
        b = b.replace(
            "case 'ssrf_attempt':        return self::SSRF_ATTEMPT_LIMIT;",
            "case 'ssrf_attempt':        return self::SSRF_ATTEMPT_LIMIT;\n"
            "\t\t\tcase 'recon_campaign':      return self::RECON_CAMPAIGN_LIMIT;", 1)
        print("  ✓ wired recon_campaign in threshold_for")
    _write(BLOCK, b)

    for p in (MAIN, BLOCK, DST):
        r = subprocess.run(["php", "-l", p], capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"lint failed {p}: {r.stderr or r.stdout}")
    print("  ✓ lint ok")
    r = subprocess.run(["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True)
    if r.returncode != 0: sys.exit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")
    print("v1.2 recon-campaign sensor wired.")


if __name__ == "__main__":
    main()
