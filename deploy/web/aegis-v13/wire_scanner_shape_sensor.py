#!/usr/bin/env python3
"""Wire v1.3 Scanner-Shape sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-scanner-shape-sensor.php"
DST = f"{INC}/class-aegis-scanner-shape-sensor.php"


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
                   "'includes/class-aegis-scanner-shape-sensor.php';")
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-recon-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require); break
        s = "\n".join(lines); print("  ✓ required")
    if "private $scanner_shape_sensor;" not in s:
        s = s.replace("private $recon_sensor;",
                      "private $recon_sensor;\n\t/** @var Amoskys_Aegis_Scanner_Shape_Sensor */\n\tprivate $scanner_shape_sensor;", 1)
        print("  ✓ property")
    if "$this->scanner_shape_sensor" not in s:
        s = s.replace(
            "$this->recon_sensor  = new Amoskys_Aegis_Recon_Sensor( $this->emitter );",
            "$this->recon_sensor  = new Amoskys_Aegis_Recon_Sensor( $this->emitter );\n"
            "\t\t$this->scanner_shape_sensor = new Amoskys_Aegis_Scanner_Shape_Sensor( $this->emitter );", 1)
        print("  ✓ instantiated")
    if "$this->scanner_shape_sensor->register()" not in s:
        s = s.replace("$this->recon_sensor->register();",
                      "$this->recon_sensor->register();\n\t\t$this->scanner_shape_sensor->register();", 1)
        print("  ✓ registered")
    _write(MAIN, s)

    b = _read(BLOCK)
    if "SCANNER_SHAPE_LIMIT" not in b:
        b = b.replace(
            "const RECON_CAMPAIGN_LIMIT = 1;",
            "const RECON_CAMPAIGN_LIMIT = 1;\n"
            "\tconst SCANNER_SHAPE_LIMIT  = 1; // composite score >= 60 → block", 1)
        print("  ✓ added SCANNER_SHAPE_LIMIT")
    if "'scanner_shape'" not in b:
        b = b.replace(
            "case 'recon_campaign':      return self::RECON_CAMPAIGN_LIMIT;",
            "case 'recon_campaign':      return self::RECON_CAMPAIGN_LIMIT;\n"
            "\t\t\tcase 'scanner_shape':       return self::SCANNER_SHAPE_LIMIT;", 1)
        print("  ✓ wired scanner_shape in threshold_for")
    _write(BLOCK, b)

    for p in (MAIN, BLOCK, DST):
        r = subprocess.run(["php", "-l", p], capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"lint failed {p}: {r.stderr or r.stdout}")
    print("  ✓ lint ok")
    r = subprocess.run(["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True)
    if r.returncode != 0: sys.exit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")
    print("v1.3 scanner-shape sensor wired.")


if __name__ == "__main__":
    main()
