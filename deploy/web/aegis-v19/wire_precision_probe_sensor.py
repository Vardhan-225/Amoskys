#!/usr/bin/env python3
"""Wire v1.9 precision-probe sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-precision-probe-sensor.php"
DST = f"{INC}/class-aegis-precision-probe-sensor.php"


def _read(p):
    return open(p).read()


def _write(p, s):
    t = p + ".tmp"
    open(t, "w").write(s)
    os.chmod(t, 0o644)
    shutil.move(t, p)


def main():
    if os.geteuid() != 0:
        sys.exit("run as root")
    if not os.path.exists(SRC):
        sys.exit(f"missing {SRC}")
    shutil.copy2(SRC, DST)
    st = os.stat(BLOCK)
    os.chown(DST, st.st_uid, st.st_gid)
    os.chmod(DST, 0o644)
    print(f"  ✓ copied → {DST}")

    s = _read(MAIN)
    add_require = (
        "require_once AMOSKYS_AEGIS_PLUGIN_DIR . "
        "'includes/class-aegis-precision-probe-sensor.php';"
    )
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-scanner-shape-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require)
                break
        s = "\n".join(lines)
        print("  ✓ required")
    if "private $precision_probe_sensor;" not in s:
        s = s.replace(
            "private $scanner_shape_sensor;",
            "private $scanner_shape_sensor;\n\t/** @var Amoskys_Aegis_Precision_Probe_Sensor */\n\tprivate $precision_probe_sensor;",
            1,
        )
        print("  ✓ property")
    if "$this->precision_probe_sensor" not in s:
        s = s.replace(
            "$this->scanner_shape_sensor = new Amoskys_Aegis_Scanner_Shape_Sensor( $this->emitter );",
            "$this->scanner_shape_sensor = new Amoskys_Aegis_Scanner_Shape_Sensor( $this->emitter );\n"
            "\t\t$this->precision_probe_sensor = new Amoskys_Aegis_Precision_Probe_Sensor( $this->emitter );",
            1,
        )
        print("  ✓ instantiated")
    if "$this->precision_probe_sensor->register()" not in s:
        s = s.replace(
            "$this->scanner_shape_sensor->register();",
            "$this->scanner_shape_sensor->register();\n\t\t$this->precision_probe_sensor->register();",
            1,
        )
        print("  ✓ registered")
    _write(MAIN, s)

    b = _read(BLOCK)
    if "PRECISION_PROBE_LIMIT" not in b:
        b = b.replace(
            "const SCANNER_SHAPE_LIMIT  = 1;",
            "const SCANNER_SHAPE_LIMIT  = 1;\n"
            "\tconst PRECISION_PROBE_LIMIT = 1; // one targeted precision probe → block",
            1,
        )
        print("  ✓ added PRECISION_PROBE_LIMIT")
    if "'precision_probe'" not in b:
        b = b.replace(
            "case 'scanner_shape':       return self::SCANNER_SHAPE_LIMIT;",
            "case 'scanner_shape':       return self::SCANNER_SHAPE_LIMIT;\n"
            "\t\t\tcase 'precision_probe':     return self::PRECISION_PROBE_LIMIT;",
            1,
        )
        print("  ✓ wired precision_probe in threshold_for")
    _write(BLOCK, b)

    for p in (MAIN, BLOCK, DST):
        r = subprocess.run(["php", "-l", p], capture_output=True, text=True)
        if r.returncode != 0:
            sys.exit(f"lint failed {p}: {r.stderr or r.stdout}")
    print("  ✓ lint ok")
    r = subprocess.run(
        ["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True
    )
    if r.returncode != 0:
        sys.exit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")
    print("v1.9 precision-probe sensor wired.")


if __name__ == "__main__":
    main()
