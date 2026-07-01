#!/usr/bin/env python3
"""Wire v2.0 evasion sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-evasion-sensor.php"
DST = f"{INC}/class-aegis-evasion-sensor.php"


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
        "'includes/class-aegis-evasion-sensor.php';"
    )
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-precision-probe-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require)
                break
        s = "\n".join(lines)
        print("  ✓ required")
    if "private $evasion_sensor;" not in s:
        s = s.replace(
            "private $precision_probe_sensor;",
            "private $precision_probe_sensor;\n\t/** @var Amoskys_Aegis_Evasion_Sensor */\n\tprivate $evasion_sensor;",
            1,
        )
        print("  ✓ property")
    if "$this->evasion_sensor" not in s:
        s = s.replace(
            "$this->precision_probe_sensor = new Amoskys_Aegis_Precision_Probe_Sensor( $this->emitter );",
            "$this->precision_probe_sensor = new Amoskys_Aegis_Precision_Probe_Sensor( $this->emitter );\n"
            "\t\t$this->evasion_sensor = new Amoskys_Aegis_Evasion_Sensor( $this->emitter );",
            1,
        )
        print("  ✓ instantiated")
    if "$this->evasion_sensor->register()" not in s:
        s = s.replace(
            "$this->precision_probe_sensor->register();",
            "$this->precision_probe_sensor->register();\n\t\t$this->evasion_sensor->register();",
            1,
        )
        print("  ✓ registered")
    _write(MAIN, s)

    b = _read(BLOCK)
    if "EVASION_ATTEMPT_LIMIT" not in b:
        b = b.replace(
            "const PRECISION_PROBE_LIMIT = 1;",
            "const PRECISION_PROBE_LIMIT = 1;\n"
            "\tconst EVASION_ATTEMPT_LIMIT = 1; // one evasion-shaped request → block",
            1,
        )
        print("  ✓ added EVASION_ATTEMPT_LIMIT")
    if "'evasion_attempt'" not in b:
        b = b.replace(
            "case 'precision_probe':     return self::PRECISION_PROBE_LIMIT;",
            "case 'precision_probe':     return self::PRECISION_PROBE_LIMIT;\n"
            "\t\t\tcase 'evasion_attempt':     return self::EVASION_ATTEMPT_LIMIT;",
            1,
        )
        print("  ✓ wired evasion_attempt in threshold_for")
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
    print("v2.0 evasion sensor wired.")


if __name__ == "__main__":
    main()
