#!/usr/bin/env python3
"""Wire the v0.5 SQL sensor into the live lab plugin.

Steps (all idempotent):
  1. Copy class-aegis-sql-sensor.php into includes/
  2. Require + register it from amoskys-aegis.php
  3. Extend class-aegis-block.php with a sqli_attempt strike rule
     (threshold = 2 hits / 60s → immediate 10-min block).
  4. php -l + systemctl reload php8.3-fpm

Run as root on the lab:
    sudo python3 /tmp/wire_sql_sensor.py
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

PLUGIN_DIR = "/var/www/html/wp-content/plugins/amoskys-aegis"
INCLUDES = os.path.join(PLUGIN_DIR, "includes")
MAIN_PLUGIN = os.path.join(PLUGIN_DIR, "amoskys-aegis.php")
BLOCK_CLASS = os.path.join(INCLUDES, "class-aegis-block.php")
SQL_SENSOR_SRC = "/tmp/class-aegis-sql-sensor.php"
SQL_SENSOR_DST = os.path.join(INCLUDES, "class-aegis-sql-sensor.php")


def _read(p):
    return open(p, "r").read()


def _write(p, s):
    tmp = p + ".tmp"
    open(tmp, "w").write(s)
    os.chmod(tmp, 0o644)
    shutil.move(tmp, p)


def step_copy():
    if not os.path.exists(SQL_SENSOR_SRC):
        raise SystemExit(
            f"missing {SQL_SENSOR_SRC} — scp the file onto the lab first."
        )
    shutil.copy2(SQL_SENSOR_SRC, SQL_SENSOR_DST)
    os.chmod(SQL_SENSOR_DST, 0o644)
    # Preserve the file's ownership to match sibling classes.
    st = os.stat(BLOCK_CLASS)
    os.chown(SQL_SENSOR_DST, st.st_uid, st.st_gid)
    print(f"  ✓ copied sql-sensor → {SQL_SENSOR_DST}")


def step_main_plugin():
    s = _read(MAIN_PLUGIN)

    add_require = (
        "require_once AMOSKYS_AEGIS_PLUGIN_DIR . "
        "'includes/class-aegis-sql-sensor.php';"
    )
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-beacon.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require)
                break
        s = "\n".join(lines)
        print("  ✓ required class-aegis-sql-sensor.php")
    else:
        print("  = require already present")

    # Property declaration
    needle_prop = "private $beacon;"
    add_prop = "\n\t/** @var Amoskys_Aegis_Sql_Sensor */\n\tprivate $sql_sensor;"
    if "private $sql_sensor;" not in s:
        s = s.replace(needle_prop, needle_prop + add_prop, 1)
        print("  ✓ declared $sql_sensor property")
    else:
        print("  = property already declared")

    # Instantiation
    needle_inst = (
        "$this->beacon   = new Amoskys_Aegis_Beacon( $this->emitter );"
    )
    add_inst = (
        "\n\t\t$this->sql_sensor = new Amoskys_Aegis_Sql_Sensor( $this->emitter );"
    )
    if "$this->sql_sensor" not in s:
        s = s.replace(needle_inst, needle_inst + add_inst, 1)
        print("  ✓ instantiated $sql_sensor")
    else:
        print("  = already instantiated")

    # Register call — AFTER the beacon register.
    needle_reg = "$this->beacon->register();"
    add_reg = "\n\t\t$this->sql_sensor->register();"
    if "$this->sql_sensor->register()" not in s:
        s = s.replace(needle_reg, needle_reg + add_reg, 1)
        print("  ✓ registered $sql_sensor")
    else:
        print("  = already registered")

    _write(MAIN_PLUGIN, s)


def step_block_strike_rule():
    """Add sqli_attempt threshold = 2 to Amoskys_Aegis_Block."""
    s = _read(BLOCK_CLASS)

    needle_const = "const POI_ATTEMPT_LIMIT   = 1;"
    add_const = "\n\tconst SQLI_ATTEMPT_LIMIT  = 2; // two suspicious queries in 60s → block"
    if "SQLI_ATTEMPT_LIMIT" not in s:
        s = s.replace(needle_const, needle_const + add_const, 1)
        print("  ✓ added SQLI_ATTEMPT_LIMIT const")
    else:
        print("  = constant already present")

    # threshold_for switch
    needle_switch = "case 'poi_attempt': return self::POI_ATTEMPT_LIMIT;"
    add_switch = (
        "\n\t\t\tcase 'sqli_attempt': return self::SQLI_ATTEMPT_LIMIT;"
    )
    if "'sqli_attempt'" not in s:
        s = s.replace(needle_switch, needle_switch + add_switch, 1)
        print("  ✓ wired sqli_attempt into threshold_for()")
    else:
        print("  = already in switch")

    _write(BLOCK_CLASS, s)


def step_lint():
    for path in (MAIN_PLUGIN, BLOCK_CLASS, SQL_SENSOR_DST):
        r = subprocess.run(
            ["php", "-l", path], capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"  ✗ php lint failed on {path}:\n{r.stderr or r.stdout}")
            raise SystemExit(1)
        print(f"  ✓ lint ok {os.path.basename(path)}")


def step_reload():
    r = subprocess.run(
        ["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True
    )
    if r.returncode != 0:
        print(f"  ✗ FPM reload failed: {r.stderr}")
        raise SystemExit(1)
    print("  ✓ FPM reloaded")


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    step_copy()
    step_main_plugin()
    step_block_strike_rule()
    step_lint()
    step_reload()
    print("v0.5 SQL sensor wired and active.")


if __name__ == "__main__":
    main()
