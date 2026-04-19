#!/usr/bin/env python3
"""Wire v0.6 Upload sensor into the live lab plugin. Idempotent."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

PLUGIN_DIR = "/var/www/html/wp-content/plugins/amoskys-aegis"
INCLUDES = os.path.join(PLUGIN_DIR, "includes")
MAIN = os.path.join(PLUGIN_DIR, "amoskys-aegis.php")
BLOCK_CLASS = os.path.join(INCLUDES, "class-aegis-block.php")
SRC = "/tmp/class-aegis-upload-sensor.php"
DST = os.path.join(INCLUDES, "class-aegis-upload-sensor.php")


def _read(p): return open(p).read()


def _write(p, s):
    tmp = p + ".tmp"
    open(tmp, "w").write(s)
    os.chmod(tmp, 0o644)
    shutil.move(tmp, p)


def step_copy():
    if not os.path.exists(SRC):
        raise SystemExit(f"missing {SRC}")
    shutil.copy2(SRC, DST)
    st = os.stat(BLOCK_CLASS)
    os.chown(DST, st.st_uid, st.st_gid)
    os.chmod(DST, 0o644)
    print(f"  ✓ copied → {DST}")


def step_main_plugin():
    s = _read(MAIN)

    add_require = (
        "require_once AMOSKYS_AEGIS_PLUGIN_DIR . "
        "'includes/class-aegis-upload-sensor.php';"
    )
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-sql-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require)
                break
        s = "\n".join(lines)
        print("  ✓ required upload sensor")
    else:
        print("  = require present")

    if "private $upload_sensor;" not in s:
        s = s.replace(
            "private $sql_sensor;",
            "private $sql_sensor;\n\t/** @var Amoskys_Aegis_Upload_Sensor */\n\tprivate $upload_sensor;",
            1,
        )
        print("  ✓ declared property")

    if "$this->upload_sensor" not in s:
        s = s.replace(
            "$this->sql_sensor = new Amoskys_Aegis_Sql_Sensor( $this->emitter );",
            "$this->sql_sensor = new Amoskys_Aegis_Sql_Sensor( $this->emitter );\n\t\t$this->upload_sensor = new Amoskys_Aegis_Upload_Sensor( $this->emitter );",
            1,
        )
        print("  ✓ instantiated")

    if "$this->upload_sensor->register()" not in s:
        s = s.replace(
            "$this->sql_sensor->register();",
            "$this->sql_sensor->register();\n\t\t$this->upload_sensor->register();",
            1,
        )
        print("  ✓ registered")

    _write(MAIN, s)


def step_block_strike_rule():
    s = _read(BLOCK_CLASS)
    if "FILE_UPLOAD_LIMIT" not in s:
        s = s.replace(
            "const SQLI_ATTEMPT_LIMIT  = 2;",
            "const SQLI_ATTEMPT_LIMIT  = 2;\n"
            "\tconst FILE_UPLOAD_LIMIT   = 1; // one dangerous upload → block",
            1,
        )
        print("  ✓ added FILE_UPLOAD_LIMIT const")
    if "'file_upload_attempt'" not in s:
        s = s.replace(
            "case 'sqli_attempt': return self::SQLI_ATTEMPT_LIMIT;",
            "case 'sqli_attempt': return self::SQLI_ATTEMPT_LIMIT;\n"
            "\t\t\tcase 'file_upload_attempt': return self::FILE_UPLOAD_LIMIT;",
            1,
        )
        print("  ✓ wired file_upload_attempt in switch")
    _write(BLOCK_CLASS, s)


def step_lint():
    for path in (MAIN, BLOCK_CLASS, DST):
        r = subprocess.run(["php", "-l", path], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  ✗ lint failed {path}:\n{r.stderr or r.stdout}")
            raise SystemExit(1)
    print("  ✓ lint ok on all 3 files")


def step_reload():
    r = subprocess.run(["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")


def main():
    if os.geteuid() != 0:
        sys.exit("run as root (sudo)")
    step_copy()
    step_main_plugin()
    step_block_strike_rule()
    step_lint()
    step_reload()
    print("v0.6 upload sensor wired.")


if __name__ == "__main__":
    main()
