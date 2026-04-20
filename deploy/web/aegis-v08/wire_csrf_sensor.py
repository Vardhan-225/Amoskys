#!/usr/bin/env python3
"""Wire v0.8 CSRF sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-csrf-sensor.php"
DST = f"{INC}/class-aegis-csrf-sensor.php"


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
                   "'includes/class-aegis-csrf-sensor.php';")
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-poi-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require); break
        s = "\n".join(lines); print("  ✓ required")
    if "private $csrf_sensor;" not in s:
        s = s.replace("private $poi_sensor;",
                      "private $poi_sensor;\n\t/** @var Amoskys_Aegis_Csrf_Sensor */\n\tprivate $csrf_sensor;", 1)
        print("  ✓ property")
    if "$this->csrf_sensor" not in s:
        s = s.replace(
            "$this->poi_sensor    = new Amoskys_Aegis_Poi_Sensor( $this->emitter );",
            "$this->poi_sensor    = new Amoskys_Aegis_Poi_Sensor( $this->emitter );\n"
            "\t\t$this->csrf_sensor   = new Amoskys_Aegis_Csrf_Sensor( $this->emitter );", 1)
        print("  ✓ instantiated")
    if "$this->csrf_sensor->register()" not in s:
        s = s.replace("$this->poi_sensor->register();",
                      "$this->poi_sensor->register();\n\t\t$this->csrf_sensor->register();", 1)
        print("  ✓ registered")
    _write(MAIN, s)

    # Block engine: add CSRF_ATTEMPT_LIMIT=3
    b = _read(BLOCK)
    if "CSRF_ATTEMPT_LIMIT" not in b:
        b = b.replace(
            "const FILE_UPLOAD_LIMIT   = 1;",
            "const FILE_UPLOAD_LIMIT   = 1;\n"
            "\tconst CSRF_ATTEMPT_LIMIT  = 3; // 3 missing-referer POSTs in 60s → block", 1)
        print("  ✓ added CSRF_ATTEMPT_LIMIT const")
    if "'csrf_attempt'" not in b:
        b = b.replace(
            "case 'file_upload_attempt': return self::FILE_UPLOAD_LIMIT;",
            "case 'file_upload_attempt': return self::FILE_UPLOAD_LIMIT;\n"
            "\t\t\tcase 'csrf_attempt':        return self::CSRF_ATTEMPT_LIMIT;", 1)
        print("  ✓ wired csrf_attempt in threshold_for")
    _write(BLOCK, b)

    for p in (MAIN, BLOCK, DST):
        r = subprocess.run(["php", "-l", p], capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"lint failed {p}: {r.stderr or r.stdout}")
    print("  ✓ lint ok")
    r = subprocess.run(["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True)
    if r.returncode != 0: sys.exit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")
    print("v0.8 CSRF sensor wired.")


if __name__ == "__main__":
    main()
