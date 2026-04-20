#!/usr/bin/env python3
"""Wire v0.9 SSRF sensor. Idempotent."""
from __future__ import annotations
import os, shutil, subprocess, sys

PLUGIN = "/var/www/html/wp-content/plugins/amoskys-aegis"
INC = f"{PLUGIN}/includes"
MAIN = f"{PLUGIN}/amoskys-aegis.php"
BLOCK = f"{INC}/class-aegis-block.php"
SRC = "/tmp/class-aegis-ssrf-sensor.php"
DST = f"{INC}/class-aegis-ssrf-sensor.php"


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
                   "'includes/class-aegis-ssrf-sensor.php';")
    if add_require not in s:
        lines = s.split("\n")
        for i, ln in enumerate(lines):
            if "class-aegis-csrf-sensor.php" in ln and "require_once" in ln:
                lines.insert(i + 1, add_require); break
        s = "\n".join(lines); print("  ✓ required")
    if "private $ssrf_sensor;" not in s:
        s = s.replace("private $csrf_sensor;",
                      "private $csrf_sensor;\n\t/** @var Amoskys_Aegis_Ssrf_Sensor */\n\tprivate $ssrf_sensor;", 1)
        print("  ✓ property")
    if "$this->ssrf_sensor" not in s:
        s = s.replace(
            "$this->csrf_sensor   = new Amoskys_Aegis_Csrf_Sensor( $this->emitter );",
            "$this->csrf_sensor   = new Amoskys_Aegis_Csrf_Sensor( $this->emitter );\n"
            "\t\t$this->ssrf_sensor   = new Amoskys_Aegis_Ssrf_Sensor( $this->emitter );", 1)
        print("  ✓ instantiated")
    if "$this->ssrf_sensor->register()" not in s:
        s = s.replace("$this->csrf_sensor->register();",
                      "$this->csrf_sensor->register();\n\t\t$this->ssrf_sensor->register();", 1)
        print("  ✓ registered")
    _write(MAIN, s)

    b = _read(BLOCK)
    if "SSRF_ATTEMPT_LIMIT" not in b:
        b = b.replace(
            "const CSRF_ATTEMPT_LIMIT  = 3;",
            "const CSRF_ATTEMPT_LIMIT  = 3;\n"
            "\tconst SSRF_ATTEMPT_LIMIT  = 1; // any critical-class SSRF → block", 1)
        print("  ✓ added SSRF_ATTEMPT_LIMIT")
    if "'ssrf_attempt'" not in b:
        b = b.replace(
            "case 'csrf_attempt':        return self::CSRF_ATTEMPT_LIMIT;",
            "case 'csrf_attempt':        return self::CSRF_ATTEMPT_LIMIT;\n"
            "\t\t\tcase 'ssrf_attempt':        return self::SSRF_ATTEMPT_LIMIT;", 1)
        print("  ✓ wired ssrf_attempt in threshold_for")
    _write(BLOCK, b)

    for p in (MAIN, BLOCK, DST):
        r = subprocess.run(["php", "-l", p], capture_output=True, text=True)
        if r.returncode != 0: sys.exit(f"lint failed {p}: {r.stderr or r.stdout}")
    print("  ✓ lint ok")
    r = subprocess.run(["systemctl", "reload", "php8.3-fpm"], capture_output=True, text=True)
    if r.returncode != 0: sys.exit(f"FPM reload failed: {r.stderr}")
    print("  ✓ FPM reloaded")
    print("v0.9 SSRF sensor wired.")


if __name__ == "__main__":
    main()
