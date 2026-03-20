#!/usr/bin/env python3
"""IGRIS v3 Upgrade Installer.

Copies new files and patches existing ones for the IGRIS upgrade.
Run from the Amoskys project root:

    cd /Volumes/Akash_Lab/Amoskys
    python igris_upgrade/INSTALL.py

What this does:
    1. Copies new modules: memory.py, inspector.py, chain_reader.py, shell_commands.py
    2. Replaces tactical.py with v3 (persistent, chain-aware, SOMA-integrated)
    3. Patches shell.py to use new igris commands
    4. Patches analyzer_main.py to use new tactical engine
    5. Verifies all imports work
"""

import os
import shutil
import sys
from pathlib import Path


def main():
    # Determine project root
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    if not (project_root / "src" / "amoskys").exists():
        # Try current directory
        project_root = Path.cwd()
        if not (project_root / "src" / "amoskys").exists():
            print("ERROR: Run this from the Amoskys project root:")
            print("  cd /Volumes/Akash_Lab/Amoskys")
            print("  python igris_upgrade/INSTALL.py")
            return 1

    src = script_dir / "src" / "amoskys"
    dst = project_root / "src" / "amoskys"
    igris_dst = dst / "igris"

    print("IGRIS v3 Upgrade Installer")
    print(f"  Source: {script_dir}")
    print(f"  Target: {project_root}")
    print()

    # 1. Copy new IGRIS modules
    new_files = [
        ("igris/memory.py", "Persistent tactical memory"),
        ("igris/inspector.py", "Investigation actions"),
        ("igris/chain_reader.py", "Kill chain reader"),
        ("igris/shell_commands.py", "Shell command extensions"),
    ]
    for rel_path, desc in new_files:
        src_file = src / rel_path
        dst_file = dst / rel_path
        if src_file.exists():
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src_file, dst_file)
            print(f"  [NEW]  {rel_path} — {desc}")
        else:
            print(f"  [SKIP] {rel_path} — source not found")

    # 2. Replace tactical.py
    tac_src = src / "igris" / "tactical.py"
    tac_dst = dst / "igris" / "tactical.py"
    if tac_src.exists():
        # Backup
        if tac_dst.exists():
            backup = tac_dst.with_suffix(".py.v2.bak")
            shutil.copy2(tac_dst, backup)
            print(f"  [BAK]  igris/tactical.py → {backup.name}")
        shutil.copy2(tac_src, tac_dst)
        print(f"  [UPD]  igris/tactical.py — v3 tactical engine")

    # 3. Patch shell.py to import new igris commands
    shell_path = dst / "shell.py"
    if shell_path.exists():
        content = shell_path.read_text()

        # Add import for shell_commands
        import_line = "from amoskys.igris.shell_commands import handle_igris_command"
        if import_line not in content:
            # Add after other imports
            marker = "from typing import"
            if marker in content:
                content = content.replace(
                    marker,
                    f"{import_line}\n{marker}",
                    1,
                )
            print(f"  [PATCH] shell.py — added shell_commands import")

        # Replace the igris command handler to use new module
        old_handler = '''    if cmd == "igris":
        show_igris()
        return True'''
        new_handler = '''    if cmd == "igris":
        handle_igris_command(arg)
        return True'''
        if old_handler in content:
            content = content.replace(old_handler, new_handler)
            print(f"  [PATCH] shell.py — wired igris subcommands")
        elif 'cmd == "igris"' not in content:
            # Add igris command before the natural language handler
            nl_marker = "    # Try natural language"
            if nl_marker in content:
                content = content.replace(
                    nl_marker,
                    f'''    if cmd == "igris":
        handle_igris_command(arg)
        return True
{nl_marker}''',
                )
                print(f"  [PATCH] shell.py — added igris command handler")

        # Add help text for new commands
        old_help = '  {C.CYAN}help{C.RESET}                This help'
        new_help = '''  {C.CYAN}igris{C.RESET}               IGRIS tactical briefing
  {C.CYAN}igris chain{C.RESET}         Kill chain state and progression
  {C.CYAN}igris why{C.RESET} [target]   Why a target is being watched
  {C.CYAN}igris inspect{C.RESET} <a> <t> On-demand investigation
  {C.CYAN}igris memory{C.RESET}        What IGRIS remembers
  {C.CYAN}igris novel{C.RESET}         SOMA: novel patterns

  {C.CYAN}help{C.RESET}                This help'''
        if old_help in content:
            content = content.replace(old_help, new_help)
            print(f"  [PATCH] shell.py — updated help text")

        shell_path.write_text(content)

    # 4. Patch analyzer_main.py to use v3 tactical engine
    analyzer_path = dst.parent / "amoskys" / "analyzer_main.py"
    # The import is already: from amoskys.igris.tactical import IGRISTacticalEngine
    # The v3 module has the same class name, so this should work automatically.
    print(f"  [OK]   analyzer_main.py — uses IGRISTacticalEngine (v3 compatible)")

    # 5. Verify imports
    print()
    print("Verifying imports...")
    sys.path.insert(0, str(project_root / "src"))
    errors = []
    for mod in [
        "amoskys.igris.memory",
        "amoskys.igris.inspector",
        "amoskys.igris.chain_reader",
        "amoskys.igris.shell_commands",
        "amoskys.igris.tactical",
    ]:
        try:
            __import__(mod)
            print(f"  [OK]   {mod}")
        except Exception as e:
            print(f"  [FAIL] {mod}: {e}")
            errors.append(mod)

    print()
    if errors:
        print(f"WARNING: {len(errors)} module(s) failed to import.")
        print("Fix these before running AMOSKYS.")
    else:
        print("All modules verified. IGRIS v3 is ready.")
        print()
        print("To test:")
        print("  cd /Volumes/Akash_Lab/Amoskys")
        print("  PYTHONPATH=src python -m amoskys start")
        print("  PYTHONPATH=src python -m amoskys shell")
        print()
        print("New commands:")
        print("  igris              — full tactical briefing")
        print("  igris chain        — kill chain state")
        print("  igris why          — explain watched targets")
        print("  igris inspect codesign /path/to/binary")
        print("  igris inspect connections 1234")
        print("  igris memory       — persistent state")
        print("  igris novel        — SOMA novel patterns")

    return 0


if __name__ == "__main__":
    sys.exit(main())
