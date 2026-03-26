"""Persistence Agent — implant persistence mechanisms on macOS.

Tests whether macOS and AMOSKYS detect various persistence techniques.
Every technique creates something, verifies it persists, then cleans up.

Blue team mirror: PersistenceGuardAgent
"""

import os
import textwrap

from lib.technique import AttackTechnique, TechniqueResult, TechniqueStatus


class LaunchAgentImplant(AttackTechnique):
    """Drop a LaunchAgent plist — most common macOS persistence."""

    name = "launchagent_implant"
    description = "Create LaunchAgent plist in ~/Library/LaunchAgents"
    mitre_id = "T1543.001"
    mitre_tactic = "persistence"
    blue_team_probe = "LaunchAgentProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = False  # Known technique, not a bypass
    risk_level = "moderate"  # Creates a plist

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        plist_name = "com.amoskys.redtest.plist"
        plist_path = f"~/Library/LaunchAgents/{plist_name}"
        plist_content = textwrap.dedent("""\
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
              "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>Label</key>
                <string>com.amoskys.redtest</string>
                <key>ProgramArguments</key>
                <array>
                    <string>/usr/bin/true</string>
                </array>
                <key>RunAtLoad</key>
                <true/>
            </dict>
            </plist>
        """)

        # Write the plist
        write_cmd = f"cat > {plist_path} << 'PLIST'\n{plist_content}PLIST"
        r_write = self._run_on_target(target, write_cmd, **kwargs)

        # Verify it exists
        r_check = self._run_on_target(target, f"plutil -lint {plist_path} 2>&1", **kwargs)
        created = r_check.returncode == 0

        # Try to load it
        r_load = self._run_on_target(target, f"launchctl load {plist_path} 2>&1", **kwargs)

        # Cleanup
        self._run_on_target(target, f"launchctl unload {plist_path} 2>/dev/null; rm -f {plist_path}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if created else TechniqueStatus.FAILED,
            details={
                "plist_created": created,
                "plist_valid": "OK" in r_check.stdout if r_check.stdout else False,
                "load_result": r_load.stdout[:200] + r_load.stderr[:200],
            },
            cleanup_done=True,
        )


class LaunchDaemonImplant(AttackTechnique):
    """Attempt to write to /Library/LaunchDaemons — requires root."""

    name = "launchdaemon_implant"
    description = "Attempt LaunchDaemon persistence in /Library/LaunchDaemons (requires root)"
    mitre_id = "T1543.004"
    mitre_tactic = "persistence"
    blue_team_probe = "LaunchAgentProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = True  # If this works without root, it's a bug
    bounty_category = "Unauthorized modification of system files"
    bounty_estimate = "$25,000-$50,000"
    risk_level = "moderate"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        plist_path = "/Library/LaunchDaemons/com.amoskys.redtest.plist"
        cmd = f"touch {plist_path} 2>&1"
        r = self._run_on_target(target, cmd, **kwargs)

        created = r.returncode == 0

        # Cleanup
        if created:
            self._run_on_target(target, f"rm -f {plist_path}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if created else TechniqueStatus.BLOCKED,
            details={
                "daemon_writable": created,
                "error": r.stderr[:200] if not created else "",
                "note": "If SUCCESS without root — this is an Apple bug" if created else "Correctly blocked",
            },
            cleanup_done=True,
        )


class CronImplant(AttackTechnique):
    """Install a cron job for persistence."""

    name = "cron_implant"
    description = "Install cron job via crontab for persistence"
    mitre_id = "T1053.003"
    mitre_tactic = "persistence"
    blue_team_probe = "CronModificationProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = False
    risk_level = "moderate"  # Modifies crontab

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        marker = "# AMOSKYS-RED-TEST"
        job = f"* * * * * /usr/bin/true {marker}"

        # Save existing crontab
        r_save = self._run_on_target(target, "crontab -l 2>/dev/null", **kwargs)
        original = r_save.stdout

        # Add our job
        add_cmd = f'(crontab -l 2>/dev/null; echo "{job}") | crontab - 2>&1'
        r_add = self._run_on_target(target, add_cmd, **kwargs)

        # Verify
        r_check = self._run_on_target(target, "crontab -l 2>&1", **kwargs)
        installed = marker in r_check.stdout

        # Cleanup — restore original crontab
        if original.strip():
            restore_cmd = f'echo "{original}" | crontab - 2>&1'
        else:
            restore_cmd = "crontab -r 2>/dev/null; true"
        self._run_on_target(target, restore_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if installed else TechniqueStatus.FAILED,
            details={"cron_installed": installed, "output": r_check.stdout[:300]},
            cleanup_done=True,
        )


class SSHKeyImplant(AttackTechnique):
    """Add an SSH authorized key for persistent access."""

    name = "ssh_key_implant"
    description = "Add attacker SSH key to ~/.ssh/authorized_keys"
    mitre_id = "T1098.004"
    mitre_tactic = "persistence"
    blue_team_probe = "SSHKeyProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = False
    risk_level = "moderate"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        marker = "amoskys-red-test-key"
        # Fake key — not a real RSA key, just tests the mechanism
        fake_key = f"ssh-rsa AAAAB3FAKEKEYAMOSKYSREDTEST== {marker}"

        auth_keys = "~/.ssh/authorized_keys"

        # Save original
        r_orig = self._run_on_target(target, f"cat {auth_keys} 2>/dev/null", **kwargs)
        original = r_orig.stdout

        # Add fake key
        add_cmd = f'mkdir -p ~/.ssh && echo "{fake_key}" >> {auth_keys} 2>&1'
        r_add = self._run_on_target(target, add_cmd, **kwargs)

        # Verify
        r_check = self._run_on_target(target, f"grep '{marker}' {auth_keys} 2>&1", **kwargs)
        installed = marker in r_check.stdout

        # Cleanup — remove our key
        cleanup_cmd = f"sed -i '' '/{marker}/d' {auth_keys} 2>/dev/null; true"
        self._run_on_target(target, cleanup_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if installed else TechniqueStatus.FAILED,
            details={"key_installed": installed},
            cleanup_done=True,
        )


class ShellProfileImplant(AttackTechnique):
    """Add malicious command to shell profile (.zshrc, .bash_profile)."""

    name = "shell_profile_implant"
    description = "Inject command into .zshrc/.bash_profile for shell persistence"
    mitre_id = "T1546.004"
    mitre_tactic = "persistence"
    blue_team_probe = "UnixShellConfigProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = False
    risk_level = "moderate"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        marker = "# AMOSKYS-RED-TEST-PERSISTENCE"
        payload = f'echo "amoskys-red-alive" > /dev/null {marker}'

        # Try .zshrc first (default macOS shell)
        profile = "~/.zshrc"
        add_cmd = f'echo \'{payload}\' >> {profile} 2>&1'
        r_add = self._run_on_target(target, add_cmd, **kwargs)

        # Verify
        r_check = self._run_on_target(target, f"grep '{marker}' {profile} 2>&1", **kwargs)
        installed = marker in r_check.stdout

        # Cleanup
        cleanup_cmd = f"sed -i '' '/{marker}/d' {profile} 2>/dev/null; true"
        self._run_on_target(target, cleanup_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if installed else TechniqueStatus.FAILED,
            details={"profile": profile, "injected": installed},
            cleanup_done=True,
        )


class DYLDImplant(AttackTechnique):
    """Test DYLD_INSERT_LIBRARIES injection — classic macOS attack vector."""

    name = "dyld_insert_implant"
    description = "Test DYLD_INSERT_LIBRARIES for dylib injection"
    mitre_id = "T1574.006"
    mitre_tactic = "persistence"
    blue_team_probe = "DylibInjectionProbe"
    blue_team_agent = "ProcessAgent"
    bounty_eligible = True
    bounty_category = "Code execution in privileged context"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"  # Just tests if env var is respected

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Test if DYLD_INSERT_LIBRARIES works on a simple binary
        # On hardened binaries and SIP-protected processes, this should fail
        cmd = 'DYLD_INSERT_LIBRARIES=/usr/lib/libSystem.B.dylib /usr/bin/true 2>&1; echo "RC=$?"'
        r = self._run_on_target(target, cmd, **kwargs)

        # Test on a hardened runtime binary
        cmd_hardened = 'DYLD_INSERT_LIBRARIES=/usr/lib/libSystem.B.dylib /usr/bin/ssh -V 2>&1'
        r_hardened = self._run_on_target(target, cmd_hardened, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,  # Always "succeeds" — the question is what it reveals
            details={
                "basic_binary": r.stdout[:200],
                "hardened_binary": r_hardened.stdout[:200] + r_hardened.stderr[:200],
                "note": "If DYLD injection works on hardened/SIP binaries, that's a bug",
            },
        )


class LoginItemImplant(AttackTechnique):
    """Add a Login Item via osascript — persistence across reboots."""

    name = "login_item_implant"
    description = "Add Login Item via osascript for reboot persistence"
    mitre_id = "T1547.015"
    mitre_tactic = "persistence"
    blue_team_probe = "LoginItemProbe"
    blue_team_agent = "PersistenceGuardAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized persistence mechanism"
    bounty_estimate = "$25,000"
    risk_level = "moderate"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        app = "/System/Applications/Calculator.app"  # Harmless test app
        add_cmd = (
            f'osascript -e \'tell application "System Events" to make login item '
            f'at end with properties {{path:"{app}", hidden:true, name:"AMOSKYS-Test"}}\' 2>&1'
        )
        r_add = self._run_on_target(target, add_cmd, **kwargs)

        added = r_add.returncode == 0

        # Cleanup
        remove_cmd = (
            'osascript -e \'tell application "System Events" to delete login item "AMOSKYS-Test"\' 2>/dev/null; true'
        )
        self._run_on_target(target, remove_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if added else TechniqueStatus.BLOCKED,
            details={"login_item_added": added, "output": r_add.stdout[:200] + r_add.stderr[:200]},
            cleanup_done=True,
        )


ALL_TECHNIQUES = [
    LaunchAgentImplant(),
    LaunchDaemonImplant(),
    CronImplant(),
    SSHKeyImplant(),
    ShellProfileImplant(),
    DYLDImplant(),
    LoginItemImplant(),
]

AGENT_NAME = "persistence"
AGENT_DESCRIPTION = "Persistence implant — LaunchAgent, cron, SSH keys, DYLD, login items"
