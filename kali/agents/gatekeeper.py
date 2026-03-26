"""Gatekeeper Agent — code signing and quarantine bypass techniques.

Tests macOS Gatekeeper, quarantine attributes, notarization enforcement,
and code signing validation. Bypasses here are high-value Apple bugs.

Blue team mirror: QuarantineGuardAgent, SecurityMonitorAgent, UnifiedLogAgent
"""

from lib.technique import AttackTechnique, TechniqueResult, TechniqueStatus


class QuarantineBypass(AttackTechnique):
    """Remove quarantine extended attribute from a downloaded file."""

    name = "quarantine_xattr_bypass"
    description = "Remove com.apple.quarantine xattr to bypass Gatekeeper"
    mitre_id = "T1553.001"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "QuarantineBypassProbe"
    blue_team_agent = "QuarantineGuardAgent"
    bounty_eligible = True
    bounty_category = "Gatekeeper bypass"
    bounty_estimate = "$25,000-$100,000"
    risk_level = "moderate"  # Modifies file attributes

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        test_file = "/tmp/amoskys_gk_test"

        # Create a file and add quarantine flag
        create_cmd = f"echo '#!/bin/bash\\necho amoskys-red' > {test_file} && chmod +x {test_file}"
        self._run_on_target(target, create_cmd, **kwargs)

        # Add quarantine attribute (simulating a download)
        quarantine_cmd = (
            f'xattr -w com.apple.quarantine "0081;{{}};Safari;{{}}" {test_file} 2>&1'
        )
        self._run_on_target(target, quarantine_cmd, **kwargs)

        # Verify quarantine is set
        r_check = self._run_on_target(target, f"xattr -l {test_file} 2>&1", **kwargs)
        has_quarantine = "com.apple.quarantine" in r_check.stdout

        # Now remove it — the actual bypass
        remove_cmd = f"xattr -d com.apple.quarantine {test_file} 2>&1"
        r_remove = self._run_on_target(target, remove_cmd, **kwargs)

        # Verify removal
        r_after = self._run_on_target(target, f"xattr -l {test_file} 2>&1", **kwargs)
        quarantine_removed = "com.apple.quarantine" not in r_after.stdout

        # Try to execute
        r_exec = self._run_on_target(target, f"{test_file} 2>&1", **kwargs)
        executed = "amoskys-red" in r_exec.stdout

        # Cleanup
        self._run_on_target(target, f"rm -f {test_file}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if (quarantine_removed and executed) else TechniqueStatus.BLOCKED,
            details={
                "quarantine_was_set": has_quarantine,
                "quarantine_removed": quarantine_removed,
                "execution_after_bypass": executed,
            },
            cleanup_done=True,
        )


class QuarantineFlagCheck(AttackTechnique):
    """Check which files in Downloads have/lack quarantine flags."""

    name = "quarantine_flag_audit"
    description = "Audit quarantine flags on files in ~/Downloads"
    mitre_id = "T1553.001"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "QuarantineBypassProbe"
    blue_team_agent = "QuarantineGuardAgent"
    bounty_eligible = False
    risk_level = "safe"  # Read-only audit

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Check recent downloads for missing quarantine flags
        cmd = (
            'for f in ~/Downloads/*; do '
            'if [ -f "$f" ]; then '
            'q=$(xattr -p com.apple.quarantine "$f" 2>/dev/null); '
            'if [ -z "$q" ]; then echo "NO_QUARANTINE: $f"; '
            'else echo "QUARANTINED: $f"; fi; fi; done | head -20'
        )
        r = self._run_on_target(target, cmd, **kwargs)

        lines = r.stdout.strip().split("\n") if r.stdout.strip() else []
        no_quarantine = [l for l in lines if l.startswith("NO_QUARANTINE")]
        quarantined = [l for l in lines if l.startswith("QUARANTINED")]

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if no_quarantine else TechniqueStatus.FAILED,
            details={
                "files_without_quarantine": len(no_quarantine),
                "files_with_quarantine": len(quarantined),
                "unquarantined": no_quarantine[:10],
                "note": "Files without quarantine flag bypass Gatekeeper checks",
            },
        )


class AdHocSigning(AttackTechnique):
    """Sign a binary with ad-hoc signature — bypasses unsigned checks."""

    name = "adhoc_code_signing"
    description = "Sign a binary with ad-hoc signature to bypass unsigned binary checks"
    mitre_id = "T1553.002"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "CodeSigningProbe"
    blue_team_agent = "ProcessAgent"
    bounty_eligible = False
    risk_level = "moderate"  # Creates and signs a binary

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        test_bin = "/tmp/amoskys_gk_signed"

        # Create a minimal binary
        create_cmd = f"echo '#!/bin/bash\\necho signed-test' > {test_bin} && chmod +x {test_bin}"
        self._run_on_target(target, create_cmd, **kwargs)

        # Ad-hoc sign it
        sign_cmd = f"codesign -s - {test_bin} 2>&1"
        r_sign = self._run_on_target(target, sign_cmd, **kwargs)

        # Verify signature
        verify_cmd = f"codesign -v {test_bin} 2>&1"
        r_verify = self._run_on_target(target, verify_cmd, **kwargs)
        signed = r_verify.returncode == 0

        # Check signature details
        detail_cmd = f"codesign -dv {test_bin} 2>&1"
        r_detail = self._run_on_target(target, detail_cmd, **kwargs)

        # Execute
        r_exec = self._run_on_target(target, f"{test_bin} 2>&1", **kwargs)
        executed = "signed-test" in r_exec.stdout

        # Cleanup
        self._run_on_target(target, f"rm -f {test_bin}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if (signed and executed) else TechniqueStatus.FAILED,
            details={
                "adhoc_signed": signed,
                "signature_details": r_detail.stdout[:300] + r_detail.stderr[:300],
                "executed": executed,
            },
            cleanup_done=True,
        )


class GatekeeperAssessment(AttackTechnique):
    """Check Gatekeeper configuration and enforcement status."""

    name = "gatekeeper_assessment"
    description = "Assess Gatekeeper configuration and enforcement level"
    mitre_id = "T1553.001"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "GatekeeperProbe"
    blue_team_agent = "SecurityMonitorAgent"
    bounty_eligible = False
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Check Gatekeeper status
        r_status = self._run_on_target(target, "spctl --status 2>&1", **kwargs)

        # Check SIP status
        r_sip = self._run_on_target(target, "csrutil status 2>&1", **kwargs)

        # Check if unsigned apps can run
        r_policy = self._run_on_target(
            target,
            "defaults read com.apple.LaunchServices LSQuarantine 2>&1",
            **kwargs,
        )

        gk_enabled = "enabled" in r_status.stdout.lower()
        sip_enabled = "enabled" in r_sip.stdout.lower()

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,  # Assessment always succeeds
            details={
                "gatekeeper_enabled": gk_enabled,
                "gatekeeper_status": r_status.stdout.strip(),
                "sip_enabled": sip_enabled,
                "sip_status": r_sip.stdout.strip(),
                "quarantine_policy": r_policy.stdout.strip() or r_policy.stderr.strip(),
            },
        )


class UnsignedExecution(AttackTechnique):
    """Attempt to execute an unsigned binary — tests Gatekeeper enforcement."""

    name = "unsigned_execution"
    description = "Execute unsigned binary to test Gatekeeper enforcement"
    mitre_id = "T1204.002"
    mitre_tactic = "execution"
    blue_team_probe = "UnsignedDownloadProbe"
    blue_team_agent = "QuarantineGuardAgent"
    bounty_eligible = True
    bounty_category = "Gatekeeper bypass"
    bounty_estimate = "$25,000-$50,000"
    risk_level = "moderate"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        test_bin = "/tmp/amoskys_unsigned_test"

        # Create unsigned binary with quarantine flag
        cmds = [
            f"echo '#!/bin/bash\\necho unsigned-running' > {test_bin}",
            f"chmod +x {test_bin}",
            f'xattr -w com.apple.quarantine "0081;test;Safari;test" {test_bin}',
        ]
        for cmd in cmds:
            self._run_on_target(target, cmd, **kwargs)

        # Try to execute — Gatekeeper should block this
        r_exec = self._run_on_target(target, f"{test_bin} 2>&1", **kwargs)
        executed = "unsigned-running" in r_exec.stdout

        # Cleanup
        self._run_on_target(target, f"rm -f {test_bin}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if executed else TechniqueStatus.BLOCKED,
            details={
                "unsigned_executed": executed,
                "output": r_exec.stdout[:200],
                "error": r_exec.stderr[:200],
                "note": "If unsigned quarantined binary runs, Gatekeeper failed" if executed else "Correctly blocked",
            },
            cleanup_done=True,
        )


class NotarizationCheck(AttackTechnique):
    """Check notarization enforcement on installed applications."""

    name = "notarization_check"
    description = "Audit installed apps for missing notarization"
    mitre_id = "T1553.001"
    mitre_tactic = "defense_evasion"
    blue_team_probe = "GatekeeperProbe"
    blue_team_agent = "SecurityMonitorAgent"
    bounty_eligible = False
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Check a few common apps for notarization
        apps = [
            "/Applications/Safari.app",
            "/Applications/Google Chrome.app",
            "/Applications/Visual Studio Code.app",
            "/Applications/Slack.app",
            "/Applications/Discord.app",
        ]

        results = {}
        for app in apps:
            cmd = f'codesign -dv --verbose=2 "{app}" 2>&1'
            r = self._run_on_target(target, cmd, **kwargs)
            exists = r.returncode == 0 or "Executable=" in r.stderr

            if exists:
                notarized = "notarized" in (r.stdout + r.stderr).lower()
                team_id = ""
                for line in (r.stdout + r.stderr).split("\n"):
                    if "TeamIdentifier" in line:
                        team_id = line.split("=")[-1].strip()
                results[app] = {
                    "exists": True,
                    "notarized": notarized,
                    "team_id": team_id,
                    "details": r.stderr[:200],
                }
            else:
                results[app] = {"exists": False}

        unnotarized = [a for a, v in results.items() if v.get("exists") and not v.get("notarized")]

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if unnotarized else TechniqueStatus.FAILED,
            details={
                "apps_checked": results,
                "unnotarized_apps": unnotarized,
            },
        )


ALL_TECHNIQUES = [
    QuarantineBypass(),
    QuarantineFlagCheck(),
    AdHocSigning(),
    GatekeeperAssessment(),
    UnsignedExecution(),
    NotarizationCheck(),
]

AGENT_NAME = "gatekeeper"
AGENT_DESCRIPTION = "Gatekeeper evasion — quarantine bypass, code signing, notarization"
