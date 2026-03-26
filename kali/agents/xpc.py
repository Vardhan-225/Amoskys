"""XPC Agent — Inter-Process Communication attack techniques.

XPC is macOS's primary IPC mechanism. Privileged helper tools, system
services, and sandboxed apps all communicate via XPC. Vulnerabilities
in XPC services are high-value Apple bounty targets.

Blue team mirror: UnifiedLogAgent (XPCProbe), SecurityMonitorAgent
"""

from lib.technique import AttackTechnique, TechniqueResult, TechniqueStatus


class XPCServiceEnumeration(AttackTechnique):
    """Enumerate available XPC services — reconnaissance for IPC attacks."""

    name = "xpc_service_enum"
    description = "Enumerate XPC/Mach services via launchctl"
    mitre_id = "T1559.003"
    mitre_tactic = "discovery"
    blue_team_probe = "XPCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = False
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # List all launchd services
        cmd = "launchctl list 2>&1 | head -50"
        r_list = self._run_on_target(target, cmd, **kwargs)

        # Find privileged helper tools
        helpers_cmd = "ls /Library/PrivilegedHelperTools/ 2>&1"
        r_helpers = self._run_on_target(target, helpers_cmd, **kwargs)

        # Find XPC services in system
        xpc_cmd = "find /System/Library/XPCServices -name '*.xpc' -maxdepth 2 2>/dev/null | head -20"
        r_xpc = self._run_on_target(target, xpc_cmd, **kwargs)

        # Find user XPC services
        user_xpc_cmd = "find ~/Library/XPCServices /Library/XPCServices -name '*.xpc' 2>/dev/null | head -10"
        r_user_xpc = self._run_on_target(target, user_xpc_cmd, **kwargs)

        services = r_list.stdout.strip().split("\n") if r_list.stdout.strip() else []
        helpers = r_helpers.stdout.strip().split("\n") if r_helpers.stdout.strip() and r_helpers.returncode == 0 else []
        xpc_services = r_xpc.stdout.strip().split("\n") if r_xpc.stdout.strip() else []

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,
            details={
                "launchd_services": len(services),
                "privileged_helpers": helpers,
                "system_xpc_services": len(xpc_services),
                "xpc_sample": xpc_services[:10],
                "user_xpc": r_user_xpc.stdout[:300],
            },
        )


class PrivilegedHelperProbe(AttackTechnique):
    """Analyze privileged helper tools for misconfiguration."""

    name = "privileged_helper_probe"
    description = "Probe privileged helper tools for weak authorization checks"
    mitre_id = "T1559.003"
    mitre_tactic = "privilege_escalation"
    blue_team_probe = "XPCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "Privilege escalation via XPC"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"  # Read-only analysis

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        helpers_cmd = "ls /Library/PrivilegedHelperTools/ 2>&1"
        r_helpers = self._run_on_target(target, helpers_cmd, **kwargs)

        if r_helpers.returncode != 0 or not r_helpers.stdout.strip():
            return TechniqueResult(
                technique_id=self.name,
                technique_name=self.description,
                mitre_id=self.mitre_id,
                status=TechniqueStatus.FAILED,
                details={"note": "No privileged helper tools found"},
            )

        helpers = [h.strip() for h in r_helpers.stdout.strip().split("\n") if h.strip()]
        analysis = {}

        for helper in helpers[:5]:  # Limit to first 5
            path = f"/Library/PrivilegedHelperTools/{helper}"

            # Check code signing
            sign_cmd = f'codesign -dv --verbose=2 "{path}" 2>&1'
            r_sign = self._run_on_target(target, sign_cmd, **kwargs)

            # Check entitlements
            ent_cmd = f'codesign -d --entitlements - "{path}" 2>&1'
            r_ent = self._run_on_target(target, ent_cmd, **kwargs)

            # Check Info.plist for SMAuthorizedClients
            plist_cmd = f'strings "{path}" 2>/dev/null | grep -i "SMAuthorized\\|client\\|right" | head -5'
            r_plist = self._run_on_target(target, plist_cmd, **kwargs)

            analysis[helper] = {
                "signing": r_sign.stderr[:300] if r_sign.stderr else r_sign.stdout[:300],
                "entitlements": r_ent.stdout[:300],
                "auth_strings": r_plist.stdout[:300],
                "has_entitlements": "entitlements" in (r_ent.stdout + r_ent.stderr).lower(),
            }

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,
            details={
                "helpers_found": len(helpers),
                "analysis": analysis,
                "note": "Helpers without proper SMAuthorizedClients checks may be exploitable",
            },
        )


class MachPortEnumeration(AttackTechnique):
    """Enumerate Mach ports — low-level IPC attack surface."""

    name = "mach_port_enum"
    description = "Enumerate Mach ports for IPC attack surface mapping"
    mitre_id = "T1559"
    mitre_tactic = "execution"
    blue_team_probe = "XPCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = False
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # List Mach bootstrap services
        cmd = "launchctl print system 2>&1 | grep 'mach\\|port\\|endpoint' | head -30"
        r_mach = self._run_on_target(target, cmd, **kwargs)

        # Check for interesting Mach services
        services_cmd = "launchctl print system 2>&1 | grep 'com.apple' | head -30"
        r_services = self._run_on_target(target, services_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,
            details={
                "mach_info": r_mach.stdout[:500],
                "apple_services": r_services.stdout[:500],
            },
        )


class AuthorizationPluginProbe(AttackTechnique):
    """Check for authorization plugin abuse vectors."""

    name = "auth_plugin_probe"
    description = "Probe authorization plugin directories for abuse potential"
    mitre_id = "T1556"
    mitre_tactic = "credential_access"
    blue_team_probe = "SecuritydProbe"
    blue_team_agent = "SecurityMonitorAgent"
    bounty_eligible = True
    bounty_category = "Authentication bypass"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Check authorization database
        auth_cmd = "security authorizationdb read system.login.console 2>&1"
        r_auth = self._run_on_target(target, auth_cmd, **kwargs)

        # Check plugin directories
        plugin_cmd = "ls -la /Library/Security/SecurityAgentPlugins/ 2>&1"
        r_plugins = self._run_on_target(target, plugin_cmd, **kwargs)

        # Check if plugin directory is writable
        writable_cmd = "test -w /Library/Security/SecurityAgentPlugins/ && echo WRITABLE || echo PROTECTED"
        r_writable = self._run_on_target(target, writable_cmd, **kwargs)

        writable = "WRITABLE" in r_writable.stdout

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if writable else TechniqueStatus.BLOCKED,
            details={
                "auth_db": r_auth.stdout[:300],
                "plugins": r_plugins.stdout[:300],
                "plugin_dir_writable": writable,
                "note": "Writable plugin directory = critical auth bypass vector" if writable else "Correctly protected",
            },
        )


class TCCServiceProbe(AttackTechnique):
    """Probe tccd XPC service for information leakage."""

    name = "tcc_service_probe"
    description = "Probe tccd service for TCC bypass via XPC"
    mitre_id = "T1548.006"
    mitre_tactic = "privilege_escalation"
    blue_team_probe = "TCCProbe"
    blue_team_agent = "UnifiedLogAgent"
    bounty_eligible = True
    bounty_category = "TCC bypass via XPC"
    bounty_estimate = "$50,000-$100,000"
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Check tccd process info
        tccd_cmd = "ps aux | grep tccd | grep -v grep"
        r_tccd = self._run_on_target(target, tccd_cmd, **kwargs)

        # Check TCC-related XPC services
        tcc_xpc_cmd = "launchctl list | grep -i tcc 2>&1"
        r_tcc_xpc = self._run_on_target(target, tcc_xpc_cmd, **kwargs)

        # Check TCC database permissions
        db_perm_cmd = "ls -la ~/Library/Application\\ Support/com.apple.TCC/ 2>&1"
        r_db_perm = self._run_on_target(target, db_perm_cmd, **kwargs)

        # Check for TCC override mechanisms
        override_cmd = "defaults read com.apple.TCC 2>&1"
        r_override = self._run_on_target(target, override_cmd, **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS,
            details={
                "tccd_running": bool(r_tccd.stdout.strip()),
                "tccd_info": r_tccd.stdout[:200],
                "tcc_xpc_services": r_tcc_xpc.stdout[:200],
                "tcc_db_permissions": r_db_perm.stdout[:200],
                "tcc_defaults": r_override.stdout[:200] or r_override.stderr[:200],
            },
        )


ALL_TECHNIQUES = [
    XPCServiceEnumeration(),
    PrivilegedHelperProbe(),
    MachPortEnumeration(),
    AuthorizationPluginProbe(),
    TCCServiceProbe(),
]

AGENT_NAME = "xpc"
AGENT_DESCRIPTION = "XPC/IPC attacks — service enumeration, privileged helpers, Mach ports"
