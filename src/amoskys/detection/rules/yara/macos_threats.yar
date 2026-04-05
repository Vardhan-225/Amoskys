/*
    AMOSKYS YARA Rules — macOS Threat Detection

    These rules detect known macOS malware families and suspicious patterns.
    Used by the FIM agent and file scanning pipeline.

    Coverage:
      - AMOS Stealer (Atomic macOS Stealer)
      - Poseidon Stealer
      - Banshee Stealer
      - Suspicious persistence mechanisms
      - Packed/encrypted binary indicators
      - Webshell patterns
*/

rule AMOS_Stealer_Strings
{
    meta:
        description = "Detects AMOS (Atomic macOS Stealer) by string artifacts"
        author = "AMOSKYS Detection Team"
        severity = "critical"
        mitre = "T1555,T1539,T1005"
        family = "AMOS"

    strings:
        $s1 = "Keychain" ascii
        $s2 = "Login Data" ascii
        $s3 = "Cookies" ascii
        $s4 = "wallet.dat" ascii
        $s5 = "exodus" ascii nocase
        $s6 = "metamask" ascii nocase
        $s7 = "AppleScript" ascii
        $s8 = "osascript" ascii
        $grab1 = "grabber" ascii nocase
        $grab2 = "stealer" ascii nocase
        $grab3 = "credentials" ascii nocase

    condition:
        uint32(0) == 0xFEEDFACF and  // Mach-O 64-bit magic
        ($s7 or $s8) and
        3 of ($s1, $s2, $s3, $s4, $s5, $s6) and
        1 of ($grab*)
}

rule Poseidon_Stealer
{
    meta:
        description = "Detects Poseidon Stealer for macOS"
        author = "AMOSKYS Detection Team"
        severity = "critical"
        mitre = "T1555.001,T1539"
        family = "Poseidon"

    strings:
        $plist = "com.apple.Safari" ascii
        $keychain = "security find-generic-password" ascii
        $dump = "security dump-keychain" ascii
        $telegram = "tdata" ascii
        $discord = "discord" ascii nocase
        $browser = "Chrome" ascii
        $exfil = "multipart/form-data" ascii

    condition:
        uint32(0) == 0xFEEDFACF and
        ($keychain or $dump) and
        2 of ($plist, $telegram, $discord, $browser) and
        $exfil
}

rule Banshee_Stealer
{
    meta:
        description = "Detects Banshee Stealer for macOS"
        author = "AMOSKYS Detection Team"
        severity = "critical"
        mitre = "T1555,T1059.002"
        family = "Banshee"

    strings:
        $xor_key = { 73 69 67 6E 61 74 75 72 65 }  // "signature" used as XOR key
        $as1 = "do shell script" ascii
        $as2 = "with administrator privileges" ascii
        $cred1 = "Passwords.db" ascii
        $cred2 = "logins.json" ascii
        $crypto1 = "Electrum" ascii
        $crypto2 = "Coinomi" ascii

    condition:
        uint32(0) == 0xFEEDFACF and
        ($as1 and $as2) and
        1 of ($cred*) and
        1 of ($crypto*)
}

rule Suspicious_LaunchAgent
{
    meta:
        description = "Detects suspicious LaunchAgent/LaunchDaemon plist patterns"
        author = "AMOSKYS Detection Team"
        severity = "high"
        mitre = "T1543.001,T1543.004"

    strings:
        $plist = "<?xml" ascii
        $label = "<key>Label</key>" ascii
        $prog = "<key>ProgramArguments</key>" ascii
        $hidden1 = "/tmp/" ascii
        $hidden2 = "/var/tmp/" ascii
        $hidden3 = "/Users/Shared/" ascii
        $hidden4 = ".hidden" ascii
        $script = "/bin/bash" ascii
        $curl = "curl" ascii
        $wget = "wget" ascii

    condition:
        $plist and $label and $prog and
        1 of ($hidden*) and
        ($script or $curl or $wget)
}

rule Mach_O_Packed_Binary
{
    meta:
        description = "Detects potentially packed or encrypted Mach-O binaries"
        author = "AMOSKYS Detection Team"
        severity = "medium"
        mitre = "T1027,T1027.002"

    strings:
        $upx = "UPX!" ascii
        $pyinst = "PYZ-00.pyz" ascii
        $nuitka = "nuitka" ascii nocase
        $encrypted_header = { CF FA ED FE 07 00 00 01 03 00 00 00 }

    condition:
        uint32(0) == 0xFEEDFACF and
        (
            $upx or $pyinst or $nuitka or
            // High entropy in first section (>7.5)
            math.entropy(0, filesize) > 7.5
        )
}

rule MacOS_Webshell
{
    meta:
        description = "Detects web shell scripts on macOS"
        author = "AMOSKYS Detection Team"
        severity = "high"
        mitre = "T1505.003"

    strings:
        $php1 = "<?php" ascii nocase
        $php2 = "eval(" ascii
        $php3 = "base64_decode" ascii
        $php4 = "system(" ascii
        $php5 = "exec(" ascii
        $php6 = "passthru(" ascii
        $py1 = "import subprocess" ascii
        $py2 = "os.system" ascii
        $py3 = "os.popen" ascii

    condition:
        ($php1 and 2 of ($php2, $php3, $php4, $php5, $php6)) or
        ($py1 and ($py2 or $py3))
}

rule Fake_DMG_Installer
{
    meta:
        description = "Detects fake installer DMGs used for malware delivery"
        author = "AMOSKYS Detection Team"
        severity = "high"
        mitre = "T1204.002"

    strings:
        $dmg_magic = { 78 01 73 0D 62 62 60 }
        $app_bundle = ".app/Contents/MacOS/" ascii
        $fake1 = "Adobe" ascii
        $fake2 = "Chrome" ascii
        $fake3 = "Zoom" ascii
        $fake4 = "Teams" ascii
        $unsigned = "com.apple.quarantine" ascii
        $dropper = "/bin/bash" ascii

    condition:
        $app_bundle and $dropper and
        1 of ($fake*) and
        filesize < 10MB
}

rule Credential_Harvester_Script
{
    meta:
        description = "Detects scripts that harvest credentials on macOS"
        author = "AMOSKYS Detection Team"
        severity = "critical"
        mitre = "T1555.001,T1056"

    strings:
        $script = "#!/bin/" ascii
        $keychain1 = "security find-generic-password" ascii
        $keychain2 = "security find-internet-password" ascii
        $keychain3 = "security dump-keychain" ascii
        $dialog = "osascript -e" ascii
        $password_prompt = "password" ascii nocase
        $exfil1 = "curl " ascii
        $exfil2 = "wget " ascii
        $exfil3 = "nc " ascii

    condition:
        $script and
        1 of ($keychain*) and
        ($dialog or $password_prompt) and
        1 of ($exfil*)
}
