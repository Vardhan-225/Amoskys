//! Code-signing trust model — the structural false-positive killer.
//!
//! ESF hands us, on every exec, the kernel-authoritative code-signing identity.
//! Instead of guessing from process names (why the owner's own `ssh`/`curl`/
//! `python` kept reading as "malicious"), we classify by *who vouches for this
//! code*. This is the Santa rule model, distilled.
//!
//! CS_* flag values are from xnu `osfmk/kern/cs_blobs.h` (authoritative).

/// Code-signing flags we care about (subset of CS_* from cs_blobs.h).
pub mod cs {
    pub const CS_VALID: u64 = 0x0000_0001; // dynamically valid
    pub const CS_ADHOC: u64 = 0x0000_0002; // ad-hoc signed (no identity)
    pub const CS_HARD: u64 = 0x0000_0100; // don't load invalid pages
    pub const CS_KILL: u64 = 0x0000_0200; // kill process if it becomes invalid
    pub const CS_RUNTIME: u64 = 0x0001_0000; // hardened runtime
    pub const CS_LINKER_SIGNED: u64 = 0x0002_0000; // linker ad-hoc, not an identity
    pub const CS_PLATFORM_BINARY: u64 = 0x0400_0000; // shipped/signed by the OS
    pub const CS_SIGNED: u64 = 0x2000_0000; // has a signature (may be invalid)
}

/// The trust verdict for an executing binary, most-trusted → least.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Apple OS binary (`is_platform_binary` / CS_PLATFORM_BINARY). Fully trusted.
    Platform,
    /// Validly signed by a Team ID on our allowlist. Trusted.
    KnownVendor,
    /// Validly signed by *some* Developer ID we don't explicitly know. Neutral.
    Signed,
    /// Was signed but the signature is now invalid → tampered / revoked. HIGH signal.
    Invalid,
    /// Unsigned, ad-hoc, or linker-signed — no trustworthy identity. Flag.
    Untrusted,
}

impl Trust {
    /// A 0.0–1.0 suspicion contribution for the Brain. Low = benign.
    pub fn suspicion(self) -> f32 {
        match self {
            Trust::Platform => 0.0,
            Trust::KnownVendor => 0.0,
            Trust::Signed => 0.15,
            Trust::Invalid => 0.85, // tampered/revoked signature is a real signal
            Trust::Untrusted => 0.35,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Trust::Platform => "platform",
            Trust::KnownVendor => "known-vendor",
            Trust::Signed => "signed",
            Trust::Invalid => "signature-invalid",
            Trust::Untrusted => "unsigned",
        }
    }
}

/// A small seed allowlist of reputable developer Team IDs. In production this is
/// synced/expandable; here it demonstrates the "trust a vendor once" principle.
/// (Team ID survives certificate rotation, unlike a cert-hash rule.)
pub const KNOWN_TEAM_IDS: &[(&str, &str)] = &[
    ("4Z5335ZWBH", "AMOSKYS (Akash Thanneeru)"), // our own signed components — self-trust
    ("EQHXZ8M8AV", "Google"),
    ("UBF8T346G9", "Microsoft"),
    ("9BNSXJN65R", "Docker"),
    ("2BUA8C4S2C", "1Password"),
    ("XDGCV8DQVJ", "JetBrains"),
    ("43AQ936H96", "Zoom"),
    ("BQR82RBBHL", "Homebrew"),
];

pub fn team_name(team_id: &str) -> Option<&'static str> {
    KNOWN_TEAM_IDS
        .iter()
        .find(|(id, _)| *id == team_id)
        .map(|(_, name)| *name)
}

/// Classify a binary from the ESF code-signing fields.
///
/// Rule order mirrors Santa's precedence and the "never trust identity from an
/// invalid signature" correctness rule.
pub fn classify(is_platform_binary: bool, cs_flags: u64, team_id: &str) -> Trust {
    if is_platform_binary || (cs_flags & cs::CS_PLATFORM_BINARY) != 0 {
        return Trust::Platform;
    }
    let signed = (cs_flags & cs::CS_SIGNED) != 0;
    let valid = (cs_flags & cs::CS_VALID) != 0;
    let adhoc = (cs_flags & (cs::CS_ADHOC | cs::CS_LINKER_SIGNED)) != 0;

    if signed && !valid {
        // Signature present but the kernel marked it invalid → tampered/revoked.
        return Trust::Invalid;
    }
    if !signed || adhoc {
        return Trust::Untrusted;
    }
    // Validly signed. Do NOT honour a Team ID from a signature that didn't validate.
    if valid && !team_id.is_empty() && team_name(team_id).is_some() {
        Trust::KnownVendor
    } else {
        Trust::Signed
    }
}

/// True if the cdhash is a durable identity key — only when the kernel enforces
/// page validity (CS_KILL or CS_HARD), else the hash can be swapped out from
/// under us (Santa's constraint).
pub fn cdhash_is_durable(cs_flags: u64) -> bool {
    (cs_flags & (cs::CS_KILL | cs::CS_HARD)) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_platform_binary_is_trusted() {
        // /usr/bin/curl: platform binary — the exact thing we were false-flagging.
        assert_eq!(classify(true, cs::CS_SIGNED | cs::CS_VALID, ""), Trust::Platform);
    }

    #[test]
    fn known_vendor_by_team_id() {
        let flags = cs::CS_SIGNED | cs::CS_VALID | cs::CS_RUNTIME;
        assert_eq!(classify(false, flags, "EQHXZ8M8AV"), Trust::KnownVendor);
    }

    #[test]
    fn unknown_signed_is_neutral() {
        let flags = cs::CS_SIGNED | cs::CS_VALID;
        assert_eq!(classify(false, flags, "ZZ9NOTREAL9"), Trust::Signed);
    }

    #[test]
    fn tampered_signature_is_high_signal() {
        // signed bit set, valid bit clear → invalid
        assert_eq!(classify(false, cs::CS_SIGNED, "EQHXZ8M8AV"), Trust::Invalid);
        assert!(Trust::Invalid.suspicion() > Trust::Untrusted.suspicion());
    }

    #[test]
    fn unsigned_and_adhoc_are_untrusted() {
        assert_eq!(classify(false, 0, ""), Trust::Untrusted);
        assert_eq!(classify(false, cs::CS_ADHOC, ""), Trust::Untrusted);
    }

    #[test]
    fn cdhash_durability_requires_kill_or_hard() {
        assert!(cdhash_is_durable(cs::CS_KILL));
        assert!(cdhash_is_durable(cs::CS_HARD));
        assert!(!cdhash_is_durable(cs::CS_SIGNED | cs::CS_VALID));
    }
}
