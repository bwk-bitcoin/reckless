//! Key record model for Reckless's hardware/software key registry.
//!
//! A key is identified by its master fingerprint, one record per fingerprint, and
//! records are scoped per network: the same seed on testnet and on mainnet are two
//! separate records.

pub mod bridge;
pub mod crypto;
pub mod error;
pub mod hot;
pub mod ledger_nonces;
pub mod manager;
pub mod musig_sessions;
pub mod portable;
pub mod psbt;
pub mod qr;
pub mod record;
pub mod sdcard;
pub mod store;

pub use bridge::{new_keys_module, KeysModule};
pub use crypto::Password;
pub use error::Error;
pub use hot::{generate_mnemonic, MNEMONIC_WORDS_LONG, MNEMONIC_WORDS_SHORT};
pub use manager::{KeyManager, KeyManagerImpl, LiveDevice};
pub use psbt::{inspect, PsbtArtifacts};
pub use record::{
    DescriptorEntry, DeviceRecord, KeyRecord, RouteKind, Routes, SecretEnvelope, XpubEntry,
};
pub use store::KeyStore;

use bipqr::ll::response::Capabilities;

/// Bump when `KeyRecord`'s on-disk shape changes in a way older Reckless versions cannot
/// read. `KeyRecord::check_version` refuses to load anything greater than this.
pub const KEY_RECORD_VERSION: u32 = 1;

/// Directory name (under the account/module data dir) where key records are stored.
pub const KEYS_DIR_NAME: &str = "keys";

/// The capability bits a device reports, a USB one and a QR one alike: bipqr's
/// `CAPABILITIES` field (ENCODING.md), as `bipqr::ll::response::Capabilities` names
/// them (ws-plaude/silent#139). A QR device's bits are read as they come, its unknown
/// ones dropped; a USB device or a plugin signer is described with the same bits.
pub const CAPABILITY_BIP380_DESCRIPTORS: u32 = Capabilities::BIP380_DESCRIPTORS;
pub const CAPABILITY_BIP388_POLICIES: u32 = Capabilities::BIP388_WALLET_POLICIES;
/// Miniscript under SegWit v0: the ordinary signing every key does.
pub const CAPABILITY_ORDINARY: u32 = Capabilities::MINISCRIPT_SEGWIT_V0;
pub const CAPABILITY_TAPROOT: u32 = Capabilities::MINISCRIPT_TAPROOT;
/// Signs a transaction paying silent payment outputs (BIP-375 shares and proofs).
pub const CAPABILITY_SP_SENDS: u32 = Capabilities::SILENT_PAYMENT_SENDS;
/// Holds silent payment accounts: their `m/352'` keys, addresses and received outputs.
pub const CAPABILITY_SP_ACCOUNTS: u32 = Capabilities::SILENT_PAYMENT_ACCOUNTS;
pub const CAPABILITY_UNREGISTER: u32 = Capabilities::UNREGISTER_DESCRIPTOR;
pub const CAPABILITY_MUSIG: u32 = Capabilities::MUSIG2;
/// The device issues MuSig2 nonces ahead of any transaction and signs with them in one
/// round, from its nonce cache sessions.
pub const CAPABILITY_MUSIG_CACHE: u32 = Capabilities::NONCE_CACHE;
/// Silent payments as a USB device or a plugin signer reports them: one support, both
/// bits.
pub const CAPABILITY_SILENT_PAYMENTS: u32 = CAPABILITY_SP_SENDS | CAPABILITY_SP_ACCOUNTS;

/// The layout `DeviceRecord::capabilities` is stored in: 1 is bipqr `d7363e0`'s. A
/// record without one was stored with the earlier layout and is converted on load.
pub const CAPABILITY_LAYOUT: u32 = 1;

/// A QR device's reported bits, as Reckless keeps them: the bits this version defines.
pub fn qr_capabilities(reported: u32) -> u32 {
    reported & Capabilities::DEFINED
}

/// `stored` in the earlier layout (bit 0 SegWit miniscript, 1 Taproot, 2 silent
/// payments, 3 MuSig2, 4 nonce cache, 5 PSBT trimming), in the current one. A QR device
/// of that layout took BIP-380 descriptors; PSBT trimming has no bit any more.
pub fn upgrade_capabilities(stored: u32, qr: bool) -> u32 {
    let mut bits = 0;
    for (old, new) in [
        (1 << 0, CAPABILITY_ORDINARY),
        (1 << 1, CAPABILITY_TAPROOT),
        (1 << 2, CAPABILITY_SILENT_PAYMENTS),
        (1 << 3, CAPABILITY_MUSIG),
        (1 << 4, CAPABILITY_MUSIG_CACHE),
    ] {
        if stored & old != 0 {
            bits |= new;
        }
    }
    if qr && stored != 0 {
        bits |= CAPABILITY_BIP380_DESCRIPTORS;
    }
    bits
}

/// Full signing metadata for a supported HWI record; locked records export no bits.
pub fn hwi_device_capabilities(
    kind: &bwk_hwi::DeviceKind,
    version: Option<&bwk_hwi::Version>,
) -> u32 {
    let capabilities = bwk_hwi::service::capabilities(kind, version);
    let mut bits = CAPABILITY_ORDINARY | hwi_capabilities(capabilities);
    let taproot_kind = match kind {
        bwk_hwi::DeviceKind::LedgerSimulator => &bwk_hwi::DeviceKind::Ledger,
        kind => kind,
    };
    if bwk_hwi::service::is_compatible_with_tapminiscript(taproot_kind, version) {
        bits |= CAPABILITY_TAPROOT;
    }
    bits
}

/// The capability bits of a device bwk-hwi lists.
pub fn hwi_capabilities(capabilities: bwk_hwi::service::Capabilities) -> u32 {
    let mut bits = 0;
    if capabilities.silent_payments {
        bits |= CAPABILITY_SILENT_PAYMENTS;
    }
    if capabilities.musig {
        bits |= CAPABILITY_MUSIG;
    }
    bits
}

/// Whether `capabilities` include silent payment accounts: the `m/352'` keys and the
/// accounts built on them.
pub fn supports_silent_payments(capabilities: u32) -> bool {
    capabilities & CAPABILITY_SP_ACCOUNTS != 0
}

/// The capability bits, for the C++ side.
pub fn capability_bits() -> crate::ffi::CapabilityBits {
    crate::ffi::CapabilityBits {
        ordinary: CAPABILITY_ORDINARY,
        taproot: CAPABILITY_TAPROOT,
        silent_payments: CAPABILITY_SILENT_PAYMENTS,
        musig2: CAPABILITY_MUSIG,
    }
}

/// Whether the device implements Unregister Descriptor.
pub fn supports_unregister(capabilities: u32) -> bool {
    capabilities & CAPABILITY_UNREGISTER != 0
}

/// Whether `capabilities` include MuSig2.
pub fn supports_musig(capabilities: u32) -> bool {
    capabilities & CAPABILITY_MUSIG != 0
}

/// The network name used both for directory layout and as crypto associated data, so
/// the two always agree.
pub fn network_name(network: bitcoin::Network) -> Result<&'static str, Error> {
    match network {
        bitcoin::Network::Bitcoin => Ok("bitcoin"),
        bitcoin::Network::Testnet => Ok("testnet"),
        bitcoin::Network::Signet => Ok("signet"),
        bitcoin::Network::Regtest => Ok("regtest"),
        _ => Err(Error::UnsupportedNetwork(network.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwi_capabilities_maps_to_the_bwk_qr_bits() {
        for (silent_payments, musig, bits) in [
            (false, false, 0),
            (true, false, CAPABILITY_SILENT_PAYMENTS),
            (false, true, CAPABILITY_MUSIG),
            (true, true, CAPABILITY_SILENT_PAYMENTS | CAPABILITY_MUSIG),
        ] {
            let mapped = hwi_capabilities(bwk_hwi::service::Capabilities {
                silent_payments,
                musig,
            });
            assert_eq!(
                mapped, bits,
                "silent_payments {silent_payments}, musig {musig}: expected {bits:#x}, got {mapped:#x}"
            );
            assert_eq!(
                supports_silent_payments(mapped),
                silent_payments,
                "supports_silent_payments({mapped:#x})"
            );
        }
    }

    // ws-plaude/silent#139: bipqr d7363e0's layout.
    #[test]
    fn a_kern_on_the_new_layout_reads_its_capabilities() {
        // Kern ddf6fc7 answers every bit; 0xFD is one without policies and the cache.
        let all = qr_capabilities(0x0000_01ff);
        assert!(supports_silent_payments(all) && supports_musig(all) && supports_unregister(all));
        assert_ne!(all & CAPABILITY_MUSIG_CACHE, 0, "the nonce cache");
        assert_ne!(all & CAPABILITY_BIP388_POLICIES, 0, "wallet policies");
        let fd = qr_capabilities(0x0000_00fd);
        assert!(
            supports_silent_payments(fd),
            "bit 5: silent payment accounts, m/352'"
        );
        assert!(supports_musig(fd), "bit 7: MuSig2");
        assert!(supports_unregister(fd), "bit 6: Unregister Descriptor");
        assert_eq!(fd & CAPABILITY_MUSIG_CACHE, 0, "no nonce cache");
        assert_eq!(fd & CAPABILITY_BIP388_POLICIES, 0, "no wallet policies");
        assert_eq!(
            fd & (CAPABILITY_ORDINARY | CAPABILITY_TAPROOT | CAPABILITY_BIP380_DESCRIPTORS),
            CAPABILITY_ORDINARY | CAPABILITY_TAPROOT | CAPABILITY_BIP380_DESCRIPTORS,
            "SegWit and Taproot miniscript, BIP-380 descriptors"
        );
        assert_eq!(
            qr_capabilities(0x0000_01ff | 1 << 20 | 1 << 31),
            all,
            "a reserved bit is ignored, not kept"
        );
    }

    #[test]
    fn capabilities_stored_in_the_earlier_layout_upgrade() {
        // A Kern stored before: miniscript v0, Taproot, SP, MuSig2, nonce cache.
        assert_eq!(
            upgrade_capabilities(0x1f, true),
            CAPABILITY_BIP380_DESCRIPTORS
                | CAPABILITY_ORDINARY
                | CAPABILITY_TAPROOT
                | CAPABILITY_SP_SENDS
                | CAPABILITY_SP_ACCOUNTS
                | CAPABILITY_MUSIG
                | CAPABILITY_MUSIG_CACHE,
            "the same capabilities, and the descriptors it always took"
        );
        assert_eq!(
            upgrade_capabilities(0x3f, true),
            upgrade_capabilities(0x1f, true),
            "PSBT trimming has no bit any more"
        );
        assert_eq!(
            upgrade_capabilities(0b1011, false),
            CAPABILITY_ORDINARY | CAPABILITY_TAPROOT | CAPABILITY_MUSIG,
            "a USB device takes no descriptor form bit"
        );
        assert_eq!(
            upgrade_capabilities(0, true),
            0,
            "nothing reported stays nothing"
        );
        assert!(
            !supports_unregister(upgrade_capabilities(0x1f, true)),
            "unknown before"
        );
    }

    #[test]
    fn hwi_device_capabilities_use_provider_kind_and_version() {
        let version = |minor| bwk_hwi::Version {
            major: 2,
            minor,
            patch: 0,
            prerelease: None,
        };
        let ordinary = CAPABILITY_ORDINARY;
        let taproot = ordinary | CAPABILITY_TAPROOT;
        let musig = taproot | CAPABILITY_MUSIG;
        for (kind, firmware, expected) in [
            (bwk_hwi::DeviceKind::Ledger, Some(version(1)), ordinary),
            (bwk_hwi::DeviceKind::Ledger, Some(version(2)), taproot),
            (bwk_hwi::DeviceKind::Ledger, Some(version(4)), musig),
            (
                bwk_hwi::DeviceKind::LedgerSimulator,
                Some(version(4)),
                musig,
            ),
            (bwk_hwi::DeviceKind::Jade, None, ordinary),
            (bwk_hwi::DeviceKind::Specter, None, taproot),
            (bwk_hwi::DeviceKind::ColdcardSimulator, None, musig),
        ] {
            assert_eq!(
                hwi_device_capabilities(&kind, firmware.as_ref()),
                expected,
                "provider metadata {kind}, {firmware:?}"
            );
        }
    }

    #[test]
    fn network_name_covers_supported_networks() {
        assert_eq!(
            network_name(bitcoin::Network::Bitcoin).expect("bitcoin is supported"),
            "bitcoin"
        );
        assert_eq!(
            network_name(bitcoin::Network::Testnet).expect("testnet is supported"),
            "testnet"
        );
        assert_eq!(
            network_name(bitcoin::Network::Signet).expect("signet is supported"),
            "signet"
        );
        assert_eq!(
            network_name(bitcoin::Network::Regtest).expect("regtest is supported"),
            "regtest"
        );
    }
}
