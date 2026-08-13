#![no_main]

use libfuzzer_sys::fuzz_target;
use signify_crypto::{
    salt::{KeyDerivationProfile, Salt, SecurityTier},
    verifier::KeyTransferability,
};

fuzz_target!(|data: &[u8]| {
    let _ = Salt::parse_raw_prefix(data, SecurityTier::Low);
    let _ = Salt::parse_qb2(data, SecurityTier::Medium);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Salt::parse_qb64(text, SecurityTier::High);
    }

    if let Some(raw) = data.get(..16)
        && let Ok(salt) = Salt::from_raw(raw, SecurityTier::Low)
    {
        let path_bytes = data.get(16..).unwrap_or_default();
        if let Ok(path) = std::str::from_utf8(path_bytes) {
            for transferability in [
                KeyTransferability::Transferable,
                KeyTransferability::NonTransferable,
            ] {
                let _ = salt.derive_signer_with_profile(
                    path,
                    transferability,
                    KeyDerivationProfile::Temporary,
                );
            }
        }
    }
});
