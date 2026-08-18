#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::{
    cipher::{Ciphertext, CiphertextKind, Decrypter},
    salt::SecurityTier,
    verifier::KeyTransferability,
};

// Deterministic public fuzz key; never a production secret.
const FIXED_PRIVATE_KEY: [u8; 32] = [0x42; 32];

fuzz_target!(|data: &[u8]| {
    // Hostile private-key material may only produce typed results.
    let _ = Decrypter::from_raw(data);
    let _ = Decrypter::parse_raw_prefix(data);
    let _ = Decrypter::parse_qb64_bytes(data);
    let _ = Decrypter::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = Decrypter::from_qb64(text);
    }

    // Hostile ciphertexts against a fixed key must fail or succeed without panicking, and every
    // recovered secret must come from an authenticated, exactly shaped sealed box.
    if let Ok(decrypter) = Decrypter::from_raw(&FIXED_PRIVATE_KEY) {
        for kind in [CiphertextKind::QualifiedSeed, CiphertextKind::QualifiedSalt] {
            if let Ok(ciphertext) = Ciphertext::from_raw(kind, data) {
                let _ = decrypter.decrypt_seed(&ciphertext, KeyTransferability::Transferable);
                let _ = decrypter.decrypt_salt(&ciphertext, SecurityTier::Low);
            }
        }
        if let Ok(parsed) = Ciphertext::parse_qb64_bytes(data) {
            let _ = decrypter.decrypt_seed(parsed.ciphertext(), KeyTransferability::NonTransferable);
            let _ = decrypter.decrypt_salt(parsed.ciphertext(), SecurityTier::Low);
        }
    }
});
