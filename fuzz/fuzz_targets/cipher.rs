#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::cipher::{Ciphertext, CiphertextKind, Encrypter};

fuzz_target!(|data: &[u8]| {
    let _ = Ciphertext::infer_from_raw(data);
    let _ = Ciphertext::parse_raw_prefix(CiphertextKind::QualifiedSeed, data);
    let _ = Ciphertext::parse_raw_prefix(CiphertextKind::QualifiedSalt, data);
    let _ = Ciphertext::parse_qb2(data);
    let _ = Encrypter::parse_raw_prefix(data);
    let _ = Encrypter::parse_qb2(data);
    if let Ok(encrypter) = Encrypter::from_qb64("CAF7Wr3XNq5hArcOuBJzaY6Nd23jgtUVI6KDfb3VngkR") {
        let _ = encrypter.matches_seed_qb64(data);
        let _ = encrypter.encrypt_seed_qb64(data);
    }
    if let Ok(text) = utf8_text(data) {
        let _ = Ciphertext::parse_qb64(text);
        let _ = Encrypter::parse_qb64(text);
    }
});
