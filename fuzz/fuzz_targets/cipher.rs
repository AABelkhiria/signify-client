#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::cipher::{Ciphertext, CiphertextKind};

fuzz_target!(|data: &[u8]| {
    let _ = Ciphertext::infer_from_raw(data);
    let _ = Ciphertext::parse_raw_prefix(CiphertextKind::QualifiedSeed, data);
    let _ = Ciphertext::parse_raw_prefix(CiphertextKind::QualifiedSalt, data);
    let _ = Ciphertext::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = Ciphertext::parse_qb64(text);
    }
});
