#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::verifier::{KeyTransferability, VerificationAlgorithm, VerificationKey};

const ED25519_RAW: [u8; 32] = [
    3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48,
    155, 165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184,
];
const P256_RAW: [u8; 33] = [
    3, 230, 229, 40, 20, 228, 78, 65, 4, 57, 127, 216, 171, 120, 183, 43, 22, 73, 189, 193,
    218, 172, 247, 238, 253, 202, 202, 87, 7, 31, 19, 11, 208,
];

fuzz_target!(|data: &[u8]| {
    for algorithm in [VerificationAlgorithm::Ed25519, VerificationAlgorithm::EcdsaP256] {
        let _ = VerificationKey::parse_raw_prefix(
            algorithm,
            KeyTransferability::Transferable,
            data,
        );
    }
    let _ = VerificationKey::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = VerificationKey::parse_qb64(text);
    }

    for (algorithm, raw) in [
        (VerificationAlgorithm::Ed25519, ED25519_RAW.as_slice()),
        (VerificationAlgorithm::EcdsaP256, P256_RAW.as_slice()),
    ] {
        if let Ok(key) = VerificationKey::from_raw(
            algorithm,
            KeyTransferability::Transferable,
            raw,
        ) {
            let _ = key.verify(data, data);
        }
    }
});
