#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::signature::{SignatureAlgorithm, UnindexedSignature};

fuzz_target!(|data: &[u8]| {
    for algorithm in [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::EcdsaSecp256k1,
        SignatureAlgorithm::EcdsaP256,
    ] {
        let _ = UnindexedSignature::parse_raw_prefix(algorithm, data);
    }
    let _ = UnindexedSignature::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = UnindexedSignature::parse_qb64(text);
    }
});
