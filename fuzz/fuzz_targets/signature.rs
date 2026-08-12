#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_cesr::indexer::IndexerCode;
use signify_crypto::signature::{IndexedSignature, SignatureAlgorithm, UnindexedSignature};

fuzz_target!(|data: &[u8]| {
    for algorithm in [
        SignatureAlgorithm::Ed25519,
        SignatureAlgorithm::EcdsaSecp256k1,
        SignatureAlgorithm::EcdsaP256,
    ] {
        let _ = UnindexedSignature::parse_raw_prefix(algorithm, data);
    }
    for code in [
        IndexerCode::ED25519,
        IndexerCode::ED25519_CURRENT,
        IndexerCode::ECDSA_256K1,
        IndexerCode::ECDSA_256K1_CURRENT,
        IndexerCode::ECDSA_256R1,
        IndexerCode::ECDSA_256R1_CURRENT,
        IndexerCode::ED448,
        IndexerCode::ED448_CURRENT,
        IndexerCode::ED25519_BIG,
        IndexerCode::ED25519_BIG_CURRENT,
        IndexerCode::ECDSA_256K1_BIG,
        IndexerCode::ECDSA_256K1_BIG_CURRENT,
        IndexerCode::ECDSA_256R1_BIG,
        IndexerCode::ECDSA_256R1_BIG_CURRENT,
        IndexerCode::ED448_BIG,
        IndexerCode::ED448_BIG_CURRENT,
    ] {
        let _ = IndexedSignature::parse_raw_prefix(code, 0, None, data);
    }
    let _ = UnindexedSignature::parse_qb2(data);
    let _ = IndexedSignature::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = UnindexedSignature::parse_qb64(text);
        let _ = IndexedSignature::parse_qb64(text);
    }
});
