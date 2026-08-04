#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::{
    bytes::utf8_text,
    code::DerivationCode,
    matter::QualifiedMaterial,
};

fuzz_target!(|data: &[u8]| {
    let _ = QualifiedMaterial::parse_qb2(data);
    let _ = QualifiedMaterial::new(DerivationCode::BASE64_TEXT_LEAD_0, data);
    if let Ok(text) = utf8_text(data) {
        let _ = QualifiedMaterial::parse_qb64(text);
    }
});
