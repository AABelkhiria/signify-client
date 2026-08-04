#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::{bytes::utf8_text, indexer::IndexedMaterial};

fuzz_target!(|data: &[u8]| {
    let _ = IndexedMaterial::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = IndexedMaterial::parse_qb64(text);
    }
});
