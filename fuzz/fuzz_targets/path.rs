#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::{
    bytes::utf8_text,
    path::{PathComponent, SadPath},
};

fuzz_target!(|data: &[u8]| {
    let _ = SadPath::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = PathComponent::parse(text);
        let _ = SadPath::from_text(text);
        let _ = SadPath::parse_qb64(text);
    }
});
