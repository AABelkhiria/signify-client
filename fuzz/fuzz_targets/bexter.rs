#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::{bexter::Base64Text, bytes::utf8_text};

fuzz_target!(|data: &[u8]| {
    let _ = Base64Text::parse_qb2(data);
    if let Ok(text) = utf8_text(data) {
        let _ = Base64Text::new(text);
        let _ = Base64Text::parse_qb64(text);
    }
});
