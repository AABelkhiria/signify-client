#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use keri_cesr::bytes::utf8_text;
use signify_keri::threshold::{RationalWeight, SigningThreshold};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = utf8_text(data) {
        let _ = RationalWeight::parse(text);
        let _ = SigningThreshold::from_sith(text);
        let _ = SigningThreshold::from_json(text);
    }
});
