#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::{
    base64::{decode_u64, decode_url_safe},
    bytes::{bytes_to_integer, utf8_text},
};

fuzz_target!(|data: &[u8]| {
    let _ = bytes_to_integer(data);
    if let Ok(text) = utf8_text(data) {
        let _ = decode_url_safe(text);
        let _ = decode_u64(text);
    }
});
