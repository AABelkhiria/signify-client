#![no_main]
#![forbid(unsafe_code)]

use std::str::FromStr;

use keri_cesr::bytes::utf8_text;
use libfuzzer_sys::fuzz_target;
use signify_keri::event::kind::EventKind;
use signify_keri::serialization::{Protocol, SerializationKind, VersionString};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = utf8_text(data) {
        if let Ok(version) = VersionString::from_str(text) {
            // Strict parsing accepts only canonical text, so acceptance implies identity.
            assert_eq!(version.to_string(), text);
            if let Ok(reparsed) = VersionString::from_str(&version.to_string()) {
                assert_eq!(reparsed, version);
            }
        }
        if let Ok(kind) = EventKind::from_str(text) {
            assert_eq!(kind.as_str(), text);
        }
        let _ = Protocol::from_str(text);
        let _ = SerializationKind::from_str(text);
    }
});
