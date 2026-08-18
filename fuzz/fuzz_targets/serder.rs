#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_keri::serialization::{Sad, SerializedEvent};

fuzz_target!(|data: &[u8]| {
    // Untrusted JSON must only ever produce a typed error or a value that survives a byte-exact
    // encode/parse round trip, because a SAID is computed over exactly those bytes.
    if let Ok(sad) = Sad::from_json_bytes(data) {
        let Ok(encoded) = sad.to_json_bytes() else {
            panic_free_failure("accepted data did not re-encode");
            return;
        };
        let Ok(reparsed) = Sad::from_json_bytes(&encoded) else {
            panic_free_failure("canonical output did not re-parse");
            return;
        };
        assert_eq!(reparsed, sad, "encode/parse round trip changed the value");
        let Ok(re_encoded) = reparsed.to_json_bytes() else {
            panic_free_failure("round-tripped value did not re-encode");
            return;
        };
        assert_eq!(re_encoded, encoded, "encoding is not a fixed point");
    }

    // A parsed message must always agree with its own declared size and canonical form.
    if let Ok(event) = SerializedEvent::parse(data) {
        assert_eq!(event.raw(), data, "parse accepted non-canonical bytes");
        assert_eq!(event.size(), data.len(), "size disagrees with input length");
        assert_eq!(
            usize::try_from(event.version_string().size()).unwrap_or(usize::MAX),
            data.len(),
            "declared size disagrees with input length"
        );
        // Field accessors must never panic on hostile content.
        let _ = event.said();
        let _ = event.identifier_prefix();
        let _ = event.event_kind();
        let _ = event.sequence_number();
        let _ = event.verification_keys();
        let _ = event.next_key_digests();
    }
});

/// Fails the fuzz run without a denied `panic!`/`expect` when an invariant cannot hold.
fn panic_free_failure(reason: &str) {
    assert_eq!("invariant held", reason);
}
