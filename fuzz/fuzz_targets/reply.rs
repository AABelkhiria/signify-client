#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_keri::event::reply::{MAX_ROUTE_BYTES, ReplyBuilder};
use signify_keri::event::timestamp::Timestamp;
use signify_keri::said::{DEFAULT_SAID_LABEL, SaidVerification};
use signify_keri::serialization::{Sad, SadValue, SerializedEvent};

fuzz_target!(|data: &[u8]| {
    // The timestamp parser is the only parser in this module and it runs on caller-supplied text,
    // so anything it accepts must reproduce itself exactly and nothing may panic.
    if let Ok(text) = core::str::from_utf8(data) {
        if let Ok(stamp) = Timestamp::parse(text) {
            assert_eq!(stamp.as_str(), text, "an accepted timestamp did not round trip");
            assert_eq!(text.len(), Timestamp::LENGTH);
            assert_eq!(stamp.clone().into_string(), text);
        }

        // A route is attacker-influenced text; it is either accepted whole or refused.
        let Ok(stamp) = Timestamp::parse("2021-06-27T21:26:21.233257+00:00") else {
            return;
        };
        match ReplyBuilder::new(text, stamp.clone()).build() {
            Ok(reply) => {
                assert!(text.len() <= MAX_ROUTE_BYTES, "an overlong route was accepted");
                assert_eq!(reply.route(), Some(text), "a route was not written verbatim");
                assert_eq!(reply.serialized().size(), reply.raw().len());
                match SerializedEvent::parse(reply.raw()) {
                    Ok(reparsed) => assert_eq!(reparsed.sad(), reply.sad(), "a reply did not survive reparsing"),
                    Err(error) => panic!("a built reply failed to parse: {error}"),
                }
                assert!(
                    reply
                        .said()
                        .verify(reply.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
                        .is_ok(),
                    "a reply's SAID did not verify against itself",
                );
            }
            Err(_) => assert!(text.len() > MAX_ROUTE_BYTES, "a bounded route was refused"),
        }

        // Hostile attribute blocks must survive the same round trip.
        if let Ok(attributes) = Sad::from_json_bytes(data) {
            if let Ok(reply) = ReplyBuilder::new("/x", stamp).attributes(attributes).build() {
                assert_eq!(reply.serialized().size(), reply.raw().len());
                assert!(
                    reply
                        .said()
                        .verify(reply.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
                        .is_ok(),
                );
                assert!(reply.sad().get("a").and_then(SadValue::as_map).is_some());
            }
        }
    }
});
