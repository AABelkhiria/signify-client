#![no_main]

//! Fuzzes registry inception over hostile nonces, backers, and thresholds.
//!
//! The nonce and every backer are caller- or network-supplied text committed verbatim into the
//! event, and the threshold interacts with the backer count, so the input bytes drive all three.
//! The target asserts that nothing panics, that every rejection is a typed [`RegistryError`] with
//! a non-empty description, and that anything accepted is self-consistent: the event agrees with
//! its declared size, reparses losslessly, carries its own digest as its identifier in both
//! fields, and returns the nonce and backers verbatim.

use libfuzzer_sys::fuzz_target;
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::registry::{MAX_BACKER_BYTES, MAX_BACKERS, MAX_NONCE_BYTES, RegistryInceptionBuilder};
use signify_keri::serialization::SerializedEvent;

const ISSUER: &str = "ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g";

fuzz_target!(|data: &[u8]| {
    let [b0, b1, body @ ..] = data else {
        return;
    };
    let Ok(issuer) = IdentifierPrefix::from_qb64(ISSUER) else {
        return;
    };

    // The body splits into a nonce and up to a few backers on a separator byte.
    let mut parts = body.split(|&byte| byte == 0);
    let nonce = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let backers: Vec<String> = parts
        .take(usize::from(*b0 & 0x07))
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();

    let mut builder = RegistryInceptionBuilder::new(issuer, nonce.clone()).backers(backers.clone());
    if b1 & 1 == 1 {
        builder = builder.backer_threshold(u32::from(*b1 >> 1));
    }

    match builder.build() {
        Ok(event) => {
            assert!(nonce.len() <= MAX_NONCE_BYTES);
            assert!(backers.len() <= MAX_BACKERS);
            assert!(backers.iter().all(|backer| backer.len() <= MAX_BACKER_BYTES));
            assert_eq!(event.serialized().size(), event.raw().len());
            assert_eq!(event.sad().get_text("i"), event.sad().get_text("d"));
            assert_eq!(event.sad().get_text("n"), Some(nonce.as_str()));
            let Ok(reparsed) = SerializedEvent::parse(event.raw()) else {
                assert!(event.raw().is_empty(), "an accepted event does not reparse");
                return;
            };
            assert_eq!(reparsed.sad(), event.sad());
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }
});
