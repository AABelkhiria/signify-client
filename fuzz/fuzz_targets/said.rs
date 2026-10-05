#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use keri_cesr::crypto::digest::DigestAlgorithm;
use signify_keri::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use signify_keri::serialization::Sad;

fuzz_target!(|data: &[u8]| {
    // Hostile qualified text may only ever produce a typed error or a usable identifier.
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(said) = Said::from_qb64(text)
    {
        if let Ok(qb64) = said.qb64() {
            assert_eq!(qb64, text, "an accepted identifier did not round trip");
        }
    }

    // Hostile self-addressing data must derive deterministically or fail cleanly, and anything
    // derived must verify against the data it commits to.
    if let Ok(sad) = Sad::from_json_bytes(data) {
        if let Ok(computed) = Said::compute(&sad, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL) {
            let said = *computed.said();

            // Strict verification of the completed data is the core invariant: derivation and
            // verification must agree, or a peer could not check what we produced.
            assert!(
                said.verify(computed.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
                    .is_ok(),
                "derived identifier failed to verify against its own completed data"
            );

            // Derivation is idempotent: recomputing over completed data reproduces it exactly.
            if let Ok(again) = Said::compute(computed.sad(), DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL) {
                assert_eq!(again.said(), computed.said(), "derivation is not idempotent");
                assert_eq!(again.sad(), computed.sad(), "completed data is not stable");
            }
        }

        // A non-default label must never panic, whether or not the field exists.
        let _ = Said::compute(&sad, DigestAlgorithm::Blake3_256, "id");
    }
});
