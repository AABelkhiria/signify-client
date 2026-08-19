#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::sequence::SequenceNumber;
use signify_crypto::signature::IndexedSignature;
use signify_keri::attachment::{
    AttachmentError, AttachmentFraming, SealSourceCouple, SealSourceTriple, SignatureSeal, SignedMessageBuilder,
};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::SerializedEvent;

const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";

/// Reads one byte from the fuzz input, cycling when it runs out.
fn byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        0
    } else {
        data.get(index % data.len()).copied().unwrap_or(0)
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(signature) = IndexedSignature::from_qb64(SIGNATURE) else {
        return;
    };
    let Ok(identifier) = IdentifierPrefix::from_qb64(IDENTIFIER) else {
        return;
    };
    let Ok(said) = Said::from_qb64(IDENTIFIER) else { return };

    let signature_count = usize::from(byte(data, 0) % 9);
    let flags = byte(data, 1);
    let sequence_number = u128::from(u64::from_le_bytes([
        byte(data, 2),
        byte(data, 3),
        byte(data, 4),
        byte(data, 5),
        byte(data, 6),
        byte(data, 7),
        byte(data, 8),
        byte(data, 9),
    ]));
    let framing = if flags & 1 == 0 {
        AttachmentFraming::Plain
    } else {
        AttachmentFraming::Pipelined
    };

    // The event half comes straight from the fuzz input, so only a well-formed one gets this far.
    if let Ok(event) = SerializedEvent::parse(data) {
        let mut builder = SignedMessageBuilder::new(&event)
            .controller_signatures(core::iter::repeat_n(signature.clone(), signature_count).collect())
            .framing(framing);
        if flags & 2 != 0 {
            builder = builder.seal(if flags & 4 == 0 {
                SignatureSeal::Event {
                    identifier: identifier.clone(),
                    sequence_number: SequenceNumber::new(sequence_number),
                    said,
                }
            } else {
                SignatureSeal::Last {
                    identifier: identifier.clone(),
                }
            });
        }

        match builder.build() {
            Ok(message) => {
                assert!(signature_count > 0, "an unsigned message was accepted");
                // The event survives attachment untouched and still parses on its own.
                assert_eq!(message.event(), event.raw(), "attaching disturbed the event");
                match SerializedEvent::parse(message.event()) {
                    Ok(reparsed) => assert_eq!(reparsed.sad(), event.sad(), "the event half stopped parsing"),
                    Err(error) => panic!("an attached event failed to reparse: {error}"),
                }
                // The two halves reassemble into exactly the message.
                assert_eq!(
                    [message.event(), message.attachments()].concat(),
                    message.as_bytes(),
                    "the event and attachment halves do not reassemble",
                );
                // Every stream is quadlet-aligned, which is what makes pipelining possible.
                if framing == AttachmentFraming::Plain {
                    assert!(
                        message.attachments().len().is_multiple_of(4),
                        "a plain attachment stream is not quadlet-aligned",
                    );
                }
            }
            Err(error) => assert!(
                matches!(
                    error,
                    AttachmentError::MissingSignatures | AttachmentError::TooManySignatures { .. }
                ),
                "unexpected attachment failure: {error}",
            ),
        }
    }

    // Seal sources encode from arbitrary positions without panicking, and always align.
    let couple = SealSourceCouple::new(SequenceNumber::new(sequence_number), said);
    let triple = SealSourceTriple::new(identifier, SequenceNumber::new(sequence_number), said);
    for encoded in [couple.attachment(framing), triple.attachment(framing)] {
        if let Ok(bytes) = encoded {
            assert!(bytes.len().is_multiple_of(4), "a seal source is not quadlet-aligned");
            assert!(bytes.starts_with(b"-"), "a seal source did not start with a counter");
        }
    }
});
