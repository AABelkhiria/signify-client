#![no_main]
#![forbid(unsafe_code)]

use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::sequence::SequenceNumber;
use libfuzzer_sys::fuzz_target;
use signify_keri::attachment::{
    AttachmentError, AttachmentFraming, ReceiptCouple, SealSourceCouple, SealSourceTriple, SignatureSeal,
    SignedMessageBuilder,
};
use signify_keri::prefix::IdentifierPrefix;
use signify_keri::said::Said;
use signify_keri::serialization::SerializedEvent;

const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const TRANSFERABLE_KEY: &str = "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const WITNESS_SIGNATURE: &str =
    "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
const RECEIPT_SIGNATURE: &str =
    "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";

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
    let Ok(witness_key) = VerificationKey::from_qb64(WITNESS_KEY) else {
        return;
    };
    let Ok(transferable_key) = VerificationKey::from_qb64(TRANSFERABLE_KEY) else {
        return;
    };
    let Ok(witness_signature) = IndexedSignature::from_qb64(WITNESS_SIGNATURE) else {
        return;
    };
    let Ok(receipt_signature) = UnindexedSignature::from_qb64(RECEIPT_SIGNATURE) else {
        return;
    };
    let Ok(receipt_couple) = ReceiptCouple::new(witness_key.clone(), receipt_signature) else {
        return;
    };

    let signature_count = usize::from(byte(data, 0) % 9);
    let flags = byte(data, 1);
    let witness_count = usize::from(byte(data, 10) % 5);
    let receipt_count = usize::from(byte(data, 11) % 5);
    // Flag 8 poisons the last witness signature with a transferable verifier.
    let poison_witness = flags & 8 != 0 && witness_count > 0;
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
        let mut witness_signatures: Vec<IndexedSignature> = Vec::new();
        for index in 0..witness_count {
            let verifier = if poison_witness && index == witness_count - 1 {
                transferable_key.clone()
            } else {
                witness_key.clone()
            };
            let Ok(with_verifier) = witness_signature.clone().with_verifier(verifier) else {
                return;
            };
            witness_signatures.push(with_verifier);
        }

        let mut builder = SignedMessageBuilder::new(&event)
            .controller_signatures(core::iter::repeat_n(signature.clone(), signature_count).collect())
            .witness_signatures(witness_signatures)
            .receipt_couples(core::iter::repeat_n(receipt_couple.clone(), receipt_count).collect())
            .framing(framing);
        let sealed = flags & 2 != 0;
        if sealed {
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
                assert!(
                    signature_count + witness_count + receipt_count > 0,
                    "an unsigned message was accepted"
                );
                assert!(
                    signature_count > 0 || !sealed,
                    "a seal without a controller group was accepted"
                );
                assert!(!poison_witness, "a transferable witness key was accepted");
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
                    AttachmentError::MissingSignatures
                        | AttachmentError::TooManySignatures { .. }
                        | AttachmentError::SealWithoutControllerSignatures
                        | AttachmentError::TransferableWitnessKey { .. }
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
