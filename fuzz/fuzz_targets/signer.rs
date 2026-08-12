#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use signify_cesr::bytes::utf8_text;
use signify_crypto::{
    signer::{SignaturePlacement, Signer},
    verifier::KeyTransferability,
};

fuzz_target!(|data: &[u8]| {
    for transferability in [KeyTransferability::NonTransferable, KeyTransferability::Transferable] {
        let parsed = Signer::parse_seed_prefix(data, transferability);
        let _ = Signer::parse_qb2(data, transferability);
        if let Ok(text) = utf8_text(data) {
            let _ = Signer::parse_qb64(text, transferability);
        }

        if let Ok(parsed) = parsed {
            let signer = parsed.signer();
            if let Ok(signature) = signer.sign_unindexed(data) {
                let _ = signer.verifier().verify(signature.raw(), data);
            }
            let length = u32::try_from(data.len()).map_or(u32::MAX, |length| length);
            let both_index = length % 4096;
            let prior_index = data
                .iter()
                .fold(0_u32, |value, byte| value.wrapping_add(u32::from(*byte)))
                % 4096;
            let current_index = length % 16_777_216;
            if let Ok(signature) =
                signer.sign_indexed(data, SignaturePlacement::both_lists_with_prior(both_index, prior_index))
            {
                let _ = signer.verifier().verify(signature.raw(), data);
            }
            if let Ok(signature) = signer.sign_indexed(data, SignaturePlacement::current_list(current_index)) {
                let _ = signer.verifier().verify(signature.raw(), data);
            }
        }
    }
});
