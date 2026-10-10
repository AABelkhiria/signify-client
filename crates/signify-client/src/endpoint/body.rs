//! Writing the parts of a request body that more than one endpoint family shares.
//!
//! A KERIA request that carries signed events also carries the key-manager block the agent stores
//! for the identifier that signed them — `data[keeper.algo] = keeper.params()` upstream. Roadmap
//! 6.6 wrote that first for the identifier family; Roadmap 6.9 needs the identical block for a
//! registry creation, which is what moved it here rather than duplicating it.
//!
//! The field order inside a block is the keeper's own `params()` literal, which is deliberately
//! **not** the schema's declaration order: a salty keeper writes `sxlt` first and `tier` fifth
//! where `SaltyState` declares `tier` first. The two genuinely differ upstream, because one is a
//! request and the other a response. See `fixtures/client-identifiers/` and
//! `fixtures/client-registries/`.

use keri_cesr::crypto::verifier::KeyTransferability;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::{Sad, SadError, SadValue};
use keria_types::api::{AcceptedHab, KeyManagerState, RandyState, SaltyState};
use signify_keys::manager::IdentifierKeeper;

use crate::error::ClientError;

/// Reads a stored record's transferability from its own prefix.
///
/// This is where the reference's keeper factory reads it too — `new Prefixer({qb64:
/// aid['prefix']}).transferable` — which matters because a randy keeper writes the value back into
/// a request body under a field the schema does not declare.
pub(crate) fn stored_transferability(record: &AcceptedHab) -> Result<KeyTransferability, ClientError> {
    let prefix = IdentifierPrefix::from_qb64(&record.common.prefix)?;
    Ok(if prefix.is_transferable() {
        KeyTransferability::Transferable
    } else {
        KeyTransferability::NonTransferable
    })
}

/// Writes the one key-manager block a body carries, under the keeper's own label.
///
/// The field order inside the block is the keeper's `params()` literal, not the schema's
/// declaration order. `transferability` supplies the one value a randy keeper writes and
/// [`RandyState`] does not carry.
pub(crate) fn insert_algorithm(
    body: &mut Sad,
    keeper: &dyn IdentifierKeeper,
    transferability: KeyTransferability,
) -> Result<(), ClientError> {
    let state = keeper.parameters()?;
    let block = algorithm_block(&state, transferability)?;
    body.insert(state.label(), SadValue::Map(block)).map_err(sad_error)
}

/// Renders one key-manager state in the order the reference's `params()` writes it.
pub(crate) fn algorithm_block(
    state: &KeyManagerState,
    transferability: KeyTransferability,
) -> Result<Sad, ClientError> {
    let mut block = Sad::new();
    match state {
        KeyManagerState::Salty(salty) => salty_block(&mut block, salty)?,
        KeyManagerState::Randy(randy) => randy_block(&mut block, randy, transferability)?,
        KeyManagerState::Group(group) => {
            // The member record is a response document travelling back out unchanged, so it is
            // written in the schema's own field order — which is what Roadmap 4.1 verified its
            // encoding reproduces.
            block
                .insert("mhab", SadValue::Map(record_document(&group.member)?))
                .map_err(sad_error)?;
            block
                .insert("keys", text_array(group.keys.clone()))
                .map_err(sad_error)?;
            block
                .insert("ndigs", text_array(group.next_key_digests.clone()))
                .map_err(sad_error)?;
        }
        KeyManagerState::Extern(external) => {
            block
                .insert("extern_type", external.extern_type.clone())
                .map_err(sad_error)?;
            block
                .insert("pidx", index_value(external.key_pair_index)?)
                .map_err(sad_error)?;
            for (label, value) in &external.additional {
                block.insert(label.clone(), json_value(value)?).map_err(sad_error)?;
            }
        }
    }
    Ok(block)
}

/// Writes a salty block in `params()` order: `sxlt, pidx, kidx, stem, tier, icodes, ncodes, dcode,
/// transferable`.
pub(crate) fn salty_block(block: &mut Sad, salty: &SaltyState) -> Result<(), ClientError> {
    block.insert("sxlt", salty.encrypted_salt.clone()).map_err(sad_error)?;
    block
        .insert("pidx", index_value(salty.key_pair_index)?)
        .map_err(sad_error)?;
    block.insert("kidx", index_value(salty.key_index)?).map_err(sad_error)?;
    block.insert("stem", salty.stem.clone()).map_err(sad_error)?;
    block.insert("tier", salty.tier.as_str()).map_err(sad_error)?;
    block
        .insert("icodes", text_array(salty.inception_codes.clone()))
        .map_err(sad_error)?;
    block
        .insert("ncodes", text_array(salty.next_codes.clone()))
        .map_err(sad_error)?;
    block.insert("dcode", salty.digest_code.clone()).map_err(sad_error)?;
    block.insert("transferable", salty.transferable).map_err(sad_error)
}

/// Writes a randy block in `params()` order: `nxts, prxs, transferable`.
pub(crate) fn randy_block(
    block: &mut Sad,
    randy: &RandyState,
    transferability: KeyTransferability,
) -> Result<(), ClientError> {
    block
        .insert("nxts", text_array(randy.encrypted_next_keys.clone()))
        .map_err(sad_error)?;
    block
        .insert("prxs", text_array(randy.encrypted_signing_keys.clone()))
        .map_err(sad_error)?;
    block
        .insert(
            "transferable",
            matches!(transferability, KeyTransferability::Transferable),
        )
        .map_err(sad_error)
}

/// Re-encodes one identifier record as the ordered document it decoded from.
pub(crate) fn record_document(record: &AcceptedHab) -> Result<Sad, ClientError> {
    let encoded = serde_json::to_vec(record).map_err(|source| ClientError::Api {
        source: Box::new(keria_types::api::ApiError::Json {
            source: Box::new(source),
        }),
    })?;
    Sad::from_json_bytes(&encoded).map_err(sad_error)
}

/// Converts one decoded JSON value into an ordered document value.
///
/// Only whole numbers within the reference-representable range are accepted; a fractional or
/// out-of-range number in a module's own parameters is refused rather than rounded.
pub(crate) fn json_value(value: &serde_json::Value) -> Result<SadValue, ClientError> {
    Ok(match value {
        serde_json::Value::Null => SadValue::Null,
        serde_json::Value::Bool(flag) => SadValue::Bool(*flag),
        serde_json::Value::Number(number) => {
            let exact = number.as_i64().ok_or(ClientError::UnrepresentableNumber)?;
            SadValue::integer(exact).map_err(sad_error)?
        }
        serde_json::Value::String(text) => SadValue::Text(text.clone()),
        serde_json::Value::Array(items) => {
            SadValue::Array(items.iter().map(json_value).collect::<Result<Vec<_>, _>>()?)
        }
        serde_json::Value::Object(fields) => {
            let mut document = Sad::new();
            for (label, field) in fields {
                document.insert(label.clone(), json_value(field)?).map_err(sad_error)?;
            }
            SadValue::Map(document)
        }
    })
}

/// Builds an ordered array of text values.
pub(crate) fn text_array(values: Vec<String>) -> SadValue {
    SadValue::Array(values.into_iter().map(SadValue::Text).collect())
}

/// Builds an exact index value, which cannot overflow the safe range from a `u32`.
pub(crate) fn index_value(index: u32) -> Result<SadValue, ClientError> {
    SadValue::integer(i64::from(index)).map_err(sad_error)
}

pub(crate) fn sad_error(source: SadError) -> ClientError {
    ClientError::Serialization {
        source: Box::new(source.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keria_types::api::KeyTier;
    use std::error::Error;

    fn salty_state() -> SaltyState {
        SaltyState {
            tier: KeyTier::Low,
            encrypted_salt: "0AASEALED".to_owned(),
            key_pair_index: 0,
            key_index: 1,
            stem: "signify:aid".to_owned(),
            digest_code: "E".to_owned(),
            inception_codes: vec!["A".to_owned()],
            next_codes: vec!["A".to_owned()],
            transferable: true,
        }
    }

    fn rendered(state: &KeyManagerState, transferability: KeyTransferability) -> Result<String, Box<dyn Error>> {
        let block = algorithm_block(state, transferability)?;
        Ok(String::from_utf8(block.to_json_bytes()?)?)
    }

    #[test]
    fn a_salty_block_is_written_in_the_references_parameter_order() -> Result<(), Box<dyn Error>> {
        let text = rendered(&KeyManagerState::Salty(salty_state()), KeyTransferability::Transferable)?;
        // `params()` writes sxlt first and tier fifth; the schema declares tier first.
        assert_eq!(
            text,
            r#"{"sxlt":"0AASEALED","pidx":0,"kidx":1,"stem":"signify:aid","tier":"low","icodes":["A"],"ncodes":["A"],"dcode":"E","transferable":true}"#
        );
        Ok(())
    }

    #[test]
    fn a_randy_block_carries_a_transferability_the_schema_does_not_declare() -> Result<(), Box<dyn Error>> {
        let state = KeyManagerState::Randy(RandyState {
            encrypted_signing_keys: vec!["0ACURRENT".to_owned()],
            encrypted_next_keys: vec!["0ANEXT".to_owned()],
        });
        assert_eq!(
            rendered(&state, KeyTransferability::Transferable)?,
            r#"{"nxts":["0ANEXT"],"prxs":["0ACURRENT"],"transferable":true}"#
        );
        // The same stored state, reloaded for a non-transferable identifier, writes `false` —
        // which is exactly what the reference's factory derives from the prefix.
        assert_eq!(
            rendered(&state, KeyTransferability::NonTransferable)?,
            r#"{"nxts":["0ANEXT"],"prxs":["0ACURRENT"],"transferable":false}"#
        );
        Ok(())
    }

    #[test]
    fn an_external_block_keeps_its_modules_own_parameters() -> Result<(), Box<dyn Error>> {
        let external: KeyManagerState = KeyManagerState::Extern(serde_json::from_str(
            r#"{"extern_type":"hsm","pidx":3,"slot":7,"label":"signing"}"#,
        )?);
        assert_eq!(
            rendered(&external, KeyTransferability::Transferable)?,
            r#"{"extern_type":"hsm","pidx":3,"label":"signing","slot":7}"#
        );
        Ok(())
    }

    #[test]
    fn an_unrepresentable_module_parameter_is_refused() {
        let value = serde_json::json!({ "ratio": 0.5 });
        assert!(matches!(json_value(&value), Err(ClientError::UnrepresentableNumber)));
    }

    #[test]
    fn a_record_re_encodes_in_the_schemas_field_order() -> Result<(), Box<dyn Error>> {
        let document = r#"{"name":"aid1","prefix":"BPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9","icp_dt":"2021-06-27T21:26:21.233257+00:00","state":{"vn":[1,0],"i":"BPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9","s":"0","p":"","d":"BPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9","f":"0","dt":"2021-06-27T21:26:21.233257+00:00","et":"icp","kt":"1","k":["BPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"ee":{"s":"0","d":"BPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9","br":[],"ba":[]},"di":""},"transferable":false,"windexes":[],"salty":{"tier":"low","sxlt":"0AASEALED","pidx":0,"kidx":0,"stem":"signify:aid","dcode":"B","icodes":["A"],"ncodes":["A"],"transferable":false}}"#;
        let record: AcceptedHab = serde_json::from_str(document)?;
        assert_eq!(String::from_utf8(record_document(&record)?.to_json_bytes()?)?, document);
        // A non-transferable prefix reports itself as such, which is where a reloaded randy
        // keeper's transferability comes from.
        assert!(matches!(
            stored_transferability(&record)?,
            KeyTransferability::NonTransferable
        ));
        Ok(())
    }
}
