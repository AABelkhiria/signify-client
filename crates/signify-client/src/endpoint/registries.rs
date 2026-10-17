//! The registries endpoint: the credential registries an identifier owns.
//!
//! A credential registry is a TEL — a transaction event log — anchored in its issuer's KEL. This
//! family is the three calls that read, create, and rename them, and `create` is the only one in
//! the crate that builds *two* events: the registry's own inception and the interaction event that
//! anchors it in the issuer's log.
//!
//! This ports `Registries` and `RegistryResult` from the pinned `src/keri/app/credentialing.ts`.
//!
//! # Backers are a choice, not a flag beside a list
//!
//! Upstream, `noBackers` defaults to `true` while `baks` and `toad` are accepted alongside it — so
//! a caller who names backers without also clearing the flag gets a registry configured to have
//! none, and the backers they supplied are written into an event that declares it cannot use them.
//! Here [`RegistryBacking`] makes naming backers *be* the choice, so the two cannot disagree.
//!
//! # An establishment-only issuer is refused before anything is built
//!
//! The reference pushes the `EO` trait into the registry configuration, builds the whole registry
//! inception from it, and *then* throws `establishment only not implemented` — after the identifier
//! lookup has already gone out. Here it is a typed refusal checked first, which is what the
//! issuance artifacts decided for an establishment-only issuer. See `fixtures/client-registries/`.

use keri_protocol::event::ConfigurationTrait;
use keri_protocol::registry::RegistryInceptionBuilder;
use keri_protocol::serialization::{Sad, SadValue};
use keria_types::api::{Hab, Registry, RegistryOperation};
use signify_http::request::ResourcePath;
use signify_http::transport::Method;
use signify_keys::identifier::interact_identifier;

use crate::client::{ClientRequest, ConnectedClient};
use crate::endpoint::body::{insert_algorithm, sad_error, stored_transferability, text_array};
use crate::endpoint::decode_json;
use crate::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use crate::error::ClientError;

/// Path segment an identifier's registries live under.
pub const REGISTRIES_SEGMENT: &str = "registries";

/// Configuration trait an unbacked registry declares; the reference's `TraitDex.NoBackers`.
pub const NO_BACKERS_TRAIT: &str = "NB";

/// Who witnesses a registry's transaction events.
///
/// The reference carries this as a `noBackers` flag with a `baks` list and a `toad` beside it, all
/// three independently settable — so the flag can say one thing and the list another. Naming
/// backers is the choice here, which makes that disagreement unrepresentable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryBacking {
    /// No backers: the registry declares the `NB` trait and its events stand on the issuer's KEL
    /// alone. This is the reference's default.
    None,
    /// Backed by the named witnesses, with the threshold that must receipt each event.
    Backers {
        /// The backer identifiers, carried as text because the reference validates none of them —
        /// the registry builder's own vector commits the string `'a backer'`.
        backers: Vec<String>,
        /// How many must receipt; the reference's `toad`.
        threshold: u32,
    },
}

impl RegistryBacking {
    /// The configuration traits this backing writes into the registry inception.
    fn traits(&self) -> Vec<ConfigurationTrait> {
        match self {
            Self::None => vec![ConfigurationTrait::NoBackers],
            Self::Backers { .. } => Vec::new(),
        }
    }
}

/// What to create; the reference's `CreateRegistryArgs`.
#[derive(Clone, Debug)]
pub struct CreateRegistryRequest {
    /// Alias of the identifier that will own the registry; the reference's `name`.
    pub identifier: String,
    /// Alias the registry is stored under; the reference's `registryName`.
    pub registry: String,
    /// Who witnesses its events.
    pub backing: RegistryBacking,
    /// Nonce the registry identifier derives from; the reference's `nonce`.
    ///
    /// Absent, one is drawn from the operating system, which is what `vdr.incept` does with
    /// `randomNonce()`. Supplying one makes the registry identifier reproducible.
    pub nonce: Option<String>,
}

impl CreateRegistryRequest {
    /// An unbacked registry under one identifier, with a generated nonce — the reference's
    /// defaults.
    #[must_use]
    pub fn new(identifier: impl Into<String>, registry: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            registry: registry.into(),
            backing: RegistryBacking::None,
            nonce: None,
        }
    }

    /// Sets who witnesses the registry's events.
    #[must_use]
    pub fn with_backing(mut self, backing: RegistryBacking) -> Self {
        self.backing = backing;
        self
    }

    /// Pins the nonce, making the registry identifier reproducible.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }
}

/// A created registry: both events, the signatures over the anchoring one, and the agent's answer.
///
/// This is the reference's `RegistryResult`, with one difference that matters. Upstream it holds
/// the fetch **promise** rather than its response, so `create` resolves before the `POST` does and
/// a rejected `POST` is invisible unless the caller awaits `op()`. Here the submission is awaited,
/// so a failure is a failure at the call site — and the artifacts are still available beside it.
///
/// Not `Clone`: it owns the signatures, and signing material is deliberately non-cloneable.
#[derive(Debug)]
pub struct CreatedRegistry {
    /// The registry's own inception event; the reference's `regser`. Its SAID is the registry
    /// identifier.
    pub inception: keri_protocol::event::KeyEvent,
    /// The issuer's interaction event anchoring it; the reference's `serder`.
    pub anchor: keri_protocol::event::KeyEvent,
    /// The issuer's signatures over that interaction event.
    pub signatures: signify_keys::manager::ManagedSignatures,
    response: Vec<u8>,
}

impl CreatedRegistry {
    /// Returns the agent's answer, unparsed.
    #[must_use]
    pub fn response_body(&self) -> &[u8] {
        &self.response
    }

    /// Reads the agent's answer as the long-running operation that creates the registry.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Api`] when the answer is not a registry operation.
    pub fn operation(&self) -> Result<RegistryOperation, ClientError> {
        decode_json(&self.response)
    }
}

/// The registries endpoint family.
///
/// Borrowed from a connected client, so it costs nothing to hold and cannot outlive the client it
/// speaks through.
#[derive(Debug)]
pub struct Registries<'client> {
    client: &'client ConnectedClient,
}

impl<'client> Registries<'client> {
    /// Binds this family to a connected client.
    #[must_use]
    pub const fn new(client: &'client ConnectedClient) -> Self {
        Self { client }
    }

    /// Lists the registries one identifier owns.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Status`] for a non-success answer, [`ClientError::Api`] when a
    /// record does not decode, and the request, transport, and authentication failures
    /// [`ConnectedClient::fetch`] returns.
    pub async fn list(&self, identifier: &str) -> Result<Vec<Registry>, ClientError> {
        let response = self
            .client
            .fetch(ClientRequest::new(Method::Get, Self::collection_path(identifier)?))
            .await?;
        decode_json(response.body())
    }

    /// Creates a registry: builds its inception, anchors it in the issuer's log, and submits both.
    ///
    /// Three requests' worth of work upstream becomes two here — the identifier lookup and the
    /// submission — because the issuer's keeper is resolved once and reused, where the reference
    /// resolves it in `create` to sign and again in `createFromEvents` to write its parameters.
    /// For a salty identifier that is one Argon2 derivation rather than two, and it changes no
    /// byte.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::EstablishmentOnlyIssuer`] when the identifier may not carry an
    /// interaction event — checked **before** anything is built — whatever
    /// [`Identifiers::get`](crate::endpoint::identifiers::Identifiers::get) returns,
    /// [`ClientError::Manager`] when the keeper cannot be rebuilt, layered registry and identifier
    /// failures, and whatever [`ConnectedClient::fetch`] returns.
    pub async fn create(&self, request: &CreateRegistryRequest) -> Result<CreatedRegistry, ClientError> {
        let record = self.client.identifiers().get(&request.identifier).await?;

        // The reference builds the whole registry inception and only then throws. Nothing is
        // derived here until this holds.
        if record.state.configuration.iter().any(|trait_| trait_ == "EO") {
            return Err(ClientError::EstablishmentOnlyIssuer {
                identifier: record.common.prefix.clone(),
            });
        }

        let issuer = keri_protocol::prefix::IdentifierPrefix::from_qb64(&record.common.prefix)?;
        let nonce = match &request.nonce {
            Some(nonce) => nonce.clone(),
            None => crate::random::random_nonce()?,
        };
        let mut inception = RegistryInceptionBuilder::new(issuer, nonce).configuration(request.backing.traits());
        if let RegistryBacking::Backers { backers, threshold } = &request.backing {
            inception = inception.backers(backers.clone()).backer_threshold(*threshold);
        }
        let inception = inception.build()?;

        // The anchor seals the registry to itself: a registry inception's SAID *is* its prefix, so
        // the identifier and the digest are the same value.
        let registry = inception.identifier().qb64()?;
        let mut seal = Sad::new();
        seal.insert("i", registry.clone()).map_err(sad_error)?;
        seal.insert("s", "0".to_owned()).map_err(sad_error)?;
        seal.insert("d", registry).map_err(sad_error)?;

        let keeper = self.client.keepers().keeper_for(&Hab::Accepted(record.clone()))?;
        let anchor = interact_identifier(keeper.as_ref(), &record.state, vec![seal])?;

        let mut body = Sad::new();
        body.insert("name", request.registry.clone()).map_err(sad_error)?;
        body.insert("vcp", SadValue::Map(inception.sad().clone()))
            .map_err(sad_error)?;
        body.insert("ixn", SadValue::Map(anchor.event.sad().clone()))
            .map_err(sad_error)?;
        body.insert("sigs", text_array(anchor.signatures.qb64()?))
            .map_err(sad_error)?;
        insert_algorithm(&mut body, keeper.as_ref(), stored_transferability(&record)?)?;

        let submitted = ClientRequest::new(Method::Post, Self::collection_path(&request.identifier)?)
            .body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(submitted).await?;

        Ok(CreatedRegistry {
            inception,
            anchor: anchor.event,
            signatures: anchor.signatures,
            response: response.into_body(),
        })
    }

    /// Renames one registry.
    ///
    /// # Errors
    ///
    /// Returns whatever [`Self::list`] returns.
    pub async fn rename(&self, identifier: &str, registry: &str, new_name: &str) -> Result<Registry, ClientError> {
        let mut body = Sad::new();
        body.insert("name", new_name.to_owned()).map_err(sad_error)?;
        let path = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(identifier)
            .segment(REGISTRIES_SEGMENT)
            .segment(registry)
            .build()?;
        let request = ClientRequest::new(Method::Put, path).body(body.to_json_bytes().map_err(sad_error)?);
        let response = self.client.fetch(request).await?;
        decode_json(response.body())
    }

    /// Builds `/identifiers/<identifier>/registries`.
    fn collection_path(identifier: &str) -> Result<ResourcePath, ClientError> {
        Ok(ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment(identifier)
            .segment(REGISTRIES_SEGMENT)
            .build()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn the_path_constants_are_the_references_own() {
        assert_eq!(REGISTRIES_SEGMENT, "registries");
        assert_eq!(NO_BACKERS_TRAIT, "NB");
        assert_eq!(ConfigurationTrait::NoBackers.as_str(), NO_BACKERS_TRAIT);
    }

    #[test]
    fn both_paths_encode_every_name_they_carry() -> Result<(), Box<dyn Error>> {
        // The reference concatenates all four dynamic values raw, so `list('a/b')` addresses
        // `/identifiers/a/b/registries` and a rename addresses two extra segments.
        assert_eq!(
            Registries::collection_path("a/b")?.as_str(),
            "/identifiers/a%2Fb/registries"
        );
        let rename = ResourcePath::builder()
            .segment(IDENTIFIERS_SEGMENT)
            .segment("a/b")
            .segment(REGISTRIES_SEGMENT)
            .segment("c/d")
            .build()?;
        assert_eq!(rename.as_str(), "/identifiers/a%2Fb/registries/c%2Fd");
        assert_eq!(rename.path().split('/').count(), 5);
        Ok(())
    }

    #[test]
    fn an_unbacked_registry_declares_the_trait_and_a_backed_one_does_not() {
        assert_eq!(RegistryBacking::None.traits(), vec![ConfigurationTrait::NoBackers]);
        let backed = RegistryBacking::Backers {
            backers: vec!["BAK".to_owned()],
            threshold: 1,
        };
        assert_eq!(backed.traits(), [] as [ConfigurationTrait; 0]);
    }

    #[test]
    fn the_request_defaults_are_the_references_own() {
        let request = CreateRegistryRequest::new("issuer", "vLEI");
        assert_eq!(request.identifier, "issuer");
        assert_eq!(request.registry, "vLEI");
        // `noBackers` defaults to true upstream, so an ordinary registry is unbacked.
        assert_eq!(request.backing, RegistryBacking::None);
        // No nonce means one is drawn, which is what `vdr.incept` does.
        assert_eq!(request.nonce, None);

        let pinned = CreateRegistryRequest::new("issuer", "vLEI").with_nonce("0AACDEF");
        assert_eq!(pinned.nonce.as_deref(), Some("0AACDEF"));
    }

    #[test]
    fn naming_backers_is_the_choice_rather_than_a_flag_beside_them() -> Result<(), Box<dyn Error>> {
        // Upstream these are three independent arguments, so `{baks: [...]}` without
        // `noBackers: false` writes backers into a registry declaring it has none.
        let request = CreateRegistryRequest::new("issuer", "backed").with_backing(RegistryBacking::Backers {
            backers: vec!["BAK0".to_owned(), "BAK1".to_owned()],
            threshold: 2,
        });
        let RegistryBacking::Backers { backers, threshold } = &request.backing else {
            return Err("the backing was not preserved".into());
        };
        assert_eq!(backers.len(), 2);
        assert_eq!(*threshold, 2);
        assert_eq!(request.backing.traits(), [] as [ConfigurationTrait; 0]);
        Ok(())
    }

    #[test]
    fn a_rename_body_carries_exactly_one_field() -> Result<(), Box<dyn Error>> {
        let mut body = Sad::new();
        body.insert("name", "renamed".to_owned())?;
        assert_eq!(String::from_utf8(body.to_json_bytes()?)?, r#"{"name":"renamed"}"#);
        Ok(())
    }

    #[test]
    fn the_anchor_seals_the_registry_to_itself() -> Result<(), Box<dyn Error>> {
        // A registry inception's SAID is its prefix, so the seal names it twice.
        let registry = "EJ1TxRlqdIeonxEd8aYwA_HI22ACwqEUrfpL8Y20qHKQ";
        let mut seal = Sad::new();
        seal.insert("i", registry.to_owned())?;
        seal.insert("s", "0".to_owned())?;
        seal.insert("d", registry.to_owned())?;
        assert_eq!(
            String::from_utf8(seal.to_json_bytes()?)?,
            format!(r#"{{"i":"{registry}","s":"0","d":"{registry}"}}"#)
        );
        Ok(())
    }
}
