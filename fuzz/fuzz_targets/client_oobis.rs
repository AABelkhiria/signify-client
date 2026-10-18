#![no_main]

//! Fuzzes the OOBI endpoint over hostile aliases, roles, AIDs, OOBI URLs, and agent answers.
//!
//! Five things here come from outside, and this family is the one where the most of them reach a
//! path. An **alias** and an **AID** are path components the reference interpolates unencoded; a
//! **role** is both — a query value in `get` and a path segment in `endroles` — and the reference
//! interpolates it into the query by hand rather than through `URLSearchParams`, so a role holding
//! `&` chooses a second parameter. The request signature covers `@path`, so each also changes what
//! a signature commits to. An **OOBI URL** does not reach this client's path at all: it reaches a
//! JSON body, and then somebody else fetches it. And an **agent's answer** decides what a caller
//! believes about who may speak for an identifier.
//!
//! The target asserts that nothing panics, that an alias and a role filter can never escape their
//! own segment whatever they hold, that a role writes exactly one query parameter and never
//! changes the signed path, that a resolution body always names its URL byte for byte and writes
//! an alias exactly when it has one, and that an answer either decodes into the shape it claims or
//! is refused.

use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{EndRole, Oobi, OobiOperation, Role};
use libfuzzer_sys::fuzz_target;
use signify_client::endpoint::identifiers::IDENTIFIERS_SEGMENT;
use signify_client::endpoint::oobis::{
    END_ROLES_SEGMENT, OOBIS_SEGMENT, OobiResolution, RESOLUTIONS_SEGMENT, ROLE_PARAMETER,
};
use signify_http::request::ResourcePath;
use signify_http::transport::RequestUrl;

/// Every character that would give a path component a meaning it did not have.
const PATH_DELIMITERS: [char; 3] = ['/', '?', '#'];

/// Asserts one encoded component is exactly one segment and introduces no delimiter.
fn assert_single_segment(component: &str, what: &str, source: &str) {
    for delimiter in PATH_DELIMITERS {
        assert!(
            !component.contains(delimiter),
            "an encoded {what} still carries {delimiter:?}: {source:?}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut parts = data.split(|&byte| byte == 0xff);
    let alias = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let role_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let aid_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let oobi_text = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let alias_present = parts.next().is_some_and(|part| !part.is_empty());
    let document = parts.next().unwrap_or_default();

    // A role is whatever the agent or the caller says it is: `Role::Other` keeps an unnamed one,
    // which is what makes a hostile role representable at all.
    let role = Role::from(role_text.clone());
    assert_eq!(role.as_str(), role_text, "a role changed on its way through the type");

    // `get`: three segments and exactly one query parameter, whatever the alias and role hold.
    match ResourcePath::builder()
        .segment(IDENTIFIERS_SEGMENT)
        .segment(&alias)
        .segment(OOBIS_SEGMENT)
        .parameter(ROLE_PARAMETER, role.as_str())
        .build()
    {
        Ok(path) => {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(
                segments.len(),
                3,
                "an alias became {} segments: {alias:?}",
                segments.len()
            );
            assert_eq!(segments.first().copied(), Some(IDENTIFIERS_SEGMENT));
            assert_eq!(segments.get(2).copied(), Some(OOBIS_SEGMENT));
            assert_single_segment(segments.get(1).copied().unwrap_or_default(), "alias", &alias);

            let query = path.query().unwrap_or_default();
            assert!(query.starts_with("role="), "a role wrote {query:?}");
            assert_eq!(
                query.matches('&').count(),
                0,
                "a role wrote two parameters: {role_text:?}"
            );
            assert_eq!(query.matches('=').count(), 1, "a role wrote two values: {role_text:?}");
            // The signed path never carries the query, so no role can change what is signed.
            assert!(!path.path().contains('?'));
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    // `resolve`: one constant address, and an OOBI that is a URL or is refused.
    let resolution_path = ResourcePath::builder().segment(RESOLUTIONS_SEGMENT).build();
    match resolution_path {
        Ok(path) => {
            assert_eq!(path.as_str(), "/oobis");
            assert_eq!(path.query(), None);
        }
        Err(error) => assert!(!error.to_string().is_empty()),
    }

    if let Ok(url) = RequestUrl::new(oobi_text.clone()) {
        // A URL that validated is preserved exactly: the agent fetches these bytes.
        assert_eq!(url.as_str(), oobi_text);
        let mut resolution = OobiResolution::new(url);
        if alias_present {
            resolution = resolution.with_alias(alias.clone());
        }
        if let Ok(body) = resolution.body() {
            let parsed = serde_json::from_slice::<serde_json::Value>(&body);
            assert!(parsed.is_ok(), "a resolution body was not JSON: {oobi_text:?}");
            let decoded = parsed.unwrap_or(serde_json::Value::Null);
            assert_eq!(
                decoded.get("url").and_then(serde_json::Value::as_str),
                Some(oobi_text.as_str()),
                "a resolution body rewrote its URL"
            );
            let written = decoded.get("oobialias").and_then(serde_json::Value::as_str);
            assert_eq!(
                written,
                if alias_present { Some(alias.as_str()) } else { None },
                "an absent alias and an empty one stopped being distinguishable"
            );
            assert_eq!(
                decoded.as_object().map(serde_json::Map::len),
                Some(if alias_present { 2 } else { 1 })
            );
        }
    }

    // `endroles`: an AID is a validated prefix, so nothing hostile reaches the path at all, and a
    // role filter is exactly one more segment.
    if let Ok(identifier) = IdentifierPrefix::from_qb64(&aid_text) {
        let re_encoded = identifier.qb64();
        assert!(re_encoded.is_ok(), "a parsed prefix failed to re-encode: {aid_text:?}");
        let text = re_encoded.unwrap_or_default();
        // A qualified prefix's alphabet is URL-safe Base64, so it reaches the path unchanged —
        // which is what makes the reference's raw interpolation harmless for every real AID.
        assert_single_segment(&text, "AID", &aid_text);

        if let Ok(path) = ResourcePath::builder()
            .segment(END_ROLES_SEGMENT)
            .segment(&text)
            .segment(role.as_str())
            .build()
        {
            let segments: Vec<&str> = path.path().split('/').skip(1).collect();
            assert_eq!(
                segments.len(),
                3,
                "a role filter became {} segments: {role_text:?}",
                segments.len()
            );
            assert_eq!(segments.first().copied(), Some(END_ROLES_SEGMENT));
            assert_eq!(segments.get(1).copied(), Some(text.as_str()));
            assert_single_segment(segments.get(2).copied().unwrap_or_default(), "role filter", &role_text);
            assert_eq!(path.query(), None, "a role filter introduced a query");
        }
    }

    // The agent's answers. Each decodes into the shape it claims or is refused; nothing is cast.
    if let Ok(listing) = serde_json::from_slice::<Oobi>(document) {
        // A role that came back is kept exactly, named or not, and survives a round trip.
        let encoded = serde_json::to_vec(&listing);
        assert!(encoded.is_ok(), "a decoded listing failed to re-encode");
        let again = serde_json::from_slice::<Oobi>(&encoded.unwrap_or_default());
        assert!(again.is_ok(), "a re-encoded listing failed to decode");
        assert_eq!(
            again.ok(),
            Some(listing),
            "an OOBI listing did not survive a round trip"
        );
    }

    if let Ok(roles) = serde_json::from_slice::<Vec<EndRole>>(document) {
        for record in &roles {
            // A role that came back is read back to exactly what it was, named or not — which is
            // what makes decoding an answer rather than casting it lossless.
            assert_eq!(record.role, Role::from(record.role.as_str()));
        }
        let encoded = serde_json::to_vec(&roles);
        assert!(encoded.is_ok(), "decoded end roles failed to re-encode");
        let again = serde_json::from_slice::<Vec<EndRole>>(&encoded.unwrap_or_default());
        assert!(again.is_ok(), "re-encoded end roles failed to decode");
        assert_eq!(again.map(|records| records.len()).ok(), Some(roles.len()));
    }

    if let Ok(operation) = serde_json::from_slice::<OobiOperation>(document) {
        // An operation is pending or finished, never both and never neither.
        let done = operation.outcome.is_done();
        assert_eq!(
            done,
            operation.outcome.response().is_some() || operation.outcome.error().is_some()
        );
    }
});
