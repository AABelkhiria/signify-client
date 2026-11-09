//! Invariants of the IPEX presentation workflow.
//!
//! A step answers exactly the step it was given, and what an apply asks for survives being read.

mod support;

use std::error::Error;
use std::sync::Arc;

use crate::support::{ADMIN, AgentTransport, BOOT, PASSCODE, agent_state, block_on, clock};
use keri_protocol::event::Timestamp;
use keria_types::api::ExchangeResource;
use proptest::prelude::*;
use signify_client::client::{ConnectedClient, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::error::ClientError;
use signify_client::presentation::{ATTRIBUTE_FILTER_PREFIX, ReceivedStep, SCHEMA_FILTER, requested_credentials};
use signify_http::transport::Transport;
use signify_keys::acdc::ipex::IpexRoute;
use signify_keys::manager::DerivationCost;

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SAID: &str = "EDgvqnAQWAks1nXM1WD8kXRAan4ZkdoGAhP9_UtkGfFg";
const PRIOR: &str = "EM_FKO3crm8s4dpQ0aBl8pO2tz0B35hAWmuPBy0mns9v";
const SCHEMA: &str = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const STAMP: &str = "2023-11-14T22:13:20.123000+00:00";
const CREDENTIAL: &str = "EGdeVjXib7lVynr1NAddi1YTO2BCU5oi_I5DT69n9zJd";

fn embeds(route: IpexRoute) -> String {
    match route {
        IpexRoute::Offer => format!(
            r#"{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}","i":"{LOCAL}","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}}}}"#
        ),
        IpexRoute::Grant => format!(
            r#"{{"d":"EEMB","acdc":{{"v":"ACDC10JSON000100_","d":"{CREDENTIAL}","i":"{LOCAL}","s":"{SCHEMA}","a":{{"LEI":"5493001KJTIIGC8Y1R17"}}}},"iss":{{"v":"KERI10JSON000100_","t":"iss","d":"EISS","i":"{CREDENTIAL}","s":"0","ri":"EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX","dt":"2023-11-14T22:13:20.123000+00:00"}},"anc":{{"v":"KERI10JSON000100_","t":"ixn","d":"EANC","i":"{LOCAL}","s":"1","p":"{LOCAL}","a":[]}}}}"#
        ),
        IpexRoute::Apply | IpexRoute::Agree | IpexRoute::Admit => "{}".to_owned(),
    }
}

fn step(route: IpexRoute, prior: &str, attributes: &str) -> Result<ReceivedStep, TestCaseError> {
    let document = format!(
        r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"{SAID}","i":"{LOCAL}","rp":"{PEER}","p":"{prior}","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{attributes},"e":{embeds}}},"pathed":{{}}}}"#,
        route = route.as_str(),
        embeds = embeds(route)
    );
    let resource: ExchangeResource =
        serde_json::from_str(&document).map_err(|error| TestCaseError::fail(error.to_string()))?;
    ReceivedStep::of("0AAnote", &resource).map_err(|error| TestCaseError::fail(error.to_string()))
}

fn label() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_]{0,12}".prop_filter("the message and schema labels are the request's own", |text| {
        text != "m" && text != "s" && text != "a"
    })
}

proptest! {
    #[test]
    fn a_request_survives_becoming_a_filter(
        attributes in prop::collection::hash_map(label(), "[a-zA-Z0-9 ]{0,20}", 0..6)
    ) {
        let written_attributes = attributes
            .iter()
            .map(|(name, value)| format!(r#""{name}":"{value}""#))
            .collect::<Vec<_>>()
            .join(",");
        let block = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{{written_attributes}}}}}"#);
        let apply = step(IpexRoute::Apply, "", &block)?;

        let filter = requested_credentials(&apply).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let bytes = filter.to_json_bytes().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let written = String::from_utf8(bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;

        let schema_entry = format!(r#""{SCHEMA_FILTER}":"{SCHEMA}""#);
        prop_assert!(written.contains(&schema_entry), "{written}");
        for (name, value) in &attributes {
            let entry = format!(r#""{ATTRIBUTE_FILTER_PREFIX}{name}":"{value}""#);
            prop_assert!(written.contains(&entry), "{name} did not survive: {written}");
        }
    }

    #[test]
    fn a_step_names_what_it_answers(answered in prop::bool::ANY) {
        let prior = if answered { PRIOR } else { "" };
        let received = step(IpexRoute::Offer, prior, r#"{"m":""}"#)?;

        let named = received.answers().map_err(|error| TestCaseError::fail(error.to_string()))?;
        if answered {
            let text = named
                .map(|said| said.qb64())
                .transpose()
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
            prop_assert_eq!(text, Some(PRIOR.to_owned()));
        } else {
            prop_assert!(named.is_none());
        }
    }

    #[test]
    fn a_step_reads_its_own_identity(chosen in 0usize..5) {
        let Some(route) = IpexRoute::ALL.get(chosen) else {
            return Err(TestCaseError::fail("the route table shrank"));
        };
        let attributes = if *route == IpexRoute::Apply {
            format!(r#"{{"m":"","s":"{SCHEMA}","a":{{}}}}"#)
        } else {
            r#"{"m":""}"#.to_owned()
        };
        let received = step(*route, "", &attributes)?;

        let said = received
            .said()
            .and_then(|said| Ok(said.qb64()?))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let sender = received
            .sender()
            .and_then(|prefix| Ok(prefix.qb64()?))
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(said, SAID.to_owned());
        prop_assert_eq!(sender, LOCAL.to_owned());
        prop_assert_eq!(received.notification(), "0AAnote");
        prop_assert_eq!(received.exchange().route.as_str(), route.as_str());
    }

    #[test]
    fn an_attribute_keeps_its_type(number in 0i64..1_000_000, flag in prop::bool::ANY) {
        let block = format!(r#"{{"m":"","s":"{SCHEMA}","a":{{"count":{number},"exact":{flag}}}}}"#);
        let apply = step(IpexRoute::Apply, "", &block)?;
        let filter = requested_credentials(&apply).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let bytes = filter.to_json_bytes().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let written = String::from_utf8(bytes).map_err(|error| TestCaseError::fail(error.to_string()))?;

        let counted = format!(r#""{ATTRIBUTE_FILTER_PREFIX}count":{number}"#);
        let exact = format!(r#""{ATTRIBUTE_FILTER_PREFIX}exact":{flag}"#);
        prop_assert!(written.contains(&counted), "{written}");
        prop_assert!(written.contains(&exact), "{written}");
    }

    #[test]
    fn only_the_five_routes_are_steps(route in "/[a-z]{2,8}/[a-z]{2,8}") {
        prop_assume!(!IpexRoute::ALL.iter().any(|known| known.as_str() == route));
        let document = format!(
            r#"{{"exn":{{"v":"KERI10JSON000100_","t":"exn","d":"{SAID}","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{route}","q":{{}},"a":{{}},"e":{{}}}},"pathed":{{}}}}"#
        );
        let resource: ExchangeResource =
            serde_json::from_str(&document).map_err(|error| TestCaseError::fail(error.to_string()))?;

        let refused = matches!(
            ReceivedStep::of("", &resource),
            Err(ClientError::NotADisclosureStep { .. })
        );
        prop_assert!(refused, "{route} classified as a disclosure step");
    }

    #[test]
    fn a_request_without_a_schema_is_refused(labels in prop::collection::vec(label(), 0..4)) {
        let attributes = labels
            .iter()
            .map(|name| format!(r#""{name}":"x""#))
            .collect::<Vec<_>>()
            .join(",");
        let block = format!(r#"{{"m":"","a":{{{attributes}}}}}"#);
        let apply = step(IpexRoute::Apply, "", &block)?;

        let refused = matches!(
            requested_credentials(&apply),
            Err(ClientError::MalformedDisclosureRequest { .. })
        );
        prop_assert!(refused, "an apply with no schema produced a filter");
    }
}

/// Each answering call, the route it answers, and that route's wire text.
const ANSWERING: [(IpexRoute, &str); 3] = [
    (IpexRoute::Apply, "/ipex/apply"),
    (IpexRoute::Offer, "/ipex/offer"),
    (IpexRoute::Grant, "/ipex/grant"),
];

/// Every step and its wire text.
const STEPS: [(IpexRoute, &str); 5] = [
    (IpexRoute::Apply, "/ipex/apply"),
    (IpexRoute::Offer, "/ipex/offer"),
    (IpexRoute::Agree, "/ipex/agree"),
    (IpexRoute::Grant, "/ipex/grant"),
    (IpexRoute::Admit, "/ipex/admit"),
];

fn connected() -> Result<(ConnectedClient, Arc<AgentTransport>), Box<dyn Error>> {
    let configuration = || {
        ClientConfig::new(ADMIN, PASSCODE)
            .and_then(|config| config.with_boot_url(BOOT))
            .map(|config| config.with_derivation_cost(DerivationCost::Ephemeral))
    };
    let probe = SignifyClient::new(
        configuration()?,
        AgentTransport::new(&[]) as Arc<dyn Transport>,
        clock(),
    )?;
    let prefix = probe.controller().prefix().qb64()?;
    let inception = core::str::from_utf8(probe.controller().current_event().raw())?.to_owned();

    let state = agent_state(&prefix, &inception);
    let transport = AgentTransport::new(&[state.as_bytes(), b"{}"]);
    let client = SignifyClient::new(configuration()?, Arc::clone(&transport) as Arc<dyn Transport>, clock())?;
    Ok((block_on(client.connect())?, transport))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 32, ..ProptestConfig::default() })]

    #[test]
    fn a_step_answers_only_its_own_kind(chosen in 0usize..5, asked in 0usize..3) {
        let (Some(&(carried, carried_text)), Some(&(answers, answers_text))) = (STEPS.get(chosen), ANSWERING.get(asked)) else {
            return Err(TestCaseError::fail("the route table shrank"));
        };
        let attributes = if carried == IpexRoute::Apply {
            format!(r#"{{"m":"","s":"{SCHEMA}","a":{{}}}}"#)
        } else {
            r#"{"m":""}"#.to_owned()
        };
        let received = step(carried, "", &attributes)?;

        if carried == answers {
            // Only the apply's answer is local; the other two go on to sign through the agent.
            if answers == IpexRoute::Apply {
                let filter = requested_credentials(&received).map_err(|error| TestCaseError::fail(error.to_string()))?;
                prop_assert_eq!(filter.filter.get_text(SCHEMA_FILTER), Some(SCHEMA));
            }
            return Ok(());
        }

        let (client, transport) = connected().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let stamp = STAMP.parse::<Timestamp>().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let outcome = match answers {
            IpexRoute::Apply => requested_credentials(&received).map(drop),
            IpexRoute::Offer => block_on(client.presentation().agree("aid1", &received, "", &stamp)).map(drop),
            _ => block_on(client.presentation().admit("aid1", &received, "", &stamp)).map(drop),
        };
        match outcome {
            Err(ClientError::WrongDisclosureStep { expected, found }) => {
                prop_assert_eq!(expected, answers_text);
                prop_assert_eq!(found, carried_text);
            }
            other => return Err(TestCaseError::fail(format!("a {carried_text} answered as a {answers_text}: {other:?}"))),
        }
        let sent = transport.endpoint_requests().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(sent.is_empty(), "a refused step reached the agent");
    }
}
