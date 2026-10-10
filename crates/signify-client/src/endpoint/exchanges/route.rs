//! The typed exchange route table.
//!
//! An exchange message's `r` field says what the message means. The pinned
//! `src/keri/app/exchanging.ts` exports thirteen constants for it — eight multisig coordination
//! steps and the five IPEX steps — and thirteen `is*` guards and thirteen `assert*` assertions that
//! do nothing but compare `r` with one of them.
//!
//! Here the thirteen are one enum, so a comparison is a `match` and the guards have nothing left to
//! do. The five IPEX routes are **not redefined**: they are Roadmap 6.3's
//! [`IpexRoute`], which already builds and submits those messages, so
//! the table composes rather than duplicates.
//!
//! # The table is not closed
//!
//! Thirteen constants, and the reference's own `Challenges.respond` sends a fourteenth —
//! `/challenge/response` — which no constant, guard, or assertion names. A route this table does
//! not name is therefore a message rather than an error; see
//! [`ClassifiedExchange::Other`](super::message::ClassifiedExchange::Other).

use core::fmt;
use core::str::FromStr;

use signify_keys::acdc::ipex::IpexRoute;

/// Which multisig coordination step a message proposes.
///
/// The variants are named for what the step *is* rather than for the ilk it carries, which is what
/// the route text spells: `/multisig/vcp` proposes a registry inception, and `/multisig/exn`
/// proposes another exchange message.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum MultisigRoute {
    /// Propose the group's inception; route `/multisig/icp`.
    Inception,
    /// Propose a rotation of the group's keys; route `/multisig/rot`.
    Rotation,
    /// Propose an interaction event; route `/multisig/ixn`.
    Interaction,
    /// Propose an authorization reply; route `/multisig/rpy`.
    Reply,
    /// Propose a credential registry; route `/multisig/vcp`.
    RegistryInception,
    /// Propose issuing a credential; route `/multisig/iss`.
    Issuance,
    /// Propose sending another exchange message; route `/multisig/exn`.
    Exchange,
    /// Propose revoking a credential; route `/multisig/rev`.
    Revocation,
}

impl MultisigRoute {
    /// Every multisig route, in the order the reference declares its constants.
    pub const ALL: [Self; 8] = [
        Self::Inception,
        Self::Rotation,
        Self::Interaction,
        Self::Reply,
        Self::RegistryInception,
        Self::Issuance,
        Self::Exchange,
        Self::Revocation,
    ];

    /// Returns the exact route text a message carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inception => "/multisig/icp",
            Self::Rotation => "/multisig/rot",
            Self::Interaction => "/multisig/ixn",
            Self::Reply => "/multisig/rpy",
            Self::RegistryInception => "/multisig/vcp",
            Self::Issuance => "/multisig/iss",
            Self::Exchange => "/multisig/exn",
            Self::Revocation => "/multisig/rev",
        }
    }

    /// Returns whether this step names the members it is proposing to.
    ///
    /// Inception, rotation, and interaction carry `smids` — the reference declares it required on
    /// exactly those three, and every call site in `test-integration/multisig.test.ts` sends it
    /// together with `rmids`. The other five carry the group identifier alone there. This port
    /// *sends* both lists on every route but *requires* them only where the reference does, so
    /// a reference proposal carrying `{ gid }` alone is still read.
    #[must_use]
    pub const fn names_members(self) -> bool {
        matches!(self, Self::Inception | Self::Rotation | Self::Interaction)
    }
}

impl fmt::Display for MultisigRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A route this port knows the shape of.
///
/// ```
/// use signify_client::endpoint::exchanges::{ExchangeRoute, MultisigRoute};
/// use signify_keys::acdc::ipex::IpexRoute;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// assert_eq!(ExchangeRoute::ALL.len(), 13);
/// assert_eq!(
///     "/multisig/icp".parse::<ExchangeRoute>()?,
///     ExchangeRoute::Multisig(MultisigRoute::Inception)
/// );
/// assert_eq!("/ipex/grant".parse::<ExchangeRoute>()?, ExchangeRoute::Ipex(IpexRoute::Grant));
/// // The table is not closed: this crate's own challenge answer is not in it.
/// assert!("/challenge/response".parse::<ExchangeRoute>().is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExchangeRoute {
    /// One of the eight multisig coordination steps.
    Multisig(MultisigRoute),
    /// One of the five IPEX disclosure steps, which are Roadmap 6.3's.
    Ipex(IpexRoute),
}

impl ExchangeRoute {
    /// Every route the reference declares a constant for, multisig first.
    pub const ALL: [Self; 13] = [
        Self::Multisig(MultisigRoute::Inception),
        Self::Multisig(MultisigRoute::Rotation),
        Self::Multisig(MultisigRoute::Interaction),
        Self::Multisig(MultisigRoute::Reply),
        Self::Multisig(MultisigRoute::RegistryInception),
        Self::Multisig(MultisigRoute::Issuance),
        Self::Multisig(MultisigRoute::Exchange),
        Self::Multisig(MultisigRoute::Revocation),
        Self::Ipex(IpexRoute::Grant),
        Self::Ipex(IpexRoute::Offer),
        Self::Ipex(IpexRoute::Apply),
        Self::Ipex(IpexRoute::Agree),
        Self::Ipex(IpexRoute::Admit),
    ];

    /// Returns the exact route text a message carries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Multisig(route) => route.as_str(),
            Self::Ipex(route) => route.as_str(),
        }
    }

    /// Returns the route this text names, or `None` when the table does not name it.
    ///
    /// This is the non-failing form of [`FromStr`], for the common case where an unnamed route is
    /// an ordinary message rather than a mistake.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|route| route.as_str() == text)
    }
}

impl fmt::Display for ExchangeRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ExchangeRoute {
    type Err = UnknownExchangeRoute;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text).ok_or_else(|| UnknownExchangeRoute { route: text.to_owned() })
    }
}

/// A route text the table does not name.
///
/// This is not always a failure: the route space is open, and the classifier reports an unnamed
/// route as [`ClassifiedExchange::Other`](super::message::ClassifiedExchange::Other) rather than
/// refusing it. The error exists for callers who genuinely require one of the thirteen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownExchangeRoute {
    /// The route text that was not recognised, as the message carried it.
    pub route: String,
}

impl fmt::Display for UnknownExchangeRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?} is not an exchange route this table names", self.route)
    }
}

impl std::error::Error for UnknownExchangeRoute {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_route_writes_the_references_own_literal() {
        assert_eq!(
            MultisigRoute::ALL.map(MultisigRoute::as_str),
            [
                "/multisig/icp",
                "/multisig/rot",
                "/multisig/ixn",
                "/multisig/rpy",
                "/multisig/vcp",
                "/multisig/iss",
                "/multisig/exn",
                "/multisig/rev",
            ]
        );
        // The five IPEX routes are Roadmap 6.3's, not redefined here.
        assert_eq!(
            ExchangeRoute::ALL
                .into_iter()
                .filter_map(|route| match route {
                    ExchangeRoute::Ipex(ipex) => Some(ipex.as_str()),
                    ExchangeRoute::Multisig(_) => None,
                })
                .collect::<Vec<&str>>(),
            [
                "/ipex/grant",
                "/ipex/offer",
                "/ipex/apply",
                "/ipex/agree",
                "/ipex/admit"
            ]
        );
    }

    #[test]
    fn the_table_holds_thirteen_distinct_routes() {
        assert_eq!(ExchangeRoute::ALL.len(), 13);
        let texts: BTreeSet<&str> = ExchangeRoute::ALL.iter().map(|route| route.as_str()).collect();
        assert_eq!(texts.len(), 13, "two routes share one text");
        // Eight multisig and five IPEX, which is how the reference groups its constants.
        assert_eq!(texts.iter().filter(|text| text.starts_with("/multisig/")).count(), 8);
        assert_eq!(texts.iter().filter(|text| text.starts_with("/ipex/")).count(), 5);
    }

    #[test]
    fn every_route_round_trips_through_its_text() {
        for route in ExchangeRoute::ALL {
            assert_eq!(ExchangeRoute::parse(route.as_str()), Some(route));
            assert_eq!(route.as_str().parse::<ExchangeRoute>(), Ok(route));
            assert_eq!(route.to_string(), route.as_str());
        }
    }

    #[test]
    fn a_route_the_table_does_not_name_is_refused_by_name() {
        // The reference's own `Challenges.respond` sends this one, so it is a real route that
        // simply is not in the table.
        let outcome = "/challenge/response".parse::<ExchangeRoute>();
        assert_eq!(
            outcome,
            Err(UnknownExchangeRoute {
                route: "/challenge/response".to_owned()
            })
        );
        assert!(ExchangeRoute::parse("/challenge/response").is_none());
        if let Err(error) = outcome {
            assert!(error.to_string().contains("/challenge/response"));
        }
    }

    #[test]
    fn a_near_miss_is_not_a_route() {
        for text in [
            "",
            "/multisig",
            "/multisig/",
            "/multisig/icp/",
            "multisig/icp",
            "/MULTISIG/ICP",
            "/multisig/icp ",
            " /multisig/icp",
            "/ipex/spurn",
            "/multisig/dip",
        ] {
            assert!(ExchangeRoute::parse(text).is_none(), "{text:?} was accepted as a route");
        }
    }

    #[test]
    fn only_the_three_member_bearing_steps_name_members() {
        // The reference declares `smids` required on exactly these three.
        let naming: Vec<&str> = MultisigRoute::ALL
            .into_iter()
            .filter(|route| route.names_members())
            .map(MultisigRoute::as_str)
            .collect();
        assert_eq!(naming, ["/multisig/icp", "/multisig/rot", "/multisig/ixn"]);
    }
}
