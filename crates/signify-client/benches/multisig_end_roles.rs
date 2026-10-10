//! Microbenchmark for a group's agent end-role round.
//!
//! The two reads the round rests on, both over input from other parties: a joining member reading
//! the end role a proposal asks it to sign, and a proposing member reading every member's agent
//! out of the group's listing. The listing grows with the group, so it is measured at two, sixteen,
//! and sixty-four members; a proposal does not grow.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_protocol::prefix::IdentifierPrefix;
use keria_types::api::{ExchangeEmbed, GroupMember, MultisigExchangeResource};
use signify_client::endpoint::exchanges::{ClassifiedExchange, GROUP_LABEL};
use signify_client::multisig::{REPLY_ROUTE, REPLY_SLOT, member_agents, proposed_end_role};

const LOCAL: &str = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const PEER: &str = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const GROUP: &str = "EISBcwQkfNCtFc-9k1IiB7neavhY4ZoQ0IRf-Rcev5Tk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";

fn proposal() -> String {
    let reply = format!(
        r#"{{"v":"KERI10JSON000111_","t":"rpy","d":"EJpM2-CCJv10ZqUmui0pe1Og_T-hpwx5poeYEKmPlWpn","dt":"2023-11-14T22:13:20.123000+00:00","r":"/end/role/add","a":{{"cid":"{GROUP}","role":"agent","eid":"{AGENT}"}}}}"#
    );
    let exn = format!(
        r#"{{"v":"KERI10JSON000_","t":"exn","d":"EEXN","i":"{LOCAL}","rp":"{PEER}","p":"","dt":"2023-11-14T22:13:20.123000+00:00","r":"{REPLY_ROUTE}","q":{{}},"a":{{"{GROUP_LABEL}":"{GROUP}"}},"e":{{"d":"EEMB","{REPLY_SLOT}":{reply}}}}}"#
    );
    format!(r#"[{{"exn":{exn},"paths":{{}}}}]"#)
}

fn listing(members: usize) -> String {
    let record = format!(r#"{{"aid":"{LOCAL}","ends":{{"agent":{{"{AGENT}":{{"http":"http://127.0.0.1:3902/"}}}}}}}}"#);
    let records = vec![record; members].join(",");
    format!(r#"{{"signing":[{records}],"rotation":[]}}"#)
}

fn read_proposal(document: &str, group: &IdentifierPrefix) -> bool {
    let listing: Vec<MultisigExchangeResource> = serde_json::from_str(document).unwrap_or_default();
    listing
        .first()
        .and_then(|entry| ClassifiedExchange::try_from(entry).ok())
        .and_then(|classified| classified.as_multisig().cloned())
        .is_some_and(|proposal| match &proposal.proposed.message {
            ExchangeEmbed::Reply(embed) => proposed_end_role(group, &embed.rpy).is_ok(),
            _ => false,
        })
}

fn read_listing(document: &str) -> usize {
    serde_json::from_str::<GroupMember>(document)
        .ok()
        .and_then(|listing| member_agents(&listing).ok())
        .map_or(0, |agents| agents.len())
}

fn benchmark_multisig_end_roles(criterion: &mut Criterion) {
    let Ok(group) = IdentifierPrefix::from_qb64(GROUP) else {
        return;
    };
    let document = proposal();
    criterion.bench_function("multisig_read_end_role_proposal", |bencher| {
        bencher.iter(|| read_proposal(black_box(&document), &group));
    });

    for members in [2_usize, 16, 64] {
        let document = listing(members);
        criterion.bench_function(&format!("multisig_read_member_agents_{members}"), |bencher| {
            bencher.iter(|| read_listing(black_box(&document)));
        });
    }
}

criterion_group!(benches, benchmark_multisig_end_roles);
criterion_main!(benches);
