//! Microbenchmark for the client lifecycle.
//!
//! Almost everything here is dominated by key derivation. Constructing a client derives the
//! controller's two keys, and connecting derives a third for the authenticator plus the salt the
//! keeper factory needs — so at the **production** profile a connect is four Argon2 runs at 64 MiB
//! each, which is the number worth knowing before an SDK does it on a UI thread.
//!
//! The per-request costs are measured at the ephemeral profile, because they do not depend on it:
//! a signed request is one Ed25519 signature over a short base, whatever the keys cost to make.

use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use signify_client::client::{ClientRequest, SignifyClient};
use signify_client::config::ClientConfig;
use signify_client::random::{random_nonce, random_passcode};
use signify_http::header::{HeaderName, HeaderValue, Headers};
use signify_http::request::ResourcePath;
use signify_http::retry::{Clock, TestClock};
use signify_http::transport::{Method, Response, ScriptedTransport, StatusCode};
use signify_keys::manager::DerivationCost;

const ADMIN: &str = "http://127.0.0.1:3901";
const BOOT: &str = "http://127.0.0.1:3903";
const PASSCODE: &str = "0123456789abcdefghijk";
const AGENT: &str = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
const AGENT_KEY: &str = "BHptu91ecGv_mxO8T3b98vNQUCghT8nfYkWRkVqOZark";

/// A minimal executor; every future here is ready on its first poll.
fn block_on<F: core::future::Future>(future: F) -> F::Output {
    use core::task::{Context, Poll, Waker};
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

fn clock() -> Arc<dyn Clock> {
    Arc::new(TestClock::with_wall_clock(
        SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_123),
    ))
}

fn config(cost: DerivationCost) -> Option<ClientConfig> {
    ClientConfig::new(ADMIN, PASSCODE)
        .ok()?
        .with_boot_url(BOOT)
        .ok()
        .map(|config| config.with_derivation_cost(cost))
}

fn agent_state(controller_prefix: &str, inception: &str) -> String {
    let agent = format!(
        r#"{{"vn":[1,0],"i":"{AGENT}","s":"0","p":"","d":"{AGENT}","f":"0","dt":"2023-12-01T10:05:25.062609+00:00","et":"dip","kt":"1","k":["{AGENT_KEY}"],"nt":"1","n":["EL6zVoZ0F8OXcbXP4LOm5oJTxCXP6ZLp5o3vNfvVZ9YB"],"bt":"0","b":[],"c":[],"ee":{{"s":"0","d":"{AGENT}","br":[],"ba":[]}},"di":"{controller_prefix}"}}"#
    );
    format!(r#"{{"agent":{agent},"controller":{{"state":{agent},"ee":{inception}}},"ridx":0,"pidx":0}}"#)
}

fn response(body: Vec<u8>) -> Option<Response> {
    let mut headers = Headers::new();
    headers
        .insert(HeaderName::new("signify-resource").ok()?, HeaderValue::new(AGENT).ok()?)
        .ok()?;
    Response::new(StatusCode::new(200).ok()?, headers, body).ok()
}

fn benchmark_lifecycle(criterion: &mut Criterion) {
    let (Some(cheap), Some(production)) = (config(DerivationCost::Ephemeral), config(DerivationCost::Production))
    else {
        return;
    };

    // Constructing a client derives the controller's current and next key.
    criterion.bench_function("client_new_ephemeral", |bencher| {
        bencher
            .iter(|| SignifyClient::new(black_box(cheap.clone()), Arc::new(ScriptedTransport::new()), clock()).is_ok());
    });
    criterion.bench_function("client_new_production", |bencher| {
        bencher.iter(|| {
            SignifyClient::new(
                black_box(production.clone()),
                Arc::new(ScriptedTransport::new()),
                clock(),
            )
            .is_ok()
        });
    });

    let Ok(client) = SignifyClient::new(cheap.clone(), Arc::new(ScriptedTransport::new()), clock()) else {
        return;
    };
    let (Ok(prefix), Ok(inception)) = (
        client.controller().prefix().qb64(),
        core::str::from_utf8(client.controller().current_event().raw()).map(str::to_owned),
    ) else {
        return;
    };
    let state = agent_state(&prefix, &inception);

    // The boot body: one signature over the inception, plus the JSON assembly.
    criterion.bench_function("boot_body", |bencher| {
        bencher.iter(|| black_box(&client).boot_body().is_ok());
    });

    // Connecting: a state read, a controller rebuild (two more derivations), the authenticator's
    // key (a third), the keeper salt, and the delegation approval.
    criterion.bench_function("connect_ephemeral", |bencher| {
        bencher.iter_batched(
            || {
                let transport = Arc::new(ScriptedTransport::new());
                response(state.clone().into_bytes()).map(|answer| {
                    transport.push_response(answer);
                    if let Some(empty) = response(b"{}".to_vec()) {
                        transport.push_response(empty);
                    }
                    transport
                })
            },
            |transport| {
                transport.and_then(|transport| {
                    SignifyClient::new(cheap.clone(), transport, clock())
                        .ok()
                        .map(|client| block_on(client.connect()).is_ok())
                })
            },
            BatchSize::SmallInput,
        );
    });

    // One signed request, which is where an SDK spends its time once connected.
    let connected = {
        let transport = Arc::new(ScriptedTransport::new());
        let Some(answer) = response(state.clone().into_bytes()) else {
            return;
        };
        transport.push_response(answer);
        let Some(empty) = response(b"{}".to_vec()) else {
            return;
        };
        transport.push_response(empty);
        for _ in 0..1_000_000 {
            match response(b"[]".to_vec()) {
                Some(answer) => transport.push_response(answer),
                None => return,
            }
        }
        match SignifyClient::new(cheap.clone(), transport, clock()) {
            Ok(client) => match block_on(client.connect()) {
                Ok(connected) => connected,
                Err(_) => return,
            },
            Err(_) => return,
        }
    };
    let Ok(path) = ResourcePath::builder().segment("contacts").build() else {
        return;
    };
    criterion.bench_function("signed_request", |bencher| {
        bencher.iter(|| {
            block_on(black_box(&connected).fetch(ClientRequest::new(Method::Get, black_box(path.clone())))).is_err()
        });
    });

    // Both random helpers, which are one entropy draw and one qualification each.
    criterion.bench_function("random_passcode", |bencher| {
        bencher.iter(|| random_passcode().is_ok());
    });
    criterion.bench_function("random_nonce", |bencher| {
        bencher.iter(|| random_nonce().is_ok());
    });
}

criterion_group!(benches, benchmark_lifecycle);
criterion_main!(benches);
