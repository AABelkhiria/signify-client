# HTTP retry and clock reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/coring.ts` (`Operations.wait`), `test-integration/utils/retry.ts`
- Binary fields: none. Delays are integer milliseconds exactly as the reference passed them to
  `setTimeout`.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/http_retry.mjs --write   # regenerate
node tools/reference-vectors/http_retry.mjs --check   # verify determinism
```

## What this fixture is

There is no retry module upstream to port. The delay formula appears exactly **twice** in the
pinned tree — in the production `Operations.wait` of `src/keri/app/coring.ts`, and in
`test-integration/utils/retry.ts` — and nothing else retries anything. So the fixture holds three
different kinds of evidence.

### `wait_schedules` — executed

`Operations.wait` sleeps with `new Promise((resolve) => setTimeout(resolve, delay))` against the
**global** timer, so the generator replaces that global with a recorder that captures each delay and
resolves immediately. No wall-clock time passes and the schedule is exact. The operation responses
are canned, exactly as the `http-transport` generator cans `fetch`.

Five cases: the defaults, the two option sets the pinned integration suites actually pass
(`singlesig-vlei-issuance`/`delegation-multisig` and `multisig-join`), an operation already finished
on the first poll, and a run long enough for the ceiling to bind.

At the defaults the recorded schedule is `50, 100, 200, 400, 800, 1600, 3200, 6400, 10000, 10000, …`
— doubling from `increaseFactor` and flattening at `maxSleep`.

### `integration_helper` — read from the syntax tree

The test helper is **not** executed. Intercepting its sleep would mean rewriting its
`timers/promises` import, which changes the code under test; instead the reference's own pinned
TypeScript 5.9.2 parses it and the fixture records its default values and its delay expression —
the technique established for the shared KERIA API types. That also proves the two formulas are
textually identical, which is why executing only the production one is sufficient.

### `server_guidance_scan` — a search, so the absence is evidence

All 117 `.ts` files under `src`, `test`, and `test-integration` are searched for `Retry-After` in
every spelling, and for the `429` and `503` statuses. **Every count is zero.** That is what makes
"the reference ignores server guidance" a recorded fact rather than a claim, and it is why the
`Retry-After` support in `signify-http::retry` has no cross-language counterpart: it is governed by
RFC 9110 alone.

## Reference behavior recorded as deliberate divergences

- **Production polling is unbounded.** `Operations.wait` is a `while (true)` with no deadline and
  no attempt cap, so an operation the agent never finishes hangs the caller forever; only a
  caller-supplied `AbortSignal` can end it. Rust's policy is bounded by construction — a maximum
  attempt count is required and a total deadline is checked.
- **Aborting is checked after sleeping.** The production loop passes no signal to its `setTimeout`
  and checks the signal only after waking, so aborting during a sleep still waits out the full
  delay — up to the 10 s ceiling. In Rust cancellation is dropping the future, so a dropped retry
  stops inside the sleep.
- **The helper and production disagree about aborting.** `retry.ts` passes its signal into
  `setTimeout(delay, undefined, { signal })`, so its sleep really is interruptible. The production
  loop does not. Rust has one behaviour at the one place a wait happens.
- **There is no jitter anywhere.** The delay is a pure function of the attempt number, so every
  client that starts an operation at the same moment retries at the same moments forever. Rust
  jitters by default (`Jitter::Equal`, a delay in `[d/2, d]`); `Jitter::None` reproduces this
  schedule exactly and is what the cross-language test compares against.
- **Server guidance is ignored** — see the scan above. Rust honours a valid `Retry-After` in
  delta-seconds or as an HTTP-date, bounded by a configured ceiling so a hostile or mistaken server
  cannot park a client indefinitely.
- **`minSleep` cannot bind at the defaults.** The floor is compared against `2**0 * increaseFactor`,
  already 50 ms, so the documented 10 ms minimum can never take effect unless a caller raises it —
  as the vLEI suites do, to 1000 ms, where it binds for the first five attempts. Rust keeps the
  floor as a real parameter and reproduces the schedule exactly, floor included.
- **An equal floor and ceiling flattens the curve.** `multisig-join` passes
  `minSleep === maxSleep === 500`, making the exponential term irrelevant. Reproduced.
- **The floor is applied outside the ceiling**, so a floor above the ceiling wins:
  `Math.max(minSleep, Math.min(maxSleep, …))`. Rust reproduces that ordering rather than clamping,
  because a clamp with an inverted range is a different function.
- **The helper retries every failure.** `retry.ts` retries whatever the callback threw — a network
  fault, a 400, a programming error — and the integration suites wrap whole credential lookups in
  it, so a permanently wrong request is repeated until the 10 s timeout elapses. Rust classifies an
  outcome before retrying it, and will not retry a method HTTP does not define as idempotent unless
  the caller widens the scope explicitly.

Rust tests consume the checked-in fixture and require neither Node nor network access.
