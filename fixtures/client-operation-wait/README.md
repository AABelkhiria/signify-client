# Operation polling reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/coring.ts`, `src/types/keria-api-schema.ts`,
  `test/app/coring.test.ts`, `test-integration/utils/test-util.ts`
- Binary fields: none. Paths, delays, and thrown messages are exact text; answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_operation_wait.mjs --write   # regenerate
node tools/reference-vectors/client_operation_wait.mjs --check   # verify determinism
```

## Determinism

The **global timer is replaced** with a recorder, so every delay is captured and nothing waits in
wall-clock time — the technique Roadmap 5.4's fixture established. Nothing here derives a key, reads
a clock, or is secret.

## What the evidence is

Roadmap 7.2 ports `Operations.wait`, together with the private `hasDepends` it consults and the
`throwIfFailed` it applies at every exit.

Roadmap 5.4 already recorded this function's **delay schedule** by executing it, and reproduces all
five recorded schedules exactly (`fixtures/http-retry/`). So what this fixture adds is everything
else the loop does: how many requests each shape costs and in what order, when the dependency is
walked and when it is skipped, which exits throw, and what the thrown message carries.

`Operations` takes an `OperationsDeps` — one `fetch` method — so the reference's own class is driven
against a recorder, exactly as the pinned `coring.test.ts` drives it.

The pinned unit test has **five `wait` cases, four of which assert an exact request count**, and one
of which asserts the returned object is the very one passed in. `pinned_confirmations.unit_test_cases`
reproduces every count from the reference's own driven output, and the generator fails if any stops
matching.

## Contents

- `calls` pins fifteen waits: the five pinned cases, both dependency-skipping branches, a dependency
  that fails while being polled, three failure exits, the null-error branch, a metadata block with no
  dependency, and a twelve-sleep run that reaches the ceiling.
- `declarations` pins the whole `wait` body, its three defaults, its delay expression, its unbounded
  loop, the abort read after the sleep, `hasDepends`, `throwIfFailed`, the integration helper, and
  **every schema property named `depends`** — all read from the reference's own syntax tree.
- `pinned_confirmations` pins the five unit-test cases with their asserted counts, the six direct
  `wait` call sites, the 262 `waitOperation` ones, and the helper's 30-second timeout.
- `reference_quirks` pins ten behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **The loop has no bound at all.** `while (true)` with no deadline, no attempt cap, and no total
  budget: an operation the agent never finishes is polled forever, ten seconds apart, for as long as
  the process lives. **Bounded by construction** here — `PollPolicy` carries Roadmap 5.4's
  `RetryPolicy`, so every recorded delay still reproduces, plus a maximum attempt count and a total
  deadline. The default deadline is **thirty seconds**, which is not invented: it is what the
  reference's own `waitOperation` supplies through `AbortSignal.timeout(30000)`.
- **The abort is read only after sleeping.** `options.signal?.throwIfAborted()` sits *after* the
  `await`, so a caller who aborts during a wait still waits out the full delay — up to ten seconds —
  and the signal is never read before the first request either. **Unrepresentable** here:
  cancellation is dropping the future (ADR `0019`), which cancels the outstanding sleep at once. A
  test polls the future once, drops it mid-sleep, and asserts no further request is made.
- **A failed dependency is skipped in silence.** The guard is `!op.metadata.depends.done` — it tests
  whether the dependency *finished*, not whether it succeeded — so a snapshot whose dependency is
  already done-and-failed polls the parent as though nothing were wrong. **Reproduced**, because the
  parent's own outcome is what is being waited on and the agent still decides it; what is not
  reproduced is the silence, which the method's own documentation and a test now name.
- **The chain is one link long.** `wait` calls itself on `op.metadata.depends`, which reads as
  arbitrary depth. The schema declares `depends` on exactly three shapes — registry, credential, and
  delegator — and all three type it as a `KelOperation`, which declares none. **Reproduced as a loop
  over one optional dependency** rather than as recursion over remote data, and the generator fails
  if that owner set ever changes.
- **The guard tests the key, not the value.** `hasDepends` is `'depends' in op.metadata`, true for a
  block carrying `depends: null`; the truthiness test beside it is what actually skips it. Here an
  absent dependency and a null one are one `Option`, and the recorded request count is unchanged.
- **An already-finished operation costs nothing** and is returned *by identity* — the pinned test
  asserts `op === result`. Reproduced: the operation is taken by value and moved through, with zero
  requests asserted.
- **An already-failed operation throws before asking.** Reproduced, through Roadmap 6.5's
  `completed`.
- **A null error is not a failure.** `'error' in op && op.error !== null`, which is the shape a KERIA
  agent sends for a successful operation. Reproduced by Roadmap 4.1's three-state decoder.
- **The failure message is one interpolated string** — name, code, message, and detail block in a
  sentence. Roadmap 6.5 already keeps the four apart in `ClientError::OperationFailed`, with the
  remote message bounded; `wait` reuses it and adds no failure variant of its own.
- **The integration helper deletes what it waited for**, walking the whole dependency chain to do
  it. The timeout becomes this port's default deadline; the **deletion is not ported** — it is a
  test helper's cleanup, `Operations::delete` is already available, and a wait that silently deleted
  its subject would be a surprising side effect. Recorded so the omission is a decision.

## One shape this port refuses

Three of the reference's own queued answers are `{name, done: true}` with neither a response nor an
error, which Roadmap 4.1's decoder refuses because it leaves the outcome undecided. The request
counts above are therefore reproduced with well-formed bodies, and
`a_finished_operation_with_no_response_is_refused` proves the reference's own literal refused, with
its recorded result showing it carried no response.

Rust tests consume the checked-in fixture and require neither Node nor network access.
