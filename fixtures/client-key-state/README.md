# Key-event and key-state endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Corroborating: `https://github.com/WebOfTrust/keripy.git` at `4ce4cc79` (see below — evidence, not
  a governing reference)
- Generated: 2026-08-24
- Sources: `src/keri/app/coring.ts`, `src/types/keria-api-schema.ts`, `test/app/coring.test.ts`
- Binary fields: none. Paths and bodies are exact text; the answers are exact JSON.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_key_state.mjs --write   # regenerate
node tools/reference-vectors/client_key_state.mjs --check   # verify determinism
```

## Determinism

The **clock** and the **agent's key** are pinned, as the `client-lifecycle` fixture pinned them, so
a signed request is exact. Nothing in either family derives an identifier key, so the generator is
fast.

## What the evidence is

This port covers `KeyEvents.get` and `KeyStates.{get,list,query}`. `Config` lives in the same
upstream file and has its own `client-config` fixture; nothing here touches it.

Both classes take a whole `SignifyClient` rather than a narrow dependency interface — unlike
`Operations` and `Identifier`, which take one — so this fixture drives the reference the way the
`client-lifecycle` fixture did: `globalThis.fetch` is replaced with a recorder that answers and
signs as a KERIA agent would, and the real client is walked through boot, connect, and then all
eleven calls.

`declarations` holds the four path expressions, the query body literal, `query`'s parameter list
and its own JSDoc, and the schema's `QueryMetadata.sn`, `QueryMetadata.anchor`, `Anchor`, `Seal`,
and `KeyEventRecord` members, read out of the reference's own syntax tree.
`pinned_confirmations` closes the loop against the test suite: the four paths `coring.test.ts`
asserts are all produced here by the reference's own classes, and the query body is the one it
inspects field by field.

Every one of the eleven calls **succeeds** upstream — including an empty listing, a prefix carrying
query delimiters, and a two-digit sequence number. The reference validates none of them.

## Contents

- `calls` pins eleven requests: two key-event reads, four key-state reads, and five queries.
- `reference_quirks` pins seven behaviours, each with what the reference does and what this port
  does instead.

## Reference behavior recorded as deliberate divergences

- **No query value is encoded.** All three read paths interpolate their prefix straight in, so
  `get("E&pre=EOTHER#x")` addresses `/events?pre=E&pre=EOTHER#x` — a second parameter and a
  fragment. **Refused twice over**: the argument is a validated `IdentifierPrefix` rather than a
  string, and the request builder would encode it exactly once regardless. Because a qualified
  prefix's alphabet is URL-safe Base64, encoding leaves every real prefix byte-identical to what
  the reference sends.
- **An empty listing addresses `/states?`.** `list([])` joins nothing and still interpolates the
  question mark — the same defect the `client-operations` fixture recorded for `/operations?`. **Not
  reproduced**, on that fixture's own three grounds; here it is `ClientError::EmptyKeyStateListing`
  before anything is sent, because asking for no key states is a caller mistake rather than a
  request.
- **A listing is unbounded.** `list` maps and joins however many prefixes it is handed. The
  request builder bounds a query at 32 parameters and 1,024 bytes, so about twenty prefixes fit and
  more is a typed refusal rather than a request a server rejects.
- **The sequence number has three spellings and no settled base.** The parameter is declared
  `string`, its own JSDoc says `number`, and the schema's `QueryMetadata.sn` is a `number` — while
  the value actually sent is text. Worse, **which base that text is in is undetermined by the
  pinned tree**: of the 42 recorded `keyStates().query` call sites, every literal is a single
  digit, where decimal and hexadecimal agree; the one call site that passes a computed value hands
  over a key state's `s` — a field the protocol writes in *hexadecimal* — while the same file reads
  that field back with a base-ten `parseInt`. This port therefore **does not guess**:
  `QuerySequence` is a two-variant enum, `Decimal` or `Hexadecimal`, so the rendering is the
  caller's and the ambiguity is visible at the call site. Both variants reproduce every recorded
  call byte for byte, because every one is below ten. This stays an open question, owed a
  live confirmation against KERIA.
- **The anchor has three shapes.** `anchor` is `any`. The pinned unit test passes a bare SAID
  string; every integration caller passes a `Seal` (`{i, s, d}`); the schema's
  `QueryMetadata.anchor` is an `Anchor` (`{pre, sn, d}`). Only the integration shape has ever
  reached a live KERIA, so the Rust request takes a `Seal`. The unit test's string is recorded
  verbatim here and is unrepresentable; the schema's `Anchor` stays what it always was — the
  *response* metadata's type, which the shared API types already carry.
- **A query body omits what it was not given.** `query` writes `pre` always and adds `sn` and
  `anchor` only when defined. Reproduced exactly: the body is an ordered `Sad` and an absent value
  is not written.
- **Both families take the whole client**, where `Operations` takes an `OperationsDeps` and
  `Identifier` an `IdentifierDeps` — so neither can be exercised upstream without a full client.
  Here both are borrowed handles over a `ConnectedClient`, as the operations endpoint settled.

## On the keripy corroboration

keripy is a **governing** reference only for capabilities signify-ts cannot emit, and the sequence
number's base is not one of those. The `keripy` block under
`reference_quirks.the_sequence_number_has_three_spellings.base` is recorded as *corroborating
evidence* and labelled as such: keripy's own HTTP surface reads an `sn` query parameter with
falcon's `get_param_as_int`, which parses base ten. KERIA is a different service, so this narrows
the likelihood without settling it — which is exactly why the Rust API makes the caller choose
rather than defaulting silently.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
one controller at the ephemeral cost and run in well under a second.
