# Authenticated transport composition reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/clienting.ts` (`SignifyClient.fetch`), `src/keri/core/authing.ts`,
  `src/keri/core/httping.ts`
- Binary fields: none. Every header is the exact text the reference passed to `fetch`.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/http_auth.mjs --write   # regenerate
node tools/reference-vectors/http_auth.mjs --check   # verify determinism
```

## The clock is pinned, so nothing is masked

The `http-transport`, `http-request-response`, and `http-retry` fixtures all had to record
`Signature`, `Signature-Input`, and `Signify-Timestamp` as `masked: true` with a null value, because
each is a clock reading or covers one. **This generator replaces `globalThis.Date`** with a subclass
whose no-argument constructor returns a fixed instant (`1700000000123`, or
`2023-11-14T22:13:20.123Z`), so the entire pipeline becomes deterministic and all three are recorded
with their exact bytes.

That makes this the first byte-exact evidence for the **composed** request. The `authing` port
verified `siginput` and `Authenticater` in isolation with `created` supplied as a parameter; what is
proven here is everything `SignifyClient.fetch` does around them — stamp the resource and the
timestamp, declare the content type, sign, and then check the response.

## What the fixture holds

- `constants` — `Authenticater.DefaultFields` read from the built module, and the expression
  `Signify-Timestamp` is set from, read from the reference's own syntax tree and then evaluated at
  the pinned clock.
- `requests` — five authenticated calls driven through `SignifyClient.fetch` itself, one per method
  plus one whose query must be stripped before signing. Each records the exact URL, every header
  with its value, and the body.
- `response_verification` — seven results from the reference's own `Authenticater.verify`: a valid
  response, three tampered ones, two with a header removed, and one replayed.
- `freshness_scan` — see below.

## Reference behavior recorded as deliberate divergences

- **There is no freshness check anywhere.** This is the finding that shapes the Rust design, so it
  is machine-checked rather than asserted. Two needles do match the tree — `expires` is a signature
  parameter the grammar carries, and `replay` names KEL replay messages in `escrowing.ts`,
  `exchanging.ts`, and `grouping.ts` — so the raw counts are recorded *with their file lists*, and
  three booleans carry the actual claim: `Authenticater.sign` never sets an `expires`, no parameter
  is ever compared to anything, and verification reads no clock at all. The `replayed_after_the_fact`
  case demonstrates the consequence: a captured response authenticates forever. Rust applies a
  `Freshness` window by default; `Freshness::Ignore` reproduces the reference.
- **The timestamp claims precision it does not have.**
  `new Date().toISOString().replace('Z', '000+00:00')` takes a millisecond-precision value and
  appends three zeros, so it always ends in `000` and looks like microseconds. Reproduced exactly —
  it is a covered header, and any other spelling would change the bytes a signature commits to.
- **There are two clock readings per request.** `SignifyClient.fetch` reads the clock for
  `Signify-Timestamp` and `siginput` reads it again for `created`, so the header and the parameter
  can disagree by however long the two calls are apart. Rust takes one reading and uses it for both.
  The two agree in this fixture only because the clock is pinned.
- **The query is stripped before signing.** `path.split('?')[0]` means two requests differing only
  in their query have the same signature base. Reproduced — it is also what `RequestUrl::path`
  returns.
- **The covered fields are fixed and exclude the body.** The same four components sign every
  request, and nothing signed covers what was sent. Reproduced; inventing a body digest would
  produce a signature KERIA cannot verify.
- **Signature headers are appended, not set.** `sign` uses `headers.append`, so signing the same
  collection twice yields two comma-joined values instead of an error. `keri-http-auth`'s
  `Headers` refuses a duplicate name, so a request signed twice does not build.
- **A missing header and a bad signature are the same outcome.** `verify` returns `false` for an
  absent header and throws for an invalid signature, and `SignifyClient.fetch` collapses both into
  the single message `response verification failed`. Each is a distinct typed error in Rust, as
  request authentication already decided.
- **The resource check is an equality on an untyped header.**
  `this.agent?.pre === res.headers.get('signify-resource')` compares a prefix against a raw header,
  so an absent header compares against `null` and a client with no agent compares `undefined` —
  neither distinguished from a genuine mismatch. Rust takes a validated expected value and reports
  an absent header as its own error.

Rust tests consume the checked-in fixture and require neither Node nor network access.
