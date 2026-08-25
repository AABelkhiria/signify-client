# IPEX submission endpoint reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-25
- Sources: `src/keri/app/credentialing.ts`, `test/app/credentialing.test.ts`,
  `test/app/clienting.test.ts`
- Binary fields: none. Paths, bodies, messages, and attachments are exact text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/client_ipex.mjs --write   # regenerate
node tools/reference-vectors/client_ipex.mjs --check   # verify determinism
```

## Determinism

Nothing here needs the clock pinned, because every IPEX builder takes its timestamp as an argument
and the generator supplies one. The sender's keys derive from the passcode the pinned tests publish,
at the reference's **production** Argon2 profile, so every signature in a recorded body is the real
one and the generator takes several seconds.

Unlike Roadmap 6.9's and 6.11's fixtures there is no sealed salt to mask: a submission body carries
no key-manager block, only the message, its signatures, its attachment, and the recipients.

## What the evidence is

Roadmap 6.12 ports `Ipex.{submitApply,submitOffer,submitAgree,submitGrant,submitAdmit}`. The five
artifact builders beside them are Roadmap 6.3's and are already `VERIFIED`, so this generator builds
each message through the reference's own builder and then submits it through the reference's own
submitter, recording the request that leaves. **Every recorded `exn` is one
`fixtures/acdc-ipex/v1.json` has already proven byte-exact**; what this fixture adds is the body
assembled around it.

**The pinned unit tree exercises all five.** The three IPEX cases in
`test/app/credentialing.test.ts` call every submitter and assert each one's full URL — eight
assertions over five distinct addresses, which is the whole of what the file checks about them. No
body is asserted anywhere, so the bodies here are new evidence rather than a restatement.

One absence is recorded rather than claimed: `clienting.test.ts` type-asserts five other endpoint
accessors and **not** `client.ipex()`, which the generator scans for and fails on if it changes.

## Contents

- `declarations` pins each submitter's parameter list, body literal, path template, and return
  expression, plus the class's own member list — read from the reference's own syntax tree, so a
  drift fails a test rather than passing silently.
- `embedded_artifacts` pins the credential, issuance event, anchoring key event, and anchor
  attachment a grant embeds, so the Rust side rebuilds the same five messages.
- `messages` pins all five messages: exact bytes, identifier, route, addressee, attachment, and
  signatures.
- `calls` pins eleven submissions: the five the pinned unit test performs, plus a two-recipient
  grant, an empty-recipient grant, a grant delivered to someone other than its addressee, an alias
  the path does not encode, and both directions of a route/resource mismatch.
- `pinned_confirmations` pins the unit test's file set, its eight published submission URLs and five
  published routes, the missing accessor assertion, a 117-file call-site scan per submitter, and
  every recipient list the pinned tree passes.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **Two submitters discard their own attachment.** `Ipex.apply` and `Ipex.agree` each return an
  attachment as the third element of their tuple, and `submitApply` and `submitAgree` declare no
  `atc` parameter and write no `atc` field. It is always the empty string, because neither route
  embeds anything, so nothing is lost — the asymmetry is in the API rather than in the bytes.
  **Reproduced exactly**: the route decides whether the body carries `atc`, so an apply and an agree
  write three fields and the other three write four. A property asserts an apply's and an agree's
  attachment is always empty, which is what makes the omission lossless.
- **The route and the resource agree only by convention.** Each submitter appends its own path
  segment and accepts any `exn`, so posting a grant through `submitApply` addresses `/ipex/apply`
  with a message whose own `r` says `/ipex/grant`, and posting an apply through `submitGrant` adds
  an `atc` the message never had. Both are recorded here. **Unrepresentable**: there is one
  `submit`, and the path segment is read from the message's own route.
- **Nothing compares the recipients with the addressee.** The list is copied into the body as `rec`
  and never checked against the `rp` and `a.i` the message carries, so a grant addressed to one
  identifier can be handed to the agent for delivery to another — recorded here. **Kept as
  upstream**: every call site in the pinned tree passes exactly one recipient and it is the
  addressee, so the reference proves nothing either way about fanning out, and a multisig sender
  plausibly needs more than one. The method documents that it does not check.
- **An empty recipient list is sent.** `recp: []` reaches the wire as `"rec":[]`, a submission the
  agent is asked to deliver to no one, and the reference neither refuses it nor reports it. **A
  typed refusal here**, before anything is built.
- **The alias is not encoded.** All five paths interpolate the sender's alias raw, so an alias
  holding a slash posts a disclosure under a different identifier's resource — and Roadmap 3.10
  signs `@path`. **Refused by construction**, as every other family in this crate does.
- **The answer is cast rather than decoded.** Every submitter returns `response.json()` cast to
  `ExchangeOperation`. **Decoded here**, as Roadmap 6.8, 6.10, and 6.11 decided.

Rust tests consume the checked-in fixture and require neither Node nor network access. They derive
real keys at the production Argon2 profile, which is why they are slower than the reading families.
