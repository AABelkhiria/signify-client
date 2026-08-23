# IPEX message reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/app/credentialing.ts`, `src/keri/app/exchanging.ts`,
  `test/app/credentialing.test.ts`
- Binary fields: none. Identifiers and signatures are qualified Base64; messages are exact
  serialized text and attachment streams are exact CESR text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/acdc_ipex.mjs --write   # regenerate
node tools/reference-vectors/acdc_ipex.mjs --check   # verify determinism
```

## Determinism

Every message's timestamp is supplied rather than read from the clock, and the sender's keys derive
from the passcode the pinned tests publish, so every recorded value is exact — including the
signatures. The generator takes about a second, all of it Argon2.

## What the evidence is

Roadmap 6.3 ports the pure half of `Ipex.apply`, `.offer`, `.agree`, `.grant`, and `.admit`,
together with the `createExchangeMessage` composition each calls. Submitting the result — the five
`submit*` methods — is Roadmap 6.12.

**Unlike Roadmap 6.1's and 6.2's fixtures, this one does not re-express the ported code.** It
drives the reference's own `Ipex` methods end to end:

1. `globalThis.fetch` is replaced, so `client.identifiers().get(...)` returns a habitat state the
   generator derives with the reference's own `Controller`, `IdentifierManagerFactory`, and
   `incept` — by the same route the pinned `test/app/test-utils.ts` derives its mock — and every
   mocked response is signed by an `Authenticater` so `SignifyClient.fetch` accepts it.
2. The client is booted and connected, so its real key manager is in place, at the reference's
   **production** Argon2 cost.
3. The five methods are called, and everything they return is recorded: the exact message bytes,
   the signatures, and the transposed attachment stream.

So the recorded values are the reference's real output rather than a paraphrase of it — and Rust
reproduces all of it, signatures included, with a keeper derived from the same published passcode.

`pinned_confirmations` closes the loop against the reference's *test suite* as well as its
implementation: each driven message's identifier and signature are looked for among the literals
`credentialing.test.ts` asserts, and the generator fails if any is missing. `declarations` holds
the five routes and each method's payload and embed expressions, read out of the reference's own
syntax tree, so the typed `IpexRoute` is checked against the literals rather than against memory.

## Contents

- `messages` pins eight: the pinned suite's full apply → offer → agree → grant → admit
  conversation, plus an apply with neither message nor attributes, an offer with no prior, and a
  grant with no prior — the last two being the openings a discloser-initiated flow uses. The grant
  with no prior is the same message the *first* pinned IPEX test publishes.
- `embedded_artifacts` holds the credential, its issuance event, and the anchoring key event a
  grant embeds; the first two are Roadmap 6.1's and 6.2's own output.
- `reference_quirks` pins six behaviours, each with what the reference does and what this port does
  instead.

## Reference behavior recorded as deliberate divergences

- **An admit's message has no default.** The other four routes write `m: args.message ?? ''`;
  `admit` writes `m: args.message`, so an admit built without one emits an attribute block carrying
  **no `m` at all** — the fixture records the payload labels as `["i"]` and confirms the resulting
  identifier differs from the one an empty string produces. A payload whose fields depend on which
  argument was omitted is refused here: the message is required on every route and an empty one is
  spelled explicitly.
- **A grant with no `ancAttachment` signs the issuer's key event with the *sender's* keeper.** That
  is only correct when the discloser is the issuer; anyone re-disclosing a credential they hold
  would attach a signature over someone else's event made with their own key. The anchor attachment
  is a required input here, and `Disclosure::from_issuance` derives it from the signatures Roadmap
  6.2's issuance actually produced.
- **An offer embeds the credential with an `undefined` attachment.** The transposed stream for such
  an embed is empty — the label goes into the `e` block and nothing follows it in the attachment
  stream. Reproduced: Roadmap 3.8's `ExchangeEmbed::new` without `with_attachment` is exactly this
  case, and it is distinct from an explicitly empty attachment, which still writes its path.
- **The routes are bare string literals** at each call site; the pinned `app/exchanging.ts`
  declares a route table for multisig but none for IPEX. Here they are an `IpexRoute` enum whose
  `as_str` is asserted against the literals read from the reference's syntax tree.
- **The sender and recipient are unvalidated.** `senderName` is an alias looked up remotely and
  `recipient` is free text interpolated into the message, so a typo becomes part of the exchange's
  identifier. Both are typed prefixes here, as Roadmap 3.8 already types them.
- **An apply's attributes are an untyped `Record<string, unknown>`**, spread into the payload with
  no bound and no label check. Here they are an ordered `Sad`, and one naming the recipient label
  is refused rather than silently readdressing the message.

Note that the payload's serialized field order is `i`, then whatever the route supplies — the
recipient is written first and the payload spread over it. The pinned test's assertions display a
different order, but `assert.deepStrictEqual` does not compare key order; the recorded bytes do.

Rust tests consume the checked-in fixture and require neither Node nor network access. The
cross-language test derives one keeper at the reference's production cost, which takes about ten
seconds.
