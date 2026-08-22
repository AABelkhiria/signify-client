# KERI registry-inception reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-22
- Sources: `src/keri/core/vdring.ts`, `test/core/vdring.test.ts`
- Binary fields: none. Identifiers are qualified Base64; events are exact serialized text.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/keri_registry.mjs --write   # regenerate
node tools/reference-vectors/keri_registry.mjs --check   # verify determinism
```

## Determinism

`vdr.incept` derives no keys, so every recorded event is exact and the generator is instant. The
one non-deterministic input — the default random nonce — is recorded by shape only; its Rust
equivalent arrives with Roadmap 6.4's `randomNonce`, and until then the nonce is a required
builder input.

## Contents

- `inceptions` pins eleven complete events: both pinned unit-test vectors (each under an explicit
  and a defaulted threshold), the no-backers trait alone and all three traits, three-, five-, and
  twelve-backer cases exercising the `ample` default and the hexadecimal threshold, and an empty
  nonce, which the reference accepts.
- `rejections` pins the five threshold/duplicate/configuration refusals — four of them the pinned
  unit test's own — plus the non-digestive `code` argument, which crashes reading fields a `vcp`
  does not carry.

## Reference behavior recorded as deliberate divergences

- **A non-numeric `toad` emits `bt: "NaN"`.** `+toad` coerces the string to `NaN`, every
  comparison on `NaN` is false, and the event — a threshold nothing can satisfy — is committed
  into the registry identifier. Unrepresentable in Rust, where the threshold is a `u32`; the
  string spelling `"1"`, which coerces to the same event as `1`, is likewise unrepresentable.
- **Backers are unvalidated text.** The pinned unit test commits `'a backer'`, space and all, into
  a registry identifier, so Rust backers are bounded text rather than typed prefixes — refusing
  what the reference commits to would derive a different registry from the same inputs.
- **The issuer is likewise unchecked** — the fixture records the reference accepting
  `'not an identifier'` — but Rust types it as an `IdentifierPrefix`, this port's convention for
  caller-side identifiers.

Rust tests consume the checked-in fixture and require neither Node nor network access.
