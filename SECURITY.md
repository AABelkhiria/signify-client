# Security Policy

## Supported versions

Security fixes go to the latest `0.x` release of each crate. Older `0.x` versions are not patched.
`signify-client`, `signify-http` and `signify-keys` are released together and share a version.

## Reporting a vulnerability

Please don't open a public issue for something you think is exploitable.

Use GitHub's [private vulnerability reporting][gh-pvr] on this repository instead: *Security* →
*Report a vulnerability*.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

Useful things to include: the crate and version, platform and features you were using, something
we can run to reproduce it, and what you think the impact is. If secret material was involved, say
so, but please generate throwaway keys and passcodes for the report. Never send a real passcode,
seed, salt or private key, and never send the admin URL of an agent you use.

## Threat model

The sensitive material is the passcode a client is configured with, the salts and seeds derived
from it, every signing key a keeper holds, and the intermediate buffers used to derive any of
those. The passcode is the root of the whole identity: whoever has it can derive the controller,
rotate it, and sign as any identifier the agent manages.

Everything that arrives from outside is assumed hostile: KERIA responses and their bodies, the
`Signature` and `Signature-Input` headers on them, `Content-Range` values, key states, key event
logs, credentials, exchange messages, and OOBI answers. The agent itself is a peer to be verified,
not a trusted party: `connect` checks the agent's commitment to the controller and the delegation
before anything is signed, and every response is verified against the agent's key before it is
read.

Given that, the implementation is built to hold up against a few specific things.

Malformed input shouldn't be able to panic or abort the process, so crate-owned code contains no
`unsafe`, `unwrap`, `expect`, panicking macro, or indexing that can fail, and every rejection is a
typed error. Every request carries a response-body limit, and the parsers beneath enforce their
own ceilings before allocating from a size the input declares.

A request is signed over exactly the components the reference signs, and a response is accepted
only when its signature covers what was received. A connected client cannot send an unsigned
request by mistake: connecting is a type change, and the three calls the reference leaves unsigned
are the only ones that bypass the signing stack, documented as such.

Secrets are kept away from anywhere they might leak by accident: the passcode redacts its `Debug`
output, and signing keys live in `keri-cesr` signers, which redact theirs, expose no raw-byte
accessor and zero their buffers on drop.

## Randomness

`random::random_passcode` and `random::random_nonce` take their entropy from the operating system
through `getrandom`, as does the retry jitter in `signify-http`. A failure is returned as an error;
nothing falls back to a seeded generator. Key creation in `signify-keys` takes its randomness as an
argument, which is what makes its output reproducible in tests.

## Known limitations

Zeroization covers the key material, the passcode once it is held by a `Passcode` or
`IdentifierPasscode`, and the stretched salt input derived from it. Text you pass by reference to
build one is yours to erase, as is any other buffer you lend; the sixteen random bytes
`random_passcode` draws are not wiped before they are encoded. Where zeroization does apply it is a
language-level guarantee at most, and it doesn't help against a compromised OS, a debugger, a core
dump, or pages swapped to disk.

The passcode is sent to the agent over an unsigned request in the three calls the reference also
leaves unsigned: approving a delegation, saving an old passcode and deleting one. Transport-level
TLS is the only protection there, as it is upstream.

`HttpTransport` trusts the platform's root certificates through rustls. Certificate pinning is not
provided.

`DerivationCost::Ephemeral` runs the passcode derivation on a deliberately cheap profile. It exists
for tests and must not protect real secrets.

Constant-time behavior rests on `keri-cesr` and the crates beneath it. We haven't measured it with
dedicated tooling like `dudect`.

## Dependencies

Production dependencies have known licenses and active maintenance, with default features off. The
TLS stack (hyper, hyper-rustls, hyper-util, tokio) is only built with the `http-client` feature.
The protocol crates `keri-cesr`, `keri-protocol`, `keri-acdc`, `keri-http-auth` and `keria-types`
are first-party, written and maintained by this crate's author, and their outputs are checked byte
for byte against the signify-ts fixtures. `cargo deny` and the resolved graph get reviewed before
each release.
