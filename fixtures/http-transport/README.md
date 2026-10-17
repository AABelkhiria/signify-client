# HTTP transport reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-22
- Sources: `src/keri/app/clienting.ts`, `src/keri/app/aiding.ts`, `src/keri/app/contacting.ts`
- Binary fields: none. URLs, header values, and bodies are recorded as the exact text the
  reference passed to `fetch`.

Generate and verify from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/http_transport.mjs --write   # regenerate
node tools/reference-vectors/http_transport.mjs --check   # verify determinism
```

## What this fixture is, and why it looks different from the others

**There is no transport module upstream to port.** `app/clienting.ts` calls the global `fetch`
directly and every endpoint module calls that client, so there is no function whose output can be
compared byte for byte. The generator therefore replaces `globalThis.fetch` with a recorder and
drives the reference's *own* client and endpoint code — boot, state, connect, and one authenticated
call of each HTTP method — capturing the exact method, URL, header order, and body of every call
it makes. The Rust evidence is that `signify-http`'s `Request` can express each one without loss:
same method, same URL bytes, same header names in the same order, same body or same absence of
one.

## Determinism, and what is masked

Three things are non-deterministic by construction and are recorded by name or shape only:

- **`Signify-Timestamp` is a clock read**, and **`Signature`** covers it, so both — and
  `Signature-Input`, which carries the same `created` value — are recorded with `masked: true` and
  a null value. Their exact bytes are request authentication's evidence, already verified.
- **A salty keeper's `sxlt`** inside a creation body is a sealed salt, and a sealed box draws a
  fresh ephemeral key each call; it is replaced by a marker. What it opens to is the `keri-keeping`
  fixture's evidence.

Everything else — including the percent-encoded path, the query string, and the `Range` header —
is recorded verbatim.

The five `responses` entries are not recordings but the response shapes a transport must be able
to carry back: an ordinary JSON success, a list with `Content-Range`, a `202` operation, a `404`
with a text body, and a `204` with no body at all.

## A note on the canned answers

After `connect`, `SignifyClient.fetch` requires the response to carry the agent's `Signify-Resource`
header and an agent signature over it — producing those is the `http-auth` fixture's subject. The
generator's canned answers are unsigned, so the reference rejects them *after* sending; the request
has already been recorded by then, and the request is what this fixture is about. The generator
fails loudly on any other error.

## Reference behavior recorded as deliberate divergences

- **A `GET` carries no body at all.** `SignifyClient.fetch` sends
  `method == 'GET' ? null : JSON.stringify(data)`. Rust keeps an absent body and an empty body as
  different values, and a transport may not turn one into the other.
- **Duplicate header names are joined with a comma.** The reference builds headers with the WHATWG
  `Headers` class, whose `append` merges a repeated name into one value — silently changing what a
  signature covers. `keri-http-auth`'s `Headers` refuses a duplicate, so such a request does not
  build.
- **The delegation approval is unauthenticated.** `approveDelegation` calls the global `fetch`
  directly rather than `SignifyClient.fetch`, so the `PUT` that anchors the agent's delegation
  carries no `Signature`, `Signature-Input`, `Signify-Resource`, or `Signify-Timestamp` header —
  only the payload's own KERI signatures authenticate it. Recorded, not corrected: a transport
  sends what it is handed, and whether this call is signed is the client lifecycle's composition
  decision.
- **Boot uses a second base URL.** A client holds an admin URL and a boot URL, so the transport
  must carry whichever absolute URL it is given; choosing between them is the client lifecycle's.
- **No request sets a timeout or an abort signal anywhere in the pinned source**, so a call can
  hang until the platform's default gives up. A timeout is a transport outcome here
  (`TransportError::Timeout`) and the policy that sets one is the retry policy.

Rust tests consume the checked-in fixture and require neither Node nor network access.
