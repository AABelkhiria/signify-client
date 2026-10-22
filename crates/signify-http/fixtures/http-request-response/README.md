# HTTP request-builder and response-decoder reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `91a04a5edd804425f42be75ffbf034f8d14e5cb2`
- Generated: 2026-08-23
- Sources: `src/keri/core/httping.ts`, `src/keri/app/clienting.ts`, `src/keri/app/aiding.ts`,
  `src/keri/app/contacting.ts`, `src/keri/app/coring.ts`, `src/keri/app/credentialing.ts`,
  `src/keri/app/escrowing.ts`, `src/keri/app/notifying.ts`
- Binary fields: none. URLs, header values, and bodies are the exact text the reference produced.

Generate and verify from the repository root after installing the pinned references:

```bash
npm ci --prefix tools/reference-vectors
node tools/reference-vectors/http_request_response.mjs --write   # regenerate
node tools/reference-vectors/http_request_response.mjs --check   # verify determinism
```

## What this fixture covers

The request builder and response decoder are two halves, and they have two different kinds of
evidence.

The **response** half has one real upstream function: `parseRangeHeaders` in `core/httping.ts`, the
last capability of that file left unported after request authentication. `content_ranges` calls it
directly across thirty-one well-formed and malformed `Content-Range` values. Its results are
JavaScript numbers, so a `NaN` is recorded as the string `"NaN"` — JSON cannot spell one, which is
itself part of what the entry demonstrates.

The **request** half has no single upstream function. `SignifyClient.fetch` concatenates a base URL
with a path its endpoint modules already assembled, so the evidence is the reference's own output:

- `path_segments` — `encodeURIComponent` applied to twenty-three dynamic components, which is the
  function `app/aiding.ts` uses for the two paths it encodes.
- `query_strings` — `URLSearchParams` serialization for thirteen parameter lists, which is what
  `app/contacting.ts`, `app/coring.ts`, and `app/escrowing.ts` build their queries with.
- `requests` — sixteen real endpoint calls, captured by replacing `globalThis.fetch` with a
  recorder and driving the reference's own client, exactly as the `http-transport` generator does.
  Each records the method, the exact URL, the header order and values, and the body.
- `status_outcomes` — eight statuses driven through `SignifyClient.fetch` itself, recording whether
  it accepted the response and, when it did not, the exact message it threw.
- `payload_decoding` — twelve platform `Response` values, recording what `.json()` and `.text()`
  return or throw for each declared content type.
- `media_types` — the complete set of media types and range units the pinned source names.

## Determinism, and what is masked

`Signify-Timestamp` is a clock read and `Signature`/`Signature-Input` cover it, so those three
header values are recorded with `masked: true` and a null value, exactly as the `http-transport`
fixture does. Their exact bytes are request authentication's evidence, already verified. Everything
else — every URL, every `Range` and `Accept` value, every body — is recorded verbatim.

The generator's canned answers are unsigned, so after `connect` the reference rejects them *after*
sending; the request is already recorded by then. The generator fails loudly on any other error.

## Reference behavior recorded as deliberate divergences

- **Dynamic components are usually not encoded.** Of the forty-three dynamic values the pinned
  source interpolates into a path or a query — a count the generator reads from the source itself
  and records with its method — only two are encoded, both in `aiding.get`/`aiding.update`. Every
  other dynamic path component, and every query value built outside `URLSearchParams`, is
  interpolated raw, so a value holding `/`, `?`, `#`, or `..` changes which resource is addressed: `operations().get('../identifiers')` sends `/operations/../identifiers`,
  `contacts().delete('a/b')` sends `/contacts/a/b`, and `keyStates().get('a&b=c')` sends
  `/states?pre=a&b=c` with an injected second parameter. Request authentication signs `@path`, so
  this changes what a signature covers too. Rust encodes every dynamic component exactly once.
- **An absent `Content-Range` is `{0,0,0}`,** which a caller cannot tell apart from a server that
  really answered `aids 0-0/0`. Rust returns `None` for the absent case.
- **Every `Content-Range` field is `parseInt` of whatever the split produced,** so a hexadecimal,
  exponential, fractional, signed, or missing field becomes a silently wrong number or a `NaN` that
  flows on into arithmetic. `aids 0x10-0x20/0x30` parses as 16, 32, 48. Rust parses strictly.
- **`Content-Range` loses precision past 2^53,** because the results are doubles: a total of
  `9007199254740995` comes back as `9007199254740996`. Rust's fields are `u64`.
- **`res.json()` ignores the declared content type,** so a `text/plain` error page is decoded as a
  domain record whenever it happens to be valid JSON. Rust refuses a declared type that is not
  `application/json`, and accepts an absent one because nothing contradicts it.
- **The status error message interpolates the whole response body** and the request path including
  its query. Rust's typed `Status` error carries a bounded excerpt and omits the query.
- **`statusText` is empty**, because the platform leaves it so unless a server sends a reason
  phrase; the message reads `- 500  - internal error`, with two spaces. Rust does not model the
  reason phrase at all.
- **`Content-Type: application/json` is set on every request,** including a `GET` that carries no
  body. Rust sets the content type and the body independently, so this stays expressible.
- **A body-less `PUT` sends the four bytes `null`** while a body-less `DELETE` sends nothing: the
  two endpoint modules differ only in whether they passed `null` or `undefined` into the same
  `JSON.stringify`. Rust has no absent value that becomes a JSON document.
- **An empty query still emits a bare trailing `?`** — `/contacts?`. Rust omits the delimiter with
  the query.
- **The recorded header order is the platform's sort,** not a choice: the WHATWG `Headers` class
  iterates by lowercased name. Rust preserves insertion order, and the wire order of the
  authentication headers is the authenticated transport's composition — it does not affect a
  signature, whose base order comes from the covered-fields list.

Rust tests consume the checked-in fixture and require neither Node nor network access.
