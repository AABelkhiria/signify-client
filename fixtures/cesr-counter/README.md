# CESR counter reference vectors

- Fixture schema: `v1`
- Upstream: `https://github.com/WebOfTrust/signify-ts.git`
- Commit: `ae92eceb8e776ad57669707bff7f84db9390b711`
- Generated: 2026-08-04
- Sources: `src/keri/core/counter.ts`, `test/core/counter.test.ts`
- Binary fields: lowercase hexadecimal; qualified text is canonical unpadded URL-safe Base64.

Generate from the repository root after building the pinned checkout:

```bash
npm --prefix reference/signify-ts run build
node tools/reference-vectors/cesr_counter.mjs
```

Every supported counter code is constructed and parsed by the reference with deterministic counts.
The fixture includes default/count-Base64 construction, prefix-stream behavior, all semantic-version
forms asserted upstream, and reference-rejected boundary inputs. `qb2_hex` is derived by applying
the pinned reference Base64 decoder to reference-produced `qb64`: the pinned `Counter` constructor's
`qb2` branch is empty and leaves an unusable object.

The fixture also records three deliberate strictness decisions. Rust rejects partial numeric
version components and versions with more than three components rather than inheriting JavaScript
`parseInt` behavior. Rust also rejects non-Base64 soft-count characters that the reference's bitwise
decoder coerces to zero.
