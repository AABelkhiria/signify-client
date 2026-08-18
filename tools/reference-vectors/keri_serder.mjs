// Generates and checks deterministic-serialization vectors from the compiled pinned signify-ts
// checkout.
//
// Where the pinned unit test derives values with `Prefixer` (Roadmap 3.4), this generator records
// the resulting self-addressing data verbatim so the Rust side can prove byte parity for Roadmap
// 3.2 without implementing prefix derivation.
import { readFileSync, writeFileSync } from "node:fs";

import { b, Ilks } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Prefixer } from "../../reference/signify-ts/dist/keri/core/prefixer.js";
import { Serder, dumps, sizeify } from "../../reference/signify-ts/dist/keri/core/serder.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function rejectedCase(name, operation, rustErrorCategory) {
  try {
    operation();
  } catch (error) {
    return {
      name,
      reference_error_category: error?.constructor?.name ?? "Unknown",
      reference_error_message: String(error?.message ?? error),
      rust_error_category: rustErrorCategory,
    };
  }
  throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

// Records one SAD together with the exact bytes the reference produces for it. `sad_json` is the
// reference's own serialization of the *input* order, which the Rust parser reads back so both
// sides start from identical field order.
function serializationCase(name, sad) {
  const input = JSON.parse(JSON.stringify(sad));
  const serder = new Serder(sad);
  return {
    name,
    input_sad_json: JSON.stringify(input),
    raw: serder.raw,
    raw_hex: hex(b(serder.raw)),
    byte_size: b(serder.raw).length,
    reference_size_accessor: serder.size,
    version_string: serder.sad.v,
    proto: serder.proto,
    kind: serder.kind,
    said: serder.said ?? null,
    pre: serder.pre ?? null,
  };
}

// 1. The pinned inception event, exactly as `test/core/serder.test.ts` builds it.
const keys = ["DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e"];
const nxt = ["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"];
const ked0 = {
  v: "KERI10JSON000000_",
  t: Ilks.icp,
  d: "",
  i: "",
  s: (0).toString(16),
  kt: (1).toString(16),
  k: keys,
  nt: (1).toString(16),
  n: nxt,
  bt: (0).toString(16),
  b: [],
  c: [],
  a: [],
};
const inception = serializationCase("pinned_inception", { ...ked0 });

// 2. Reproduce the pinned test's mutation sequence: `Serder` then two `Prefixer` derivations, which
// rewrite `ked0.i`/`ked0.d` in place, then the non-ASCII anchor case.
const mutated = { ...ked0 };
new Serder(mutated);
new Prefixer({ code: MtrDex.Ed25519 }, mutated);
const blake3Prefixer = new Prefixer({ code: MtrDex.Blake3_256 }, mutated);
const nonAscii = serializationCase("pinned_non_ascii_anchor", {
  ...mutated,
  a: { n: "Lenksjö" },
});

// 3. The pinned interaction event, used for sequence-number and parse coverage.
const interaction = serializationCase("pinned_interaction", {
  v: "KERI10JSON00013b_",
  t: "ixn",
  d: "EDMbT6cc2P4aPozDJhat1T_S-G98Gc7Jj8K0qxAL7EuC",
  i: "EDKLs7y-U4N_EIv_oqJqdmWOvR5Y-nSEHJPrprT1RLFb",
  s: "39",
  p: "EI696dhEGo9cDK7MpvSsPkNkVhF4pwwgof3GaRVVESXb",
  a: [
    {
      i: "EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH",
      s: "0",
      d: "EFMXIFSIyEL6JTCyZAbO3nHgSdOw5UbLH9fAr9zO8_LH",
    },
  ],
});

// 4. Escaping and value-shape matrix. Every entry is a value the Rust codec also accepts, so the
// reference's `dumps` output is a direct byte-for-byte expectation.
const escapeSource = {};
for (let code = 0; code < 0x20; code += 1) {
  escapeSource[`c${code.toString(16).padStart(2, "0")}`] = String.fromCharCode(code);
}
const escapeMatrix = {
  v: "KERI10JSON000000_",
  quote: '"',
  backslash: "\\",
  solidus: "/",
  del: String.fromCharCode(0x7f),
  latin: "Lenksjö",
  cjk: "漢字",
  astral: "😀",
  line_separator: "\u2028",
  paragraph_separator: "\u2029",
  ...escapeSource,
};
const escaping = {
  name: "escape_matrix",
  input_sad_json: JSON.stringify(escapeMatrix),
  raw: dumps(escapeMatrix, "JSON"),
  raw_hex: hex(b(dumps(escapeMatrix, "JSON"))),
};

// 5. Value shapes: nesting, empty containers, and exactly representable integers.
const shapes = {
  v: "KERI10JSON000000_",
  empty_object: {},
  empty_array: [],
  nested: { a: [{ b: [] }] },
  null_value: null,
  true_value: true,
  false_value: false,
  zero: 0,
  negative: -17,
  max_safe: Number.MAX_SAFE_INTEGER,
  min_safe: -Number.MAX_SAFE_INTEGER,
};
const valueShapes = {
  name: "value_shapes",
  input_sad_json: JSON.stringify(shapes),
  raw: dumps(shapes, "JSON"),
  raw_hex: hex(b(dumps(shapes, "JSON"))),
};

// 6. Reference rejections.
const rejected = [
  rejectedCase("missing_version_field", () => sizeify({ t: "icp" }), "MissingVersionField"),
  rejectedCase(
    "malformed_version_string",
    () => sizeify({ v: "NOPE10JSON000000_", t: "icp" }),
    "Version",
  ),
  rejectedCase("unsupported_kind", () => dumps({ v: "x" }, "CBOR"), "UnsupportedSerializationKind"),
];

// 7. Reference quirks that Rust deliberately does not reproduce.
const outOfOrder = { t: "icp", v: "KERI10JSON000000_" };
const outOfOrderSerder = new Serder({ ...outOfOrder });
const numericKeys = { v: "KERI10JSON000000_", b: 1, 1: 2, 0: 3 };
const numericKeysRaw = dumps(numericKeys, "JSON");
const duplicateRaw = '{"v":"KERI10JSON000000_","a":1,"a":2}';
const duplicateReparsed = dumps(JSON.parse(duplicateRaw), "JSON");
const embeddedVersion = { v: "XXKERI10JSON000000_YY", t: "icp" };
const embeddedSerder = new Serder({ ...embeddedVersion });
const numberRenormalization = '{"v":"KERI10JSON000000_","a":1.50,"b":1e2,"c":9007199254740993,"d":3.0}';

const quirks = {
  version_field_not_first: {
    input_sad_json: JSON.stringify(outOfOrder),
    reference_raw: outOfOrderSerder.raw,
    note: "the reference sizes and emits a message whose version string is not the first field, so a stream parser cannot sniff it",
    rust_error_category: "VersionFieldNotFirst",
  },
  numeric_key_hoisting: {
    input_sad_json: JSON.stringify(numericKeys),
    reference_raw: numericKeysRaw,
    note: "JavaScript objects order array-index-like keys numerically ahead of the rest; keripy dicts and the Rust port preserve insertion order",
    rust_raw: '{"v":"KERI10JSON000000_","b":1,"1":2,"0":3}',
  },
  duplicate_field_last_wins: {
    input_raw: duplicateRaw,
    reference_reparsed: duplicateReparsed,
    note: "JSON.parse keeps the last value at the first position; Rust rejects the ambiguity",
    rust_error_category: "DuplicateField",
  },
  embedded_version_string_undersizes: {
    input_sad_json: JSON.stringify(embeddedVersion),
    reference_raw: embeddedSerder.raw,
    reference_byte_size: b(embeddedSerder.raw).length,
    reference_declared_size: embeddedSerder.sad.v,
    note: "the reference's unanchored version regex accepts a padded version string, computes the size while the longer value is still present, then substitutes a 17-byte one, so the declared size overstates the message by the padding width",
    rust_error_category: "Version",
  },
  utf16_size_accessor: {
    raw: nonAscii.raw,
    reference_size_accessor: nonAscii.reference_size_accessor,
    byte_size: nonAscii.byte_size,
    note: "Serder.size reports a JavaScript string length, so it undercounts every non-ASCII message; the version string itself correctly counts UTF-8 bytes",
  },
  number_renormalization: {
    input_raw: numberRenormalization,
    reference_reparsed: dumps(JSON.parse(numberRenormalization), "JSON"),
    note: "JSON.parse/stringify re-spells numbers through IEEE-754, changing bytes and therefore any SAID computed over them; Rust rejects fractional, exponent, and unsafe-magnitude numbers instead",
    rust_error_categories: ["UnsupportedNumber", "IntegerOutOfRangeAt"],
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-18",
  sources: ["src/keri/core/serder.ts", "test/core/serder.test.ts"],
  notes:
    "pinned_non_ascii_anchor reproduces the unit test's mutation sequence, in which two Prefixer derivations rewrite i and d before the anchor is added",
  blake3_prefix: blake3Prefixer.qb64,
  cases: [inception, nonAscii, interaction],
  encoding_cases: [escaping, valueShapes],
  rejected_cases: rejected,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-serder/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-serder fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
