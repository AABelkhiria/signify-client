// Generates Base64-text material vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Bexter } from "../../reference/signify-ts/dist/keri/core/bexter.js";
import {
  Matter,
  MtrDex,
} from "../../reference/signify-ts/dist/keri/core/matter.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function bexterCase(name, input) {
  const value = new Bexter({}, input);
  const reparsed = new Bexter({ qb64: value.qb64 });
  return {
    name,
    input,
    canonical_text: value.bext,
    code: value.code,
    size: value.size,
    both: value.both,
    raw_hex: hex(value.raw),
    qb64: value.qb64,
    qb64_bytes_hex: hex(value.qb64b),
    qb2_hex: hex(decodeBase64Url(value.qb64)),
    parsed_canonical_text: reparsed.bext,
  };
}

function repeatedCase(name, character, length) {
  const input = character.repeat(length);
  const value = new Bexter({}, input);
  const reparsed = new Bexter({ qb64: value.qb64 });
  return {
    name,
    input_pattern: character,
    input_length: length,
    code: value.code,
    size: value.size,
    both: value.both,
    raw_hex: hex(value.raw),
    qb64: value.qb64,
    qb2_hex: hex(decodeBase64Url(value.qb64)),
    parsed_text_matches_input: reparsed.bext === input,
  };
}

function errorCase(name, operation, rustErrorCategory) {
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

const path = new Bexter({}, "-a-field0-1");
const stream = `${path.qb64}ABCD`;
const streamed = new Bexter({ qb64: stream });
const truncated = new Bexter({ qb64: "4AAB" });
let truncatedReencodeError;
try {
  truncated.qb64;
} catch (error) {
  truncatedReencodeError = error?.constructor?.name ?? "Unknown";
}
if (truncatedReencodeError === undefined) {
  throw new Error("reference unexpectedly re-encoded truncated Bexter material");
}
const wrongCode = new Matter({
  raw: new Uint8Array(32),
  code: MtrDex.Blake3_256,
});

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: [
    "src/keri/core/bexter.ts",
    "src/keri/core/matter.ts",
    "src/keri/core/base64.ts",
    "test/core/bexter.test.ts",
    "test/core/pather.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; parsed_canonical_text is accepted by the pinned Bexter qb64 constructor",
  cases: [
    bexterCase("empty", ""),
    bexterCase("one_hyphen", "-"),
    bexterCase("two_chars", "-A"),
    bexterCase("three_chars", "-A-"),
    bexterCase("four_chars", "-A-B"),
    bexterCase("one_zero_sextet", "A"),
    bexterCase("two_zero_sextets", "AA"),
    bexterCase("three_zero_sextets", "AAA"),
    bexterCase("ambiguous_four_zero_sextets", "AAAA"),
    bexterCase("leading_zero_three_chars", "ABB"),
    bexterCase("nonzero_three_chars", "BBB"),
    bexterCase("ambiguous_leading_zero", "ABBB"),
    bexterCase("dependent_path_shape", "-a-field0-1"),
  ],
  boundary_cases: [
    repeatedCase("largest_small_code", "B", 16_380),
    repeatedCase("first_large_code", "B", 16_381),
  ],
  stream_case: {
    input: stream,
    declared_material_characters: path.qb64.length,
    rust_parsed_canonical_text: path.bext,
    reference_observed_canonical_text: streamed.bext,
  },
  reference_quirks: {
    truncated_qb64_acceptance: {
      input: "4AAB",
      observed_code: truncated.code,
      observed_raw_hex: hex(truncated.raw),
      observed_canonical_text: truncated.bext,
      reencode_error_category: truncatedReencodeError,
      rust_error_category: "Truncated",
    },
  },
  rejected_cases: [
    errorCase(
      "missing_text",
      () => new Bexter({}),
      "Unrepresentable",
    ),
    errorCase(
      "invalid_alphabet",
      () => new Bexter({}, "@!"),
      "InvalidBase64Character",
    ),
    errorCase(
      "standard_alphabet",
      () => new Bexter({}, "+/"),
      "InvalidBase64Character",
    ),
    errorCase(
      "padding_character",
      () => new Bexter({}, "AA="),
      "InvalidBase64Character",
    ),
    errorCase(
      "wrong_raw_code",
      () => new Bexter({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 }),
      "InvalidBase64TextCode",
    ),
    errorCase(
      "wrong_qb64_code",
      () => new Bexter({ qb64: wrongCode.qb64 }),
      "InvalidBase64TextCode",
    ),
    errorCase(
      "qb2_constructor",
      () => new Bexter({ qb2: decodeBase64Url(path.qb64) }),
      "ReferenceUnsupported",
    ),
  ],
};

const outputUrl = new URL(
  "../../fixtures/cesr-bexter/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
