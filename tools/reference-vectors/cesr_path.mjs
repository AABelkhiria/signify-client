// Generates SAD-path vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Pather } from "../../reference/signify-ts/dist/keri/core/pather.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function pathCase(name, components) {
  const value = new Pather({}, undefined, components);
  const reparsed = new Pather({ qb64: value.qb64 });
  return {
    name,
    components: components.map((component) => String(component)),
    text: value.bext,
    parsed_components: reparsed.path,
    code: value.code,
    size: value.size,
    both: value.both,
    raw_hex: hex(value.raw),
    qb64: value.qb64,
    qb64_bytes_hex: hex(value.qb64b),
    qb2_hex: hex(decodeBase64Url(value.qb64)),
  };
}

function repeatedCase(name, componentLength) {
  const component = "B".repeat(componentLength);
  const value = new Pather({}, undefined, [component]);
  const reparsed = new Pather({ qb64: value.qb64 });
  return {
    name,
    component_pattern: "B",
    component_length: componentLength,
    text_length: value.bext.length,
    code: value.code,
    size: value.size,
    both: value.both,
    raw_hex: hex(value.raw),
    qb64: value.qb64,
    qb2_hex: hex(decodeBase64Url(value.qb64)),
    parsed_components_match: JSON.stringify(reparsed.path) === JSON.stringify([component]),
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

function componentEdge(name, components, rustErrorCategory) {
  const value = new Pather({}, undefined, components);
  return {
    name,
    components,
    observed_text: value.bext,
    observed_round_trip_components: value.path,
    qb64: value.qb64,
    rust_error_category: rustErrorCategory,
  };
}

const path = new Pather({}, undefined, ["e", "credential"]);
const stream = `${path.qb64}ABCD`;
const streamed = new Pather({ qb64: stream });
const invalidPointer = new Pather({}, "not-a-pointer");
let invalidPointerError;
try {
  invalidPointer.path;
} catch (error) {
  invalidPointerError = error?.constructor?.name ?? "Unknown";
}
if (invalidPointerError === undefined) {
  throw new Error("reference unexpectedly decoded path text without a leading hyphen");
}

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: [
    "src/keri/core/pather.ts",
    "src/keri/core/bexter.ts",
    "src/keri/core/matter.ts",
    "src/keri/core/base64.ts",
    "src/keri/app/exchanging.ts",
    "test/core/pather.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; each parsed_components value comes from the pinned Pather qb64 constructor",
  access_methods_state:
    "The pinned TypeScript source marks root, strip, startswith, tail, and resolve TODO; Rust behavior is specified independently and is not claimed as TypeScript cross-language evidence.",
  cases: [
    pathCase("root", []),
    pathCase("three_labels", ["a", "b", "c"]),
    pathCase("three_ordinals", ["0", "1", "2"]),
    pathCase("mixed_field_ordinals", ["field0", "1", "0"]),
    pathCase("documented_mixed_types", ["A", 1, "B", 3]),
    pathCase("exchange_embed_attachment", ["e", "credential"]),
  ],
  boundary_cases: [
    repeatedCase("largest_small_code", 16_379),
    repeatedCase("first_large_code", 16_380),
  ],
  stream_case: {
    input: stream,
    declared_material_characters: path.qb64.length,
    expected_components: path.path,
    reference_observed_components: streamed.path,
  },
  reference_quirks: {
    component_edges: [
      componentEdge("internal_identity_component", ["a", "", "b"], "Matched"),
      componentEdge(
        "leading_identity_component",
        ["", "a"],
        "InvalidPathComponent",
      ),
      componentEdge("separator_in_component", ["a-b"], "InvalidPathComponent"),
    ],
    missing_leader_text: {
      input: invalidPointer.bext,
      qb64: invalidPointer.qb64,
      path_getter_error_category: invalidPointerError,
      rust_error_category: "InvalidPath",
    },
  },
  rejected_cases: [
    errorCase("missing_path", () => new Pather({}), "Unrepresentable"),
    errorCase(
      "invalid_dollar_component",
      () => new Pather({}, undefined, ["Not$Base64"]),
      "InvalidBase64Character",
    ),
    errorCase(
      "invalid_at_component",
      () => new Pather({}, undefined, ["@moreso"]),
      "InvalidBase64Character",
    ),
    errorCase(
      "invalid_star_component",
      () => new Pather({}, undefined, ["*again"]),
      "InvalidBase64Character",
    ),
    errorCase(
      "qb2_constructor",
      () => new Pather({ qb2: decodeBase64Url(path.qb64) }),
      "ReferenceUnsupported",
    ),
  ],
};

const outputUrl = new URL("../../fixtures/cesr-path/v1.json", import.meta.url);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
