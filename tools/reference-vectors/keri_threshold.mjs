// Generates exact signing-threshold vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Tholder } from "../../reference/signify-ts/dist/keri/core/tholder.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return bytes === undefined ? null : Buffer.from(bytes).toString("hex");
}

function thresholdCase(name, inputKind, input, construct, satisfactionIndices) {
  const threshold = construct();
  return {
    name,
    input_kind: inputKind,
    input,
    weighted: threshold.weighted,
    size: threshold.size,
    sith: threshold.sith,
    json: threshold.json,
    limen_hex: hex(threshold.limen),
    num: threshold.num ?? null,
    satisfaction: satisfactionIndices.map((indices) => ({
      indices,
      result: threshold.satisfy(indices),
    })),
  };
}

function errorCase(name, inputKind, input, operation, rustErrorCategory) {
  try {
    operation();
  } catch (error) {
    return {
      name,
      input_kind: inputKind,
      input,
      reference_error_category: error?.constructor?.name ?? "Unknown",
      reference_error_message: String(error?.message ?? error),
      rust_error_category: rustErrorCategory,
    };
  }
  throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

const cases = [
  thresholdCase("numeric_hex_b", "sith_string", "b", () => new Tholder({ sith: "b" }), [[1, 2, 3], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]]),
  thresholdCase("numeric_number_11", "sith_number", 11, () => new Tholder({ sith: 11 }), [[1, 2, 3], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]]),
  thresholdCase("numeric_thold_2", "thold_number", 2, () => new Tholder({ thold: 2 }), [[1], [1, 2], [1, 2, 3, 4]]),
  thresholdCase("numeric_zero", "sith_number", 0, () => new Tholder({ sith: 0 }), [[], [0]]),
  thresholdCase("single_clause", "sith_value", ["1/2", "1/2", "1/4", "1/4", "1/4"], () => new Tholder({ sith: ["1/2", "1/2", "1/4", "1/4", "1/4"] }), [[0, 1], [0, 2, 4], [0, 0, 1, 2, 1], [0], [2, 3, 4]]),
  thresholdCase("multiple_clauses", "sith_value", [["1/2", "1/2", "1/2"], ["1/3", "1/3", "1/3", "1/3"]], () => new Tholder({ sith: [["1/2", "1/2", "1/2"], ["1/3", "1/3", "1/3", "1/3"]] }), [[0, 2, 3, 5, 6], [1, 2, 3, 4, 5], [0, 1], [4, 5, 6]]),
  thresholdCase("json_clauses", "sith_json", '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]]', () => new Tholder({ sith: '[["1/2", "1/2", "1/4", "1/4", "1/4"], ["1/1", "1"]]' }), [[1, 2, 3, 5], [0, 1, 6], [0, 1], [5, 6], []]),
  thresholdCase("decimal_weights", "sith_value", ["0.1", "0.9"], () => new Tholder({ sith: ["0.1", "0.9"] }), [[0], [1], [0, 1]]),
  thresholdCase("zero_weight", "sith_value", ["1", "0"], () => new Tholder({ sith: ["1", "0"] }), [[0], [1], [0, 1]]),
];

const rejectedCases = [
  errorCase("missing_expression", "missing", null, () => new Tholder({}), "EmptyExpression"),
  errorCase("negative_numeric", "sith_number", -1, () => new Tholder({ sith: -1 }), "Unrepresentable"),
  errorCase("empty_weight_list", "sith_value", [], () => new Tholder({ sith: [] }), "EmptyThreshold"),
  errorCase("mixed_clause_shape", "sith_value", ["1/2", "1/2", ["1/3", "1/3", "1/3"]], () => new Tholder({ sith: ["1/2", "1/2", ["1/3", "1/3", "1/3"]] }), "InvalidExpressionShape"),
  errorCase("clause_below_one", "sith_value", [["1/2", "1/2"], ["1/4", "1/4", "1/4"]], () => new Tholder({ sith: [["1/2", "1/2"], ["1/4", "1/4", "1/4"]] }), "ClauseBelowOne"),
  errorCase("invalid_weight", "sith_value", ["nope"], () => new Tholder({ sith: ["nope"] }), "InvalidWeight"),
  errorCase("zero_denominator", "sith_value", ["1/0"], () => new Tholder({ sith: ["1/0"] }), "InvalidWeight"),
  errorCase("numeric_limen", "limen", "MAAL", () => new Tholder({ limen: "MAAL" }), "ReferenceUnsupported"),
];

const greaterThanOne = new Tholder({ sith: ["2"] });
const negativeWeight = new Tholder({ sith: ["-1", "2"] });
const partialHex = new Tholder({ sith: "bzz" });
const outOfRangeIndex = new Tholder({ sith: ["1"] });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-09",
  sources: ["src/keri/core/tholder.ts", "test/core/tholder.test.ts"],
  cases,
  rejected_cases: rejectedCases,
  reference_quirks: {
    greater_than_one_weight: {
      input: ["2"],
      sith: greaterThanOne.sith,
      satisfies_zero: greaterThanOne.satisfy([0]),
      rust_error_category: "WeightOutOfRange",
    },
    negative_weight: {
      input: ["-1", "2"],
      sith: negativeWeight.sith,
      satisfies_all: negativeWeight.satisfy([0, 1]),
      rust_error_category: "InvalidWeight",
    },
    partial_numeric_hex: {
      input: "bzz",
      sith: partialHex.sith,
      num: partialHex.num,
      rust_error_category: "InvalidHexCharacter",
    },
    out_of_range_signature_index: {
      input: ["1"],
      indices: [3],
      result: outOfRangeIndex.satisfy([3]),
      rust_error_category: "IndexOutOfRange",
    },
  },
};

const outputUrl = new URL("../../fixtures/keri-threshold/v1.json", import.meta.url);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
