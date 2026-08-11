// Generates digest vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function digestCase(name, serialization) {
  const digest = new Diger({}, serialization);
  const reparsed = new Diger({ qb64: digest.qb64 });
  const changed = new Uint8Array(serialization.length + 1);
  changed.set(serialization);
  changed.set(Uint8Array.of(0xff), serialization.length);
  return {
    name,
    serialization_hex: hex(serialization),
    code: digest.code,
    raw_hex: hex(digest.raw),
    qb64: digest.qb64,
    qb64_bytes_hex: hex(digest.qb64b),
    qb2_hex: hex(decodeBase64Url(digest.qb64)),
    qb64_round_trip: reparsed.qb64,
    verifies_serialization: digest.verify(serialization),
    verifies_changed_serialization: digest.verify(changed),
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

const unitSerialization = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456789",
);
const binarySerialization = Uint8Array.from(
  { length: 256 },
  (_, index) => index,
);
const unitDigest = new Diger({}, unitSerialization);
const unitDigestCopy = new Diger({ qb64: unitDigest.qb64 });
const differentDigest = new Diger({}, new TextEncoder().encode("different"));

const excessRaw = new Uint8Array(33);
excessRaw.set(Uint8Array.of(0xff), 32);
const truncatedDigest = new Diger({
  raw: excessRaw,
  code: MtrDex.Blake3_256,
});
const fallbackDigest = new Diger(
  { raw: new Uint8Array(31), code: MtrDex.Blake3_256 },
  unitSerialization,
);

const unsupportedRaw = new Uint8Array(32);
const unsupportedQb64 = `H${unitDigest.qb64.slice(1)}`;
const invalidQb64 = `D${unitDigest.qb64.slice(1)}`;
const acceptedUnsupportedQb64 = new Diger({ qb64: unsupportedQb64 });
const acceptedInvalidQb64 = new Diger({ qb64: invalidQb64 });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-11",
  sources: [
    "src/keri/core/diger.ts",
    "src/keri/core/matter.ts",
    "test/core/diger.test.ts",
  ],
  algorithm_dependency: "@noble/hashes 1.8.0 blake3 with dkLen 32",
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; qb64_round_trip is accepted by the pinned Diger constructor",
  cases: [
    digestCase("upstream_unit_serialization", unitSerialization),
    digestCase("empty_serialization", new Uint8Array()),
    digestCase("all_byte_values", binarySerialization),
  ],
  rejected_cases: [
    errorCase(
      "missing_material_without_serialization",
      () => new Diger({}),
      "Unrepresentable",
    ),
    errorCase(
      "short_raw_without_serialization",
      () =>
        new Diger({
          raw: new Uint8Array(31),
          code: MtrDex.Blake3_256,
        }),
      "Truncated",
    ),
    errorCase(
      "unsupported_sha3_raw",
      () => new Diger({ raw: unsupportedRaw, code: MtrDex.SHA3_256 }),
      "UnsupportedDigestAlgorithm",
    ),
    errorCase(
      "qb2_constructor",
      () => new Diger({ qb2: decodeBase64Url(unitDigest.qb64) }),
      "ReferenceUnsupported",
    ),
    errorCase(
      "compare_without_other_digest",
      () => unitDigest.compare(unitSerialization),
      "MissingComparisonDigest",
    ),
  ],
  reference_quirks: {
    compare_identical_instance: {
      reference_result: unitDigest.compare(unitSerialization, null, unitDigest),
      rust_result: true,
      rust_decision: "implement documented digest equality semantics",
    },
    compare_equal_copy: {
      reference_result: unitDigest.compare(
        unitSerialization,
        null,
        unitDigestCopy,
      ),
      rust_result: true,
      rust_decision: "implement documented digest equality semantics",
    },
    compare_equal_qb64_bytes: {
      reference_result: unitDigest.compare(
        unitSerialization,
        unitDigest.qb64b,
      ),
      rust_result: true,
      rust_decision: "typed Digest input avoids byte/string coercion",
    },
    compare_different_same_algorithm: {
      reference_result: unitDigest.compare(
        unitSerialization,
        null,
        differentDigest,
      ),
      rust_result: false,
    },
    excess_raw_truncation: {
      input_raw_hex: hex(excessRaw),
      retained_raw_hex: hex(truncatedDigest.raw),
      qb64: truncatedDigest.qb64,
      rust_error_category: "TrailingMaterial",
    },
    invalid_raw_falls_back_to_serialization: {
      invalid_raw_length: 31,
      serialization_hex: hex(unitSerialization),
      derived_qb64: fallbackDigest.qb64,
      rust_decision:
        "separate raw construction and derivation methods make conflicting sources unrepresentable",
    },
    encoded_code_is_not_validated: {
      unsupported_digest_code: acceptedUnsupportedQb64.code,
      unsupported_digest_qb64: acceptedUnsupportedQb64.qb64,
      unsupported_digest_verifies_with_blake3:
        acceptedUnsupportedQb64.verify(unitSerialization),
      non_digest_code: acceptedInvalidQb64.code,
      non_digest_qb64: acceptedInvalidQb64.qb64,
      non_digest_verifies_with_blake3:
        acceptedInvalidQb64.verify(unitSerialization),
      rust_unsupported_error_category: "UnsupportedDigestAlgorithm",
      rust_invalid_error_category: "InvalidDigestCode",
      rust_decision:
        "validate the parsed CESR code before selecting a digest algorithm",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-digest/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
