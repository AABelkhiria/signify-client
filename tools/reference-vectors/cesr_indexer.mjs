// Generates indexed-material vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import {
  IdxCrtSigDex,
  Indexer,
} from "../../reference/signify-ts/dist/keri/core/indexer.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function deterministicRaw(length, salt) {
  return Uint8Array.from(
    { length },
    (_, offset) => (salt * 23 + offset * 31) % 256,
  );
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
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

const codeSizes = Array.from(Indexer.Sizes.entries()).map(([code, size]) => ({
  code,
  hard_size: size.hs,
  soft_size: size.ss,
  other_index_size: size.os,
  full_size: size.fs ?? null,
  lead_size: size.ls,
}));

const fixedCodes = codeSizes.filter(({ code }) => !code.endsWith("z"));

const fixedCases = fixedCodes.map(
  ({ code, hard_size, soft_size, other_index_size, full_size }, offset) => {
    const rawLength = Math.floor(((full_size - hard_size - soft_size) * 3) / 4);
    const raw = deterministicRaw(rawLength, offset + 1);
    const big = code.startsWith("2") || code.startsWith("3");
    const index = big ? 67 + offset : 3 + (offset % 16);
    let ondex;
    if (!IdxCrtSigDex.has(code)) {
      ondex = other_index_size === 0 ? index : index + 1;
    }
    const material = new Indexer({ raw, code, index, ondex });
    const parsed = new Indexer({ qb64: material.qb64 });
    if (
      parsed.code !== code ||
      parsed.index !== index ||
      parsed.ondex !== ondex ||
      hex(parsed.raw) !== hex(raw)
    ) {
      throw new Error(`reference indexed round trip failed for ${code}`);
    }
    return {
      code,
      raw_hex: hex(raw),
      index,
      other_index: ondex ?? null,
      qb64: material.qb64,
      qb2_hex: hex(decodeBase64Url(material.qb64)),
    };
  },
);

const streamMaterial = new Indexer({
  raw: deterministicRaw(64, 201),
  code: "2A",
  index: 90,
  ondex: 65,
});
const streamInput = `${streamMaterial.qb64}ABCD`;
const streamParsed = new Indexer({ qb64: streamInput });
const rawStreamInput = deterministicRaw(67, 202);
const rawStreamParsed = new Indexer({
  raw: rawStreamInput,
  code: "A",
  index: 5,
});

const validCurrentBig = new Indexer({
  raw: deterministicRaw(64, 222),
  code: "2B",
  index: 68,
});
const nonZeroReservedOther = `${validCurrentBig.qb64.slice(0, 5)}B${validCurrentBig.qb64.slice(6)}`;

const ecdsaR1Raw = deterministicRaw(64, 223);
const referenceDefaultR1 = new Indexer({
  raw: ecdsaR1Raw,
  code: "2E",
  index: 90,
});
const parsedReferenceDefaultR1 = new Indexer({
  qb64: referenceDefaultR1.qb64,
});
const explicitSafeR1 = new Indexer({
  raw: ecdsaR1Raw,
  code: "2E",
  index: 90,
  ondex: 90,
});

const rejectedCases = [
  errorCase("empty_qb64", () => new Indexer({ qb64: "" }), "EmptyInput"),
  errorCase(
    "unsupported_code",
    () => new Indexer({ qb64: `G${"A".repeat(87)}` }),
    "UnsupportedCode",
  ),
  errorCase("truncated_qb64", () => new Indexer({ qb64: "AA" }), "Truncated"),
  errorCase(
    "short_raw",
    () => new Indexer({ raw: new Uint8Array(63), code: "A" }),
    "RawSizeMismatch",
  ),
  errorCase(
    "index_out_of_range",
    () => new Indexer({ raw: new Uint8Array(64), code: "A", index: 64 }),
    "IndexOutOfRange",
  ),
  errorCase(
    "implicit_other_mismatch",
    () =>
      new Indexer({ raw: new Uint8Array(64), code: "A", index: 5, ondex: 4 }),
    "InvalidIndexRelation",
  ),
  errorCase(
    "current_only_other_index",
    () =>
      new Indexer({ raw: new Uint8Array(64), code: "B", index: 3, ondex: 3 }),
    "InvalidIndexRelation",
  ),
  errorCase(
    "other_index_out_of_range",
    () =>
      new Indexer({
        raw: new Uint8Array(64),
        code: "2A",
        index: 1,
        ondex: 4096,
      }),
    "IndexOutOfRange",
  ),
  errorCase(
    "non_zero_alignment_bits",
    () => new Indexer({ qb64: `AA_${streamMaterial.qb64.slice(3, 88)}` }),
    "NonZeroPadding",
  ),
  errorCase(
    "non_zero_current_reserved_other",
    () => new Indexer({ qb64: nonZeroReservedOther }),
    "InvalidIndexRelation",
  ),
  errorCase(
    "variable_length_code",
    () => new Indexer({ raw: new Uint8Array(), code: "0z", index: 0 }),
    "UnsupportedVariableLength",
  ),
];

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: ["src/keri/core/indexer.ts", "test/core/indexer.test.ts"],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference Indexer.qb64); pinned Indexer._bexfil is unsupported",
  reference_quirks: {
    raw_size_helper: {
      code: "A",
      reference_reported: Indexer._rawSize("A"),
      constructor_required: 64,
    },
    omitted_ecdsa_r1_big_other_index: {
      code: "2E",
      index: 90,
      raw_hex: hex(ecdsaR1Raw),
      constructed_other_index: referenceDefaultR1.ondex ?? null,
      reference_qb64: referenceDefaultR1.qb64,
      parsed_other_index: parsedReferenceDefaultR1.ondex,
      explicit_safe_other_index: explicitSafeR1.ondex,
      explicit_safe_qb64: explicitSafeR1.qb64,
    },
  },
  code_sizes: codeSizes,
  fixed_cases: fixedCases,
  stream_case: {
    input: streamInput,
    consumed_characters: streamMaterial.qb64.length,
    parsed_qb64: streamParsed.qb64,
    raw_input_hex: hex(rawStreamInput),
    consumed_raw_bytes: rawStreamParsed.raw.length,
    raw_parsed_qb64: rawStreamParsed.qb64,
  },
  rejected_cases: rejectedCases,
};

const outputUrl = new URL(
  "../../fixtures/cesr-indexer/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
