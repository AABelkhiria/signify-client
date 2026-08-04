// Generates CESR counter vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { b64ToInt } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Counter } from "../../reference/signify-ts/dist/keri/core/counter.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

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

const codeSizes = Array.from(Counter.Sizes.entries()).map(([code, size]) => ({
  code,
  hard_size: size.hs,
  soft_size: size.ss,
  full_size: size.fs,
  lead_size: size.ls,
}));

const cases = codeSizes.map(({ code }, offset) => {
  let count = offset + 1;
  if (code === "-0V") count = 1024;
  if (code === "--AAA") count = b64ToInt(Counter.semVerToB64("1.2.3"));
  const counter = new Counter({ code, count });
  const parsed = new Counter({ qb64: counter.qb64 });
  if (parsed.code !== code || parsed.count !== count) {
    throw new Error(`reference counter round trip failed for ${code}`);
  }
  return {
    code,
    count,
    qb64: counter.qb64,
    qb2_hex: hex(decodeBase64Url(counter.qb64)),
  };
});

const short = new Counter({ code: "-A", count: 5 });
const streamInput = `${short.qb64}ABCD`;
const streamParsed = new Counter({ qb64: streamInput });
const defaultCounter = new Counter({ code: "-A" });
const countB64Counter = new Counter({ code: "-A", countB64: "F" });

const versionInputs = [
  { version: "1.2.3", fallback: [0, 0, 0] },
  { version: "", fallback: [0, 0, 0] },
  { version: "", fallback: [1, 0, 0] },
  { version: "", fallback: [0, 1, 0] },
  { version: "", fallback: [0, 0, 1] },
  { version: "", fallback: [3, 4, 5] },
  { version: "1.1", fallback: [0, 0, 0] },
  { version: "1.", fallback: [0, 0, 0] },
  { version: "1", fallback: [0, 0, 0] },
  { version: "1.2.", fallback: [0, 0, 0] },
  { version: "..", fallback: [0, 0, 0] },
  { version: "1..3", fallback: [0, 0, 0] },
  { version: "4", fallback: [1, 2, 3] },
];

const versionCases = versionInputs.map(({ version, fallback }) => ({
  version,
  fallback,
  qb64_digits: Counter.semVerToB64(version, ...fallback),
}));

const qb2Probe = new Counter({ qb2: decodeBase64Url(short.qb64) });
let qb2ReencodeError;
try {
  void qb2Probe.qb64;
} catch (error) {
  qb2ReencodeError = {
    category: error?.constructor?.name ?? "Unknown",
    message: String(error?.message ?? error),
  };
}
if (qb2ReencodeError === undefined) {
  throw new Error("reference qb2 counter unexpectedly re-encoded");
}

const malformedSoft = new Counter({ qb64: "-A!A" });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-04",
  sources: ["src/keri/core/counter.ts", "test/core/counter.test.ts"],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference Counter.qb64); pinned Counter qb2 construction leaves an invalid empty object",
  code_sizes: codeSizes,
  cases,
  default_case: {
    code: defaultCounter.code,
    count: defaultCounter.count,
    qb64: defaultCounter.qb64,
  },
  count_b64_case: {
    input: "F",
    count: countB64Counter.count,
    qb64: countB64Counter.qb64,
  },
  stream_case: {
    input: streamInput,
    consumed_characters: short.qb64.length,
    parsed_qb64: streamParsed.qb64,
  },
  version_cases: versionCases,
  reference_quirks: {
    qb2_constructor: {
      parsed_code: qb2Probe.code,
      parsed_count: qb2Probe.count,
      reencode_error: qb2ReencodeError,
    },
    permissive_version_prefix: {
      input: "1x.2.3",
      reference_qb64_digits: Counter.semVerToB64("1x.2.3"),
      rust_error_category: "InvalidSemanticVersion",
    },
    extra_version_component: {
      input: "1.2.3.4",
      reference_qb64_digits: Counter.semVerToB64("1.2.3.4"),
      rust_error_category: "InvalidSemanticVersion",
    },
    invalid_soft_digits: {
      input: "-A!A",
      parsed_count: malformedSoft.count,
      canonical_qb64: malformedSoft.qb64,
      rust_error_category: "InvalidBase64Character",
    },
  },
  rejected_cases: [
    errorCase("empty_qb64", () => new Counter({ qb64: "" }), "EmptyInput"),
    errorCase(
      "unsupported_selector",
      () => new Counter({ qb64: "AAAA" }),
      "UnsupportedCode",
    ),
    errorCase(
      "reserved_code",
      () => new Counter({ qb64: "-MAA" }),
      "UnsupportedCode",
    ),
    errorCase("truncated_qb64", () => new Counter({ qb64: "-AA" }), "Truncated"),
    errorCase(
      "negative_count",
      () => new Counter({ code: "-A", count: -1 }),
      "Unrepresentable",
    ),
    errorCase(
      "short_count_too_large",
      () => new Counter({ code: "-A", count: 4096 }),
      "CounterOutOfRange",
    ),
    errorCase(
      "big_count_too_large",
      () => new Counter({ code: "-0V", count: 1073741824 }),
      "CounterOutOfRange",
    ),
    errorCase(
      "version_component_too_large",
      () => Counter.semVerToB64("64.0.0"),
      "SemanticVersionOutOfRange",
    ),
    errorCase(
      "negative_version_component",
      () => Counter.semVerToB64("-1.0.0"),
      "InvalidSemanticVersion",
    ),
  ],
};

const outputUrl = new URL(
  "../../fixtures/cesr-counter/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
