// Generates exact protocol/serialization/version-string vectors from the compiled pinned
// signify-ts checkout.
//
// Ordering note: the pinned `deversify` writes the parsed digits into the module-global
// `Vrsn_1_0` object that `versify` uses as its default version. Every default-version `versify`
// case therefore runs before the first `deversify` call, and the mutation itself is recorded last
// as a reference quirk.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  deversify,
  Ilks,
  MINSIGSIZE,
  MINSNIFFSIZE,
  Protocols,
  Serials,
  VEREX,
  VERFULLSIZE,
  versify,
  Version,
  Vrsn_1_0,
} from "../../reference/signify-ts/dist/keri/core/core.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

function versifyCase(name, protocol, major, minor, kind, size) {
  return {
    name,
    protocol,
    major,
    minor,
    kind,
    size,
    output: versify(protocol, new Version(major, minor), kind, size),
  };
}

function deversifyCase(name, input) {
  const [proto, kind, version, sizeHex] = deversify(input);
  return {
    name,
    input,
    protocol: proto,
    kind,
    major: String(version.major),
    minor: String(version.minor),
    size_hex: sizeHex,
  };
}

function errorCase(name, input, rustErrorCategory) {
  try {
    deversify(input);
  } catch (error) {
    return {
      name,
      input,
      reference_error_message: String(error?.message ?? error),
      rust_error_category: rustErrorCategory,
    };
  }
  throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

// 1. Default-version versify cases, before any deversify mutation.
const defaultOutput = versify();
const defaultKindOutput = versify(Protocols.ACDC);

// 2. Explicit-version versify cases; these never read the shared default.
const versifyCases = [
  versifyCase("keri_v1_json_empty", Protocols.KERI, 1, 0, Serials.JSON, 0),
  versifyCase("keri_v1_json_serder_size", Protocols.KERI, 1, 0, Serials.JSON, 0x11c),
  versifyCase("acdc_v1_json_251", Protocols.ACDC, 1, 0, Serials.JSON, 0xfb),
  versifyCase("keri_v1_json_max_size", Protocols.KERI, 1, 0, Serials.JSON, 0xffffff),
  versifyCase("keri_v2_1_json", Protocols.KERI, 2, 1, Serials.JSON, 0x123),
  versifyCase("keri_vf_f_json", Protocols.KERI, 15, 15, Serials.JSON, 0),
];

// 3. Deversify cases, including the exact string asserted by the pinned serder unit test.
const deversifyCases = [
  deversifyCase("serder_unit_test_vector", "KERI10JSON00011c_"),
  deversifyCase("keri_empty_size", "KERI10JSON000000_"),
  deversifyCase("acdc_251", "ACDC10JSON0000fb_"),
  deversifyCase("keri_max_size", "KERI10JSONffffff_"),
  deversifyCase("unsupported_version_2_1_accepted", "KERI21JSON000123_"),
];

// 4. Reference rejections.
const rejectedCases = [
  errorCase("empty_input", "", "InvalidLength"),
  errorCase("missing_terminator", "KERI10JSON000000", "InvalidLength"),
  errorCase("wrong_terminator", "KERI10JSON000000-", "MissingTerminator"),
  errorCase("unknown_protocol", "XERI10JSON000000_", "UnsupportedProtocol"),
  errorCase("unsupported_kind_cbor", "KERI10CBOR000000_", "UnsupportedSerialization"),
  errorCase("lowercase_kind", "KERI10json000000_", "UnsupportedSerialization"),
  errorCase("uppercase_major_digit", "KERIA0JSON000000_", "InvalidVersionDigit"),
  errorCase("uppercase_size_digit", "KERI10JSON00011C_", "InvalidSizeDigit"),
  errorCase("non_hex_size_digit", "KERI10JSON00011G_", "InvalidSizeDigit"),
];

// 5. Reference quirks, recorded last because several corrupt the shared default version.
// Every returned version object aliases the same mutable singleton, so each observation must be
// captured as text immediately, before the next deversify call overwrites it.
const embedded = deversify("XXKERI10JSON00011c_YY");
const nanParse = deversify("KERIa0JSON000000_");
const nanMajor = String(nanParse[2].major);
const nanMinor = String(nanParse[2].minor);
const mutationParse = deversify("KERI21JSON000000_");
const quirks = {
  unanchored_match: {
    input: "XXKERI10JSON00011c_YY",
    protocol: embedded[0],
    kind: embedded[1],
    size_hex: embedded[3],
    rust_error_category: "InvalidLength",
  },
  hex_digit_decimal_coercion: {
    input: "KERIa0JSON000000_",
    major: nanMajor,
    minor: nanMinor,
    rust_major: 10,
    note: "the reference coerces the hexadecimal major digit with decimal semantics",
  },
  aliased_version_objects: {
    inputs: ["XXKERI10JSON00011c_YY", "KERIa0JSON000000_", "KERI21JSON000000_"],
    all_returns_are_one_object:
      embedded[2] === nanParse[2] && nanParse[2] === mutationParse[2],
    note: "every deversify result aliases the same mutable Version singleton",
  },
  shared_default_version_mutation: {
    input: "KERI21JSON000000_",
    returns_shared_singleton: mutationParse[2] === Vrsn_1_0,
    default_versify_after_parse: versify(),
    note: "deversify mutates and returns the module-global Vrsn_1_0 default",
  },
  size_overflow_emission: {
    size: 0x1000000,
    output: versify(Protocols.KERI, new Version(1, 0), Serials.JSON, 0x1000000),
    rust_error_category: "SizeOutOfRange",
  },
  negative_size_emission: {
    size: -1,
    output: versify(Protocols.KERI, new Version(1, 0), Serials.JSON, -1),
    rust_error_category: "Unrepresentable",
  },
  major_overflow_emission: {
    major: 16,
    output: versify(Protocols.KERI, new Version(16, 0), Serials.JSON, 0),
    rust_error_category: "VersionComponentOutOfRange",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-18",
  sources: ["src/keri/core/core.ts", "test/core/serder.test.ts"],
  constants: {
    verfullsize: VERFULLSIZE,
    minsniffsize: MINSNIFFSIZE,
    minsigsize: MINSIGSIZE,
    verex: VEREX,
    protocols: Object.values(Protocols),
    serializations: Object.values(Serials),
  },
  ilks: { ...Ilks },
  default_versify: {
    no_arguments: defaultOutput,
    acdc_defaults: defaultKindOutput,
  },
  versify_cases: versifyCases,
  deversify_cases: deversifyCases,
  rejected_cases: rejectedCases,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-version/v1.json", import.meta.url);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
