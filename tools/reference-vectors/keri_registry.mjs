// Generates and checks registry-inception vectors from the compiled pinned signify-ts checkout.
//
// `vdr.incept` derives no keys, so everything here is fast and fully deterministic apart from the
// default nonce, whose shape alone is recorded.
import { readFileSync, writeFileSync } from "node:fs";

import { vdr } from "../../reference/signify-ts/dist/keri/core/vdring.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

/** The issuer and nonce the pinned `vdring.test.ts` uses throughout. */
const ISSUER = "ECJIoBpEcCWMzvquk861dXP8JJZ-vbmJczlDR-NYcE3g";
const NONCE = "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s";

/** Records one inception's complete output. */
function record(args) {
  const serder = vdr.incept({ pre: ISSUER, nonce: NONCE, ...args });
  return {
    args_note: JSON.stringify(Object.keys(args)),
    raw: serder.raw,
    pre: serder.pre,
    said: serder.sad.d,
    size: serder.size,
    backer_threshold: serder.sad.bt,
  };
}

/** Records a call the reference refuses, with the error it raises. */
function rejected(name, note, args) {
  try {
    vdr.incept({ pre: ISSUER, nonce: NONCE, ...args });
  } catch (error) {
    return { name, note, reference_error_message: String(error?.message ?? error) };
  }
  throw new Error(`the reference unexpectedly accepted ${name}`);
}

const BACKERS_3 = ["backer-0", "backer-1", "backer-2"];
const BACKERS_5 = ["backer-0", "backer-1", "backer-2", "backer-3", "backer-4"];
const BACKERS_12 = Array.from({ length: 12 }, (_, index) => `backer-${index}`);

const inceptions = {
  pinned_default: record({ toad: 0 }),
  pinned_default_without_toad: record({}),
  pinned_backer: record({ baks: ["a backer"], toad: 1 }),
  pinned_backer_without_toad: record({ baks: ["a backer"] }),
  no_backers_trait: record({ cnfg: ["NB"] }),
  all_traits: record({ cnfg: ["EO", "DND", "NB"] }),
  three_backers_default_toad: record({ baks: BACKERS_3 }),
  three_backers_explicit_toad: record({ baks: BACKERS_3, toad: 2 }),
  five_backers_default_toad: record({ baks: BACKERS_5 }),
  twelve_backers_hexadecimal_toad: record({ baks: BACKERS_12, toad: 10 }),
  empty_nonce: (() => {
    const serder = vdr.incept({ pre: ISSUER, nonce: "" });
    return { raw: serder.raw, pre: serder.pre, size: serder.size };
  })(),
};

const randomNonceShape = (() => {
  const serder = vdr.incept({ pre: ISSUER });
  const nonce = serder.sad.n;
  return {
    length: nonce.length,
    code: nonce.slice(0, 1),
    note: "the default nonce is randomNonce(): 32 random bytes as qualified Base64 under the seed code; it cannot be pinned, and its Rust equivalent arrives with Roadmap 6.4",
  };
})();

const rejections = [
  rejected("no_backers_trait_with_backers", "the pinned NB-with-backers case", {
    cnfg: ["NB"],
    baks: ["a backer"],
    toad: 0,
  }),
  rejected("duplicate_backers", "the pinned duplicate case", { baks: ["a backer", "a backer"], toad: 0 }),
  rejected("zero_toad_with_backers", "the pinned invalid-toad case", { baks: ["a backer"], toad: 0 }),
  rejected("toad_without_backers", "the pinned no-backers toad case", { toad: 1 }),
  rejected("toad_above_backer_count", "two receipts from one backer", { baks: ["a backer"], toad: 2 }),
  rejected("basic_derivation_code", "a non-digestive code reads fields a vcp does not carry", {
    toad: 0,
    code: "D",
  }),
];

const quirks = {
  non_numeric_toad_emits_nan: (() => {
    const serder = vdr.incept({ pre: ISSUER, nonce: NONCE, baks: ["a backer"], toad: "abc" });
    return {
      raw: serder.raw,
      backer_threshold: serder.sad.bt,
      note: "`+toad` coerces a non-numeric string to NaN, every comparison on NaN is false, and the event is emitted with bt: \"NaN\" — a threshold nothing can satisfy, committed into the registry identifier",
      rust_decision: "unrepresentable: the threshold is a u32",
    };
  })(),
  string_toad_is_coerced: (() => {
    const numeric = vdr.incept({ pre: ISSUER, nonce: NONCE, baks: ["a backer"], toad: 1 });
    const text = vdr.incept({ pre: ISSUER, nonce: NONCE, baks: ["a backer"], toad: "1" });
    return {
      identical: numeric.raw === text.raw,
      note: "`toad` is typed number | string and coerced with `+toad`, so \"1\" and 1 build the same event",
      rust_decision: "the threshold is a u32; there is no string spelling",
    };
  })(),
  backers_are_unvalidated: {
    note: "the pinned unit test commits the string 'a backer' — with a space — into a registry identifier; nothing checks that a backer is an identifier",
    rust_decision: "backers are bounded text, because refusing what the reference commits to would derive a different registry from the same inputs",
  },
  issuer_is_unvalidated: (() => {
    const serder = vdr.incept({ pre: "not an identifier", nonce: NONCE });
    return {
      accepted: true,
      pre: serder.pre,
      note: "the issuing prefix is likewise committed unchecked",
      rust_decision: "the issuer is a typed IdentifierPrefix; an unparseable issuer is refused, which is this port's convention for caller-side identifiers",
    };
  })(),
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-22",
  sources: ["src/keri/core/vdring.ts", "test/core/vdring.test.ts"],
  provenance: {
    issuer: ISSUER,
    nonce: NONCE,
    note: "the issuer and nonce are the pinned unit test's own constants; vdr.incept derives no keys, so every recorded event is exact",
  },
  inceptions,
  random_nonce_shape: randomNonceShape,
  rejections,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-registry/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-registry fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
