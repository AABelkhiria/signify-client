// Generates and checks identifier-prefix vectors from the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { b, Ilks } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Prefixer } from "../../reference/signify-ts/dist/keri/core/prefixer.js";
import { dumps } from "../../reference/signify-ts/dist/keri/core/serder.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// The verification key from the pinned `test/core/prefixer.test.ts`, in both transferability
// forms, plus the key from the `Prefixer` assertions in `test/core/serder.test.ts`.
const PINNED_KEY = "DKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
const PINNED_KEY_NONTRANSFERABLE = "BKxy2sgzfplyr-tgwIxS19f2OchFHtLwPWD3v4oYimBx";
const SERDER_KEY = "DAUDqkmn-hqlQKD8W-FAEa5JUvJC2I9yarEem-AAEg3e";
const P256_KEY = "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
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

// Records one derivation. The reference mutates the inception data it is handed, so the object
// left behind after a self-addressing derivation *is* the placeholder-bearing intermediate it
// hashed; re-serializing it reproduces the exact preimage.
function prefixCase(name, sad, code) {
  const input = clone(sad);
  const working = clone(sad);
  const prefixer = new Prefixer({ code }, working);
  const digestive = code === MtrDex.Blake3_256;
  const preimage = digestive ? dumps(working, "JSON") : null;
  return {
    name,
    derivation_code: code,
    input_sad_json: JSON.stringify(input),
    prefix: prefixer.qb64,
    prefix_code: prefixer.code,
    transferable: prefixer.transferable,
    digestive: prefixer.digestive,
    dummied_sad_json: digestive ? JSON.stringify(working) : null,
    placeholder: digestive ? working.i : null,
    placeholder_width: digestive ? working.i.length : null,
    preimage,
    preimage_hex: preimage === null ? null : hex(b(preimage)),
    preimage_byte_size: preimage === null ? null : b(preimage).length,
  };
}

// 1. The exact inception data from the pinned `test/core/prefixer.test.ts`. It carries an
//    identifier field but no SAID field, so the reference appends one at the end of the event.
const pinnedKed = {
  v: "KERI10JSON000000_",
  i: "",
  s: "0",
  t: Ilks.icp,
  kt: "1",
  k: [PINNED_KEY],
  n: "",
  wt: "0",
  w: [],
  c: [],
};

// 2. The inception data from the `Prefixer` assertions in `test/core/serder.test.ts`, which has
//    both fields in their normal positions.
const serderKed = {
  v: "KERI10JSON000000_",
  t: Ilks.icp,
  d: "",
  i: "",
  s: "0",
  kt: "1",
  k: [SERDER_KEY],
  nt: "1",
  n: ["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"],
  bt: "0",
  b: [],
  c: [],
  a: [],
};

// 3. Inception data for a non-transferable identifier: no next keys, backers, or anchors.
const nonTransferableKed = { ...pinnedKed, k: [PINNED_KEY_NONTRANSFERABLE] };

// 4. Neither identifier field present; the reference appends both, in order.
const bareKed = (() => {
  const bare = clone(serderKed);
  delete bare.i;
  delete bare.d;
  return bare;
})();

const cases = [
  prefixCase("pinned_prefixer_test_self_addressing", pinnedKed, MtrDex.Blake3_256),
  prefixCase("pinned_prefixer_test_basic_transferable", pinnedKed, MtrDex.Ed25519),
  prefixCase("pinned_serder_test_self_addressing", serderKed, MtrDex.Blake3_256),
  prefixCase("pinned_serder_test_basic_transferable", serderKed, MtrDex.Ed25519),
  prefixCase("basic_non_transferable", nonTransferableKed, MtrDex.Ed25519N),
  prefixCase("delegated_inception", { ...serderKed, t: Ilks.dip }, MtrDex.Blake3_256),
  prefixCase("registry_inception", { ...serderKed, t: Ilks.vcp }, MtrDex.Blake3_256),
  prefixCase("both_identifier_fields_absent", bareKed, MtrDex.Blake3_256),
];

// 5. Reverse direction. A Rust event builder fills the identifier field -- and, for a digestive
//    prefix, the SAID field -- with the derived prefix. Feeding those exact completed bytes back
//    to the reference must reproduce the same prefix, which is what makes the artifact usable by
//    a peer running the reference implementation.
const completedEvents = cases.map((entry) => {
  const completed = JSON.parse(entry.input_sad_json);
  completed.i = entry.prefix;
  if (entry.digestive) {
    completed.d = entry.prefix;
  }
  const working = clone(completed);
  const rederived = new Prefixer({ code: entry.derivation_code }, working);
  return {
    name: entry.name,
    derivation_code: entry.derivation_code,
    completed_sad_json: JSON.stringify(completed),
    reference_rederived_prefix: rederived.qb64,
    matches_original: rederived.qb64 === entry.prefix,
  };
});

// 6. Code metadata recovered by parsing a finished prefix, the reference's `Matter` accessors.
const parsed = [PINNED_KEY, PINNED_KEY_NONTRANSFERABLE, cases[0].prefix].map((qb64) => {
  const prefixer = new Prefixer({ qb64 });
  return {
    qb64,
    code: prefixer.code,
    transferable: prefixer.transferable,
    digestive: prefixer.digestive,
  };
});

// 7. Reference rejections.
const rejected = [
  rejectedCase(
    "two_keys",
    () => new Prefixer({ code: MtrDex.Ed25519 }, { ...pinnedKed, k: [PINNED_KEY, PINNED_KEY] }),
    "KeyCount",
  ),
  rejectedCase("zero_keys", () => new Prefixer({ code: MtrDex.Ed25519 }, { ...pinnedKed, k: [] }), "KeyCount"),
  rejectedCase(
    "missing_keys_field",
    () => {
      const without = clone(pinnedKed);
      delete without.k;
      return new Prefixer({ code: MtrDex.Ed25519 }, without);
    },
    "MissingKeysField",
  ),
  rejectedCase(
    "malformed_key",
    () => new Prefixer({ code: MtrDex.Ed25519 }, { ...pinnedKed, k: ["not-a-key"] }),
    "Crypto",
  ),
  rejectedCase(
    "non_transferable_derivation_with_transferable_key",
    () => new Prefixer({ code: MtrDex.Ed25519N }, clone(pinnedKed)),
    "KeyCodeMismatch",
  ),
  rejectedCase(
    "non_transferable_with_next_keys",
    () =>
      new Prefixer(
        { code: MtrDex.Ed25519N },
        { ...nonTransferableKed, n: ["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"] },
      ),
    "NonTransferableFieldNotEmpty",
  ),
  rejectedCase(
    "non_transferable_with_backers",
    () => new Prefixer({ code: MtrDex.Ed25519N }, { ...nonTransferableKed, b: [PINNED_KEY] }),
    "NonTransferableFieldNotEmpty",
  ),
  rejectedCase(
    "non_transferable_with_anchors",
    () => new Prefixer({ code: MtrDex.Ed25519N }, { ...nonTransferableKed, a: [{ d: "x" }] }),
    "NonTransferableFieldNotEmpty",
  ),
  rejectedCase(
    "non_incepting_event_kind",
    () => new Prefixer({ code: MtrDex.Blake3_256 }, { ...serderKed, t: Ilks.rot }),
    "NonInceptingEventKind",
  ),
  rejectedCase(
    "missing_event_kind",
    () => {
      const without = clone(serderKed);
      delete without.t;
      return new Prefixer({ code: MtrDex.Blake3_256 }, without);
    },
    "MissingEventKind",
  ),
  rejectedCase(
    "missing_version_string",
    () => {
      const without = clone(serderKed);
      delete without.v;
      return new Prefixer({ code: MtrDex.Blake3_256 }, without);
    },
    "Serialization",
  ),
  rejectedCase(
    "unsupported_derivation_code",
    () => new Prefixer({ code: MtrDex.SHA3_256 }, clone(serderKed)),
    "UnsupportedCode",
  ),
  rejectedCase(
    "p256_key_cannot_form_a_prefix",
    () => new Prefixer({ code: MtrDex.Ed25519 }, { ...serderKed, k: [P256_KEY] }),
    "KeyCodeMismatch",
  ),
  rejectedCase(
    "non_prefix_qualified_material",
    () => new Prefixer({ qb64: "HLEjyRTtmfyp4VpTBTkv_b6KONMS1V8-EW-aGJ5P_QMo" }),
    "UnsupportedCode",
  ),
];

// 8. Reference quirks that Rust deliberately does not reproduce.
const selfAddressingPrefixer = new Prefixer({ code: MtrDex.Blake3_256 }, clone(pinnedKed));
const basicPrefixer = new Prefixer({ code: MtrDex.Ed25519 }, clone(pinnedKed));

// The public derive/verify gate compares `sad['i']`, the identifier field, against the `icp` ilk.
// Every real event therefore throws, and the only events that get past the gate are ones whose
// identifier field holds the literal text `icp` -- which is exactly what `prefixed=true` rejects.
const gateWithRealEvent = rejectedCase(
  "public_verify_with_a_real_event",
  () => basicPrefixer.verify(clone(pinnedKed)),
  "NotReproduced",
);
const gatedKed = { ...clone(pinnedKed), i: Ilks.icp };
const prefixedGatedKed = { ...clone(serderKed), i: selfAddressingPrefixer.qb64, d: selfAddressingPrefixer.qb64 };

// The transferable derivation's key-code check reads `verfer.code in [MtrDex.Ed25519]`, which
// tests array property keys and is never true, so a `B` key silently produces a `B` prefix.
const swapped = new Prefixer({ code: MtrDex.Ed25519 }, clone(nonTransferableKed));

// Non-transferable verification checks only the next-key field, accepting an event its own
// derivation would have rejected for carrying backers.
const nonTransferablePrefixer = new Prefixer({ code: MtrDex.Ed25519N }, clone(nonTransferableKed));

// Self-addressing verification re-runs derivation on the caller's object, mutating it.
const mutated = { ...clone(pinnedKed), i: Ilks.icp };
const mutatedBefore = JSON.stringify(mutated);
const mutatedResult = selfAddressingPrefixer.verify(mutated);

const quirks = {
  public_derive_and_verify_gate_on_the_identifier_field: {
    reference_error_category: gateWithRealEvent.reference_error_category,
    reference_error_message: gateWithRealEvent.reference_error_message,
    verify_accepted_when_identifier_field_is_the_ilk: basicPrefixer.verify(clone(gatedKed)),
    verify_prefixed_when_identifier_field_is_the_ilk: basicPrefixer.verify(clone(gatedKed), true),
    verify_prefixed_on_a_completed_event: rejectedCase(
      "public_verify_prefixed_on_a_completed_event",
      () => selfAddressingPrefixer.verify(clone(prefixedGatedKed), true),
      "NotReproduced",
    ).reference_error_message,
    note: "derive(sad) and verify(sad) compare sad['i'], the identifier field, against the icp ilk instead of sad['t']; every real event throws, and verify(sad, true) can never return true because reaching the comparison requires i to be the literal text 'icp', which the comparison then rejects",
    rust_decision:
      "Rust gates self-addressing derivation on the event kind field and makes PrefixVerification::Strict -- the check the prefixed flag intends -- the default",
  },
  transferable_key_code_check_is_a_no_op: {
    requested_code: MtrDex.Ed25519,
    key: PINNED_KEY_NONTRANSFERABLE,
    reference_prefix: swapped.qb64,
    reference_prefix_code: swapped.code,
    reference_transferable: swapped.transferable,
    note: "the check is written `verfer.code in [MtrDex.Ed25519]`, which tests array property keys and is never true, so a non-transferable key passed to the transferable derivation silently yields a non-transferable prefix",
    rust_error_category: "KeyCodeMismatch",
  },
  non_transferable_verify_skips_backers_and_anchors: {
    reference_verify_with_next_keys: nonTransferablePrefixer.verify({
      ...clone(nonTransferableKed),
      i: Ilks.icp,
      n: ["EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj"],
    }),
    reference_verify_with_backers: nonTransferablePrefixer.verify({
      ...clone(nonTransferableKed),
      i: Ilks.icp,
      b: [PINNED_KEY],
    }),
    reference_verify_with_anchors: nonTransferablePrefixer.verify({
      ...clone(nonTransferableKed),
      i: Ilks.icp,
      a: [{ d: "x" }],
    }),
    note: "_verify_ed25519N checks only the next-key field, so it accepts an event carrying backers or anchors that its own _derive_ed25519N would have rejected",
    rust_decision:
      "Rust verifies by re-deriving, so every invariant derivation enforces is enforced on verification too",
    rust_error_category: "NonTransferableFieldNotEmpty",
  },
  verify_mutates_the_callers_event: {
    result: mutatedResult,
    event_before_json: mutatedBefore,
    event_after_json: JSON.stringify(mutated),
    note: "self-addressing verification calls the same _derive_blake3_256 that overwrites the identifier and SAID fields with placeholder characters and restamps the version string, so verifying destroys the caller's event",
    rust_decision: "Rust borrows the data and clones internally; the caller's event is unchanged",
  },
  constructor_super_called_twice: rejectedCase(
    "constructor_with_existing_identifier",
    () => new Prefixer({}, { ...clone(pinnedKed), i: PINNED_KEY }),
    "UnreachableInRust",
  ),
};
quirks.constructor_super_called_twice.note =
  "when no code is passed and the identifier field is already populated, the constructor calls super() twice, so the natural 'recover the derivation of a received event' path throws; callers must construct from qb64 and call verify() instead";

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/core/prefixer.ts", "test/core/prefixer.test.ts", "test/core/serder.test.ts"],
  dummy_character: "#",
  supported_codes: [MtrDex.Ed25519N, MtrDex.Ed25519, MtrDex.Blake3_256],
  incepting_ilks: [Ilks.icp, Ilks.dip, Ilks.vcp],
  cases,
  completed_events: completedEvents,
  parsed_prefixes: parsed,
  rejected_cases: rejected,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-prefix/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-prefix fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
