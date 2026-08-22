// Generates and checks Habery vectors from the compiled pinned signify-ts checkout.
//
// A Habery's `makeHab` hardcodes the production Argon2 profile (`temp: false`), so every key here
// costs a real 64 MiB derivation and this generator takes several seconds. That is the point:
// those are the keys and events a deployed client actually produces, and the Rust registry has to
// reproduce them exactly.
//
// A named salty Habery can hold only one habitat per transferability — the derivation path drops
// the prefix index under a non-empty stem — so every event case below builds a fresh Habery.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Habery } from "../../reference/signify-ts/dist/keri/app/habery.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

/** The raw salt the pinned `habery.test.ts` builds its salter from. */
const SALT_RAW = "0123456789abcdef";
const salter = new Salter({ raw: b(SALT_RAW) });
const SALT_QB64 = salter.qb64;

/** The passcode the pinned `habery.test.ts` uses. */
const PASSCODE = "0123456789abcdefghijk";

/** The delegator used by the delegated case; any valid self-addressing prefix works. */
const DELEGATOR = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";

/** Three deterministic non-transferable witness prefixes, derived cheaply as inputs only. */
const WITNESSES = ["wit0", "wit1", "wit2"].map(
  (path) => salter.signer(MtrDex.Ed25519_Seed, false, path, Tier.low, true).verfer.qb64
);

/** Records one habitat's complete inception event. */
function eventRecord(hab) {
  return {
    habitat_name: hab.name,
    raw: hab.serder.raw,
    pre: hab.pre,
    said: hab.serder.sad["d"],
    keys: hab.serder.sad["k"],
    next_digests: hab.serder.sad["n"],
  };
}

/** Records a call the reference refuses, with the error it raises. */
function rejected(name, note, run) {
  try {
    run();
  } catch (error) {
    return { name, note, reference_error_message: String(error?.message ?? error) };
  }
  throw new Error(`the reference unexpectedly accepted ${name}`);
}

// ---------------------------------------------------------------------------
// The two pinned unit-test cases, byte-complete.
// ---------------------------------------------------------------------------

const pinnedUnitTests = (() => {
  // Case 1: salt and passcode together.
  const hby = new Habery({ name: "signify", salt: SALT_QB64, passcode: PASSCODE });
  const hab = hby.makeHab("test", {});
  const caseOne = {
    aeid: hby.mgr.aeid,
    event: eventRecord(hab),
  };

  // Case 2: the passcode-derived salt used directly, with no encryption.
  const bran = MtrDex.Salt_128 + "A" + PASSCODE.substring(0, 21);
  const branSalter = new Salter({ qb64: bran });
  const signer = branSalter.signer(MtrDex.Ed25519_Seed, true);
  const hby2 = new Habery({ name: "test", salt: branSalter.qb64 });
  const hab2 = hby2.makeHab("test", { transferable: true });
  const caseTwo = {
    bran,
    signer_qb64: signer.qb64,
    signer_verfer: signer.verfer.qb64,
    event: eventRecord(hab2),
  };

  return { salt_and_passcode: caseOne, passcode_as_salt: caseTwo };
})();

// ---------------------------------------------------------------------------
// Deterministic habitat events, each from a fresh salty Habery.
// ---------------------------------------------------------------------------

const habitatCases = (() => {
  const cases = [];
  for (const [name, haberyName, args] of [
    ["default", "signify", {}],
    ["non_transferable", "signify", { transferable: false }],
    ["three_keys", "signify", { icount: 3 }],
    ["three_keys_two_next", "signify", { icount: 3, ncount: 2 }],
    ["five_keys", "signify", { icount: 5 }],
    ["explicit_thresholds", "signify", { icount: 3, isith: "2", ncount: 3, nsith: "3" }],
    ["isith_propagates_to_nsith", "signify", { icount: 2, isith: "2" }],
    ["witnessed_with_toad", "signify", { wits: WITNESSES, toad: 2 }],
    ["witnessed_default_toad", "signify", { wits: WITNESSES }],
    ["configured_with_data", "signify", { estOnly: true, DnD: true, data: [{ i: DELEGATOR }] }],
    ["delegated", "signify", { delpre: DELEGATOR }],
    ["empty_habery_name", "", {}],
    ["another_stem", "red", {}],
  ]) {
    const hby = new Habery({ name: haberyName, salt: SALT_QB64 });
    const hab = hby.makeHab("test", args);
    cases.push({ name, habery_name: haberyName, args, event: eventRecord(hab) });
  }
  return cases;
})();

// The prefix index does not reach a named salty derivation path, so a registry started at pidx 4
// produces the same habitat as one started at zero.
const pidxDoesNotChangeANamedHabitat = (() => {
  const offset = new Habery({ name: "signify", salt: SALT_QB64, pidx: 4 });
  const hab = offset.makeHab("test", {});
  const baseline = habitatCases.find((c) => c.name === "default");
  return {
    pidx: 4,
    raw_matches_default: hab.serder.raw === baseline.event.raw,
    note: "the salty path under a non-empty stem is stem + hex(ridx) + hex(kidx); pidx is dropped",
  };
})();

// ---------------------------------------------------------------------------
// One salty registry holding both transferabilities: the only reachable way it holds two.
// ---------------------------------------------------------------------------

const mixedTransferability = (() => {
  const hby = new Habery({ name: "signify", salt: SALT_QB64 });
  const controller = hby.makeHab("controller", {});
  const witness = hby.makeHab("witness", { transferable: false });
  return {
    controller: eventRecord(controller),
    witness: eventRecord(witness),
    note: "the same raw key derives under both transferabilities; the codes differ, so the store holds them as distinct public keys",
  };
})();

// ---------------------------------------------------------------------------
// Inputs the reference refuses.
// ---------------------------------------------------------------------------

const rejections = [
  rejected("passcode_too_short", "twenty characters, one below the reference's own bound", () => {
    new Habery({ name: "signify", passcode: "0123456789abcdefghij" });
  }),
  rejected(
    "second_salty_habitat",
    "a named salty registry re-derives the same keys for a second habitat",
    () => {
      const hby = new Habery({ name: "signify", salt: SALT_QB64 });
      hby.makeHab("first", {});
      hby.makeHab("second", {});
    }
  ),
  rejected("no_current_keys", "an inception with no signing keys reads position zero of an empty list", () => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    hby.makeHab("test", { icount: 0 });
  }),
  rejected("randy_without_encryption", "no salt, no passcode, no seed: random keys with nothing to seal them", () => {
    const hby = new Habery({ name: "signify" });
    hby.makeHab("test", {});
  }),
  rejected("toad_above_witness_count", "a threshold of two over one witness", () => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    hby.makeHab("test", { wits: [WITNESSES[0]], toad: 2 });
  }),
  rejected("duplicate_witnesses", "the same witness twice", () => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    hby.makeHab("test", { wits: [WITNESSES[0], WITNESSES[0]] });
  }),
  rejected("non_transferable_with_witnesses", "a non-transferable prefix derivation over a witnessed event", () => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    hby.makeHab("test", { transferable: false, wits: [WITNESSES[0]] });
  }),
  rejected("non_transferable_delegated", "delpre forces a dip event, whose prefix must be self-addressing", () => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    hby.makeHab("test", { transferable: false, delpre: DELEGATOR });
  }),
];

// ---------------------------------------------------------------------------
// Reference behaviors recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  tier_argument_is_never_read: (() => {
    const withTier = new Habery({ name: "signify", salt: SALT_QB64, tier: Tier.high });
    const without = new Habery({ name: "signify", salt: SALT_QB64 });
    return {
      tier_with_argument: withTier.mgr.tier,
      tier_without_argument: without.mgr.tier,
      identical: withTier.mgr.tier === without.mgr.tier,
      note: "`HaberyArgs` declares `tier` and the constructor never destructures it",
      rust_decision: "no tier argument exists; a salt already knows its tier",
    };
  })(),
  passcode_is_ignored_when_a_seed_is_given: (() => {
    const seed = salter.signer(MtrDex.Ed25519_Seed, false).qb64;
    const hby = new Habery({ name: "signify", salt: SALT_QB64, seed, passcode: "x" });
    return {
      accepted_with_one_character_passcode: true,
      aeid: hby.mgr.aeid ?? null,
      note: "with a seed present the passcode branch is skipped entirely, including its length check; the aeid stays undefined because nothing derives it",
      rust_decision: "unrepresentable: a passcode and a seed are different build methods",
    };
  })(),
  duplicate_name_overwrites_the_map_entry: (() => {
    // Only an empty-name registry can reach a second habitat of the same transferability,
    // because the empty stem keeps the prefix index in the derivation path.
    const hby = new Habery({ name: "", salt: SALT_QB64 });
    const first = hby.makeHab("same", {});
    const second = hby.makeHab("same", {});
    return {
      habs_length: hby.habs.length,
      identifiers_differ: first.pre !== second.pre,
      pidx_after: hby.mgr.pidx,
      note: "the map entry is overwritten while the manager keeps both identifiers, so the first habitat's handle is lost but its keys remain",
      rust_decision: "refused with DuplicateHabitat",
    };
  })(),
  randy_habitats_are_unreachable: (() => {
    const failure = rejected(
      "randy_habitat",
      "an encrypted manager's salt getter decrypts the stored salt a randy manager never has",
      () => {
        const hby = new Habery({ name: "signify", passcode: PASSCODE });
        hby.makeHab("one", {});
      }
    );
    return {
      ...failure,
      note: "`Manager.incept` reads `this.salt` unconditionally, and with a decrypter present the getter decrypts a stored global salt; a randy manager stores none, so every passcode-only Habery throws before creating a single key. The randy creator itself never uses the salt.",
      rust_decision:
        "allowed: the Rust manager reads a salt only for the salty algorithm, so a randy registry produces valid habitats; their shape is asserted by Rust tests, since the reference cannot emit one to pin",
    };
  })(),
  zero_next_keys_get_an_unsatisfiable_threshold: (() => {
    const hby = new Habery({ name: "signify", salt: SALT_QB64 });
    const hab = hby.makeHab("test", { ncount: 0 });
    return {
      raw: hab.serder.raw,
      nt: hab.serder.sad["nt"],
      next_digests: hab.serder.sad["n"],
      note: "the default nsith formula max(1, ceil(ncount / 2)) never yields zero, so the event commits to a threshold of one over zero digests, which no rotation can ever satisfy",
      rust_decision: "refused; an explicit zero next threshold still abandons the identifier cleanly",
    };
  })(),
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-21",
  sources: ["src/keri/app/habery.ts", "test/app/habery.test.ts"],
  provenance: {
    salt_raw: SALT_RAW,
    salt_qb64: SALT_QB64,
    passcode: PASSCODE,
    delegator: DELEGATOR,
    witnesses: WITNESSES,
    note: "the salt and passcode are the pinned unit test's own public constants; makeHab hardcodes the production Argon2 profile, so every key here costs a real derivation. The witness prefixes are inputs only, derived cheaply from the same salt.",
  },
  pinned_unit_tests: pinnedUnitTests,
  habitat_cases: habitatCases,
  pidx_does_not_change_a_named_habitat: pidxDoesNotChangeANamedHabitat,
  mixed_transferability: mixedTransferability,
  rejections,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-habery/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-habery fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
