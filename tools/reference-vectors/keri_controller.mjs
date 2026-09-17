// Generates and checks Controller/Agent vectors from the compiled pinned signify-ts checkout.
//
// A Controller hardcodes the production Argon2 profile, so every derived key here costs a real
// 64 MiB derivation and this generator takes several seconds. That is the point: these are the
// keys, events, and signatures a deployed client actually produces.
//
// Sealed boxes draw a fresh ephemeral key per call, so every ciphertext is recorded by what it
// opens to through the reference's own decrypter.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { SaltyCreator } from "../../reference/signify-ts/dist/keri/core/manager.js";
import { Encrypter } from "../../reference/signify-ts/dist/keri/core/encrypter.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Agent, Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

/** The passcode the pinned `controller.test.ts` uses, and a second for rotation. */
const PASSCODE = "0123456789abcdefghijk";
const SECOND_PASSCODE = "abcdefghijk0123456789";

/** The agent seed the pinned unit test uses. */
const AGENT_SEED = new Uint8Array([
  187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160,
  152, 2, 72, 122, 87, 143, 109, 39, 98, 153, 192, 148,
]);

/** The prior passcode's encryption key pair, used to seal and open rotation material. */
function priorEncryption(passcode) {
  const bran = MtrDex.Salt_128 + "A" + passcode.substring(0, 21);
  const signer = new Salter({ qb64: bran }).signer(MtrDex.Ed25519_Seed, false);
  return {
    signer,
    encrypter: new Encrypter({}, b(signer.verfer.qb64)),
    decrypter: new Decrypter({}, signer.qb64b),
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

/** Records one controller's observable state. */
function controllerRecord(controller) {
  return {
    raw: controller.serder.raw,
    pre: controller.pre,
    said: controller.serder.sad["d"],
    sequence: controller.serder.sad["s"],
    keys: controller.serder.sad["k"] ?? null,
    next_digests: controller.ndigs,
    signer_verfer: controller.signer.verfer.qb64,
  };
}

// ---------------------------------------------------------------------------
// The pinned unit-test values and deterministic controller cases.
// ---------------------------------------------------------------------------

const agentSigner = new Signer({ raw: AGENT_SEED, code: MtrDex.Ed25519_Seed, transferable: false });

const controllers = (() => {
  const first = new Controller(PASSCODE, Tier.low);
  const second = new Controller(SECOND_PASSCODE, Tier.low);
  const advanced = new Controller(PASSCODE, Tier.low, 1);
  return {
    agent_signer_verfer: agentSigner.verfer.qb64,
    first: controllerRecord(first),
    second: controllerRecord(second),
    ridx_one: controllerRecord(advanced),
    // The `event` getter signs the current event at position zero.
    first_event_signature: first.signer.sign(b(first.serder.raw), 0).qb64,
  };
})();

// ---------------------------------------------------------------------------
// Restore: the constructor's state branch.
// ---------------------------------------------------------------------------

const restoreCases = (() => {
  const fresh = new Controller(PASSCODE, Tier.low);

  // A state whose establishment event is at sequence zero is not adopted: the constructor
  // rebuilds its own inception. Both the string and number spellings take that branch, because
  // the comparison is loose equality.
  const zero = new Controller(PASSCODE, Tier.low, 0, { ee: { s: "0" } });
  const zeroNumber = new Controller(PASSCODE, Tier.low, 0, { ee: { s: 0 } });

  // A later event is adopted as found, without any ownership check: here another controller's
  // sequence-one interaction is handed to the first passcode's controller. (A foreign event at
  // sequence zero would be rebuilt, not adopted, by the rule above.)
  const foreign = new Controller(SECOND_PASSCODE, Tier.low);
  foreign.approveDelegation(new Agent(agentState(foreign.pre)));
  const adopted = new Controller(PASSCODE, Tier.low, 0, { ee: foreign.serder.sad });

  return {
    zero_rebuilds_inception: zero.serder.raw === fresh.serder.raw,
    zero_number_rebuilds_inception: zeroNumber.serder.raw === fresh.serder.raw,
    adopted: {
      raw: adopted.serder.raw,
      pre: adopted.pre,
      matches_foreign: adopted.serder.raw === foreign.serder.raw,
      signer_still_own: adopted.signer.verfer.qb64 === fresh.signer.verfer.qb64,
    },
  };
})();

// ---------------------------------------------------------------------------
// The agent: one accepted state and the reference's rejections.
// ---------------------------------------------------------------------------

/** A well-formed delegated agent state anchored to the first controller.
 *
 * The reference reads only `i`, `s`, `d`, `et`, `kt`, `k`, `nt`, `n`, and `di`; the remaining
 * fields complete the KERIA key-state shape so a typed decoder accepts the same document.
 */
function agentState(controllerPre) {
  const nextDigest = new Diger({}, b(agentSigner.verfer.qb64)).qb64;
  return {
    i: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
    s: "a",
    p: "",
    d: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
    f: "0",
    dt: "2023-12-01T10:05:25.062609+00:00",
    et: "dip",
    kt: "1",
    k: [agentSigner.verfer.qb64],
    nt: "1",
    n: [nextDigest],
    bt: "0",
    b: [],
    c: [],
    ee: { s: "0", d: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", br: [], ba: [] },
    di: controllerPre,
  };
}

const agentCases = (() => {
  const controllerPre = controllers.first.pre;
  const accepted = new Agent(agentState(controllerPre));
  const acceptedRecord = {
    input: agentState(controllerPre),
    pre: accepted.pre,
    anchor: accepted.anchor,
    sn: accepted.sn,
    said: accepted.said,
    verfer: accepted.verfer.qb64,
  };

  const reject = (name, note, mutate) =>
    rejected(name, note, () => {
      const state = agentState(controllerPre);
      mutate(state);
      new Agent(state);
    });

  const rejections = [
    reject("two_keys", "an agent inception event can only have one key", (state) => {
      state.k = [agentSigner.verfer.qb64, agentSigner.verfer.qb64];
    }),
    reject("no_next_digests", "an agent inception event can only have one next key", (state) => {
      state.n = [];
    }),
    reject("signing_threshold_two", "the signing threshold must be one", (state) => {
      state.kt = "2";
    }),
    reject("weighted_signing_threshold", "a weighted threshold has no numeric value", (state) => {
      state.kt = ["1/2", "1/2"];
    }),
    reject("not_delegated", "the establishment event must be a dip", (state) => {
      state.et = "icp";
    }),
    reject("missing_delegator", "no anchor to the controller AID", (state) => {
      state.di = "";
    }),
  ];

  return { accepted: acceptedRecord, rejections };
})();

// ---------------------------------------------------------------------------
// Delegation approval: the anchored interaction and its signature.
// ---------------------------------------------------------------------------

const approval = (() => {
  const controller = new Controller(PASSCODE, Tier.low);
  const agent = new Agent(agentState(controller.pre));
  const sigs = controller.approveDelegation(agent);
  const first = {
    raw: controller.serder.raw,
    said: controller.serder.sad["d"],
    sequence: controller.serder.sad["s"],
    anchor: controller.serder.sad["a"],
    signatures: sigs,
  };
  // A second approval chains a further interaction on the first.
  const sigs2 = controller.approveDelegation(agent);
  const second = {
    raw: controller.serder.raw,
    sequence: controller.serder.sad["s"],
    prior: controller.serder.sad["p"],
    signatures: sigs2,
  };
  return { first, second };
})();

// ---------------------------------------------------------------------------
// Passcode rotation: the complete payload, with every ciphertext recorded by what it opens to.
// ---------------------------------------------------------------------------

/** Builds a deterministic salty identifier record sealed to the prior passcode's key. */
function saltyAid(encrypter) {
  const aidSalter = new Salter({ raw: b("fedcba9876543210") });
  const creator = new SaltyCreator(aidSalter.qb64, Tier.low, "signify:aid");
  const keys = creator
    .create(["A"], undefined, MtrDex.Ed25519_Seed, true, 0, 0, 0, false)
    .signers.map((signer) => signer.verfer.qb64);
  return {
    aid_salt_qb64: aidSalter.qb64,
    record: {
      prefix: keys[0],
      salty: {
        sxlt: encrypter.encrypt(b(aidSalter.qb64)).qb64,
        pidx: 0,
        kidx: 0,
        stem: "signify:aid",
        tier: Tier.low,
        icodes: ["A"],
        ncodes: ["A"],
        transferable: true,
        dcode: MtrDex.Blake3_256,
      },
      state: { k: keys },
    },
  };
}

/** Builds a deterministic randy identifier record sealed to the prior passcode's key. */
function randyAid(encrypter) {
  const seeds = [new Uint8Array(32).fill(7), new Uint8Array(32).fill(11)];
  const signers = seeds.map((raw) => new Signer({ raw, code: MtrDex.Ed25519_Seed, transferable: true }));
  const nextSigner = new Signer({ raw: new Uint8Array(32).fill(13), code: MtrDex.Ed25519_Seed, transferable: true });
  return {
    seed_qb64s: signers.map((signer) => signer.qb64),
    next_seed_qb64: nextSigner.qb64,
    record: {
      prefix: signers[0].verfer.qb64,
      randy: {
        prxs: signers.map((signer) => encrypter.encrypt(b(signer.qb64)).qb64),
        nxts: [encrypter.encrypt(b(nextSigner.qb64)).qb64],
      },
      state: { k: signers.map((signer) => signer.verfer.qb64) },
    },
  };
}

const rotation = (() => {
  const prior = priorEncryption(PASSCODE);
  const salty = saltyAid(prior.encrypter);
  const randy = randyAid(prior.encrypter);

  const controller = new Controller(PASSCODE, Tier.low);
  const before = controllerRecord(controller);
  const data = controller.rotate(SECOND_PASSCODE, [salty.record, randy.record]);
  const after = controllerRecord(controller);

  // Sealed boxes draw a fresh ephemeral key per call, so the input ciphertexts cannot be
  // recorded byte-for-byte; the fixture records the plaintexts they sealed, and the Rust test
  // seals its own inputs to the same prior key.
  const saltyView = {
    aid_salt_qb64: salty.aid_salt_qb64,
    prefix: salty.record.prefix,
    salty: { ...salty.record.salty, sxlt: "(sealed; opens to aid_salt_qb64)" },
    state_keys: salty.record.state.k,
  };
  const randyView = {
    seed_qb64s: randy.seed_qb64s,
    next_seed_qb64: randy.next_seed_qb64,
    prefix: randy.record.prefix,
    state_keys: randy.record.state.k,
  };

  const openSalt = (qb64) => prior.decrypter.decrypt(null, new Cipher({ qb64 })).qb64;
  const openSeed = (qb64) => prior.decrypter.decrypt(null, new Cipher({ qb64 }), true).qb64;

  // The new passcode's encryption key cannot open what the payload sealed: the rotation seals to
  // the prior key, which is the arrangement Rust reproduces loudly.
  const newDecrypter = priorEncryption(SECOND_PASSCODE).decrypter;
  const newKeyOpensSxlt = (() => {
    try {
      newDecrypter.decrypt(null, new Cipher({ qb64: data.sxlt }));
      return true;
    } catch {
      return false;
    }
  })();

  return {
    salty_aid: saltyView,
    randy_aid: randyView,
    controller_before: before,
    controller_after: after,
    rotation_raw: JSON.stringify(data.rot),
    signatures: data.sigs,
    sxlt_opens_to: openSalt(data.sxlt),
    sxlt_opens_under_new_passcode: newKeyOpensSxlt,
    resealed_salty_opens_to: openSalt(data.keys[salty.record.prefix].sxlt),
    resealed_randy_prxs_open_to: data.keys[randy.record.prefix].prxs.map(openSeed),
    resealed_randy_nxts_open_to: data.keys[randy.record.prefix].nxts.map((qb64) =>
      prior.decrypter.decrypt(null, new Cipher({ qb64 })).qb64
    ),
    rejections: [
      rejected("mismatched_salty", "the re-derived keys must match the recorded key state", () => {
        const wrong = saltyAid(prior.encrypter);
        wrong.record.state.k = ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"];
        new Controller(PASSCODE, Tier.low).rotate(SECOND_PASSCODE, [wrong.record]);
      }),
      rejected("mismatched_randy", "the decrypted keys must match the recorded key state", () => {
        const wrong = randyAid(prior.encrypter);
        wrong.record.state.k = ["DAQVURvW74OJH1Q0C6YLim_tdBYoXABwg6GsAlPaUJXE"];
        new Controller(PASSCODE, Tier.low).rotate(SECOND_PASSCODE, [wrong.record]);
      }),
      rejected("group_aid", "neither salty nor randy", () => {
        new Controller(PASSCODE, Tier.low).rotate(SECOND_PASSCODE, [
          { prefix: "EPRE", group: {}, state: { k: [] } },
        ]);
      }),
    ],
  };
})();

// ---------------------------------------------------------------------------
// Reference behaviors recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  verfers_getter_always_throws: rejected(
    "verfers_getter",
    "`get verfers` calls `this.signer.verfer()`, but `verfer` is a property, not a function",
    () => new Controller(PASSCODE, Tier.low).verfers
  ),
  derive_throws_on_undefined: rejected(
    "derive_undefined",
    "`derive(undefined)` reads `state.controller` on its else branch",
    () => new Controller(PASSCODE, Tier.low).derive(undefined)
  ),
  derive_reads_a_different_shape: rejected(
    "derive_other_shape",
    "`derive` reads `state.controller['ee']` where the constructor reads `state['ee']`",
    () => new Controller(PASSCODE, Tier.low).derive({ ee: { s: "1" } })
  ),
  ridx_mutation_does_not_rederive: (() => {
    const controller = new Controller(PASSCODE, Tier.low);
    const before = controller.signer.verfer.qb64;
    controller.ridx = 5;
    return {
      signer_unchanged: controller.signer.verfer.qb64 === before,
      ridx_after: controller.ridx,
      note: "the client assigns `ridx` after construction, but no key is re-derived, so the field and the keys silently disagree",
      rust_decision: "the rotation index is fixed at construction; the inconsistent state is unrepresentable",
    };
  })(),
  rotation_always_claims_sequence_one: (() => {
    const controller = new Controller(PASSCODE, Tier.low);
    const agent = new Agent(agentState(controller.pre));
    controller.approveDelegation(agent);
    const data = controller.rotate(SECOND_PASSCODE, []);
    return {
      controller_sequence_before: controller.serder.sad["s"],
      rotation_sequence: data.rot.s,
      rotation_prior: data.rot.p,
      prior_is_interaction_said: data.rot.p === controller.serder.sad["d"],
      note: "`rotate` never passes a sequence number, so the event claims s=1 whatever the log's actual position, while its prior digest points at the current event",
      rust_decision: "not reproduced: built at the current sequence number plus one over the current event, which keripy accepts where it refuses this, and the applied rotation becomes the controller's current event (Roadmap 8.9, ADR 0034; fixtures/client-passcode-rotation-keripy)",
    };
  })(),
  second_rotation_derives_from_the_original_salt: (() => {
    const first = new Controller(PASSCODE, Tier.low);
    const one = first.rotate(SECOND_PASSCODE, []);
    const two = first.rotate("zyxwvutsrq9876543210k", []);
    return {
      old_key_identical: one.rot.k[1] === two.rot.k[1],
      note: "`rotate` never updates `this.salter` or `this.bran`, so every rotation derives its committed-to key and seals its salt from the original passcode",
      rust_decision: "reproduced; the stored salt deliberately does not move",
    };
  })(),
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-22",
  sources: ["src/keri/app/controller.ts", "test/app/controller.test.ts"],
  provenance: {
    passcode: PASSCODE,
    second_passcode: SECOND_PASSCODE,
    agent_seed: Array.from(AGENT_SEED),
    note: "the passcodes and agent seed are the pinned unit test's own public constants; a Controller hardcodes the production Argon2 profile, so every key here costs a real derivation. Sealed values are recorded by what they open to through the reference's own decrypter.",
  },
  controllers,
  restore_cases: restoreCases,
  agent: agentCases,
  approval,
  rotation,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-controller/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-controller fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
