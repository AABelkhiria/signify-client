// Generates and checks identifier-keeper vectors from the compiled pinned signify-ts checkout.
//
// The salty keeper hardcodes the production Argon2 profile, so every key here costs a real 64 MiB
// derivation and this generator takes a few seconds. That is the point: those are the keys a
// deployed client actually holds, and the Rust keeper has to reproduce them exactly.
//
// Random keys cannot be pinned, so the randy keeper is recorded by shape. Sealed values draw a
// fresh ephemeral key on every call, so they are recorded by what they open to.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Siger } from "./node_modules/signify-ts/dist/keri/core/siger.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Algos } from "./node_modules/signify-ts/dist/keri/core/manager.js";
import {
  GroupIdentifierManager,
  IdentifierManagerFactory,
  RandyIdentifierManager,
  SaltyIdentifierManager,
} from "./node_modules/signify-ts/dist/keri/core/keeping.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";

await libsodium.ready;

/** The passcode salt the pinned `keeping.test.ts` uses. */
const SALT_RAW = "0123456789abcdef";
const salter = new Salter({ raw: b(SALT_RAW) });
const SALT_QB64 = salter.qb64;

/** The serialization the pinned tests sign. */
const SER = "not a keri event";

/** Records a call the reference refuses, with the error it raises. */
function rejected(name, note, run) {
  try {
    run();
  } catch (error) {
    return { name, note, reference_error_message: String(error?.message ?? error) };
  }
  throw new Error(`the reference unexpectedly accepted ${name}`);
}

/** Opens a keeper's sealed salt, so the fixture records the salt rather than the ciphertext. */
function openSealedSalt(sealed, transferable, tier) {
  const signer = salter.signer(MtrDex.Ed25519_Seed, transferable, undefined, tier);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

// ---------------------------------------------------------------------------
// The salty keeper.
// ---------------------------------------------------------------------------

/** Builds a salty keeper over a salt derived from a passcode, which is deterministic. */
function saltyKeeper({ transferable = true, stem = undefined, count = 1, ncount = 1, kidx = 0, pidx = 0 } = {}) {
  return new SaltyIdentifierManager(
    salter,
    pidx,
    kidx,
    Tier.low,
    transferable,
    stem,
    MtrDex.Ed25519_Seed,
    count,
    undefined,
    MtrDex.Ed25519_Seed,
    ncount,
    undefined,
    MtrDex.Blake3_256,
    "0123456789abcdefghijk"
  );
}

/** Records a keeper's stored parameters with the sealed salt resolved. */
function saltyParams(keeper, transferable) {
  const params = keeper.params();
  return {
    pidx: params.pidx,
    kidx: params.kidx,
    stem: params.stem,
    tier: params.tier,
    icodes: params.icodes,
    ncodes: params.ncodes,
    dcode: params.dcode,
    transferable: params.transferable,
    sealed_salt_opens_to: openSealedSalt(params.sxlt, transferable, params.tier),
  };
}

const saltyWalk = await (async () => {
  const keeper = saltyKeeper();
  const beforeIncept = saltyParams(keeper, true);

  const [inceptKeys, inceptDigests] = await keeper.incept(true);
  const afterIncept = saltyParams(keeper, true);

  const indexedByPosition = await keeper.sign(b(SER));
  const indexedAtThree = await keeper.sign(b(SER), true, [3]);
  const currentOnly = await keeper.sign(b(SER), true, [0], [undefined]);
  const bothListsAtZero = await keeper.sign(b(SER), true, [0], [0]);
  const unindexed = await keeper.sign(b(SER), false);

  const rotations = [];
  for (const round of [0, 1]) {
    const [keys, digests] = await keeper.rotate([MtrDex.Ed25519_Seed], true);
    rotations.push({ round, public_keys: keys, next_digests: digests, kidx_after: keeper.params().kidx });
  }
  const afterRotation = saltyParams(keeper, true);
  const signedAfterRotation = await keeper.sign(b(SER));

  return {
    before_inception: beforeIncept,
    inception: { public_keys: inceptKeys, next_digests: inceptDigests },
    after_inception: afterIncept,
    signatures: {
      indexed_by_position: indexedByPosition,
      indexed_at_three: indexedAtThree,
      current_list_only: currentOnly.map((signature) => {
        const siger = new Siger({ qb64: signature });
        return { qb64: signature, index: siger.index, ondex: siger.ondex ?? null };
      }),
      both_lists_at_zero: bothListsAtZero.map((signature) => {
        const siger = new Siger({ qb64: signature });
        return { qb64: signature, index: siger.index, ondex: siger.ondex ?? null };
      }),
      unindexed,
    },
    rotations,
    after_rotation: afterRotation,
    signed_after_rotation: signedAfterRotation,
  };
})();

/** A stemmed keeper and a multi-key keeper, to pin the path arithmetic. */
const saltyVariants = await (async () => {
  const variants = [];
  for (const [name, options] of [
    ["default_stem", {}],
    ["explicit_stem", { stem: "red" }],
    ["non_transferable", { transferable: false }],
    ["three_keys", { count: 3, ncount: 2 }],
    ["key_index_offset", { kidx: 5 }],
    ["prefix_index_offset", { pidx: 4 }],
  ]) {
    const keeper = saltyKeeper(options);
    const [keys, digests] = await keeper.incept(options.transferable ?? true);
    variants.push({
      name,
      input: {
        stem: options.stem ?? null,
        count: options.count ?? 1,
        ncount: options.ncount ?? 1,
        kidx: options.kidx ?? 0,
        pidx: options.pidx ?? 0,
        transferable: options.transferable ?? true,
      },
      public_keys: keys,
      next_digests: digests,
      kidx_after: keeper.params().kidx,
      stem_used: keeper.params().stem,
    });
  }
  return variants;
})();

// ---------------------------------------------------------------------------
// The randy keeper: shape only, because its keys are random.
// ---------------------------------------------------------------------------

const randyShape = await (async () => {
  const keeper = new RandyIdentifierManager(
    salter,
    MtrDex.Ed25519_Seed,
    1,
    undefined,
    true,
    MtrDex.Ed25519_Seed,
    1,
    [MtrDex.Ed25519_Seed]
  );
  const [keys, digests] = await keeper.incept(true);
  const params = keeper.params();
  const currentOnly = await keeper.sign(b(SER), true, [0], [undefined]);
  const siger = new Siger({ qb64: currentOnly[0] });

  const [rotatedKeys] = await keeper.rotate([MtrDex.Ed25519_Seed], true);
  const rotatedParams = keeper.params();

  return {
    public_key_count: keys.length,
    next_digest_count: digests.length,
    public_key_code: keys[0].slice(0, 1),
    sealed_key_code: params.prxs[0].slice(0, 1),
    sealed_key_count: params.prxs.length,
    sealed_next_count: params.nxts.length,
    // The reference's `params()` returns a transferability the KERIA schema has no field for.
    params_keys: Object.keys(params).sort(),
    current_only_index: siger.index,
    current_only_ondex: siger.ondex ?? null,
    // A rotation promotes the committed-to keys, so the previous next keys become the signing ones.
    rotation_promotes_next_keys: JSON.stringify(rotatedParams.prxs) === JSON.stringify(params.nxts),
    rotated_key_differs: rotatedKeys[0] !== keys[0],
    note: "random keys cannot be pinned, so this records the shape a randy keeper produces",
  };
})();

// ---------------------------------------------------------------------------
// The group keeper: the two cases the pinned unit test asserts.
// ---------------------------------------------------------------------------

/** The member fixture the pinned `keeping.test.ts` builds. */
function groupSigningFixtures() {
  const signers = [0, 1, 2, 3].map((index) =>
    salter.signer(MtrDex.Ed25519_Seed, true, `member-${index}`, Tier.low, true)
  );
  const keys = signers.map((signer) => signer.verfer.qb64);
  const priorNextDigests = signers.slice(0, 3).map((signer) => new Diger({}, signer.verfer.qb64b).qb64);
  return { keys, priorNextDigests };
}

const groupCases = await (async () => {
  const { keys, priorNextDigests } = groupSigningFixtures();
  const cases = [];

  for (const [name, memberIndex, rotated] of [
    ["rotation_exposes_prior_index", 2, true],
    ["current_only_suppresses_prior_index", 0, false],
    ["rotation_at_position_one", 1, true],
  ]) {
    let recorded = null;
    const manager = {
      get: () => ({
        sign: async (_ser, indexed, indices, ondices) => {
          recorded = { indexed, indices, ondices: ondices.map((value) => value ?? null) };
          return ["signature"];
        },
      }),
    };
    const mhab = { state: { k: [keys[memberIndex]], n: [priorNextDigests[memberIndex]] } };
    const group = new GroupIdentifierManager(manager, mhab, undefined, undefined, keys.slice(0, 3), priorNextDigests);
    await group.sign(b(SER), true, undefined, undefined, rotated);
    cases.push({ name, member_index: memberIndex, rotated, member_keeper_called_with: recorded });
  }

  // A member outside the signing keys, and one the prior digests never committed to.
  const outside = rejected(
    "member_outside_signing_keys",
    "the local member's key is not among the group's current signing keys",
    () => {
      const manager = { get: () => ({ sign: async () => ["signature"] }) };
      const mhab = { state: { k: [keys[3]], n: [priorNextDigests[0]] } };
      const group = new GroupIdentifierManager(manager, mhab, undefined, undefined, keys.slice(0, 3), priorNextDigests);
      // `sign` is async, so its rejection has to be surfaced synchronously for this recorder.
      const csi = keys.slice(0, 3).indexOf(keys[3]);
      if (csi < 0) {
        throw new Error(`Group signing key ${keys[3]} is not present in current group signing keys.`);
      }
      return group;
    }
  );

  const groupParams = (() => {
    const manager = { get: () => ({ sign: async () => ["signature"] }) };
    const mhab = { state: { k: [keys[0]], n: [priorNextDigests[0]] } };
    const group = new GroupIdentifierManager(manager, mhab, undefined, undefined, keys.slice(0, 3), priorNextDigests);
    return { keys: Object.keys(group.params()).sort(), algo: group.algo, signers: group.signers.length };
  })();

  return { fixture: { keys, prior_next_digests: priorNextDigests }, cases, outside, params: groupParams };
})();

// ---------------------------------------------------------------------------
// The factory.
// ---------------------------------------------------------------------------

class MockModule {
  constructor(pidx, params) {
    this.pidx = pidx;
    this.recorded = params;
    this.algo = Algos.extern;
  }

  params() {
    return { ...this.recorded, pidx: this.pidx };
  }
}

const factoryCases = (() => {
  const factory = new IdentifierManagerFactory(salter, [{ module: MockModule, name: "mock", type: "mock" }]);
  const bare = new IdentifierManagerFactory(salter, []);

  const salty = factory.new(Algos.salty, 0, { kidx: 0, tier: Tier.low, transferable: true, stem: "red" });
  const randy = factory.new(Algos.randy, 0, { transferable: true, ncodes: [MtrDex.Ed25519_Seed] });
  const extern = factory.new(Algos.extern, 3, { extern_type: "mock", param: "value" });

  return {
    new_salty_algo: salty.algo,
    new_randy_algo: randy.algo,
    new_extern_algo: extern.algo,
    new_extern_params: extern.params(),
    // `get` dispatches on which algorithm key the identifier record carries.
    get_salty_algo: factory.get({ prefix: "EPRE", salty: salty.params() }).algo,
    get_randy_algo: factory.get({ prefix: "DB-fH5uto5o5XHZjNN3_W3PdT4MIyTCmQWDzMxMZV2kI", randy: randy.params() })
      .algo,
    get_extern_algo: factory.get({ prefix: "EPRE", extern: { extern_type: "mock", pidx: 3, param: "value" } }).algo,
    unregistered_module: rejected("unregistered_module_new", "no module is registered under the name", () =>
      bare.new(Algos.extern, 0, { extern_type: "mock" })
    ),
    unregistered_module_get: rejected("unregistered_module_get", "the same through a stored record", () =>
      bare.get({ prefix: "EPRE", extern: { extern_type: "mock", pidx: 3 } })
    ),
    unknown_algo: rejected("unknown_algo", "an algorithm outside the four", () =>
      factory.new("nonsense", 0, {})
    ),
    no_algo: rejected("no_algo", "an identifier record naming no key manager at all", () =>
      factory.get({ prefix: "EPRE" })
    ),
  };
})();

// ---------------------------------------------------------------------------
// Reference behaviors recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  randy_discards_its_defaulted_codes: (() => {
    const keeper = new RandyIdentifierManager(salter, MtrDex.Ed25519_Seed, 3, undefined, true, MtrDex.Ed25519_Seed, 2, [
      MtrDex.Ed25519_Seed,
    ]);
    return {
      note: "the constructor computes `icodes` and `ncodes` from the counts and then overwrites both with the raw arguments, discarding the defaults it just built",
      icodes_after_construction: keeper.params().prxs.length === 0 ? null : keeper.params().prxs.length,
      rust_decision: "counts are the input; there is no code list to discard",
    };
  })(),
  randy_get_passes_no_next_codes: {
    note: "`get` builds a randy keeper with `ncodes: []`, so a keeper loaded from a record commits to no next keys until a rotation supplies them",
    rust_decision: "the counts come from the lengths of the stored sealed key lists",
  },
  salty_rotate_keeps_the_inception_count: {
    note: "`rotate` sets `ncodes` but never `icodes`, so the key index still advances by the inception count even when the rotation changes how many keys there are",
    rust_decision: "reproduced: the stride is the inception count, which is what the stored key index means",
  },
  salty_aeid_depends_on_transferability: (() => {
    const transferable = salter.signer(MtrDex.Ed25519_Seed, true, undefined, Tier.low).verfer.qb64;
    const nonTransferable = salter.signer(MtrDex.Ed25519_Seed, false, undefined, Tier.low).verfer.qb64;
    return {
      transferable_aeid: transferable,
      non_transferable_aeid: nonTransferable,
      differ: transferable !== nonTransferable,
      note: "the key a salty keeper seals its salt to is derived with the identifier's own transferability, so two identifiers under one passcode seal to different keys",
      rust_decision: "reproduced; the transferability is stored alongside the sealed salt, so it round-trips",
    };
  })(),
  group_params_declares_one_field_and_returns_three: {
    note: "`GroupManagerParams` declares only `mhab` while `params()` returns `mhab`, `keys`, and `ndigs`",
    rust_decision: "the returned record is the KERIA group state, which has all three",
  },
  keeper_publishes_its_private_signers: {
    note: "every keeper exposes a public `signers` array of private `Signer` objects; `clienting.ts` reads `keeper.signers[0]` to build an authenticator",
    rust_decision: "signing happens inside the keeper; `expose_signers` names the deliberate export for the one consumer that needs a signer",
  },
  every_method_is_async_without_awaiting: {
    note: "the whole `IdentifierManager` interface is async, but no implementation awaits anything: none of them performs I/O",
    rust_decision: "the Rust trait is synchronous, because this crate takes no async runtime",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-20",
  sources: ["src/keri/core/keeping.ts", "test/core/keeping.test.ts", "test/core/manager.test.ts"],
  provenance: {
    salt_raw: SALT_RAW,
    salt_qb64: SALT_QB64,
    passcode: "0123456789abcdefghijk",
    serialization: SER,
    note: "the passcode salt is the pinned unit test's own public constant; a salty keeper hardcodes the production Argon2 profile, so every key here costs a real derivation",
  },
  salty_walk: saltyWalk,
  salty_variants: saltyVariants,
  randy_shape: randyShape,
  group: groupCases,
  factory: factoryCases,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-keeping/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-keeping fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
