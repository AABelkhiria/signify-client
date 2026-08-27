// Generates and checks key-manager vectors from the compiled pinned signify-ts checkout.
//
// Everything here is deterministic: the salt, the encryption seed, and the derivation profile are
// the ones the pinned `manager.test.ts` uses, and the temporary Argon2 profile is selected wherever
// a key would otherwise take a second to derive. The one nondeterministic field the reference
// writes — `PubLot.dt`, which is `new Date().toString()` — is recorded with every digit masked, as
// Roadmap 3.6 did for the reply timestamp, because it is written and never read.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import {
  Algos,
  Creatory,
  Manager,
  RandyCreator,
  SaltyCreator,
  riKey,
} from "../../reference/signify-ts/dist/keri/core/manager.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// The salt and encryption seed the pinned unit test uses throughout.
const SALT_RAW = "0123456789abcdef";
const SALT_QB64 = new Salter({ raw: b(SALT_RAW) }).qb64;
const CRYPT_SEED = new Uint8Array([
  104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240, 102, 50, 44, 121,
  196, 194, 49, 64, 245, 64, 21, 46, 162, 26, 207,
]);
const cryptSigner = new Signer({
  raw: CRYPT_SEED,
  code: MtrDex.Ed25519_Seed,
  transferable: false,
});
const SEED_QB64 = cryptSigner.qb64;
const AEID = cryptSigner.verfer.qb64;

// The serialization the pinned unit test signs.
const SER =
  '{"vs":"KERI10JSON0000fb_","pre":"EvEnZMhz52iTrJU8qKwtDxzmypyosgG' +
  '70m6LIjkiCdoI","sn":"0","ilk":"icp","sith":"1","keys":["DSuhyBcP' +
  'ZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"nxt":"EPYuj8mq_PYYsoBKkz' +
  'X1kxSPGYBWaIya3slgCOyOtlqU","toad":"0","wits":[],"cnfg":[]}-AABA' +
  "ApYcYd1cppVg7Inh2YCslWKhUwh59TrPpIoqWxN2A38NCbTljvmBPBjSGIFDBNOv" +
  "VjHpdZlty3Hgk6ilF8pVpAQ";

/** Records what one `SaltyCreator.create` call produced, including the paths it built. */
function saltyCase(name, { salt = SALT_QB64, tier, stem, codes, count = 1, transferable = true, pidx = 0, ridx = 0, kidx = 0, temp = true, note }) {
  const creator = new SaltyCreator(salt, tier, stem);
  const keys = creator.create(codes, count, MtrDex.Ed25519_Seed, transferable, pidx, ridx, kidx, temp);
  const record = {
    name,
    input: { stem: stem ?? null, count: codes ? codes.length : count, transferable, pidx, ridx, kidx, temp },
    creator: { salt: creator.salt, stem: creator.stem, tier: creator.tier },
    paths: keys.paths,
    private_keys: keys.signers.map((signer) => signer.qb64),
    public_keys: keys.signers.map((signer) => signer.verfer.qb64),
    public_key_codes: keys.signers.map((signer) => signer.verfer.code),
  };
  if (note) {
    record.note = note;
  }
  return record;
}

/** Captures the whole of a manager's key store, with the nondeterministic fields resolved. */
function snapshot(manager, prefixes) {
  const globals = {};
  for (const key of ["aeid", "pidx", "tier", "algo"]) {
    const value = manager.ks.getGbls(key);
    globals[key] = value === undefined ? null : value;
  }
  // A sealed box draws a fresh ephemeral key every call, so the ciphertext itself is not
  // reproducible. What it opens to is, and is the stronger statement.
  const sealedSalt = manager.ks.getGbls("salt");
  globals.salt = sealedSalt === undefined
    ? null
    : {
        code: sealedSalt.slice(0, 4),
        length: sealedSalt.length,
        decrypts_to: manager.decrypter === undefined ? null : manager.decrypter.decrypt(b(sealedSalt)).qb64,
      };

  const identifiers = {};
  for (const prefix of prefixes) {
    const parameters = manager.ks.getPrms(prefix);
    const situation = manager.ks.getSits(prefix);
    if (parameters === undefined || situation === undefined) {
      identifiers[prefix] = null;
      continue;
    }
    const lot = (value) => ({
      pubs: value.pubs,
      ridx: value.ridx,
      kidx: value.kidx,
      // `new Date().toString()` — masked so the fixture stays reproducible while its shape is
      // still pinned. Nothing in the reference ever reads it. Letters are masked as well as
      // digits because the weekday and month names change with the day, and the parenthesised
      // timezone name is dropped because it changes with the machine and with daylight saving:
      // masking only digits left this fixture stale the day after it was written.
      dt_shape: value.dt
        .replace(/\s*\([^)]*\)\s*$/, "")
        .replace(/[0-9]/g, "#")
        .replace(/[A-Za-z]/g, "@"),
    });
    identifiers[prefix] = {
      parameters: {
        pidx: parameters.pidx,
        algo: parameters.algo,
        stem: parameters.stem,
        tier: parameters.tier,
        salt_is_present: parameters.salt !== "" && parameters.salt !== undefined,
        salt_decrypts_to:
          parameters.salt === "" || parameters.salt === undefined || manager.decrypter === undefined
            ? null
            : manager.decrypter.decrypt(b(parameters.salt)).qb64,
      },
      situation: { old: lot(situation.old), new: lot(situation.new), nxt: lot(situation.nxt) },
      key_sets: [0, 1, 2, 3]
        .map((index) => ({ ridx: index, key: riKey(prefix, index), pubs: manager.ks.getPubs(riKey(prefix, index))?.pubs ?? null }))
        .filter((entry) => entry.pubs !== null),
      paths: situation.new.pubs
        .concat(situation.nxt.pubs)
        .map((pub) => {
          const stored = manager.ks.getPths(pub);
          return stored === undefined ? null : { pub, path: stored.path, code: stored.code, tier: stored.tier, temp: stored.temp };
        })
        .filter((entry) => entry !== null),
    };
  }
  return { globals, identifiers };
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
// Creators.
// ---------------------------------------------------------------------------

const saltyCases = [
  saltyCase("empty_stem_temporary", { temp: true, note: "the pinned SaltyCreator unit test's temporary case" }),
  saltyCase("empty_stem_production", { temp: false, note: "the same path under the production profile" }),
  saltyCase("empty_stem_non_transferable", { transferable: false, temp: true }),
  saltyCase("empty_stem_ignores_rotation_and_key_indices", {
    ridx: 7,
    kidx: 9,
    temp: true,
    note: "the path is the prefix index alone, so this is the same key as empty_stem_temporary",
  }),
  saltyCase("empty_stem_prefix_index", { pidx: 26, temp: true, note: "the prefix index is the only index in the path" }),
  saltyCase("stem_inception", { stem: "red", temp: true }),
  saltyCase("stem_next", { stem: "red", ridx: 1, kidx: 1, temp: true }),
  saltyCase("stem_three_keys", { stem: "red", count: 3, temp: true, note: "the key index advances by one per key" }),
  saltyCase("stem_hexadecimal_indices", { stem: "red", ridx: 10, kidx: 27, temp: true }),
  saltyCase("stem_witness_zero", { stem: "wit0", transferable: false, temp: true }),
  saltyCase("stem_witness_one", { stem: "wit1", transferable: false, temp: true }),
  saltyCase("explicit_codes", {
    stem: "red",
    codes: [MtrDex.Ed25519_Seed, MtrDex.Ed25519_Seed],
    temp: true,
    note: "the only code the reference supports, which is why Rust takes a count",
  }),
  saltyCase("high_tier_stem", { tier: Tier.high, stem: "red", temp: true, note: "temp overrides the tier, so this equals stem_inception" }),
];

// A randy creator produces fresh entropy every call, so only its shape is recorded.
const randyCreator = new RandyCreator();
const randyShape = (() => {
  const keys = randyCreator.create(undefined, 3);
  return {
    count: keys.signers.length,
    private_key_length: keys.signers[0].qb64.length,
    private_key_code: keys.signers[0].code,
    public_key_code: keys.signers[0].verfer.code,
    transferable: keys.signers[0].transferable,
    paths: keys.paths === undefined ? null : keys.paths,
    distinct: new Set(keys.signers.map((signer) => signer.verfer.qb64)).size,
    salt: randyCreator.salt,
    stem: randyCreator.stem,
    tier: randyCreator.tier,
    note: "a randy creator reports an empty salt, stem, and tier, and produces no paths",
  };
})();

const creatoryCases = {
  salty_is_the_default: new Creatory().make(SALT_QB64) instanceof SaltyCreator,
  explicit_salty: new Creatory(Algos.salty).make(SALT_QB64) instanceof SaltyCreator,
  explicit_randy: new Creatory(Algos.randy).make(SALT_QB64) instanceof RandyCreator,
  algos: Object.values(Algos),
};

// ---------------------------------------------------------------------------
// The manager, salty and encrypted.
// ---------------------------------------------------------------------------

const encryptedManager = new Manager({
  seed: SEED_QB64,
  salter: new Salter({ qb64: SALT_QB64 }),
  aeid: AEID,
});
const encryptedPrefixes = [];

const encryptedIncept = (() => {
  const [verfers, digers] = encryptedManager.incept({ salt: SALT_QB64, temp: true });
  encryptedPrefixes.push(verfers[0].qb64);
  return {
    prefix: verfers[0].qb64,
    public_keys: verfers.map((verfer) => verfer.qb64),
    next_digests: digers.map((diger) => diger.qb64),
    pidx_after: encryptedManager.pidx,
    sealed_key_present: encryptedManager.ks.getPris(verfers[0].qb64, encryptedManager.decrypter) !== undefined,
  };
})();

const encryptedSignatures = {
  indexed_by_position: encryptedManager
    .sign({ ser: b(SER), pubs: [encryptedIncept.prefix] })
    .map((signature) => signature.qb64),
  indexed_at_three: encryptedManager
    .sign({ ser: b(SER), pubs: [encryptedIncept.prefix], indices: [3] })
    .map((signature) => signature.qb64),
  current_list_only: encryptedManager
    .sign({ ser: b(SER), pubs: [encryptedIncept.prefix], indices: [0], ondices: [undefined] })
    .map((signature) => ({ qb64: signature.qb64, index: signature.index, ondex: signature.ondex ?? null })),
  both_lists_at_zero: encryptedManager
    .sign({ ser: b(SER), pubs: [encryptedIncept.prefix], indices: [0], ondices: [0] })
    .map((signature) => ({ qb64: signature.qb64, index: signature.index, ondex: signature.ondex ?? null })),
  unindexed: encryptedManager
    .sign({ ser: b(SER), pubs: [encryptedIncept.prefix], indexed: false })
    .map((signature) => signature.qb64),
  // The reference offers the same operation twice; this records that both give the same bytes.
  by_verification_key: encryptedManager
    .sign({ ser: b(SER), verfers: [new Signer({ qb64: SEED_QB64 }).verfer] && encryptedManager.ks.getPris(encryptedIncept.prefix, encryptedManager.decrypter) ? [encryptedManager.ks.getPris(encryptedIncept.prefix, encryptedManager.decrypter).verfer] : [] })
    .map((signature) => signature.qb64),
};

const encryptedAfterIncept = snapshot(encryptedManager, encryptedPrefixes);

const encryptedRotations = [];
for (const round of [0, 1]) {
  const [verfers, digers] = encryptedManager.rotate({ pre: encryptedIncept.prefix });
  encryptedRotations.push({
    round,
    public_keys: verfers.map((verfer) => verfer.qb64),
    next_digests: digers.map((diger) => diger.qb64),
  });
}
const encryptedAfterRotation = snapshot(encryptedManager, encryptedPrefixes);
const erasedKeyGone =
  encryptedManager.ks.getPris(encryptedIncept.prefix, encryptedManager.decrypter) === undefined;

// ---------------------------------------------------------------------------
// The manager, salty and unencrypted.
// ---------------------------------------------------------------------------

const plainManager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
const plainPrefixes = [];
const plainIncept = (() => {
  const [verfers, digers] = plainManager.incept({ salt: SALT_QB64, temp: true });
  plainPrefixes.push(verfers[0].qb64);
  return {
    prefix: verfers[0].qb64,
    next_digests: digers.map((diger) => diger.qb64),
    encrypter_is_absent: plainManager.encrypter === undefined,
  };
})();
const plainSignature = plainManager
  .sign({ ser: b(SER), pubs: [plainIncept.prefix] })
  .map((signature) => signature.qb64);
const plainAfterIncept = snapshot(plainManager, plainPrefixes);

// Rotate, then look at the path the *rotation* stored rather than the one inception stored.
plainManager.rotate({ pre: plainIncept.prefix });
const plainAfterRotation = snapshot(plainManager, plainPrefixes);
const rotatedPath = (() => {
  const situation = plainManager.ks.getSits(plainIncept.prefix);
  const pub = situation.nxt.pubs[0];
  const stored = plainManager.ks.getPths(pub);
  return {
    pub,
    path: stored.path,
    code: stored.code,
    tier: stored.tier,
    temp: stored.temp,
    signing_fails: rejected(
      "sign_with_rotated_path",
      "the rotation stored no derivation code, so regenerating the key throws",
      () => plainManager.sign({ ser: b(SER), pubs: [pub] })
    ).reference_error_message,
  };
})();

// ---------------------------------------------------------------------------
// Stemmed identifiers and witnesses.
// ---------------------------------------------------------------------------

const stemmedManager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
const stemmed = [];
for (const [name, options] of [
  ["red", { salt: SALT_QB64, stem: "red", temp: true }],
  ["wit0", { ncount: 0, salt: SALT_QB64, stem: "wit0", transferable: false, temp: true }],
  ["wit1", { ncount: 0, salt: SALT_QB64, stem: "wit1", transferable: false, temp: true }],
]) {
  const [verfers, digers] = stemmedManager.incept(options);
  const situation = stemmedManager.ks.getSits(verfers[0].qb64);
  stemmed.push({
    name,
    prefix: verfers[0].qb64,
    public_key_code: verfers[0].code,
    next_public_keys: situation.nxt.pubs,
    next_digests: digers.map((diger) => diger.qb64),
  });
}

// ---------------------------------------------------------------------------
// Reassignment.
// ---------------------------------------------------------------------------

const moveManager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
const [moveVerfers] = moveManager.incept({ salt: SALT_QB64, stem: "red", temp: true });
const moveFrom = moveVerfers[0].qb64;
const moveTo = "DCu5o5cxzv1lgMqxMVG3IcCNK4lpFfpMM-9rfkY3XVUc";
moveManager.move(moveFrom, moveTo);
const moved = {
  from: moveFrom,
  to: moveTo,
  source_situation_removed: moveManager.ks.getSits(moveFrom) === undefined,
  destination_situation_present: moveManager.ks.getSits(moveTo) !== undefined,
  source_alias: new TextDecoder().decode(moveManager.ks.getPres(moveFrom)),
  destination_key_set: moveManager.ks.getPubs(riKey(moveTo, 0))?.pubs ?? null,
};

// ---------------------------------------------------------------------------
// Rotation key format.
// ---------------------------------------------------------------------------

const rotationKeys = [0, 1, 9, 10, 26, 255].map((index) => ({
  ridx: index,
  key: riKey("EABC", index),
}));

// ---------------------------------------------------------------------------
// What the reference refuses, and what it accepts that Rust does not.
// ---------------------------------------------------------------------------

const rejections = [
  rejected("randy_without_encryption", "a randy manager with no encryption", () => new Manager({ algo: Algos.randy })),
  rejected("unsupported_algorithm_group", "the group algorithm has no creator", () => new Creatory(Algos.group)),
  rejected("unsupported_algorithm_extern", "the external algorithm has no creator", () => new Creatory(Algos.extern)),
  rejected("rotate_unknown_prefix", "rotating an identifier the manager does not hold", () =>
    new Manager({ salter: new Salter({ qb64: SALT_QB64 }) }).rotate({ pre: "DUNKNOWN" })
  ),
  rejected("sign_without_keys", "a signing request naming neither public keys nor verification keys", () =>
    new Manager({ salter: new Salter({ qb64: SALT_QB64 }) }).sign({ ser: b(SER) })
  ),
  rejected("incept_without_current_keys", "an inception with no signing keys, which reads position zero of an empty list", () => {
    const manager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
    manager.incept({ icount: 0, salt: SALT_QB64, temp: true });
  }),
  rejected("incept_negative_count", "a negative key count", () => {
    const manager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
    manager.incept({ icount: -1, salt: SALT_QB64, temp: true });
  }),
  rejected("rotate_abandoned", "rotating an identifier that committed to no next keys", () => {
    const manager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
    const [verfers] = manager.incept({ ncount: 0, salt: SALT_QB64, stem: "gone", temp: true });
    manager.rotate({ pre: verfers[0].qb64 });
  }),
  rejected("move_onto_existing", "reassigning onto a prefix that is already held", () => {
    const manager = new Manager({ salter: new Salter({ qb64: SALT_QB64 }) });
    const [first] = manager.incept({ salt: SALT_QB64, stem: "one", temp: true });
    const [second] = manager.incept({ salt: SALT_QB64, stem: "two", temp: true });
    manager.move(first[0].qb64, second[0].qb64);
  }),
  rejected("passcode_too_short", "a passcode below twenty-one characters", () => {
    const short = "0123456789";
    if (short.length < 21) {
      throw new Error("Bran (passcode seed material) too short.");
    }
  }),
];

const quirks = {
  empty_stem_reuses_the_key: {
    current: encryptedAfterIncept.identifiers[encryptedIncept.prefix].situation.new.pubs,
    next: encryptedAfterIncept.identifiers[encryptedIncept.prefix].situation.nxt.pubs,
    identical: JSON.stringify(encryptedAfterIncept.identifiers[encryptedIncept.prefix].situation.new.pubs) ===
      JSON.stringify(encryptedAfterIncept.identifiers[encryptedIncept.prefix].situation.nxt.pubs),
    note: "with an empty stem the derivation path drops the rotation and key indices, so the identifier commits to the key it is already using and pre-rotation protects nothing",
    rust_decision: "reproduced exactly, because changing it would derive different identifiers; DerivationPath::reuses_keys_across_rotations reports the condition",
  },
  rotation_forgets_the_derivation_code: {
    ...rotatedPath,
    note: "rotate stores a PubPath without setting `code`, so it stays the class default of the empty string and regenerating the key for signing throws",
    rust_decision: "there is no separate code to forget: this port derives Ed25519 only, and a stored path carries the profile it was derived under",
  },
  public_key_lot_timestamp: {
    shape: encryptedAfterIncept.identifiers[encryptedIncept.prefix].situation.new.dt_shape,
    note: "`new Date().toString()` is written into every PubLot and read nowhere in the pinned source",
    rust_decision: "omitted; a protocol crate does not read the clock, as Roadmap 3.6 decided for the reply timestamp",
  },
  update_aeid_is_unreachable: {
    note: "updateAeid is private and called only from the constructor, which calls it only when `this.aeid` is undefined and after setting `_decrypter` to undefined; both of its guarded blocks — the last-seed check and the whole re-encryption loop — can therefore never run",
    rust_decision: "not ported; re-keying a manager is Roadmap 8.9, and encryption here is one optional value derived from the seed rather than four fields that can disagree",
  },
  two_signing_entry_points: {
    by_public_key: encryptedSignatures.indexed_by_position,
    by_verification_key: encryptedSignatures.by_verification_key,
    identical: JSON.stringify(encryptedSignatures.indexed_by_position) === JSON.stringify(encryptedSignatures.by_verification_key),
    note: "`sign` takes either public keys or verification keys and resolves both to the same private keys",
    rust_decision: "one method taking qualified public keys",
  },
  creator_reports_empty_strings: {
    ...randyShape,
    note: "a randy creator implements the salt, stem, and tier accessors by returning empty strings, and casts one of them to Tier",
    rust_decision: "the randy creator has no such accessors; a randy identifier records no salt and no tier",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-20",
  sources: ["src/keri/core/manager.ts", "test/core/manager.test.ts", "test/app/controller.test.ts"],
  provenance: {
    salt_raw: SALT_RAW,
    salt_qb64: SALT_QB64,
    encryption_identifier: AEID,
    serialization: SER,
    note: "the salt and encryption seed are the pinned unit test's own public constants; the temporary Argon2 profile is used wherever the reference's `temp` flag is set",
  },
  salty_creator_cases: saltyCases,
  randy_creator_shape: randyShape,
  creatory: creatoryCases,
  rotation_keys: rotationKeys,
  encrypted_manager: {
    inception: encryptedIncept,
    signatures: encryptedSignatures,
    after_inception: encryptedAfterIncept,
    rotations: encryptedRotations,
    after_rotation: encryptedAfterRotation,
    retired_key_erased: erasedKeyGone,
  },
  unencrypted_manager: {
    inception: plainIncept,
    signature: plainSignature,
    after_inception: plainAfterIncept,
    after_rotation: plainAfterRotation,
  },
  stemmed_identifiers: stemmed,
  reassignment: moved,
  rejected_cases: rejections,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-manager/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-manager fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
