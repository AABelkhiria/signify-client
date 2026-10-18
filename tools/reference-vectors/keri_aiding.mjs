// Generates and checks identifier-artifact vectors from the compiled pinned signify-ts checkout.
//
// This drives `Identifier` exactly as the pinned `aiding.test.ts` does: through a mock client
// whose fetch records the request body, with all key material derived from fixed passcodes so
// every event and signature is deterministic. The salty keeper hardcodes the production Argon2
// profile, so this generator takes several seconds.
//
// Sealed values (a salty keeper's `sxlt`) draw a fresh ephemeral key per call and are recorded by
// what they open to through the reference's own decrypter.
import { readFileSync, writeFileSync } from "node:fs";

import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Algos } from "./node_modules/signify-ts/dist/keri/core/manager.js";
import { IdentifierManagerFactory } from "./node_modules/signify-ts/dist/keri/core/keeping.js";
import { incept } from "./node_modules/signify-ts/dist/keri/core/eventing.js";
import { Serials, Vrsn_1_0 } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { Identifier } from "./node_modules/signify-ts/dist/keri/app/aiding.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";

await libsodium.ready;

/** The passcodes the pinned `aiding.test.ts` uses, plus fixed ones for the group members. */
const BRAN = "0123456789abcdefghijk";
const MULTISIG_BRAN = "0123456789lmnopqrstuv";
const MEMBER_TWO_BRAN = "abcdefghijk0123456789";
const STAMP = "2021-06-27T21:26:21.233257+00:00";
const DELEGATOR = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";

/** Three deterministic non-transferable witness prefixes, inputs only. */
const WITNESSES = ["wit0", "wit1", "wit2"].map(
  (path) =>
    new Salter({ raw: b("0123456789abcdef") }).signer(MtrDex.Ed25519_Seed, false, path, Tier.low, true).verfer
      .qb64
);

/** The pinned test's mock client: a controller-backed manager and a recording fetch. */
function mockClient(bran) {
  const controller = new Controller(bran, Tier.low);
  const calls = [];
  const client = {
    pidx: 0,
    manager: new IdentifierManagerFactory(controller.salter),
    controller,
    async fetch(path, method, body) {
      calls.push({ path, method, body });
      return { json: async () => ({}), headers: new Map() };
    },
  };
  return { client, calls, identifiers: new Identifier(client) };
}

/** Opens a sealed salty salt through the controller's own decrypter. */
function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

/** Records one captured request body's artifact half, resolving sealed values. */
function artifactRecord(bran, call) {
  const body = call.body;
  const record = {
    path: call.path,
    method: call.method,
    name: body.name ?? null,
    event: body.icp ?? body.ixn ?? body.rot ?? body.rpy ?? null,
    event_raw: JSON.stringify(body.icp ?? body.ixn ?? body.rot ?? body.rpy),
    sigs: body.sigs,
    smids: body.smids ?? null,
    rmids: body.rmids ?? null,
  };
  for (const algo of ["salty", "randy", "group", "extern"]) {
    if (body[algo] !== undefined) {
      record.algorithm = algo;
      const params = { ...body[algo] };
      if (algo === "salty") {
        params.sxlt_opens_to = openSealed(bran, params.sxlt);
        delete params.sxlt;
      }
      if (algo === "randy") {
        params.prxs_count = params.prxs.length;
        params.nxts_count = params.nxts.length;
        delete params.prxs;
        delete params.nxts;
      }
      if (algo === "group" && params.mhab?.salty?.sxlt) {
        // The group parameters embed the member record, whose sealed salt draws a fresh
        // ephemeral key per run; record what it opens to instead.
        params.mhab = sanitizeMockState(params.mhab, bran);
      }
      record.params = params;
    }
  }
  return record;
}

/** Replaces a mock state's sealed salt with what it opens to, for determinism. */
function sanitizeMockState(record, bran) {
  const copy = JSON.parse(JSON.stringify(record));
  if (copy.salty?.sxlt) {
    copy.salty.sxlt_opens_to = openSealed(bran, copy.salty.sxlt);
    delete copy.salty.sxlt;
  }
  return copy;
}

/** Builds a deterministic identifier state, as `createMockIdentifierState` does. */
async function mockState(name, bran, kargs = {}) {
  const controller = new Controller(bran, Tier.low);
  const manager = new IdentifierManagerFactory(controller.salter);
  const algo = kargs.algo ?? Algos.salty;
  const transferable = kargs.transferable ?? true;
  const isith = kargs.isith ?? "1";
  const nsith = kargs.nsith ?? "1";
  const keeper = manager.new(algo, 0, { ...kargs, bran, transferable, isith, nsith });
  const [keys, ndigs] = await keeper.incept(transferable);
  const serder = incept({
    keys,
    isith,
    ndigs,
    nsith,
    toad: kargs.toad ?? 0,
    wits: kargs.wits ?? [],
    cnfg: [],
    data: [],
    version: Vrsn_1_0,
    kind: Serials.JSON,
    code: kargs.dcode ?? MtrDex.Blake3_256,
    intive: false,
  });
  return {
    name,
    prefix: serder.pre,
    [algo]: keeper.params(),
    transferable,
    windexes: [],
    state: {
      vn: [1, 0],
      i: serder.pre,
      s: "0",
      p: "",
      d: serder.pre,
      f: "0",
      dt: STAMP,
      et: "icp",
      kt: serder.sad.kt,
      k: serder.sad.k,
      nt: serder.sad.nt,
      n: serder.sad.n,
      bt: "0",
      b: [],
      c: [],
      ee: { s: "0", d: serder.pre, br: [], ba: [] },
      di: kargs.delpre ?? "",
    },
    icp_dt: STAMP,
  };
}

/** Records a call the reference refuses, with the error it raises. */
async function rejected(name, note, run) {
  try {
    await run();
  } catch (error) {
    return { name, note, reference_error_message: String(error?.message ?? error) };
  }
  throw new Error(`the reference unexpectedly accepted ${name}`);
}

// ---------------------------------------------------------------------------
// Creations.
// ---------------------------------------------------------------------------

const creations = [];
async function createCase(name, bran, aidName, kargs) {
  const { calls, identifiers } = mockClient(bran);
  await identifiers.create(aidName, kargs);
  creations.push({
    name,
    bran,
    kargs_note: JSON.stringify(Object.keys(kargs)),
    request: artifactRecord(bran, calls[calls.length - 1]),
  });
}

await createCase("salty_default", BRAN, "aid1", { bran: BRAN });
await createCase("salty_non_transferable", BRAN, "aid1", { bran: BRAN, transferable: false });
await createCase("salty_multisig", BRAN, "aid2", {
  count: 3,
  ncount: 3,
  isith: "2",
  nsith: "2",
  bran: MULTISIG_BRAN,
});
await createCase("salty_witnessed", BRAN, "aid3", {
  bran: BRAN,
  wits: WITNESSES,
  toad: 2,
});
await createCase("salty_delegated_with_data", BRAN, "aid4", {
  bran: BRAN,
  delpre: DELEGATOR,
  data: { i: DELEGATOR, s: "0", d: DELEGATOR },
});
await createCase("salty_weighted", BRAN, "aid5", {
  bran: BRAN,
  count: 2,
  ncount: 2,
  isith: ["1/2", "1/2"],
  nsith: ["1/2", "1/2"],
});

const randyShape = await (async () => {
  const { calls, identifiers } = mockClient(BRAN);
  await identifiers.create("aid1", { bran: BRAN, algo: Algos.randy });
  const body = calls[calls.length - 1].body;
  return {
    sequence: body.icp.s,
    signing_threshold: body.icp.kt,
    key_count: body.icp.k.length,
    key_code: body.icp.k[0].slice(0, 1),
    pre_code: body.icp.i.slice(0, 1),
    transferable: body.randy.transferable,
    prxs_count: body.randy.prxs.length,
    nxts_count: body.randy.nxts.length,
    sig_count: body.sigs.length,
    note: "random keys cannot be pinned, so this records the shape a randy creation has",
  };
})();

const groupCreation = await (async () => {
  const member1 = await mockState("member1", BRAN);
  const member2 = await mockState("member2", MEMBER_TWO_BRAN);
  const member3 = await mockState("member3", MULTISIG_BRAN);
  const states = [member1.state, member2.state];
  const rstates = [member2.state, member3.state];

  const { calls, identifiers } = mockClient(BRAN);
  await identifiers.create("group1", {
    algo: Algos.group,
    mhab: member1,
    isith: "1",
    nsith: "1",
    states,
    rstates,
  });
  return {
    members: {
      member1: sanitizeMockState(member1, BRAN),
      member2: sanitizeMockState(member2, MEMBER_TWO_BRAN),
      member3: sanitizeMockState(member3, MULTISIG_BRAN),
    },
    request: artifactRecord(BRAN, calls[calls.length - 1]),
  };
})();

// ---------------------------------------------------------------------------
// Interactions and rotations, over deterministic mock states.
// ---------------------------------------------------------------------------

const interactions = [];
async function interactCase(name, stateOverride, data) {
  const aid = await mockState("aid1", BRAN);
  if (stateOverride) {
    Object.assign(aid.state, stateOverride);
  }
  const { calls, identifiers, client } = mockClient(BRAN);
  const original = client.fetch.bind(client);
  let first = true;
  client.fetch = async (path, method, body) => {
    if (first) {
      first = false;
      calls.push({ path, method, body });
      return { json: async () => aid, headers: new Map() };
    }
    return original(path, method, body);
  };
  await (data === undefined ? identifiers.interact("aid1") : identifiers.interact("aid1", data));
  interactions.push({
    name,
    state: aid.state,
    data: data ?? null,
    request: artifactRecord(BRAN, calls[calls.length - 1]),
  });
}

await interactCase("with_seal_list", undefined, [
  { i: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK", s: 0, d: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK" },
]);
await interactCase("hexadecimal_sequence", { s: "a" }, [
  { i: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK", s: 0, d: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK" },
]);
await interactCase("no_data_anchors_null", undefined, undefined);

const rotations = [];
async function rotateCase(name, stateBran, stateKargs, stateOverride, args) {
  const aid = await mockState("aid1", stateBran, stateKargs ?? {});
  if (stateOverride) {
    Object.assign(aid.state, stateOverride);
  }
  const { calls, identifiers, client } = mockClient(stateBran);
  let first = true;
  const record = calls;
  client.fetch = async (path, method, body) => {
    if (first) {
      first = false;
      record.push({ path, method, body });
      return { json: async () => aid, headers: new Map() };
    }
    record.push({ path, method, body });
    return { json: async () => ({}), headers: new Map() };
  };
  await identifiers.rotate("aid1", args ?? {});
  rotations.push({
    name,
    bran: stateBran,
    state: aid.state,
    args: args ?? {},
    request: artifactRecord(stateBran, record[record.length - 1]),
  });
}

await rotateCase("salty_default", BRAN, {}, undefined, {});
await rotateCase("hexadecimal_sequence", BRAN, {}, { s: "a" }, {});
await rotateCase("delegated", BRAN, { delpre: DELEGATOR }, undefined, {});
await rotateCase("witness_changes", BRAN, { wits: WITNESSES.slice(0, 2), toad: 2 }, { b: WITNESSES.slice(0, 2) }, {
  cuts: [WITNESSES[1]],
  adds: [WITNESSES[2]],
  toad: 2,
});
await rotateCase("explicit_next_threshold", BRAN, { ncount: 2, nsith: "2", count: 2, isith: "2" }, undefined, {
  ncount: 2,
  nsith: "1",
});

// ---------------------------------------------------------------------------
// End-role and location-scheme replies.
// ---------------------------------------------------------------------------

const replies = await (async () => {
  const aid = await mockState("aid1", BRAN);
  async function replyCase(run) {
    const { calls, identifiers, client } = mockClient(BRAN);
    let first = true;
    client.fetch = async (path, method, body) => {
      if (first) {
        first = false;
        calls.push({ path, method, body });
        return { json: async () => aid, headers: new Map() };
      }
      calls.push({ path, method, body });
      return { json: async () => ({}), headers: new Map() };
    };
    await run(identifiers);
    const last = calls[calls.length - 1];
    return {
      path: last.path,
      method: last.method,
      rpy: last.body.rpy,
      rpy_raw: JSON.stringify(last.body.rpy),
      sigs: last.body.sigs,
    };
  }

  return {
    prefix: aid.prefix,
    end_role: await replyCase((identifiers) => identifiers.addEndRole("aid1", "agent", DELEGATOR, STAMP)),
    end_role_without_eid: await replyCase((identifiers) => identifiers.addEndRole("aid1", "agent", undefined, STAMP)),
    location_scheme: await replyCase((identifiers) =>
      identifiers.addLocScheme("aid1", {
        url: "https://test.com",
        scheme: "https",
        eid: "EHgwVwQT15OJvilVvW57HE4w0-GPs_Stj2OFoAHZSysY",
        stamp: STAMP,
      })
    ),
    location_scheme_defaults: await replyCase((identifiers) =>
      identifiers.addLocScheme("aid1", { url: "http://test.com", stamp: STAMP })
    ),
  };
})();

// ---------------------------------------------------------------------------
// Inputs the reference refuses, and behaviors pinned as divergences.
// ---------------------------------------------------------------------------

const rejections = [
  await rejected("witnessed_without_toad", "`create` always passes `toad ?? 0`, which one witness cannot satisfy", () => {
    const { identifiers } = mockClient(BRAN);
    return identifiers.create("aid1", { bran: BRAN, wits: [WITNESSES[0]] });
  }),
  await rejected("unknown_external_module", "no module is registered under the name", () => {
    const { identifiers } = mockClient(BRAN);
    return identifiers.create("aid1", { algo: Algos.extern, extern_type: "hsm", extern: {} });
  }),
];

const quirks = {
  non_transferable_rewrites_are_silent: await (async () => {
    const plain = mockClient(BRAN);
    await plain.identifiers.create("aid1", { bran: BRAN, transferable: false });
    const noisy = mockClient(BRAN);
    await noisy.identifiers.create("aid1", { bran: BRAN, transferable: false, ncount: 5, nsith: "3" });
    const left = plain.calls[plain.calls.length - 1].body.icp;
    const right = noisy.calls[noisy.calls.length - 1].body.icp;
    return {
      overridden_arguments_change_nothing: JSON.stringify(left) === JSON.stringify(right),
      note: "`create` silently forces ncount = 0, nsith = 0, and dcode = Ed25519N for a non-transferable identifier, whatever was passed",
      rust_decision: "the forced values are the defaults; explicit contradictions are refused, as habitat creation refuses them",
    };
  })(),
  interact_without_data_anchors_null: {
    note: "`createInteract` wraps a missing data argument as [undefined], which serializes as [null]: a seal that seals nothing, committed into the SAID. The event is recorded in the interactions section as `no_data_anchors_null`.",
    rust_decision: "unrepresentable: an anchor is a field map; an anchor-less interaction writes a: []",
  },
  create_wraps_data_even_when_it_is_a_list: await (async () => {
    const { calls, identifiers } = mockClient(BRAN);
    await identifiers.create("aid1", { bran: BRAN, data: [{ i: DELEGATOR }] });
    const anchors = calls[calls.length - 1].body.icp.a;
    return {
      anchors,
      nested: Array.isArray(anchors) && Array.isArray(anchors[0]),
      note: "`create` wraps `data` in a single-element list unconditionally, so a list argument nests a list inside the anchors",
      rust_decision: "unrepresentable: the anchor is one field map",
    };
  })(),
  unused_create_arguments: {
    note: "`pre`, `keys`, and `ndigs` are destructured from CreateIdentiferArgs and never read; `prxs`/`nxts` are read only by the factory's reload path",
    rust_decision: "no equivalent exists; reloading is KeeperFactory::keeper_for",
  },
  end_role_default_stamp_reads_the_clock: {
    note: "`addEndRole` and `addLocScheme` default their reply timestamp to the system clock when no stamp is passed",
    rust_decision: "the timestamp is a required parameter, as in the reply event builder",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-22",
  sources: ["src/keri/app/aiding.ts", "test/app/aiding.test.ts"],
  provenance: {
    bran: BRAN,
    multisig_bran: MULTISIG_BRAN,
    member_two_bran: MEMBER_TWO_BRAN,
    stamp: STAMP,
    delegator: DELEGATOR,
    witnesses: WITNESSES,
    note: "all key material derives from the pinned unit test's own passcodes at the production Argon2 profile; sealed salts are recorded by what they open to, and randy material by shape. The witness prefixes are inputs only.",
  },
  creations,
  randy_shape: randyShape,
  group_creation: groupCreation,
  interactions,
  rotations,
  replies,
  rejections,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-aiding/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-aiding fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
