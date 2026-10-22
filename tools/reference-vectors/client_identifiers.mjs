// Records the pinned signify-ts checkout's identifier endpoint family.
//
// The Rust port covers the HTTP half of `src/keri/app/aiding.ts` — `list`, `get`, `update`, the
// submission halves of `create`, `interact`, `rotate`, `addEndRole`, and `addLocScheme`,
// `members`, and the `EventResult` class — together with `SignifyClient.createSignedRequest` from
// `src/keri/app/clienting.ts`, which belongs here because it reaches an identifier's keeper
// through `identifiers().get(alias)`.
//
// As with the `client-operations` fixture, this one **drives the reference** rather than
// re-expressing it. `Identifier` takes an `IdentifierDeps` — one `fetch` method, a `pidx`, and a
// manager — so the real class is handed a recorder, exactly as the pinned `aiding.test.ts` does,
// and every request it makes is captured with its path, method, headers, and the **exact body
// bytes** `SignifyClient.fetch` would `JSON.stringify`.
//
// `createSignedRequest` needs a whole connected client, so the second half of this generator
// replaces `globalThis.fetch` and pins the clock and the agent's key, as the `client-lifecycle`
// fixture did, and drives the real `SignifyClient` through `connect` and then the signing call.
//
// Sealed values (a salty keeper's `sxlt`) draw a fresh ephemeral key per call, so a recorded body
// masks every one of them with `<SXLT>` and records what each opens to. Everything else in a body
// is byte for byte what the reference would send.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Salter, Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Algos } from "./node_modules/signify-ts/dist/keri/core/manager.js";
import { IdentifierManagerFactory } from "./node_modules/signify-ts/dist/keri/core/keeping.js";
import { incept } from "./node_modules/signify-ts/dist/keri/core/eventing.js";
import { Serials, Vrsn_1_0 } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { Identifier } from "./node_modules/signify-ts/dist/keri/app/aiding.js";
import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The passcodes and URLs the pinned unit tests publish. */
const BRAN = "0123456789abcdefghijk";
const MULTISIG_BRAN = "0123456789lmnopqrstuv";
const MEMBER_TWO_BRAN = "abcdefghijk0123456789";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const STAMP = "2021-06-27T21:26:21.233257+00:00";
const DELEGATOR = "EAKCxMOuoRzREVHsHCkLilBrUXTvyenBiuM2QtV8BB0C";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

/** Three deterministic non-transferable witness prefixes, inputs only. */
const WITNESSES = ["wit0", "wit1", "wit2"].map(
  (path) =>
    new Salter({ raw: b("0123456789abcdef") }).signer(MtrDex.Ed25519_Seed, false, path, Tier.low, true).verfer.qb64,
);

// ---------------------------------------------------------------------------
// 0. Pin the clock, so the signed request and its signature are deterministic.
// ---------------------------------------------------------------------------

const RealDate = globalThis.Date;

class FixedDate extends RealDate {
  constructor(...args) {
    if (args.length === 0) {
      super(FIXED_MS);
    } else {
      super(...args);
    }
  }

  static now() {
    return FIXED_MS;
  }
}

globalThis.Date = FixedDate;

// ---------------------------------------------------------------------------
// 1. The ported declarations, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const aiding = parse("src/keri/app/aiding.ts");
const clienting = parse("src/keri/app/clienting.ts");
const keeping = parse("src/keri/core/keeping.ts");

function method(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name?.getText() === methodName && member.body !== undefined) {
          found = member;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

function firstText(node, predicate) {
  let found = null;
  const visit = (child) => {
    if (found === null && predicate(child)) {
      found = child.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return found;
}

/** The text of a `const <name> = ...` declaration inside one method. */
function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

/** The names a class declares, in declaration order. */
function classMembers(source, className) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      found = node.members.map((member) => member.name?.getText() ?? "<constructor>");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `.ts` file in the pinned trees, so an absence can be scanned rather than asserted. */
function pinnedTypeScriptFiles() {
  const files = [];
  const walk = (relative) => {
    const url = upstreamUrl(relative);
    let entries;
    try {
      entries = readdirSync(url, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules") {
          walk(child);
        }
      } else if (entry.name.endsWith(".ts")) {
        files.push(child);
      }
    }
  };
  for (const root of ["src", "test", "test-integration", "examples"]) {
    walk(root);
  }
  return files.sort();
}

const PINNED_FILES = pinnedTypeScriptFiles();

function scan(needle) {
  const hits = [];
  let total = 0;
  for (const file of PINNED_FILES) {
    const text = readFileSync(upstreamUrl(file), "utf8");
    const count = text.split(needle).length - 1;
    if (count > 0) {
      hits.push({ file, count });
      total += count;
    }
  }
  return { needle, total, files: hits, scanned_files: PINNED_FILES.length };
}

const listMethod = method(aiding.source, "Identifier", "list");
const getMethod = method(aiding.source, "Identifier", "get");
const updateMethod = method(aiding.source, "Identifier", "update");
const createMethod = method(aiding.source, "Identifier", "create");
const interactMethod = method(aiding.source, "Identifier", "interact");
const rotateMethod = method(aiding.source, "Identifier", "rotate");
const endRoleMethod = method(aiding.source, "Identifier", "addEndRole");
const locSchemeMethod = method(aiding.source, "Identifier", "addLocScheme");
const membersMethod = method(aiding.source, "Identifier", "members");
const signedRequestMethod = method(clienting.source, "SignifyClient", "createSignedRequest");

/** Every keeper's `params()` return literal, whose key order is the body's algorithm block. */
function keeperParameters(className) {
  const found = method(keeping.source, className, "params");
  return found === null ? null : found.getText().replace(/\s+/g, " ");
}

const declarations = {
  list_range_header: firstText(
    listMethod,
    (node) => ts.isCallExpression(node) && node.getText().startsWith("extraHeaders.append("),
  ),
  list_defaults: listMethod.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")),
  list_result: localDeclaration(listMethod, "range"),
  get_path: localDeclaration(getMethod, "path"),
  update_path: localDeclaration(updateMethod, "path"),
  update_require: firstText(updateMethod, (node) => ts.isIfStatement(node) && node.getText().includes("requireAccepted")),
  create_body: localDeclaration(createMethod, "jsondata"),
  create_algorithm_key: firstText(
    createMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().startsWith("jsondata[algo] ="),
  ),
  create_pidx_increment: firstText(
    createMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().includes("this.client.pidx + 1"),
  ),
  create_fetch: firstText(
    createMethod,
    (node) => ts.isCallExpression(node) && node.getText().startsWith("this.client.fetch("),
  ),
  interact_path: firstText(
    interactMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().includes("'/events'"),
  ),
  rotate_body: localDeclaration(rotateMethod, "jsondata"),
  rotate_path: firstText(rotateMethod, (node) => ts.isBinaryExpression(node) && node.getText().includes("'/events'")),
  end_role_body: localDeclaration(endRoleMethod, "jsondata"),
  end_role_path: firstText(
    endRoleMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().includes("'/endroles'"),
  ),
  loc_scheme_path: firstText(
    locSchemeMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().includes("'/locschemes'"),
  ),
  members_path: firstText(
    membersMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().includes("'/members'"),
  ),
  event_result_members: classMembers(aiding.source, "EventResult"),
  signed_request_resource: firstText(
    signedRequestMethod,
    (node) => ts.isCallExpression(node) && node.getText().startsWith("headers.set('Signify-Resource'"),
  ),
  signed_request_sign: localDeclaration(signedRequestMethod, "signed_headers"),
  signed_request_signer: localDeclaration(signedRequestMethod, "authenticator"),
  salty_parameters: keeperParameters("SaltyIdentifierManager"),
  randy_parameters: keeperParameters("RandyIdentifierManager"),
  group_parameters: keeperParameters("GroupIdentifierManager"),
  reloaded_randy_transferability: firstText(
    method(keeping.source, "IdentifierManagerFactory", "get"),
    (node) => ts.isNewExpression(node) && node.getText().includes("Prefixer({ qb64: aid['prefix'] })"),
  ),
  notes: {
    list: "`list` is the only call in this family that sends a header: a `Range` of `aids=${start}-${end}` defaulting to 0 and 24, whose answer it reads back out of `content-range` through `parseRangeHeaders`",
    paths: "`get` and `update` encode their name with `encodeURIComponent`; the six other name-bearing paths concatenate it raw",
    body: "the request body is `JSON.stringify` of an object literal, so its field order is the literal's and an `undefined` field is dropped rather than written as null",
    signed_request:
      "`createSignedRequest` signs an *external* URL's request with the identifier keeper's first signer and stamps the identifier's own prefix as `Signify-Resource`, not the controller's",
    parameters:
      "the algorithm block a body carries is the keeper's own `params()` literal, whose key order is not the schema's: a salty keeper writes `sxlt` first and `tier` fifth where `SaltyState` declares `tier` first, and a randy keeper writes a `transferable` field `RandyKeyState` does not declare at all",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. A recording `IdentifierDeps`, exactly as the pinned `aiding.test.ts` builds one.
// ---------------------------------------------------------------------------

/** Masks every sealed salt in a rendered body, recording what each opens to. */
function maskSealed(bran, rendered) {
  const opened = [];
  const masked = rendered.replace(/"sxlt":"([^"]+)"/g, (_match, sealed) => {
    opened.push(openSealed(bran, sealed));
    return '"sxlt":"<SXLT>"';
  });
  return { body: masked, sxlt_opens_to: opened };
}

/** Opens a sealed salty salt through the controller's own decrypter. */
function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

/** The pinned test's mock client: a controller-backed manager and a recording fetch. */
function mockClient(bran) {
  const controller = new Controller(bran, Tier.low);
  const calls = [];
  /** Queue of `(path, method) -> Response` answers; the last one repeats. */
  let answers = [];
  const client = {
    pidx: 0,
    manager: new IdentifierManagerFactory(controller.salter),
    controller,
    async fetch(path, method, body, headers) {
      const recordedHeaders = [];
      if (headers !== undefined) {
        headers.forEach((value, name) => recordedHeaders.push({ name, value }));
      }
      calls.push({
        path,
        method,
        headers: recordedHeaders,
        // `SignifyClient.fetch` sends `null` for a GET and `JSON.stringify(data)` otherwise, so
        // these are the exact bytes that would leave the process.
        body: method === "GET" ? null : JSON.stringify(body),
        value: body === undefined ? null : body,
      });
      const answer = answers.length > 1 ? answers.shift() : answers[0];
      return answer === undefined ? Response.json({}) : answer();
    },
  };
  return {
    client,
    calls,
    identifiers: new Identifier(client),
    answer(...responses) {
      answers = responses;
    },
  };
}

/** Builds a deterministic identifier record, as `createMockIdentifierState` does. */
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
    ...(kargs.delpre ? { delpre: kargs.delpre } : {}),
  });
  // The field order is the schema's own `HabState` order — name, prefix, icp_dt, state,
  // transferable, windexes, then the one algorithm block — because that is what a KERIA response
  // carries, and a group creation embeds this record in its request body verbatim.
  const record = {
    name,
    prefix: serder.pre,
    icp_dt: STAMP,
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
      bt: serder.sad.bt,
      b: serder.sad.b,
      c: [],
      ee: { s: "0", d: serder.pre, br: [], ba: [] },
      di: kargs.delpre ?? "",
    },
    transferable,
    windexes: [],
  };
  const parameters = keeper.params();
  if (algo === Algos.salty) {
    // The schema's `SaltyState` order, which is not the keeper's own `params()` order.
    record.salty = {
      tier: parameters.tier,
      sxlt: parameters.sxlt,
      pidx: parameters.pidx,
      kidx: parameters.kidx,
      stem: parameters.stem,
      dcode: parameters.dcode,
      icodes: parameters.icodes,
      ncodes: parameters.ncodes,
      transferable: parameters.transferable,
    };
  } else if (algo === Algos.randy) {
    record.randy = { prxs: parameters.prxs, nxts: parameters.nxts };
  } else {
    record[algo] = parameters;
  }
  return record;
}

/** Replaces a record's sealed salt with what it opens to, for determinism. */
function sanitizeRecord(record, bran) {
  const copy = JSON.parse(JSON.stringify(record));
  if (copy.salty?.sxlt) {
    copy.salty.sxlt_opens_to = openSealed(bran, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
  }
  if (copy.group?.mhab?.salty?.sxlt) {
    copy.group.mhab.salty.sxlt_opens_to = openSealed(bran, copy.group.mhab.salty.sxlt);
    copy.group.mhab.salty.sxlt = "<SXLT>";
  }
  return copy;
}

const calls = [];

/** Runs one endpoint call and records the request it produced with whatever came back. */
async function drive(name, note, bran, run) {
  const harness = mockClient(bran);
  let result = null;
  let error = null;
  try {
    result = await run(harness);
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const last = harness.calls[harness.calls.length - 1] ?? null;
  const record = {
    name,
    note,
    request:
      last === null
        ? null
        : {
            path: last.path,
            method: last.method,
            headers: last.headers,
            body: last.body,
          },
    requests: harness.calls.length,
    pidx_after: harness.client.pidx,
    result: result === undefined ? null : result,
    error,
  };
  if (last !== null && last.body !== null) {
    const masked = maskSealed(bran, last.body);
    record.request.body = masked.body;
    if (masked.sxlt_opens_to.length > 0) {
      record.request.sxlt_opens_to = masked.sxlt_opens_to;
    }
  }
  calls.push(record);
  return record;
}

// --- list -------------------------------------------------------------------

/** Answers a listing with a `content-range` header, as KERIA does. */
function listing(aids, contentRange) {
  return () => Response.json(aids, { headers: { "content-range": contentRange } });
}

const LISTED = [
  { name: "aid1", prefix: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK" },
  { name: "aid2", prefix: "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX" },
];

await drive("list_default", "the pinned unit test's own list, at its default range", BRAN, async (harness) => {
  harness.answer(listing(LISTED, "aids 0-1/2"));
  return harness.identifiers.list();
});

await drive("list_explicit_range", "an explicit window, which is the only header this family sends", BRAN, async (harness) => {
  harness.answer(listing(LISTED, "aids 2-3/97"));
  return harness.identifiers.list(2, 5);
});

await drive("list_without_content_range", "an answer carrying no content-range at all", BRAN, async (harness) => {
  harness.answer(() => Response.json(LISTED));
  return harness.identifiers.list();
});

// --- get and update ---------------------------------------------------------

const aid1 = await mockState("aid1", BRAN);
const pendingGroup = (() => {
  const record = JSON.parse(JSON.stringify(aid1));
  delete record.state;
  record.name = "group1";
  return record;
})();

await drive("get", "the pinned unit test's get, whose name needs no encoding", BRAN, async (harness) => {
  harness.answer(() => Response.json(aid1));
  const hab = await harness.identifiers.get("aid1");
  return { prefix: hab.prefix, name: hab.name };
});

await drive(
  "get_name_needing_encoding",
  "the pinned unit test's `a name with ñ!`, which is one of only two dynamic values the reference encodes",
  BRAN,
  async (harness) => {
    harness.answer(() => Response.json(aid1));
    const hab = await harness.identifiers.get("a name with ñ!");
    return { prefix: hab.prefix };
  },
);

await drive("get_pending_refused", "a group still collecting signatures, with key state required", BRAN, async (harness) => {
  harness.answer(() => Response.json(pendingGroup));
  const hab = await harness.identifiers.get("group1");
  return { prefix: hab.prefix };
});

await drive("get_pending_accepted", "the same group, with key state not required", BRAN, async (harness) => {
  harness.answer(() => Response.json(pendingGroup));
  const hab = await harness.identifiers.get("group1", false);
  return { prefix: hab.prefix, has_state: hab.state !== undefined };
});

await drive("update", "the pinned unit test's rename", BRAN, async (harness) => {
  harness.answer(() => Response.json(aid1));
  const hab = await harness.identifiers.update("aid1", { name: "aid2" });
  return { prefix: hab.prefix };
});

await drive("update_pending_refused", "renaming a group that is still pending, with key state required", BRAN, async (harness) => {
  harness.answer(() => Response.json(pendingGroup));
  const hab = await harness.identifiers.update("group1", { name: "group2" });
  return { prefix: hab.prefix };
});

// --- create -----------------------------------------------------------------

await drive("create_salty", "the pinned unit test's default salty creation", BRAN, (harness) =>
  harness.identifiers.create("aid1", { bran: BRAN }).then((result) => result.op()),
);

await drive("create_non_transferable", "the pinned unit test's non-transferable creation", BRAN, (harness) =>
  harness.identifiers.create("aid1", { bran: BRAN, transferable: false }).then((result) => result.op()),
);

await drive("create_multisig", "the pinned unit test's three-key creation", BRAN, (harness) =>
  harness.identifiers
    .create("aid2", { count: 3, ncount: 3, isith: "2", nsith: "2", bran: MULTISIG_BRAN })
    .then((result) => result.op()),
);

await drive("create_witnessed_with_proxy", "witnesses, an explicit threshold, and a proxy, which is the only optional body field a non-group creation writes", BRAN, (harness) =>
  harness.identifiers
    .create("aid3", { bran: BRAN, wits: WITNESSES, toad: 2, proxy: "EPROXY" })
    .then((result) => result.op()),
);

await drive("create_delegated_with_data", "a delegated creation carrying an anchor", BRAN, (harness) =>
  harness.identifiers
    .create("aid4", { bran: BRAN, delpre: DELEGATOR, data: { i: DELEGATOR, s: "0", d: DELEGATOR } })
    .then((result) => result.op()),
);

const groupCreation = await (async () => {
  const member1 = await mockState("member1", BRAN);
  const member2 = await mockState("member2", MEMBER_TWO_BRAN);
  const member3 = await mockState("member3", MULTISIG_BRAN);
  const states = [member1.state, member2.state];
  const rstates = [member2.state, member3.state];
  await drive("create_group", "a three-member group, the only creation writing smids and rmids", BRAN, (harness) =>
    harness.identifiers
      .create("group1", { algo: Algos.group, mhab: member1, isith: "1", nsith: "1", states, rstates })
      .then((result) => result.op()),
  );
  return {
    members: {
      member1: sanitizeRecord(member1, BRAN),
      member2: sanitizeRecord(member2, MEMBER_TWO_BRAN),
      member3: sanitizeRecord(member3, MULTISIG_BRAN),
    },
    note: "the member records are the group creation's inputs; their sealed salts are recorded by what they open to",
  };
})();

/** Answers the identifier lookup first, then the submission. */
function withLookup(harness, record) {
  harness.answer(
    () => Response.json(record),
    () => Response.json({}),
  );
}

const randyShape = await (async () => {
  const harness = mockClient(BRAN);
  await harness.identifiers.create("aid1", { bran: BRAN, algo: Algos.randy });
  const last = harness.calls[harness.calls.length - 1];
  const body = last.value;
  return {
    path: last.path,
    method: last.method,
    body_fields: Object.keys(body),
    algorithm_field: "randy",
    randy_fields: Object.keys(body.randy),
    prxs_count: body.randy.prxs.length,
    nxts_count: body.randy.nxts.length,
    sig_count: body.sigs.length,
    note: "random keys cannot be pinned, so this records the shape of a randy creation's request body",
  };
})();

const randyReloadShape = await (async () => {
  const harness = mockClient(BRAN);
  const randy = await mockState("aid1", BRAN, { algo: Algos.randy });
  withLookup(harness, randy);
  await harness.identifiers.interact("aid1", [{ i: DELEGATOR, s: 0, d: DELEGATOR }]);
  const last = harness.calls[harness.calls.length - 1];
  return {
    path: last.path,
    method: last.method,
    body_fields: Object.keys(last.value),
    randy_fields: Object.keys(last.value.randy),
    randy_transferable: last.value.randy.transferable,
    record_transferable: randy.transferable,
    prefix_code: randy.prefix.slice(0, 1),
    note: "a reloaded randy keeper takes its transferability from the identifier's own prefix, because the stored `RandyKeyState` does not declare the field its `params()` writes back",
  };
})();

const pidxWalk = await (async () => {
  const harness = mockClient(BRAN);
  const before = harness.client.pidx;
  await harness.identifiers.create("aid1", { bran: BRAN });
  const afterFirst = harness.client.pidx;
  const firstPidx = harness.calls[harness.calls.length - 1].value.salty.pidx;
  await harness.identifiers.create("aid2", { bran: BRAN });
  const secondPidx = harness.calls[harness.calls.length - 1].value.salty.pidx;
  return {
    before,
    after_first: afterFirst,
    after_second: harness.client.pidx,
    first_body_pidx: firstPidx,
    second_body_pidx: secondPidx,
    note: "`create` builds its keeper at the client's current `pidx` and increments the client's copy after signing, so successive creations derive under successive prefix indices",
  };
})();

const pidxNotConsumedOnFailure = await (async () => {
  const harness = mockClient(BRAN);
  try {
    // One witness cannot satisfy the `toad ?? 0` the reference always passes.
    await harness.identifiers.create("aid1", { bran: BRAN, wits: [WITNESSES[0]] });
  } catch {
    // Expected.
  }
  return {
    pidx_after_failure: harness.client.pidx,
    note: "a creation that fails before its fetch leaves `pidx` untouched, so the next creation reuses the same prefix index",
  };
})();

// --- interact, rotate, endroles, locschemes, members -------------------------

await drive("interact", "the pinned unit test's interaction, whose anchors are a seal list", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers
    .interact("aid1", [
      { i: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK", s: 0, d: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK" },
    ])
    .then((result) => result.op());
});

await drive(
  "interact_name_needing_encoding",
  "the same interaction under a name carrying a slash, which the path does not encode",
  BRAN,
  (harness) => {
    withLookup(harness, aid1);
    return harness.identifiers.interact("a/b", [{ i: DELEGATOR, s: 0, d: DELEGATOR }]).then((result) => result.op());
  },
);

await drive("rotate", "the pinned unit test's rotation, which always writes smids and rmids", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers.rotate("aid1").then((result) => result.op());
});

await drive("rotate_with_witness_changes", "a rotation cutting and adding a witness", BRAN, async (harness) => {
  const witnessed = await mockState("aid1", BRAN, { wits: WITNESSES.slice(0, 2), toad: 2 });
  witnessed.state.b = WITNESSES.slice(0, 2);
  withLookup(harness, witnessed);
  return harness.identifiers
    .rotate("aid1", { cuts: [WITNESSES[1]], adds: [WITNESSES[2]], toad: 2 })
    .then((result) => result.op());
});

await drive("add_end_role", "the pinned unit test's end-role authorization, with an explicit endpoint", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers.addEndRole("aid1", "agent", DELEGATOR, STAMP).then((result) => result.op());
});

await drive("add_end_role_without_endpoint", "the same authorization with no endpoint identifier", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers.addEndRole("aid1", "agent", undefined, STAMP).then((result) => result.op());
});

await drive("add_location_scheme", "the pinned unit test's location authorization", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers
    .addLocScheme("aid1", {
      url: "https://test.com",
      scheme: "https",
      eid: "EHgwVwQT15OJvilVvW57HE4w0-GPs_Stj2OFoAHZSysY",
      stamp: STAMP,
    })
    .then((result) => result.op());
});

await drive("add_location_scheme_defaults", "the same call defaulting the scheme and the endpoint", BRAN, (harness) => {
  withLookup(harness, aid1);
  return harness.identifiers.addLocScheme("aid1", { url: "http://test.com", stamp: STAMP }).then((result) => result.op());
});

await drive("members", "the pinned unit test's group-member listing", BRAN, (harness) => {
  harness.answer(() => Response.json({ signing: [], rotation: [] }));
  return harness.identifiers.members("aid1");
});

// ---------------------------------------------------------------------------
// 3. `createSignedRequest`, driven through a whole connected client.
// ---------------------------------------------------------------------------

const signedRequest = await (async () => {
  const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
  const controllerPrefix = client.controller.pre;

  /** The agent's own key, fixed so its prefix and response signatures are reproducible. */
  const agentSigner = new Signer({
    raw: new Uint8Array([
      187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122, 87,
      143, 109, 39, 98, 153, 192, 148,
    ]),
    code: MtrDex.Ed25519_Seed,
    transferable: false,
  });
  const agentPrefix = "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY";
  const agentState = {
    vn: [1, 0],
    i: agentPrefix,
    s: "0",
    p: "",
    d: agentPrefix,
    f: "0",
    dt: "2023-12-01T10:05:25.062609+00:00",
    et: "dip",
    kt: "1",
    k: [agentSigner.verfer.qb64],
    nt: "1",
    n: [new Diger({}, b(agentSigner.verfer.qb64)).qb64],
    bt: "0",
    b: [],
    c: [],
    ee: { s: "0", d: agentPrefix, br: [], ba: [] },
    di: controllerPrefix,
  };
  const controllerState = {
    state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
    ee: { ...client.controller.serder.sad },
  };

  /** The identifier `createSignedRequest` looks up, derived from the same passcode. */
  const signingAid = await mockState("aid1", BRAN);

  const recorded = [];
  function signedHeaders(httpMethod, path) {
    const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
    const headers = new Headers([
      ["Content-Type", "application/json"],
      ["Signify-Resource", agentPrefix],
      ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
    ]);
    return authenticator.sign(headers, httpMethod, path.split("?")[0]);
  }

  globalThis.fetch = async (url, init = {}) => {
    const text = String(url);
    const httpMethod = init.method ?? "GET";
    recorded.push({ url: text, method: httpMethod });
    const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
    const payload =
      path.startsWith("/agent/") && httpMethod === "GET"
        ? { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 }
        : path.startsWith("/identifiers/")
          ? signingAid
          : {};
    const responseHeaders = signedHeaders(httpMethod, path);
    responseHeaders.set("Content-Type", "application/json");
    return new Response(JSON.stringify(payload), { status: 202, headers: responseHeaders });
  };

  await client.connect();

  const externalUrl = "https://external.example/some/path?query=1";
  const request = await client.createSignedRequest("aid1", externalUrl, { method: "POST", body: '{"hello":"world"}' });
  const headers = [];
  request.headers.forEach((value, name) => headers.push({ name, value }));
  headers.sort((left, right) => left.name.localeCompare(right.name));

  const getRequest = await client.createSignedRequest("aid1", externalUrl, {});
  const getHeaders = [];
  getRequest.headers.forEach((value, name) => getHeaders.push({ name, value }));
  getHeaders.sort((left, right) => left.name.localeCompare(right.name));

  return {
    controller_prefix: controllerPrefix,
    agent_prefix: agentPrefix,
    identifier: sanitizeRecord(signingAid, BRAN),
    identifier_signing_key: signingAid.state.k[0],
    lookup_path: recorded[recorded.length - 1]?.url ?? null,
    post: {
      url: request.url,
      method: request.method,
      headers,
      note: "the identifier's own prefix is stamped as `Signify-Resource`, and the signature covers the *external* URL's path",
    },
    get: {
      url: getRequest.url,
      method: getRequest.method,
      headers: getHeaders,
      note: "with no method in the request options, the signature covers `GET` while the Request itself defaults to `GET` too",
    },
    fixed_clock_ms: FIXED_MS,
    note: "the clock and the agent's key are pinned, so both signatures are exact",
  };
})();

// ---------------------------------------------------------------------------
// 4. The values the pinned unit tests publish.
// ---------------------------------------------------------------------------

const aidingTest = parse("test/app/aiding.test.ts");
const clientingTest = parse("test/app/clienting.test.ts");

function publishedStrings(source, predicate) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && predicate(node.text)) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const publishedPaths = [...new Set(publishedStrings(aidingTest.source, (text) => text.startsWith("/identifiers")))].sort();
const drivenPaths = calls.filter((call) => call.request !== null).map((call) => call.request.path);
const REQUIRED_PATHS = [
  "/identifiers",
  "/identifiers/a%20name%20with%20%C3%B1!",
  "/identifiers/aid1",
  "/identifiers/aid1/events",
  "/identifiers/aid1/endroles",
  "/identifiers/aid1/locschemes",
  "/identifiers/aid1/members",
];

const pinnedConfirmations = {
  published_paths: publishedPaths,
  driven_paths: [...new Set(drivenPaths)].sort(),
  every_pinned_path_is_driven: REQUIRED_PATHS.every(
    (path) => publishedPaths.includes(path) && drivenPaths.includes(path),
  ),
  create_signed_request_is_published: publishedStrings(clientingTest.source, (text) => text.includes("Signify-Resource"))
    .length > 0 || clientingTest.text.includes("createSignedRequest"),
  note: "every path the pinned `aiding.test.ts` asserts is produced here by the reference's own methods, and `clienting.test.ts` drives `createSignedRequest` itself",
};
if (!pinnedConfirmations.every_pinned_path_is_driven) {
  throw new Error("the pinned identifier paths no longer reproduce");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  only_two_paths_encode_their_name: {
    encoded: calls.find((call) => call.name === "get_name_needing_encoding")?.request?.path ?? null,
    unencoded: calls.find((call) => call.name === "interact_name_needing_encoding")?.request?.path ?? null,
    expressions: {
      get: declarations.get_path,
      update: declarations.update_path,
      interact: declarations.interact_path,
      rotate: declarations.rotate_path,
      end_role: declarations.end_role_path,
      loc_scheme: declarations.loc_scheme_path,
      members: declarations.members_path,
    },
    note: "`get` and `update` call `encodeURIComponent`; `interact`, `rotate`, `addEndRole`, `addLocScheme`, and `members` concatenate the name raw, so an alias holding a slash addresses a different resource and changes what a signature covers",
    rust_decision:
      "refused by construction: the request builder's `ResourcePath` encodes every dynamic component exactly once and offers no way to skip it, so all seven paths agree with the two the reference encodes",
  },
  list_range_is_inclusive_and_unbounded: {
    default_header: calls.find((call) => call.name === "list_default")?.request?.headers ?? null,
    explicit_header: calls.find((call) => call.name === "list_explicit_range")?.request?.headers ?? null,
    defaults: declarations.list_defaults,
    note: "`list` sends `aids=${start}-${end}` with no validation at all: a negative start, a fractional end, or an end below the start are all sent as written",
    rust_decision: "the request builder's `ItemRange` validates start ≤ end at construction and carries unsigned integers, so an unsatisfiable window is unrepresentable",
  },
  list_without_content_range_reads_undefined: {
    result: calls.find((call) => call.name === "list_without_content_range")?.result ?? null,
    error: calls.find((call) => call.name === "list_without_content_range")?.error ?? null,
    note: "`parseRangeHeaders` returns `{start: 0, end: 0, total: 0}` for an absent header, so a listing with no content-range reports a total of zero while carrying entries",
    rust_decision:
      "the range is `Option<ContentRange>` — the request builder already decided an absent header is `None` rather than three zeroes — so a caller can tell an empty window from an unreported one",
  },
  get_requires_key_state_by_throwing: {
    refused: calls.find((call) => call.name === "get_pending_refused")?.error ?? null,
    accepted: calls.find((call) => call.name === "get_pending_accepted")?.result ?? null,
    note: "`requireKeyState` throws `No key state for identifier ${name}` and is selected by a boolean parameter with three overload signatures",
    rust_decision:
      "two methods rather than a flag: `get` returns an `AcceptedHab` and `get_any` returns the shared `Hab` enum, whose pending variant simply has no key state to demand",
  },
  update_body_is_the_whole_info_object: {
    body: calls.find((call) => call.name === "update")?.request?.body ?? null,
    note: "`update` sends the `IdentifierInfo` argument as the whole body, which today is exactly `{name}`",
    rust_decision: "reproduced with a one-field `IdentifierUpdate`, so a caller cannot send a field KERIA does not read",
  },
  create_body_drops_undefined_fields: {
    salty: calls.find((call) => call.name === "create_salty")?.request?.body ?? null,
    with_proxy: calls.find((call) => call.name === "create_witnessed_with_proxy")?.request?.body ?? null,
    group: calls.find((call) => call.name === "create_group")?.request?.body ?? null,
    expression: declarations.create_body,
    note: "the body literal always names `proxy`, `smids`, and `rmids`, but `JSON.stringify` drops an `undefined` value, so a non-group creation without a proxy sends four fields and a group creation sends seven",
    rust_decision: "reproduced exactly: the body is an ordered `Sad` and an absent value is not written",
  },
  rotate_always_writes_member_lists: {
    body: calls.find((call) => call.name === "rotate")?.request?.body ?? null,
    expression: declarations.rotate_body,
    note: "`rotate` defaults `states` and `rstates` to `[]` *before* mapping them, so `smids` and `rmids` are always written — as empty arrays for a single-signature identifier — where `create` omits them",
    rust_decision: "reproduced: the asymmetry is what the agent receives, and the identifier artifact already exposed the two accessors with exactly these presence rules",
  },
  pidx_advances_on_the_client: {
    walk: pidxWalk,
    on_failure: pidxNotConsumedOnFailure,
    expression: declarations.create_pidx_increment,
    note: "`create` mutates `this.client.pidx` after signing, so the index is shared mutable state on the client and two concurrent creations would derive the same identifier's keys",
    rust_decision:
      "the index is an atomic counter reserved *before* the keys derive, so two concurrent creations can never collide; a creation that fails consumes its index, which the reference would have reused",
  },
  event_result_re_reads_the_response: {
    members: declarations.event_result_members,
    note: "`EventResult.op()` calls `response.json()` on a response the caller may already have read, so a second call throws `Body has already been read`",
    rust_decision: "the response body is owned bytes, so `operation()` can be called as often as a caller likes and narrowing it is a decode",
  },
  create_signed_request_stamps_the_identifier: {
    resource: declarations.signed_request_resource,
    signer: declarations.signed_request_signer,
    headers: signedRequest.post.headers,
    scan: scan("createSignedRequest"),
    note: "`createSignedRequest` reaches an identifier's keeper through `identifiers().get(alias)`, signs with `keeper.signers[0]`, stamps the *identifier's* prefix rather than the controller's, and mutates the caller's `RequestInit` in place",
    rust_decision:
      "the Rust method takes a built `Request` and returns a new one, so the caller's value is untouched; the signing itself is `SigningTransport::sign_request`, which was exposed for exactly this call",
  },
  randy_parameters_write_an_undeclared_field: {
    parameters: declarations.randy_parameters,
    creation: randyShape.randy_fields,
    reload: randyReloadShape,
    reloaded_from: declarations.reloaded_randy_transferability,
    note: "a randy keeper's `params()` writes `nxts`, `prxs`, and a `transferable` the schema's `RandyKeyState` does not declare; on reload the value comes from the identifier's prefix rather than from the stored block, so it is derivable and never read back",
    rust_decision:
      "reproduced from the same source the reference reloads it from — the request's transferability when creating or rotating, the identifier's prefix when interacting — because the shared `RandyState` type is schema-faithful and carries no such field",
  },
  non_transferable_stores_the_prefix_code_as_its_digest_code: {
    body: calls.find((call) => call.name === "create_non_transferable")?.request?.body ?? null,
    stored_dcode: "B",
    note: "`create` reuses one `dcode` variable for the prefix derivation and for the stored digest code, so a non-transferable identifier's record names the basic prefix code `B` in the field that says which digest algorithm commits to its next keys — a field governing a list that is empty either way",
    rust_decision:
      "not reproduced: the `keri-aiding` fixture recorded this and the Rust port stores the digest code actually used (`E`), so the request body differs in exactly that one field. A record whose `dcode` is not a digest code does not reload here.",
  },
  mock_identifier_state_names_two_key_managers: {
    note: "`test/app/test-utils.ts`'s `createMockIdentifierState` writes `extern: extern ?? {}` beside the algorithm's own field, so every record it produces names two key managers",
    rust_decision:
      "refused: the shared `Hab` type requires exactly one, and an `extern` block with no `extern_type` is not a key-manager state at all. The records in this fixture name one, as a KERIA response does.",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-24",
  sources: ["src/keri/app/aiding.ts", "src/keri/app/clienting.ts", "test/app/aiding.test.ts"],
  provenance: {
    bran: BRAN,
    multisig_bran: MULTISIG_BRAN,
    member_two_bran: MEMBER_TWO_BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    stamp: STAMP,
    delegator: DELEGATOR,
    witnesses: WITNESSES,
    fixed_clock_ms: FIXED_MS,
    note: "`Identifier` takes an `IdentifierDeps` — one `fetch` method, a `pidx`, and a manager — so the reference's own class is driven against a recorder, exactly as the pinned `aiding.test.ts` does. Every recorded body is the exact string `SignifyClient.fetch` would send, with each sealed salt masked as `<SXLT>` and recorded by what it opens to. All key material derives from the pinned unit tests' own passcodes at the production Argon2 profile. `PUBLIC TEST MATERIAL`: neither passcode has ever protected anything.",
  },
  declarations,
  calls,
  group_creation: groupCreation,
  randy_shape: randyShape,
  randy_reload_shape: randyReloadShape,
  signed_request: signedRequest,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-identifiers/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-identifiers fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
