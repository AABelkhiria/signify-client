// Records the pinned signify-ts checkout's registry endpoint.
//
// Roadmap 6.9 ports `Registries.{list,create,createFromEvents,rename}` and `RegistryResult` from
// `src/keri/app/credentialing.ts`.
//
// The pinned unit tree exercises this family in `test/app/registry.test.ts`, whose two cases
// publish an exact `vcp` and `ixn` pair and the establishment-only refusal. **Those two vectors are
// not reproducible here**: their issuer prefix is the literal `'hab prefix'`, which no
// `IdentifierPrefix` can express, so they are recorded verbatim and the input is proven refused —
// the arrangement Roadmap 3.8 established. Byte parity comes from driving the reference instead,
// the way Roadmap 6.7's and 6.8's fixtures do: `globalThis.fetch` is replaced with a recorder that
// answers and signs as a KERIA agent would, and the real client is walked through boot, connect,
// and every registry call.
//
// `create` derives real keys at the reference's production Argon2 profile and signs the anchoring
// interaction event, so this generator takes several seconds. The nonce is pinned for the exact
// vectors — `vdr.incept` draws a random one otherwise — and one case records the generated shape.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Algos } from "../../reference/signify-ts/dist/keri/core/manager.js";
import { IdentifierManagerFactory } from "../../reference/signify-ts/dist/keri/core/keeping.js";
import { incept } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import { Serials, Vrsn_1_0, b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

/** The passcode and URLs the pinned tests publish. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const STAMP = "2021-06-27T21:26:21.233257+00:00";

/** A fixed nonce, so a registry inception is reproducible; `vdr.incept` draws one otherwise. */
const NONCE = "0ACDEyMzQ1Njc4OWxtbm9wcXJzdHV2";

/** Three deterministic backer prefixes, inputs only. */
const BACKERS = ["bak0", "bak1", "bak2"].map(
  (path) =>
    new Salter({ raw: b("0123456789abcdef") }).signer(MtrDex.Ed25519_Seed, false, path, Tier.low, true).verfer.qb64,
);

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// 0. Pin the clock, so a signed request is deterministic.
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
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");
const registryTest = parse("test/app/registry.test.ts");

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

function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

function interfaceText(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isInterfaceDeclaration(node) && node.name.getText() === name) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

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
    const url = new URL(`../../reference/signify-ts/${relative}`, import.meta.url);
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
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    const count = text.split(needle).length - 1;
    if (count > 0) {
      hits.push({ file, count });
      total += count;
    }
  }
  return { needle, total, files: hits, scanned_files: PINNED_FILES.length };
}

const listMethod = method(credentialing.source, "Registries", "list");
const createMethod = method(credentialing.source, "Registries", "create");
const fromEventsMethod = method(credentialing.source, "Registries", "createFromEvents");
const renameMethod = method(credentialing.source, "Registries", "rename");

const declarations = {
  list_path: localDeclaration(listMethod, "path"),
  create_arguments: interfaceText(credentialing.source, "CreateRegistryArgs"),
  create_defaults: createMethod.parameters
    .map((parameter) => parameter.getText().replace(/\s+/g, " "))
    .join(" | "),
  create_no_backers: firstText(
    createMethod,
    (node) => ts.isIfStatement(node) && node.getText().includes("noBackers"),
  ),
  create_est_only: localDeclaration(createMethod, "estOnly"),
  create_est_only_throw: firstText(
    createMethod,
    (node) => ts.isThrowStatement(node) && node.getText().includes("establishment only"),
  ),
  create_incept: localDeclaration(createMethod, "regser"),
  create_anchor: firstText(
    createMethod,
    (node) => ts.isVariableDeclaration(node) && node.name.getText() === "data",
  ),
  from_events_path: localDeclaration(fromEventsMethod, "path"),
  from_events_body: localDeclaration(fromEventsMethod, "data"),
  from_events_algorithm: firstText(
    fromEventsMethod,
    (node) => ts.isBinaryExpression(node) && node.getText().startsWith("data[keeper.algo] ="),
  ),
  rename_path: localDeclaration(renameMethod, "path"),
  rename_body: localDeclaration(renameMethod, "data"),
  registry_result_members: classMembers(credentialing.source, "RegistryResult"),
  registry_result_op: firstText(
    method(credentialing.source, "RegistryResult", "op"),
    (node) => ts.isVariableDeclaration(node) && node.name.getText() === "res",
  ),
  unit_test_cases: scan("registries()"),
  notes: {
    paths: "all three paths interpolate their names raw — `list` and `create` the identifier alias, `rename` both the alias and the registry name — so none of the four dynamic values is encoded",
    backers:
      "`noBackers` defaults to **true**, so an ordinary creation writes the `NB` configuration trait and the backer list and threshold it also accepts are never used",
    est_only:
      "an establishment-only identifier pushes the `EO` trait into the configuration, builds the registry inception with it, and *then* throws `establishment only not implemented` — so the work is done and discarded",
    result:
      "`RegistryResult` holds the fetch **promise**, not its response, so `create` returns before the POST resolves and a failure is invisible unless `op()` is awaited",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. A KERIA agent, answering and signing as Roadmap 6.4's fixture did.
// ---------------------------------------------------------------------------

const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
const controllerPrefix = client.controller.pre;

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

/** Opens a sealed salty salt through the controller's own decrypter. */
function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

/** Masks every sealed salt in a rendered body, recording what each opens to. */
function maskSealed(bran, rendered) {
  const opened = [];
  const masked = rendered.replace(/"sxlt":"([^"]+)"/g, (_match, sealed) => {
    opened.push(openSealed(bran, sealed));
    return '"sxlt":"<SXLT>"';
  });
  return { body: masked, sxlt_opens_to: opened };
}

/** Replaces a record's sealed salt with what it opens to, so the fixture is reproducible. */
function sanitizeRecord(record) {
  const copy = JSON.parse(JSON.stringify(record));
  if (copy.salty?.sxlt) {
    copy.salty.sxlt_opens_to = openSealed(BRAN, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
  }
  return copy;
}

/** Builds a deterministic identifier record, in the schema's own field order. */
async function identifierRecord(name, bran, kargs = {}) {
  const controller = new Controller(bran, Tier.low);
  const manager = new IdentifierManagerFactory(controller.salter);
  const algo = kargs.algo ?? Algos.salty;
  const transferable = kargs.transferable ?? true;
  const keeper = manager.new(algo, 0, { ...kargs, bran, transferable, isith: "1", nsith: "1" });
  const [keys, ndigs] = await keeper.incept(transferable);
  const serder = incept({
    keys,
    isith: "1",
    ndigs,
    nsith: "1",
    toad: 0,
    wits: [],
    cnfg: kargs.cnfg ?? [],
    data: [],
    version: Vrsn_1_0,
    kind: Serials.JSON,
    code: MtrDex.Blake3_256,
    intive: false,
  });
  const parameters = keeper.params();
  return {
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
      c: kargs.cnfg ?? [],
      ee: { s: "0", d: serder.pre, br: [], ba: [] },
      di: "",
    },
    transferable,
    windexes: [],
    salty: {
      tier: parameters.tier,
      sxlt: parameters.sxlt,
      pidx: parameters.pidx,
      kidx: parameters.kidx,
      stem: parameters.stem,
      dcode: parameters.dcode,
      icodes: parameters.icodes,
      ncodes: parameters.ncodes,
      transferable: parameters.transferable,
    },
  };
}

const ORDINARY = await identifierRecord("issuer", BRAN);
const ESTABLISHMENT_ONLY = await identifierRecord("estonly", BRAN, { cnfg: ["EO"] });

const recorded = [];
/** The identifier record `/identifiers/{name}` answers with, and the payload everything else gets. */
let nextIdentifier = ORDINARY;
let nextPayload = {};

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
  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
  recorded.push({
    path,
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });

  let payload = nextPayload;
  if (path.startsWith("/agent/") && httpMethod === "GET") {
    payload = { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 };
  } else if (/^\/identifiers\/[^/]+$/.test(path) && httpMethod === "GET") {
    payload = nextIdentifier;
  }
  const responseHeaders = signedHeaders(httpMethod, path);
  responseHeaders.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status: 202, headers: responseHeaders });
};

await client.boot();
await client.connect();

const registries = client.registries();

const calls = [];

/** Runs one call, recording the request it produced with whatever came back. */
async function drive(name, note, payload, run) {
  nextPayload = payload;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    result = await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const request = recorded[recorded.length - 1] ?? null;
  const record = {
    name,
    note,
    request:
      request === null || recorded.length === before
        ? null
        : { path: request.path, method: request.method, body: request.body },
    requests: recorded.length - before,
    result,
    error,
  };
  if (record.request !== null && record.request.body !== null) {
    const masked = maskSealed(BRAN, record.request.body);
    record.request.body = masked.body;
    if (masked.sxlt_opens_to.length > 0) {
      record.request.sxlt_opens_to = masked.sxlt_opens_to;
    }
  }
  calls.push(record);
  nextPayload = {};
  return record;
}

/** The registry records a listing answers with. */
const LISTED = [
  {
    name: "vLEI",
    regk: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
    pre: ORDINARY.prefix,
    state: {
      vn: [1, 0],
      i: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
      s: "0",
      d: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
      ii: ORDINARY.prefix,
      dt: STAMP,
      et: "vcp",
      bt: "0",
      b: [],
      c: ["NB"],
    },
  },
];

// --- list -------------------------------------------------------------------

await drive("list", "the ordinary listing, whose alias is the identifier's", LISTED, () => registries.list("issuer"));

await drive(
  "list_alias_needing_encoding",
  "an alias carrying a slash, which the path does not encode",
  [],
  () => registries.list("a/b"),
);

// --- create -----------------------------------------------------------------

/** One registry operation, the shape a creation is answered with. */
const REGISTRY_OPERATION = {
  name: `registry.EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df`,
  metadata: {
    pre: ORDINARY.prefix,
    depends: { name: `witness.${ORDINARY.prefix}.1`, metadata: { pre: ORDINARY.prefix, sn: 1 }, done: false },
    anchor: { pre: ORDINARY.prefix, sn: 1, d: "EANCHOR" },
  },
  done: false,
};

await drive("create_default", "the ordinary creation: no backers, a pinned nonce", REGISTRY_OPERATION, async () => {
  const result = await registries.create({ name: "issuer", registryName: "vLEI", nonce: NONCE });
  return {
    regser_said: result.regser.pre,
    regser_raw: result.regser.raw,
    serder_said: result.serder.sad.d,
    serder_raw: result.serder.raw,
    sigs: result.sigs,
  };
});

await drive(
  "create_with_backers",
  "a backed registry: `noBackers` false, three backers and a threshold",
  REGISTRY_OPERATION,
  async () => {
    const result = await registries.create({
      name: "issuer",
      registryName: "backed",
      noBackers: false,
      toad: 2,
      baks: BACKERS,
      nonce: NONCE,
    });
    return { regser_raw: result.regser.raw, serder_raw: result.serder.raw, sigs: result.sigs };
  },
);

const generatedNonceShape = await (async () => {
  const before = recorded.length;
  const result = await registries.create({ name: "issuer", registryName: "generated" });
  const request = recorded[recorded.length - 1];
  const body = JSON.parse(request.body);
  return {
    path: request.path,
    method: request.method,
    body_fields: Object.keys(body),
    vcp_fields: Object.keys(body.vcp),
    nonce_code: body.vcp.n.slice(0, 1),
    nonce_length: body.vcp.n.length,
    requests: recorded.length - before,
    regser_said_is_vcp_prefix: result.regser.pre === body.vcp.i,
    note: "with no nonce the reference draws one from `randomNonce()`, so the registry identifier cannot be pinned; this records the shape instead",
  };
})();

const establishmentOnly = await (async () => {
  nextIdentifier = ESTABLISHMENT_ONLY;
  const before = recorded.length;
  let error = null;
  try {
    await registries.create({ name: "estonly", registryName: "nope", nonce: NONCE });
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  nextIdentifier = ORDINARY;
  return {
    identifier_configuration: ESTABLISHMENT_ONLY.state.c,
    reference_error_message: error,
    requests_made: recorded.length - before,
    note: "the configuration trait is pushed and the registry inception is built before the throw, so the work is done and discarded; only the identifier lookup reaches the wire",
  };
})();
if (establishmentOnly.reference_error_message === null) {
  throw new Error("the reference no longer refuses an establishment-only registry");
}

// --- rename -----------------------------------------------------------------

await drive("rename", "renaming a registry, whose body is the new name alone", LISTED[0], () =>
  registries.rename("issuer", "vLEI", "renamed"),
);

await drive(
  "rename_names_needing_encoding",
  "both dynamic values carrying a slash, neither of which the path encodes",
  LISTED[0],
  () => registries.rename("a/b", "c/d", "new"),
);

// ---------------------------------------------------------------------------
// 3. What the pinned unit tree does and does not contain.
// ---------------------------------------------------------------------------

const clientingTest = parse("test/app/clienting.test.ts");
const credentialingTest = parse("test/app/credentialing.test.ts");

/** Every string literal the pinned registry test asserts, longest first. */
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

/** Which pinned test files name `Registries` at all. */
function registryTestFiles() {
  return PINNED_FILES.filter((file) => {
    if (!file.startsWith("test/")) {
      return false;
    }
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    return text.includes("Registries") || text.includes("registries()");
  });
}

const publishedEvents = publishedStrings(registryTest.source, (text) => text.startsWith('{"v":"KERI10JSON'));
const publishedPaths = publishedStrings(registryTest.source, (text) => text.startsWith("/identifiers/"));
const publishedRefusal = publishedStrings(registryTest.source, (text) => text.includes("establishment only"));

const pinnedConfirmations = {
  unit_test_file: "test/app/registry.test.ts",
  unit_test_files_naming_registries: registryTestFiles(),
  published_events: publishedEvents,
  published_paths: publishedPaths,
  published_refusal: publishedRefusal,
  issuer_prefix: "hab prefix",
  nonce: "",
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "`test/app/registry.test.ts` publishes two exact events and the establishment-only refusal, and its own asserted path shows an **unencoded space** — `/identifiers/a name/registries` — which is the encoding divergence confirmed from the reference's own suite. Its issuer prefix is the literal `'hab prefix'`, which no qualified prefix can be, so the two events are recorded verbatim here and the input is proven refused on the Rust side; byte parity comes from the driven vectors above. `credentialing.test.ts` has no registry case, and `clienting.test.ts` asserts only the accessor's type.",
};
if (pinnedConfirmations.published_events.length !== 2) {
  throw new Error("the pinned registry test no longer publishes exactly two events");
}
if (!pinnedConfirmations.published_paths.includes("/identifiers/a name/registries")) {
  throw new Error("the pinned registry test's unencoded path is no longer where this fixture records it");
}
if (pinnedConfirmations.published_refusal.length !== 1) {
  throw new Error("the pinned establishment-only refusal is no longer published once");
}
if (credentialingTest.text.includes("registries()")) {
  throw new Error("credentialing.test.ts now has a registry case; fold it into the evidence");
}
if (!clientingTest.text.includes("client.registries() instanceof Registries")) {
  throw new Error("the accessor assertion this fixture records is no longer where it was");
}

// ---------------------------------------------------------------------------
// 4. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  no_path_encodes_its_names: {
    list: calls.find((call) => call.name === "list_alias_needing_encoding")?.request?.path ?? null,
    rename: calls.find((call) => call.name === "rename_names_needing_encoding")?.request?.path ?? null,
    expressions: {
      list: declarations.list_path,
      create: declarations.from_events_path,
      rename: declarations.rename_path,
    },
    published_by_the_unit_test: "/identifiers/a name/registries",
    note: "all three paths concatenate their names raw, so `list('a/b')` addresses `/identifiers/a/b/registries` and `rename('a/b','c/d',…)` addresses `/identifiers/a/b/registries/c/d` — four unencoded dynamic values, and Roadmap 3.10 signs `@path`. The pinned unit test asserts the unencoded form itself, with a literal space in `/identifiers/a name/registries`.",
    rust_decision:
      "refused by construction: Roadmap 5.3's `ResourcePath` encodes every dynamic component exactly once, as Roadmap 6.6 decided for the identifier family",
  },
  establishment_only_is_built_then_thrown_away: {
    detail: establishmentOnly,
    configuration: declarations.create_est_only,
    thrown: declarations.create_est_only_throw,
    note: "an establishment-only identifier has `EO` pushed into the registry configuration and the whole registry inception built from it, and only then does `create` throw — so the derivation is wasted and the identifier lookup has already gone out",
    rust_decision:
      "a typed refusal checked **before** anything is built, which is what Roadmap 6.2 decided for an establishment-only issuer; no request is sent at all",
  },
  no_backers_defaults_to_true: {
    declaration: declarations.create_defaults,
    guard: declarations.create_no_backers,
    default_body: calls.find((call) => call.name === "create_default")?.request?.body ?? null,
    backed_body: calls.find((call) => call.name === "create_with_backers")?.request?.body ?? null,
    note: "`noBackers` defaults to true, so an ordinary creation writes the `NB` trait and ignores the `baks` and `toad` it still accepts — a caller passing backers without clearing the flag gets a registry that cannot use them",
    rust_decision:
      "the backer configuration is one enum rather than a flag beside a list it silently disables: naming backers *is* choosing a backed registry, and a threshold without backers is refused",
  },
  the_result_holds_a_promise: {
    members: declarations.registry_result_members,
    op: declarations.registry_result_op,
    note: "`RegistryResult` stores the fetch promise, not its response, so `create` resolves before the POST does and a rejected POST is an unhandled rejection unless the caller awaits `op()`",
    rust_decision:
      "`create` awaits the submission and returns the answer, so a failure is a failure at the call site; the artifacts are still available beside it",
  },
  the_anchor_seals_the_registry_to_itself: {
    declaration: declarations.create_anchor,
    note: "the interaction event anchors `{i: regser.pre, s: '0', d: regser.pre}` — the registry's identifier in both the identifier and the digest slot, because a registry inception's SAID *is* its prefix",
    rust_decision: "reproduced exactly; Roadmap 4.7's inception yields both from one event",
  },
  create_builds_its_keeper_twice: {
    body: declarations.from_events_algorithm,
    scan: scan("this.client.manager!.get(hab)"),
    note: "`create` resolves the keeper to sign the interaction event and `createFromEvents` resolves it again to write its parameters, so a salty identifier runs its Argon2 derivation twice per registry",
    rust_decision: "resolved once and reused, which changes no byte and halves the cost",
  },
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-24",
  sources: [
    "src/keri/app/credentialing.ts",
    "test/app/registry.test.ts",
    "test/app/clienting.test.ts",
    "test/app/credentialing.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    nonce: NONCE,
    backers: BACKERS,
    stamp: STAMP,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    identifier: ORDINARY.prefix,
    establishment_only_identifier: ESTABLISHMENT_ONLY.prefix,
    note: "`Registries` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would, and the identifier lookup `create` performs is answered with a deterministic record. Key material derives at the reference's production Argon2 profile; the nonce is pinned so a registry inception is reproducible, and each sealed salt is masked as `<SXLT>` and recorded by what it opens to. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  identifier_records: {
    ordinary: sanitizeRecord(ORDINARY),
    establishment_only: sanitizeRecord(ESTABLISHMENT_ONLY),
    note: "the two identifier records `create` looks up. Each sealed salt is masked as `<SXLT>` and recorded by what it opens to, because a fresh ephemeral key seals it every run; the Rust side seals that salt again with the same controller key before reloading a keeper from the record.",
  },
  calls,
  generated_nonce_shape: generatedNonceShape,
  establishment_only: establishmentOnly,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-registries/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-registries fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
