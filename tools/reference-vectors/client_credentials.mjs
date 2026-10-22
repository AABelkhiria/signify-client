// Records the pinned signify-ts checkout's credentials endpoint.
//
// This ports `Credentials.{list,get,delete,state,issue,revoke}` from
// `src/keri/app/credentialing.ts`, together with the `CredentialFilter` declaration `list` sends as
// a body and the two result interfaces `issue` and `revoke` return.
//
// Unlike the registries endpoint, this family **is** exercised by the pinned unit tree: the single
// `Credentials` case in `test/app/credentialing.test.ts` calls all six methods and asserts their
// paths, methods, and body fields. So this generator drives the reference through that test's own
// mocks — `mockGetAID` and `mockCredential`, read out of `test/app/test-utils.ts` by the
// reference's own compiler — which makes every identifier, registry, and credential value here one
// the reference's own suite asserts against rather than one this generator invented.
//
// Two things are pinned so `issue` and `revoke` are reproducible at all: the **clock**, because
// both default their timestamp to a clock reading, and the **agent's key**, as the
// `client-lifecycle` fixture pinned it. `issue` and `revoke` sign with a real keeper at the reference's production
// Argon2 profile, so this generator takes several seconds.
//
// One field is **added** to the reference's own mock: `mockGetAID` carries no `icp_dt`, which its
// own generated schema declares required, so the identifier record would not decode on the Rust
// side. The generator adds it and records that it did. Nothing derived reads the field, so no
// recorded byte changes; the omission is itself recorded as a pinned observation, beside the larger
// one that `mockCredential` does not satisfy the `Credential` schema `get` casts its answer to.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The passcode and URLs the pinned `credentialing.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;
/** How the reference spells that instant, which is the `dt` both `issue` and `revoke` default to. */
const FIXED_STAMP = "2023-11-14T22:13:20.123000+00:00";

/** The inception timestamp the reference's own mock omits and its own schema requires. */
const ADDED_INCEPTION_STAMP = "2023-08-21T22:30:46.473545+00:00";

// ---------------------------------------------------------------------------
// 0. Pin the clock, so `issue`, `revoke`, and every signed request are deterministic.
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

const credentialing = parse("src/keri/app/credentialing.ts");
const testUtils = parse("test/app/test-utils.ts");
const credentialingTest = parse("test/app/credentialing.test.ts");
const clientingTest = parse("test/app/clienting.test.ts");
const schemaTypes = parse("src/types/keria-api-schema.ts");

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

/** The `const [, name] = …` array-destructuring declaration the two `saidify` calls use. */
function destructuredDeclaration(node, name) {
  return firstText(
    node,
    (child) =>
      ts.isVariableDeclaration(child) &&
      ts.isArrayBindingPattern(child.name) &&
      child.name.elements.some((element) => ts.isBindingElement(element) && element.name.getText() === name),
  );
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

/** The whole text of one generated schema type literal. */
function schemaType(typeName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isPropertySignature(node) && node.name?.getText() === typeName) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(schemaTypes.source, visit);
  return found;
}

/** Reads one exported object-literal constant out of a pinned file, as JSON. */
function objectLiteral(source, name) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      node.name.getText() === name &&
      node.initializer !== undefined &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      // The literals are plain JSON apart from their single quotes and trailing commas.
      found = JSON.parse(
        node.initializer
          .getText()
          .replace(/'/g, '"')
          .replace(/,(\s*[}\]])/g, "$1")
          .replace(/([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)\s*:/g, '$1"$2":'),
      );
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

const listMethod = method(credentialing.source, "Credentials", "list");
const getMethod = method(credentialing.source, "Credentials", "get");
const deleteMethod = method(credentialing.source, "Credentials", "delete");
const stateMethod = method(credentialing.source, "Credentials", "state");
const issueMethod = method(credentialing.source, "Credentials", "issue");
const revokeMethod = method(credentialing.source, "Credentials", "revoke");

const declarations = {
  class_members: classMembers(credentialing.source, "Credentials"),
  filter_interface: interfaceText(credentialing.source, "CredentialFilter"),
  issue_result_interface: interfaceText(credentialing.source, "IssueCredentialResult"),
  revoke_result_interface: interfaceText(credentialing.source, "RevokeCredentialResult"),

  list_path: localDeclaration(listMethod, "path"),
  list_filter_default: localDeclaration(listMethod, "filtr"),
  list_sort_default: localDeclaration(listMethod, "sort"),
  list_limit_default: localDeclaration(listMethod, "limit"),
  list_skip_default: localDeclaration(listMethod, "skip"),
  list_body: localDeclaration(listMethod, "data"),

  get_path: localDeclaration(getMethod, "path"),
  get_headers: localDeclaration(getMethod, "headers"),
  get_return: firstText(getMethod, (node) => ts.isReturnStatement(node) && node.getText().includes("includeCESR")),

  delete_path: localDeclaration(deleteMethod, "path"),
  delete_fetch: firstText(deleteMethod, (node) => ts.isCallExpression(node) && node.getText().includes("this.client.fetch")),

  state_path: localDeclaration(stateMethod, "path"),

  issue_est_only: localDeclaration(issueMethod, "estOnly"),
  issue_est_only_throw: firstText(
    issueMethod,
    (node) => ts.isThrowStatement(node) && node.getText().includes("Establishment only"),
  ),
  issue_subject: destructuredDeclaration(issueMethod, "subject"),
  issue_acdc: destructuredDeclaration(issueMethod, "acdc"),
  issue_iss: destructuredDeclaration(issueMethod, "iss"),
  issue_anchor: localDeclaration(issueMethod, "anc"),
  issue_path: localDeclaration(issueMethod, "path"),
  issue_body: localDeclaration(issueMethod, "body"),

  revoke_credential_lookup: localDeclaration(revokeMethod, "cred"),
  revoke_registry_lookup: firstText(
    revokeMethod,
    (node) => ts.isIfStatement(node) && node.getText().includes("'ri' in cred.sad"),
  ),
  revoke_rev: localDeclaration(revokeMethod, "_rev"),
  revoke_saidify: destructuredDeclaration(revokeMethod, "rev"),
  revoke_body: localDeclaration(revokeMethod, "body"),
  revoke_path: localDeclaration(revokeMethod, "path"),

  credential_schema: schemaType("Credential"),
  notes: {
    list: "`list` is the only read in the family that is a `POST`: its filter, sort, skip, and limit become a JSON body sent to `/credentials/query`, and all four are written whether or not the caller supplied them",
    get: "`get` takes a boolean second parameter with four overload signatures, and selects between `res.json()` and `res.text()` on it — the same call returns two unrelated types",
    delete: "`delete` calls `fetch` with three arguments, so its `data` is `undefined` and `JSON.stringify(undefined)` leaves the request with no body at all",
    issue: "`issue` addresses `hab.name` — the alias the **agent** answered with — rather than the `name` the caller asked for, and defaults the credential's issuer to `hab.prefix` without ever checking a supplied one",
    revoke: "`revoke` reads the credential back from the agent to learn its registry and its prior digest, so it cannot build a revocation offline, and writes the sequence number as the literal `'1'`",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. The reference's own mocks, read from its test helper.
// ---------------------------------------------------------------------------

const MOCK_GET_AID = objectLiteral(testUtils.source, "mockGetAID");
const MOCK_CREDENTIAL = objectLiteral(testUtils.source, "mockCredential");
if (MOCK_GET_AID === null || MOCK_CREDENTIAL === null) {
  throw new Error("the pinned mocks are no longer where this generator expects them");
}

/** Fields the generated `Credential` schema declares, so the mock can be compared with it. */
const CREDENTIAL_SCHEMA_FIELDS = ["sad", "atc", "iss", "issatc", "pre", "schema", "chains", "status", "anchor", "anc", "ancatc"];

const mockShortfall = {
  identifier_record_fields: Object.keys(MOCK_GET_AID),
  identifier_record_missing: ["icp_dt"].filter((field) => !(field in MOCK_GET_AID)),
  credential_record_fields: Object.keys(MOCK_CREDENTIAL),
  credential_schema_fields: CREDENTIAL_SCHEMA_FIELDS,
  credential_record_missing: CREDENTIAL_SCHEMA_FIELDS.filter((field) => !(field in MOCK_CREDENTIAL)),
  credential_record_extra: Object.keys(MOCK_CREDENTIAL).filter((field) => !CREDENTIAL_SCHEMA_FIELDS.includes(field)),
  added_inception_stamp: ADDED_INCEPTION_STAMP,
  credential_status_seal: MOCK_CREDENTIAL.status.a,
  credential_status_seal_sequence_type: typeof MOCK_CREDENTIAL.status.a.s,
  credential_status_schema_sequence_type: "string",
  note: "the reference's own mocks do not satisfy the schema its production code casts to. `mockGetAID` carries no `icp_dt`, which `HabState` declares required, so this generator adds one — nothing derived reads it, so no recorded byte changes. `mockCredential` is missing seven of the eleven fields `Credential` declares and carries two the schema does not, and `Credentials.get` hands it to a caller as a credential anyway; that one is recorded rather than repaired, and the Rust side is shown refusing it.",
};
if (mockShortfall.identifier_record_missing.length !== 1) {
  throw new Error("`mockGetAID` now carries an `icp_dt`; drop the added field and the note with it");
}
if (mockShortfall.credential_record_missing.length === 0) {
  throw new Error("`mockCredential` now satisfies its own schema; re-record what this fixture proves refused");
}

/** The identifier record every lookup answers with: the reference's own, with `icp_dt` added. */
const PINNED_IDENTIFIER = { ...MOCK_GET_AID, icp_dt: ADDED_INCEPTION_STAMP };
/** The same record with the `EO` trait, which refuses an interaction event. */
const ESTABLISHMENT_ONLY = {
  ...PINNED_IDENTIFIER,
  name: "estonly",
  state: { ...PINNED_IDENTIFIER.state, c: ["EO"] },
};
/** The same record answering under a different alias than the one asked for. */
const RENAMED_BY_AGENT = { ...PINNED_IDENTIFIER, name: "chosen-by-the-agent" };

/** A credential record that does satisfy the schema, so a positive `get` has an answer. */
const WELL_FORMED_CREDENTIAL = {
  sad: MOCK_CREDENTIAL.sad,
  atc: "-IABEMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo0AAAAAAAAAAAAAAAAAAAAAAAENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW",
  iss: {
    v: "KERI10JSON0000ed_",
    t: "iss",
    d: "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW",
    i: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
    s: "0",
    ri: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
    dt: "2023-08-23T15:16:07.553000+00:00",
  },
  issatc: "-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAACEIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt",
  pre: MOCK_CREDENTIAL.pre,
  schema: {
    $id: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "Qualified vLEI Issuer Credential",
    description: "A vLEI Credential issued by GLEIF to Qualified vLEI Issuers",
    type: "object",
    credentialType: "QualifiedvLEIIssuervLEICredential",
    version: "1.0.0",
    properties: { LEI: { type: "string" } },
    additionalProperties: false,
    required: ["i", "ri", "s", "d"],
  },
  chains: [],
  status: {
    vn: [1, 0],
    i: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
    s: "0",
    d: "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW",
    ri: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
    a: { s: "2", d: "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt" },
    dt: "2023-08-23T15:16:07.553000+00:00",
    et: "iss",
    ra: {},
  },
  anchor: { pre: MOCK_CREDENTIAL.pre, sn: 2, d: "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt" },
  anc: {
    v: "KERI10JSON0000cb_",
    t: "ixn",
    d: "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt",
    i: MOCK_CREDENTIAL.pre,
    s: "2",
    p: "EIpgyKVF0z0Pcn2_HgbWhEKmJhOXFeD4SA62SrxYXOLt",
    a: [{ i: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo", s: "0", d: "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW" }],
  },
  ancatc: ["-AABAAB6a1p98ULvzM8vRvZUEc6RGRQmwVXAJ7T-vfQvXvOw"],
};

/** A credential naming neither `ri` nor `rd`, which is the one input `revoke` refuses. */
const REGISTRYLESS_CREDENTIAL = {
  ...MOCK_CREDENTIAL,
  sad: { v: MOCK_CREDENTIAL.sad.v, d: MOCK_CREDENTIAL.sad.d, i: MOCK_CREDENTIAL.sad.i, s: MOCK_CREDENTIAL.sad.s, a: MOCK_CREDENTIAL.sad.a },
};

// ---------------------------------------------------------------------------
// 3. A KERIA agent, answering and signing as the `client-lifecycle` fixture did.
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

const recorded = [];
/** What each routed resource answers with next. */
let nextIdentifier = PINNED_IDENTIFIER;
let nextCredential = MOCK_CREDENTIAL;
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
    accept: init.headers instanceof Headers ? (init.headers.get("Accept") ?? null) : null,
  });

  let payload = nextPayload;
  if (path.startsWith("/agent/") && httpMethod === "GET") {
    payload = { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 };
  } else if (/^\/identifiers\/[^/]+$/.test(path) && httpMethod === "GET") {
    payload = nextIdentifier;
  } else if (path.startsWith("/credentials/") && httpMethod === "GET") {
    payload = nextCredential;
  }
  const responseHeaders = signedHeaders(httpMethod, path);
  responseHeaders.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status: 200, headers: responseHeaders });
};

await client.boot();
await client.connect();

const credentials = client.credentials();

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
        : { path: request.path, method: request.method, body: request.body, accept: request.accept },
    requests: recorded.length - before,
    // What the mocked agent answered the *last* request with, which is what a Rust test must
    // script to reach the same place; `result` is what the reference's method returned.
    answer: payload,
    result: result === undefined ? null : result,
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

// --- list -------------------------------------------------------------------

/** The exact filter the pinned `credentialing.test.ts` sends. */
const PINNED_FILTER = {
  filter: { "-i": { $eq: "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX" } },
  sort: [{ "-s": 1 }],
  limit: 25,
  skip: 5,
};

await drive("list_default", "a listing with no arguments at all, whose four fields are the defaults", [], () =>
  credentials.list(),
);

await drive("list_pinned_filter", "the exact filter the pinned unit test sends and asserts", [], () =>
  credentials.list(PINNED_FILTER),
);

await drive("list_partial", "only a limit, so the other three fields are still written", [], () =>
  credentials.list({ limit: 1 }),
);

// --- get --------------------------------------------------------------------

const PINNED_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const CREDENTIAL_SAID = MOCK_CREDENTIAL.sad.d;
const CREDENTIAL_REGISTRY = MOCK_CREDENTIAL.sad.ri;

await drive("get_json", "the pinned unit test's own read, whose SAID is a schema's", WELL_FORMED_CREDENTIAL, () => {
  nextCredential = WELL_FORMED_CREDENTIAL;
  return credentials.get(PINNED_SCHEMA_SAID);
});
nextCredential = MOCK_CREDENTIAL;

await drive("get_cesr", "the same read with `includeCESR`, which returns text rather than a document", {}, () => {
  nextCredential = WELL_FORMED_CREDENTIAL;
  return credentials.get(PINNED_SCHEMA_SAID, true);
});
nextCredential = MOCK_CREDENTIAL;

await drive(
  "get_mock_credential",
  "the reference's own `mockCredential`, handed to the caller as a `Credential` although it satisfies none of the schema",
  {},
  () => credentials.get(CREDENTIAL_SAID),
);

await drive(
  "get_said_needing_encoding",
  "a SAID carrying a slash, a query, and a fragment, none of which the path encodes",
  {},
  () => credentials.get("E/../identifiers?x=1#y"),
);

// --- delete -----------------------------------------------------------------

await drive("delete", "the pinned unit test's own delete, which sends no body at all", {}, () =>
  credentials.delete(CREDENTIAL_SAID),
);

// --- state ------------------------------------------------------------------

await drive("state", "the pinned unit test's own state read, addressing the registry and the credential", WELL_FORMED_CREDENTIAL.status, () =>
  credentials.state(CREDENTIAL_REGISTRY, CREDENTIAL_SAID),
);

await drive(
  "state_names_needing_encoding",
  "both dynamic values carrying a slash, neither of which the path encodes",
  {},
  () => credentials.state("a/b", "c/d"),
);

// --- issue ------------------------------------------------------------------

/** The exact arguments the pinned `credentialing.test.ts` passes to `issue`. */
const PINNED_ISSUE = {
  ri: "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX",
  s: PINNED_SCHEMA_SAID,
  a: { i: "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p", LEI: "1234" },
};

/** One credential operation, the shape an issuance is answered with. */
const CREDENTIAL_OPERATION = {
  name: `credential.${CREDENTIAL_SAID}`,
  metadata: { ced: MOCK_CREDENTIAL.sad, depends: null },
  done: false,
};

await drive("issue_pinned", "the pinned unit test's own issuance, against its own mocked identifier", CREDENTIAL_OPERATION, async () => {
  const result = await credentials.issue("aid1", PINNED_ISSUE);
  return {
    acdc_raw: result.acdc.raw,
    acdc_said: result.acdc.sad.d,
    attributes_said: result.acdc.sad.a.d,
    iss_raw: result.iss.raw,
    iss_said: result.iss.sad.d,
    anc_raw: result.anc.raw,
    anc_said: result.anc.sad.d,
  };
});

await drive(
  "issue_with_explicit_issuer",
  "an issuer the caller names, which the reference writes into the credential without comparing it to the identifier signing the anchor",
  CREDENTIAL_OPERATION,
  async () => {
    const result = await credentials.issue("aid1", {
      ...PINNED_ISSUE,
      i: "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
    });
    return {
      acdc_raw: result.acdc.raw,
      credential_issuer: result.acdc.sad.i,
      anchoring_identifier: result.anc.sad.i,
      iss_raw: result.iss.raw,
      anc_raw: result.anc.raw,
    };
  },
);

const renamedByAgent = await (async () => {
  nextIdentifier = RENAMED_BY_AGENT;
  const before = recorded.length;
  await credentials.issue("aid1", PINNED_ISSUE);
  nextIdentifier = PINNED_IDENTIFIER;
  const request = recorded[recorded.length - 1];
  return {
    asked_for: "aid1",
    answered_with: RENAMED_BY_AGENT.name,
    path: request.path,
    method: request.method,
    requests: recorded.length - before,
    note: "`issue` interpolates `hab.name`, the alias the agent answered with, so the resource the credential is posted to — and the path request authentication signs — is chosen by the server rather than by the caller",
  };
})();
if (renamedByAgent.path !== `/identifiers/${RENAMED_BY_AGENT.name}/credentials`) {
  throw new Error("`issue` no longer addresses the agent's own alias");
}

const issueEstablishmentOnly = await (async () => {
  nextIdentifier = ESTABLISHMENT_ONLY;
  const before = recorded.length;
  let error = null;
  try {
    await credentials.issue("estonly", PINNED_ISSUE);
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  nextIdentifier = PINNED_IDENTIFIER;
  return {
    identifier_configuration: ESTABLISHMENT_ONLY.state.c,
    reference_error_message: error,
    requests_made: recorded.length - before,
    note: "`issue` reads the configuration straight after the lookup and throws before deriving anything, so only the identifier lookup reaches the wire — which is where this port refuses too",
  };
})();
if (issueEstablishmentOnly.reference_error_message === null) {
  throw new Error("the reference no longer refuses an establishment-only issuance");
}

// --- revoke -----------------------------------------------------------------

/** One done operation, the shape a revocation is answered with. */
const REVOCATION_OPERATION = {
  name: `done.${CREDENTIAL_SAID}`,
  metadata: { pre: PINNED_IDENTIFIER.prefix, sn: 1 },
  done: true,
  response: { name: `done.${CREDENTIAL_SAID}` },
};

await drive("revoke_pinned", "the pinned unit test's own revocation, which reads the credential back first", REVOCATION_OPERATION, async () => {
  const result = await credentials.revoke("aid1", CREDENTIAL_SAID);
  return {
    rev_raw: result.rev.raw,
    rev_said: result.rev.sad.d,
    anc_raw: result.anc.raw,
    anc_said: result.anc.sad.d,
  };
});

// The pinned unit test revokes `lastBody.acdc.i` — the credential's *issuer*, which is the
// identifier's own prefix — so this reproduces the five values it asserts directly.
await drive(
  "revoke_unit_test_subject",
  "the exact SAID the pinned unit test revokes, which is the identifier's own prefix rather than a credential's",
  REVOCATION_OPERATION,
  async () => {
    const result = await credentials.revoke("aid1", PINNED_IDENTIFIER.prefix);
    return {
      rev_raw: result.rev.raw,
      rev_credential: result.rev.sad.i,
      rev_sequence: result.rev.sad.s,
      rev_kind: result.rev.sad.t,
      rev_registry: result.rev.sad.ri,
      anc_raw: result.anc.raw,
      anc_kind: result.anc.sad.t,
      anc_identifier: result.anc.sad.i,
      anc_prior: result.anc.sad.p,
    };
  },
);

await drive(
  "revoke_with_datetime",
  "a revocation whose timestamp the caller supplies rather than the clock",
  REVOCATION_OPERATION,
  async () => {
    const result = await credentials.revoke("aid1", CREDENTIAL_SAID, "2023-08-23T15:16:07.553000+00:00");
    return { rev_raw: result.rev.raw, anc_raw: result.anc.raw };
  },
);

await drive(
  "revoke_said_needing_encoding",
  "an alias and a credential SAID both carrying a slash, neither of which the path encodes",
  REVOCATION_OPERATION,
  async () => {
    const result = await credentials.revoke("a/b", "c/d");
    return { rev_raw: result.rev.raw };
  },
);

const revokeWithoutRegistry = await (async () => {
  nextCredential = REGISTRYLESS_CREDENTIAL;
  const before = recorded.length;
  let error = null;
  try {
    await credentials.revoke("aid1", CREDENTIAL_SAID);
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  nextCredential = MOCK_CREDENTIAL;
  return {
    credential_fields: Object.keys(REGISTRYLESS_CREDENTIAL.sad),
    reference_error_message: error,
    requests_made: recorded.length - before,
    note: "`revoke` names the registry from the credential the agent hands back, so a credential carrying neither `ri` nor `rd` cannot be revoked at all — and the registry a revocation commits to is the server's answer rather than the caller's input",
  };
})();
if (revokeWithoutRegistry.reference_error_message === null) {
  throw new Error("the reference no longer refuses a credential with no registry");
}

// ---------------------------------------------------------------------------
// 4. What the pinned unit tree does and does not contain.
// ---------------------------------------------------------------------------

/** Every string literal a pinned test asserts, filtered. */
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

/** Which pinned test files name this family at all. */
function credentialTestFiles() {
  return PINNED_FILES.filter((file) => {
    if (!file.startsWith("test/")) {
      return false;
    }
    const text = readFileSync(upstreamUrl(file), "utf8");
    return text.includes("credentials()") || text.includes("new Credentials");
  });
}

/** Reads back one driven call's request body as a document. */
function drivenBody(name) {
  const body = calls.find((call) => call.name === name)?.request?.body ?? null;
  return body === null ? null : JSON.parse(body);
}

/**
 * Every value the pinned unit test asserts, reproduced from the driven calls.
 *
 * The test's own `issue` and `revoke` read the clock, so it asserts fields rather than bytes; each
 * of those fields is recomputed here from what the reference actually produced under the pinned
 * clock, so the Rust side checks the same values rather than a paraphrase of them.
 */
const unitTestAssertions = (() => {
  const issued = drivenBody("issue_pinned");
  const revoked = drivenBody("revoke_unit_test_subject");
  const assertions = {
    list_path: calls.find((call) => call.name === "list_pinned_filter")?.request?.path ?? null,
    list_method: calls.find((call) => call.name === "list_pinned_filter")?.request?.method ?? null,
    list_body: PINNED_FILTER,
    get_path: calls.find((call) => call.name === "get_json")?.request?.path ?? null,
    get_method: "GET",
    issue_path: calls.find((call) => call.name === "issue_pinned")?.request?.path ?? null,
    issue_method: "POST",
    issue_acdc_registry: issued?.acdc?.ri ?? null,
    issue_acdc_schema: issued?.acdc?.s ?? null,
    issue_acdc_issuee: issued?.acdc?.a?.i ?? null,
    issue_acdc_lei: issued?.acdc?.a?.LEI ?? null,
    issue_iss_sequence: issued?.iss?.s ?? null,
    issue_iss_kind: issued?.iss?.t ?? null,
    issue_iss_registry: issued?.iss?.ri ?? null,
    issue_iss_names_the_credential: issued?.iss?.i === issued?.acdc?.d,
    issue_ixn_kind: issued?.ixn?.t ?? null,
    issue_ixn_names_the_issuer: issued?.ixn?.i === issued?.acdc?.i,
    issue_ixn_prior_is_the_issuer: issued?.ixn?.p === issued?.acdc?.i,
    issue_signature_prefix: issued?.sigs?.[0]?.slice(0, 2) ?? null,
    issue_signature_length: issued?.sigs?.[0]?.length ?? null,
    revoke_path: calls.find((call) => call.name === "revoke_unit_test_subject")?.request?.path ?? null,
    revoke_method: "DELETE",
    revoke_rev_sequence: revoked?.rev?.s ?? null,
    revoke_rev_kind: revoked?.rev?.t ?? null,
    revoke_rev_registry: revoked?.rev?.ri ?? null,
    revoke_rev_credential: revoked?.rev?.i ?? null,
    revoke_ixn_kind: revoked?.ixn?.t ?? null,
    revoke_ixn_identifier: revoked?.ixn?.i ?? null,
    revoke_ixn_prior: revoked?.ixn?.p ?? null,
    revoke_signature_prefix: revoked?.sigs?.[0]?.slice(0, 2) ?? null,
    revoke_signature_length: revoked?.sigs?.[0]?.length ?? null,
    state_path: calls.find((call) => call.name === "state")?.request?.path ?? null,
    state_method: "GET",
    state_body: calls.find((call) => call.name === "state")?.request?.body ?? null,
    delete_path: calls.find((call) => call.name === "delete")?.request?.path ?? null,
    delete_method: "DELETE",
    delete_body: calls.find((call) => call.name === "delete")?.request?.body ?? null,
  };
  const expected = {
    list_path: "/credentials/query",
    get_path: `/credentials/${PINNED_SCHEMA_SAID}`,
    issue_path: "/identifiers/aid1/credentials",
    issue_acdc_registry: PINNED_ISSUE.ri,
    issue_acdc_schema: PINNED_ISSUE.s,
    issue_acdc_issuee: PINNED_ISSUE.a.i,
    issue_acdc_lei: "1234",
    issue_iss_sequence: "0",
    issue_iss_kind: "iss",
    issue_iss_registry: PINNED_ISSUE.ri,
    issue_iss_names_the_credential: true,
    issue_ixn_kind: "ixn",
    issue_ixn_names_the_issuer: true,
    issue_ixn_prior_is_the_issuer: true,
    issue_signature_prefix: "AA",
    issue_signature_length: 88,
    revoke_path: `/identifiers/aid1/credentials/${PINNED_IDENTIFIER.prefix}`,
    revoke_rev_sequence: "1",
    revoke_rev_kind: "rev",
    revoke_rev_registry: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
    revoke_rev_credential: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
    revoke_ixn_kind: "ixn",
    revoke_ixn_identifier: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
    revoke_ixn_prior: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
    revoke_signature_prefix: "AA",
    revoke_signature_length: 88,
    state_path: `/registries/${CREDENTIAL_REGISTRY}/${CREDENTIAL_SAID}`,
    state_body: null,
    delete_path: `/credentials/${CREDENTIAL_SAID}`,
    delete_body: null,
  };
  for (const [label, value] of Object.entries(expected)) {
    if (JSON.stringify(assertions[label]) !== JSON.stringify(value)) {
      throw new Error(`the pinned unit test's ${label} no longer reproduces: ${JSON.stringify(assertions[label])}`);
    }
  }
  return {
    ...assertions,
    note: "every value `test/app/credentialing.test.ts` asserts, recomputed from what the reference produced here under the pinned clock. The generator fails if any of them stops reproducing, so this block is the anchor: the fixture's driven calls are the reference's own suite's values rather than this generator's inventions.",
  };
})();

const pinnedConfirmations = {
  unit_test_file: "test/app/credentialing.test.ts",
  unit_test_assertions: unitTestAssertions,
  unit_test_files_naming_credentials: credentialTestFiles(),
  published_paths: publishedStrings(credentialingTest.source, (text) => text.startsWith("/credentials") || text.startsWith("/identifiers") || text.startsWith("/registries")),
  published_identifiers: publishedStrings(credentialingTest.source, (text) => /^E[A-Za-z0-9_-]{43}$/.test(text)),
  asserted_registry: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
  asserted_revocation_credential: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
  accessor_assertion: clientingTest.text.includes("client.credentials() instanceof Credentials"),
  usage_scan: scan("credentials()"),
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "the pinned `credentialing.test.ts` exercises all six methods in one case, asserting each path, each method, and — for `issue` and `revoke` — the fields of each body. Its identifier is `mockGetAID` and its credential is `mockCredential`, both read here from `test/app/test-utils.ts` by the reference's own compiler, so every value in this fixture is one the reference's own suite asserts against. What it does **not** assert is any exact body: `issue` and `revoke` both read the clock, so the test checks fields rather than bytes. Pinning the clock is what makes the bytes reproducible here.",
};
if (!pinnedConfirmations.accessor_assertion) {
  throw new Error("the accessor assertion this fixture records is no longer where it was");
}
if (pinnedConfirmations.unit_test_files_naming_credentials.length !== 2) {
  throw new Error("the pinned unit tree's credential coverage has moved");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  no_path_encodes_its_names: {
    get: calls.find((call) => call.name === "get_said_needing_encoding")?.request?.path ?? null,
    state: calls.find((call) => call.name === "state_names_needing_encoding")?.request?.path ?? null,
    revoke: calls.find((call) => call.name === "revoke_said_needing_encoding")?.request?.path ?? null,
    expressions: {
      get: declarations.get_path,
      delete: declarations.delete_path,
      state: declarations.state_path,
      issue: declarations.issue_path,
      revoke: declarations.revoke_path,
    },
    note: "five of the six methods interpolate their arguments raw — seven dynamic values in all — so a SAID holding `/`, `?`, or `#` addresses a different resource, and request authentication signs `@path`, so it also changes what the signature commits to",
    rust_decision:
      "refused by construction: a SAID and a registry identifier are validated types, which cannot hold a delimiter, and `ResourcePath` encodes an alias exactly once",
  },
  issue_addresses_the_agents_own_alias: {
    detail: renamedByAgent,
    expression: declarations.issue_path,
    note: "`issue` posts to `/identifiers/${hab.name}/credentials`, where `hab` is the record the **agent** answered with — so a server that answers under a different alias chooses the resource the credential is written to and the path the request's signature covers",
    rust_decision: "the caller's own alias addresses the resource, so the server cannot redirect a write it is the recipient of",
  },
  issue_never_checks_the_issuer_it_was_given: {
    credential_issuer:
      calls.find((call) => call.name === "issue_with_explicit_issuer")?.result?.credential_issuer ?? null,
    anchoring_identifier:
      calls.find((call) => call.name === "issue_with_explicit_issuer")?.result?.anchoring_identifier ?? null,
    expression: declarations.issue_acdc,
    note: "the credential's issuer is `args.i ?? hab.prefix`, and nothing compares a supplied one with the identifier whose keeper signs the anchor — so a credential can claim an issuer whose key event log contains no anchor for it, which no verifier can ever resolve",
    rust_decision:
      "refused: the credential arrives already built, so its issuer is compared with the identifier being used to anchor it and a mismatch is a typed refusal before anything is signed",
  },
  revoke_reads_its_registry_from_the_server: {
    detail: revokeWithoutRegistry,
    lookup: declarations.revoke_registry_lookup,
    rev: declarations.revoke_rev,
    note: "`revoke` fetches the credential to learn both the registry it commits to and the prior digest it supersedes, so a revocation cannot be built offline and both values are the agent's rather than the caller's; the sequence number is the literal `'1'`, wrong in any registry whose log has moved on",
    rust_decision:
      "the revocation event is an input built by the `revocation` module, where all three are ordinary values defaulting to the reference's; the endpoint sends it and looks up nothing",
  },
  get_returns_two_unrelated_types: {
    json: calls.find((call) => call.name === "get_json")?.request?.accept ?? null,
    cesr: calls.find((call) => call.name === "get_cesr")?.request?.accept ?? null,
    headers: declarations.get_headers,
    returned: declarations.get_return,
    note: "one method, a boolean second parameter, four overload signatures, and two return types — `res.json()` or `res.text()` — selected at run time by a flag",
    rust_decision:
      "two methods, `get` and `get_cesr`, because the answers are different types; the flag has nowhere to live, and a boolean mode argument is not a shape this port's API conventions allow",
  },
  a_cesr_answer_is_repaired_rather_than_refused: {
    expression: declarations.get_return,
    note: "`res.text()` decodes the body as UTF-8 with replacement, so a CESR stream carrying an invalid byte comes back with U+FFFD substituted into it and reads as a valid — but different — stream",
    rust_decision: "a body that is not UTF-8 is a typed failure, because a repaired CESR stream is worse than none",
  },
  the_answer_is_cast_rather_than_decoded: {
    mock: mockShortfall,
    schema: declarations.credential_schema,
    recorded_answer: calls.find((call) => call.name === "get_mock_credential")?.result ?? null,
    note: "`get`, `list`, and `state` all return `res.json()` cast to a generated type, so whatever the agent sends is read as a credential. The reference's own `mockCredential` proves the gap: it is missing seven of the eleven fields `Credential` declares, carries two the schema does not, and its status has no `vn` at all — and `Credentials.get` hands it over as a credential",
    rust_decision:
      "decoded rather than cast, as the config and schemas endpoints decided; the recorded mock is proven refused, and a well-formed record beside it is proven accepted",
  },
  a_listing_writes_every_field_it_was_not_given: {
    defaults: {
      filter: declarations.list_filter_default,
      sort: declarations.list_sort_default,
      limit: declarations.list_limit_default,
      skip: declarations.list_skip_default,
    },
    empty_body: calls.find((call) => call.name === "list_default")?.request?.body ?? null,
    partial_body: calls.find((call) => call.name === "list_partial")?.request?.body ?? null,
    note: "all four fields are written whether or not the caller supplied them, so an unfiltered listing sends `{filter:{},sort:[],skip:0,limit:25}` — the limit is a silent default rather than an absent one",
    rust_decision: "reproduced exactly, with the same four defaults on a type whose `Default` is the reference's",
  },
  a_delete_sends_no_body: {
    expression: declarations.delete_fetch,
    recorded: calls.find((call) => call.name === "delete")?.request?.body ?? null,
    note: "`delete` calls `fetch` with three arguments, so `data` is `undefined` and `JSON.stringify(undefined)` is `undefined` — the request carries no body, where every other write in the file carries one",
    rust_decision: "reproduced: no body is set on the request",
  },
  an_establishment_only_issuer_throws_a_string: {
    detail: issueEstablishmentOnly,
    declaration: declarations.issue_est_only,
    thrown: declarations.issue_est_only_throw,
    note: "`issue` refuses an establishment-only identifier by throwing a string, and `revoke` declares the same `estOnly` flag twice with `var` in one scope before doing the same",
    rust_decision:
      "a typed `ClientError::EstablishmentOnlyIssuer` checked before anything derives, which is the decision the `issuance` module and the registries endpoint made, applied again",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/credentialing.ts",
    "src/types/keria-api-schema.ts",
    "test/app/credentialing.test.ts",
    "test/app/test-utils.ts",
    "test/app/clienting.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    stamp: FIXED_STAMP,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    identifier: PINNED_IDENTIFIER.prefix,
    credential: CREDENTIAL_SAID,
    registry: CREDENTIAL_REGISTRY,
    schema: PINNED_SCHEMA_SAID,
    note: "`Credentials` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The identifier and credential every lookup answers with are the pinned unit test's own `mockGetAID` and `mockCredential`, read from `test/app/test-utils.ts` by the reference's own compiler. The clock is pinned because `issue` and `revoke` both default their timestamp to a clock reading; key material derives at the reference's production Argon2 profile, and each sealed salt is masked as `<SXLT>` and recorded by what it opens to. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  mock_records: {
    identifier: sanitizeRecord(PINNED_IDENTIFIER),
    establishment_only: sanitizeRecord(ESTABLISHMENT_ONLY),
    credential: MOCK_CREDENTIAL,
    well_formed_credential: WELL_FORMED_CREDENTIAL,
    registryless_credential: REGISTRYLESS_CREDENTIAL,
    shortfall: mockShortfall,
    note: "the records every lookup answers with. The identifier is the reference's own `mockGetAID` with `icp_dt` added; its sealed salt is masked as `<SXLT>` and recorded by what it opens to, because a fresh ephemeral key seals it every run, so the Rust side seals that salt again with the same controller key before reloading a keeper from the record.",
  },
  calls,
  renamed_by_agent: renamedByAgent,
  issue_establishment_only: issueEstablishmentOnly,
  revoke_without_registry: revokeWithoutRegistry,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-credentials/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-credentials fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
