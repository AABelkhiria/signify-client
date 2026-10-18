// Records the pinned signify-ts checkout's escrows endpoint.
//
// This fixture ports the whole of `src/keri/app/escrowing.ts`: one class with one method,
// `Escrows.listReply`, and one type alias, `Rpy`. An escrow is a message the agent received but
// could not yet accept — a reply whose signer it cannot verify, or whose prior it has not seen —
// and this is the only window the reference offers onto one.
//
// `Escrows` takes a whole `SignifyClient`, as `Config`, `KeyEvents`, and `KeyStates` do, so this
// generator drives the reference the way `client_config.mjs` does: `globalThis.fetch` is replaced
// with a recorder that answers and signs as a KERIA agent would, and the real client is walked
// through boot, connect, and each call.
//
// Two things make the evidence here worth recording rather than assuming.
//
// The **request** carries exactly one caller value, and it is a query parameter rather than a path
// component — so unlike `Oobis`, which interpolates four values raw, this one builds its query with
// `URLSearchParams` and the value *is* encoded. The pinned unit test asserts the encoded form
// directly, which makes it the clearest statement in the pinned tree that the two implementations
// agree here. The generator drives eight routes, including the ones that would climb, inject, or
// split if they were not encoded.
//
// The **answer** is `res.json()` cast to `Rpy[]`, so an agent's escrow listing is whatever it says
// it is. The generator records five answers of shapes the reference accepts unchecked, and builds
// its genuine ones with the reference's own `reply()` so a decoded record is one the reference
// itself produced.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { reply } from "./node_modules/signify-ts/dist/keri/core/eventing.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { keripyUrl, upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The scoped secondary reference, read only as corroboration. */
const keripySha = "4ce4cc79e06653f77342be1bf604086b89b1f090";

/** The passcode and URLs the pinned `escrowing.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The route the pinned unit test filters on. */
const PINNED_ROUTE = "/presentation/request";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

/** The timestamp the escrowed replies carry, so their SAIDs are fixed. */
const REPLY_STAMP = "2023-11-14T22:13:20.123000+00:00";

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
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const escrowing = parse("src/keri/app/escrowing.ts");
const schema = parse("src/types/keria-api-schema.ts");
const exchanging = parse("src/keri/app/exchanging.ts");

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

/** The whole text of one exported type alias. */
function typeAlias(source, aliasName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isTypeAliasDeclaration(node) && node.name.getText() === aliasName) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The whole text of one schema type literal. */
function schemaType(typeName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isPropertySignature(node) && node.name?.getText() === typeName) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(schema.source, visit);
  return found;
}

/** Every member a class declares, in declaration order. */
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

/** Every top-level exported name a module declares. */
function exportedNames(source) {
  const names = [];
  const visit = (node) => {
    const exported = ts.canHaveModifiers(node)
      ? (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
      : false;
    if (exported && (ts.isClassDeclaration(node) || ts.isTypeAliasDeclaration(node) || ts.isFunctionDeclaration(node))) {
      names.push(node.name?.getText() ?? "<anonymous>");
    }
  };
  ts.forEachChild(source, visit);
  return names.sort();
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

const listReply = method(escrowing.source, "Escrows", "listReply");

const declarations = {
  list_reply_params: firstText(
    listReply,
    (node) => ts.isVariableDeclaration(node) && node.name.getText() === "params",
  ),
  list_reply_guard: firstText(listReply, (node) => ts.isIfStatement(node)),
  list_reply_path: firstText(listReply, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  list_reply_method: firstText(listReply, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  list_reply_fetch: firstText(listReply, (node) => ts.isCallExpression(node) && node.getText().startsWith("this.client.fetch(")),
  list_reply_return: firstText(listReply, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  list_reply_signature: listReply?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null,
  escrows_members: classMembers(escrowing.source, "Escrows"),
  escrows_exports: exportedNames(escrowing.source),
  rpy_alias: typeAlias(escrowing.source, "Rpy"),
  rpy_schema: schemaType("Rpy"),
  rpy_v1_schema: schemaType("RPY_V_1"),
  rpy_v2_schema: schemaType("RPY_V_2"),
  rpy_alias_consumers: scan("Rpy;"),
  escrows_accessor_uses: scan(".escrows()"),
  list_reply_uses: scan("listReply"),
  pinned_route_uses: scan(PINNED_ROUTE),
  reply_route_uses: {
    end_role_add: scan("'/end/role/add'"),
    loc_scheme: scan("'/loc/scheme'"),
  },
  exchanging_imports_rpy: firstText(exchanging.source, (node) => ts.isImportDeclaration(node) && node.getText().includes("escrowing")),
  notes: {
    query:
      "the query is built with `URLSearchParams`, so the one caller value in this file *is* encoded — the opposite of what `client-oobis` found in `Oobis.get`, which interpolates four values raw into the same position",
    bare_question_mark:
      "the path concatenates `'?' + params.toString()` unconditionally, so a listing with no route addresses `/escrows/rpy?` — the same bare question mark an unfiltered `/operations` listing carries",
    absent_versus_empty:
      "the guard is `route !== undefined`, so an empty string is a route: `listReply('')` asks for `?route=` and `listReply()` asks for nothing at all",
    response:
      "`Rpy` is `RPY_V_1 | RPY_V_2`, both of which type `t` as a bare `string` and `a` as `unknown`; the reference returns `res.json()` with no validation, so any JSON at all is accepted and typed `Rpy[]` at compile time only",
    vocabulary:
      "the pinned tree names exactly one escrow route, `/presentation/request`, and it appears only in the unit test — nothing in the reference ever *produces* a reply on that route, and the two routes it does produce, `/end/role/add` and `/loc/scheme`, are never used as an escrow filter",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

if (declarations.escrows_exports.join(",") !== "Escrows,Rpy") {
  throw new Error(`escrowing.ts no longer exports exactly Escrows and Rpy: ${declarations.escrows_exports}`);
}
if (declarations.escrows_members.join(",") !== "client,<constructor>,listReply") {
  throw new Error(`the Escrows class no longer has exactly one method: ${declarations.escrows_members}`);
}

// ---------------------------------------------------------------------------
// 1b. keripy, as corroboration only.
// ---------------------------------------------------------------------------
//
// signify-ts names one escrow route and only in a test, so the vocabulary question cannot be
// settled from it. keripy is where the escrow itself lives — `Revery.escrowReply` — and its
// routers declare which routes a reply may carry at all. This block records that, and one thing
// that follows from it: `/presentation/request`, the route the pinned unit test filters on, is not
// a reply route in keripy. It appears there once, in a specification document, as the `r` of an
// **`exn`**. None of this governs the port; it is why the route stays open text.

function readKeripy(relativePath) {
  return readFileSync(keripyUrl(relativePath), "utf8");
}

/** One line of keripy, trimmed: the claim is about code, not about what a comment says. */
function keripyLine(text, needle) {
  const line = text.split("\n").find((candidate) => candidate.includes(needle) && !candidate.trimStart().startsWith("#"));
  if (line === undefined) {
    throw new Error(`keripy no longer contains ${needle}`);
  }
  return line.trim();
}

/** Every `addRoute` a named method registers, in declaration order. */
function keripyRoutes(text, methodName) {
  const lines = text.split("\n");
  const start = lines.findIndex((line) => line.includes(`def ${methodName}(`));
  if (start < 0) {
    throw new Error(`keripy no longer declares ${methodName}`);
  }
  const routes = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.includes("addRoute(")) {
      const match = /addRoute\((["'])(.*?)\1/.exec(line);
      if (match !== null) {
        routes.push(match[2]);
      }
    } else if (/^\s{4}def /.test(line) && routes.length > 0) {
      break;
    }
  }
  return routes;
}

const keripyRouting = readKeripy("src/keri/core/routing.py");
const keripyEventing = readKeripy("src/keri/core/eventing.py");
const keripyVdrEventing = readKeripy("src/keri/vdr/eventing.py");
const keripyOobiing = readKeripy("src/keri/app/oobiing.py");
const keripyPeerToPeer = readKeripy("ref/Peer2PeerCredentials.md");

const keripyReplyRoutes = [
  ...keripyRoutes(keripyEventing, "registerReplyRoutes"),
  ...keripyRoutes(keripyVdrEventing, "registerReplyRoutes"),
  ...keripyRoutes(keripyOobiing, "registerReplyRoutes"),
].sort();

const keripyCorroboration = {
  keripy_sha: keripySha,
  escrow_reply_declaration: keripyLine(keripyRouting, "def escrowReply("),
  reply_routes: keripyReplyRoutes,
  presentation_request_files: [
    ["src/keri/core/routing.py", keripyRouting],
    ["src/keri/core/eventing.py", keripyEventing],
    ["src/keri/vdr/eventing.py", keripyVdrEventing],
    ["src/keri/app/oobiing.py", keripyOobiing],
    ["ref/Peer2PeerCredentials.md", keripyPeerToPeer],
  ]
    .map(([file, text]) => ({ file, count: text.split(PINNED_ROUTE).length - 1 }))
    .filter((hit) => hit.count > 0),
  presentation_request_ilk: keripyLine(keripyPeerToPeer, '"t": "exn"'),
  presentation_request_route_line: keripyLine(keripyPeerToPeer, `"r": "${PINNED_ROUTE}"`),
  presentation_request_is_a_reply_route: keripyReplyRoutes.includes(PINNED_ROUTE),
  note: "keripy's `Revery.escrowReply` is the escrow this endpoint reads out of, and its three `registerReplyRoutes` methods declare every route a reply may carry. `/presentation/request` is not among them: it appears in keripy once, in a specification document, as the route of an **`exn`**. So the one literal signify-ts offers is not evidence about reply escrows at all, which is the strongest form of the reason this port does not turn the filter into an enum.",
  scoping:
    "corroboration only. keripy is consulted only for capabilities signify-ts cannot emit; this is not one, so signify-ts governs every byte here and keripy is read for context, exactly as `client-challenges` and `client-notifications` read it.",
};

if (keripyCorroboration.reply_routes.length === 0) {
  throw new Error("keripy no longer registers any reply routes");
}
if (keripyCorroboration.presentation_request_is_a_reply_route) {
  throw new Error("keripy now registers /presentation/request as a reply route; the note is stale");
}

// ---------------------------------------------------------------------------
// 2. A KERIA agent, answering and signing as the `client-lifecycle` fixture did.
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

const recorded = [];
let nextPayload = [];

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
  recorded.push({
    url: text,
    path: text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length),
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });

  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
  const payload =
    path.startsWith("/agent/") && httpMethod === "GET"
      ? { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 }
      : nextPayload;
  const responseHeaders = signedHeaders(httpMethod, path);
  responseHeaders.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status: 202, headers: responseHeaders });
};

await client.boot();
await client.connect();

const escrows = client.escrows();

// ---------------------------------------------------------------------------
// 3. Genuine escrowed replies, built by the reference's own `reply()`.
// ---------------------------------------------------------------------------

/** One escrowed reply message, exactly as the reference's own builder emits it. */
function escrowedReply(route, data) {
  return reply(route, data, REPLY_STAMP, undefined, undefined).sad;
}

const PINNED_REPLIES = [
  escrowedReply(PINNED_ROUTE, {
    i: controllerPrefix,
    s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
    a: { d: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo" },
  }),
  escrowedReply(PINNED_ROUTE, { i: agentPrefix, s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao", a: {} }),
];

const ROLE_REPLY = escrowedReply("/end/role/add", {
  cid: controllerPrefix,
  role: "agent",
  eid: agentPrefix,
});

// ---------------------------------------------------------------------------
// 4. Drive the reference.
// ---------------------------------------------------------------------------

const calls = [];

/**
 * Runs one listing, recording the request it produced and what it returned.
 *
 * `args` is spread, so an empty array is genuinely "called with no argument" — which is the case
 * the `route !== undefined` guard exists for.
 */
async function drive(name, note, args, payload) {
  nextPayload = payload;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    result = await escrows.listReply(...args);
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const request = recorded[before] ?? null;
  calls.push({
    name,
    note,
    arguments: args,
    answer: payload,
    request: request === null ? null : { path: request.path, method: request.method, body: request.body },
    result,
    error,
  });
  nextPayload = [];
}

await drive(
  "pinned_route",
  "the route the pinned unit test filters on, answered with two replies the reference's own `reply()` built",
  [PINNED_ROUTE],
  PINNED_REPLIES,
);

await drive(
  "no_route",
  "no argument at all: the guard skips the parameter and the path still ends in a bare question mark",
  [],
  [ROLE_REPLY],
);

await drive(
  "empty_route",
  "an empty string is a route, because the guard tests `!== undefined` rather than truthiness",
  [""],
  [],
);

await drive(
  "end_role_route",
  "one of the two reply routes the reference actually produces, though it never filters an escrow on it",
  ["/end/role/add"],
  [ROLE_REPLY],
);

await drive("loc_scheme_route", "the other reply route the reference produces", ["/loc/scheme"], []);

await drive(
  "route_with_query_delimiters",
  "a route holding `&` and `=`, which `URLSearchParams` escapes — so unlike `Oobis.get` no second parameter can be injected here",
  ["a&b=c"],
  [],
);

await drive(
  "route_with_space",
  "a route holding a space, which `URLSearchParams` writes as `+` rather than `%20`",
  ["a b"],
  [],
);

await drive(
  "route_that_would_climb",
  "a route holding `..` and `/`, which is escaped here where the same value in a path component would address another resource",
  ["../../identifiers"],
  [],
);

await drive("empty_listing", "no escrows at all, which is the ordinary answer for a healthy agent", [PINNED_ROUTE], []);

await drive(
  "wrong_ilk_answer",
  "an escrow listing whose messages are inception events; `Rpy` types `t` as a bare string, so the reference accepts them as replies",
  [PINNED_ROUTE],
  [{ ...PINNED_REPLIES[0], t: "icp" }],
);

await drive(
  "not_a_list_answer",
  "an object where a list belongs; the reference casts it to `Rpy[]` and hands it over",
  [PINNED_ROUTE],
  { count: 0 },
);

await drive(
  "incomplete_answer",
  "a reply missing the timestamp its own schema declares required",
  [PINNED_ROUTE],
  [(({ dt: _dt, ...rest }) => rest)(PINNED_REPLIES[0])],
);

await drive(
  "unknown_field_answer",
  "a reply carrying a field the schema does not declare, which the reference keeps",
  [PINNED_ROUTE],
  [{ ...ROLE_REPLY, escrowed: true }],
);

// ---------------------------------------------------------------------------
// 5. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

const escrowingTest = parse("test/app/escrowing.test.ts");

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

const publishedPaths = [...new Set(publishedStrings(escrowingTest.source, (text) => text.startsWith("/escrows")))];
const publishedRoutes = [...new Set(publishedStrings(escrowingTest.source, (text) => text === PINNED_ROUTE))];
const drivenPinned = calls.find((call) => call.name === "pinned_route")?.request ?? null;

const pinnedConfirmations = {
  published_paths: publishedPaths,
  published_routes: publishedRoutes,
  published_method: "GET",
  driven_path: drivenPinned?.path ?? null,
  driven_method: drivenPinned?.method ?? null,
  every_pinned_assertion_is_driven:
    publishedPaths.length === 1 &&
    publishedPaths[0] === "/escrows/rpy?route=%2Fpresentation%2Frequest" &&
    drivenPinned?.path === publishedPaths[0] &&
    drivenPinned?.method === "GET",
  note: "the pinned `escrowing.test.ts` asserts one URL and one method; both are recomputed here from the reference's own class, and the URL it asserts is the *encoded* form — which is the tree's own statement that this file escapes its one caller value",
};
if (!pinnedConfirmations.every_pinned_assertion_is_driven) {
  throw new Error("the pinned escrows assertions no longer reproduce");
}

// ---------------------------------------------------------------------------
// 6. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function called(name) {
  return calls.find((call) => call.name === name) ?? null;
}

const quirks = {
  an_unfiltered_listing_ends_in_a_bare_question_mark: {
    declaration: declarations.list_reply_path,
    request: called("no_route")?.request ?? null,
    note: "`path` concatenates `'?' + params.toString()` unconditionally, so a listing with no route addresses `/escrows/rpy?`",
    rust_decision:
      "not reproduced, on the same three grounds as an unfiltered `/operations` listing: request signing strips the query so the signed path is identical either way, an empty query is not a distinguishable resource, and the request builder cannot spell a bare `?` without a knob whose only users would be this call and three others like it. A live KERIA run still owes it a confirmation.",
  },
  the_answer_is_never_validated: {
    declaration: declarations.list_reply_return,
    wrong_ilk: called("wrong_ilk_answer")?.result ?? null,
    not_a_list: called("not_a_list_answer")?.result ?? null,
    incomplete: called("incomplete_answer")?.result ?? null,
    note: "`listReply` returns `res.json()` cast to `Rpy[]`, so an object, a list of inception events, and a reply with no timestamp are all handed to the caller as escrowed replies. `Rpy` types `t` as a bare `string`, so even a correct-looking cast would not have caught the first.",
    rust_decision:
      "decoded into `Vec<ReplyRecord>`, whose `t` is the `ReplyIlk` marker — so a message that is not a reply is refused rather than counted as one. All three recorded answers are proven refused.",
  },
  an_undeclared_field_is_kept: {
    answer: called("unknown_field_answer")?.answer ?? null,
    result: called("unknown_field_answer")?.result ?? null,
    note: "`res.json()` returns whatever the agent sent, so a field the schema does not declare survives into the caller's value",
    rust_decision:
      "ignored, which is the rule for a schema with no index signature. A reply's own attribute block `a` is open and *is* captured, because the schema types it `unknown`.",
  },
  the_route_is_encoded: {
    declaration: declarations.list_reply_params,
    guard: declarations.list_reply_guard,
    requests: ["route_with_query_delimiters", "route_with_space", "route_that_would_climb"].map((name) => ({
      name,
      arguments: called(name)?.arguments ?? null,
      path: called(name)?.request?.path ?? null,
    })),
    note: "the query is built with `URLSearchParams`, so `&`, `=`, `/`, and a space are all escaped — this file agrees with the port, which is worth pinning because `client-oobis` found the opposite in the same position in `Oobis.get`, and `client-contacts` found this same agreement in `Contacts.list`",
    rust_decision: "reproduced exactly; a route reaches the query encoded once and can add no second parameter",
  },
  an_empty_route_is_a_route: {
    guard: declarations.list_reply_guard,
    empty: called("empty_route")?.request?.path ?? null,
    absent: called("no_route")?.request?.path ?? null,
    note: "the guard is `route !== undefined`, so an empty string is written as `?route=` while an absent one is written as nothing — two distinguishable requests",
    rust_decision:
      "reproduced: the argument is `Option<&str>`, so `Some(\"\")` writes `?route=` and `None` writes no parameter at all",
  },
  the_escrow_vocabulary_is_undetermined: {
    scan: declarations.pinned_route_uses,
    produced_routes: declarations.reply_route_uses,
    keripy: {
      reply_routes: keripyCorroboration.reply_routes,
      presentation_request_is_a_reply_route: keripyCorroboration.presentation_request_is_a_reply_route,
      presentation_request_ilk: keripyCorroboration.presentation_request_ilk,
    },
    note: "the pinned tree names exactly one escrow route and only inside a unit test; the two reply routes the reference actually produces are never used to filter an escrow. keripy, which is where the escrow lives, declares the routes a reply may carry — and `/presentation/request` is not one of them, appearing there as the route of an `exn` in a specification document.",
    rust_decision:
      "the route stays borrowed text rather than becoming an enum, which is the decision already taken for `ReplyBuilder`'s own route and for the same reason: there is no closed set to enumerate. The typed exchange route table covers *exchange* routes, which these are not.",
  },
};

// ---------------------------------------------------------------------------
// 7. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/escrowing.ts",
    "src/keri/app/exchanging.ts",
    "src/types/keria-api-schema.ts",
    "test/app/escrowing.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    reply_stamp: REPLY_STAMP,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    note: "`Escrows` takes a whole `SignifyClient`, as `Config` does, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned, and the escrowed replies are built by the reference's own `reply()` at a fixed timestamp so their SAIDs are stable. `PUBLIC TEST MATERIAL`: the passcode is the one `escrowing.test.ts` publishes and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  keripy_corroboration: keripyCorroboration,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-escrows/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-escrows fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
