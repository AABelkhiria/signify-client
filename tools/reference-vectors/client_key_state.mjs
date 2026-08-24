// Records the pinned signify-ts checkout's key-event and key-state endpoints.
//
// Roadmap 6.7 ports `KeyEvents.get` and `KeyStates.{get,list,query}` from
// `src/keri/app/coring.ts`. `Config` lives in the same file and is Roadmap 6.8; nothing here
// touches it.
//
// Both classes take a whole `SignifyClient` rather than a narrow dependency interface, so this
// generator **drives the reference** the way Roadmap 6.4's fixture did: `globalThis.fetch` is
// replaced with a recorder that answers and signs as a KERIA agent would, and the real client is
// walked through boot, connect, and then every call of both families.
//
// The clock and the agent's key are pinned, so a request's signature is exact; the calls recorded
// here are compared by path, method, and body.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const keripySha = "4ce4cc79e06653f77342be1bf604086b89b1f090";

/** The passcode and URLs the pinned `coring.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The two prefixes the pinned test queries, and the SAID it passes as an anchor. */
const PREFIX_ONE = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const PREFIX_TWO = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const ANCHOR_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

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

const coring = parse("src/keri/app/coring.ts");
const schema = parse("src/types/keria-api-schema.ts");

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

/** One property signature's text out of a schema type literal. */
function schemaMember(typeName, memberName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isPropertySignature(node) && node.name?.getText() === typeName) {
      const inner = (child) => {
        if (found === null && ts.isPropertySignature(child) && child.name?.getText() === memberName) {
          found = child.getText().replace(/\s+/g, " ");
        }
        ts.forEachChild(child, inner);
      };
      ts.forEachChild(node, inner);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(schema.source, visit);
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

/** Every `keyStates().query(...)` call in the pinned tree, with the arguments it passes. */
function queryCallSites() {
  const found = [];
  for (const file of PINNED_FILES) {
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    if (!text.includes(".query(")) {
      continue;
    }
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
    const visit = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.getText() === "query" &&
        node.expression.expression.getText().includes("keyStates")
      ) {
        found.push({
          file,
          call: node.getText().replace(/\s+/g, " "),
          arguments: node.arguments.map((argument) => argument.getText().replace(/\s+/g, " ")),
        });
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(source, visit);
  }
  return found;
}

const keyEventsGet = method(coring.source, "KeyEvents", "get");
const keyStatesGet = method(coring.source, "KeyStates", "get");
const keyStatesList = method(coring.source, "KeyStates", "list");
const keyStatesQuery = method(coring.source, "KeyStates", "query");

const declarations = {
  events_path: localDeclaration(keyEventsGet, "path"),
  states_path: localDeclaration(keyStatesGet, "path"),
  states_list_path: localDeclaration(keyStatesList, "path"),
  queries_path: localDeclaration(keyStatesQuery, "path"),
  query_body: localDeclaration(keyStatesQuery, "data"),
  query_signature: keyStatesQuery.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")),
  query_sn_doc: (() => {
    const text = keyStatesQuery.getFullText();
    const line = text.split("\n").find((entry) => entry.includes("[sn]"));
    return line === undefined ? null : line.trim();
  })(),
  query_anchor_doc: (() => {
    const text = keyStatesQuery.getFullText();
    const line = text.split("\n").find((entry) => entry.includes("[anchor]"));
    return line === undefined ? null : line.trim();
  })(),
  query_metadata_sn: schemaMember("QueryMetadata", "sn"),
  query_metadata_anchor: schemaMember("QueryMetadata", "anchor"),
  anchor_schema: schemaMember("Anchor", "pre"),
  seal_schema: schemaMember("Seal", "s"),
  key_event_record: schemaMember("KeyEventRecord", "ked"),
  notes: {
    paths: "all four dynamic values are interpolated into the query with no encoding at all; `list` joins its prefixes with `&` and, given none, produces a bare question mark",
    query_body:
      "`query` builds `{pre}` and adds `sn` and `anchor` only when they are defined, so an absent one is not written rather than being written as null",
    sn: "`sn` is declared `string` on the parameter, documented `number` in the JSDoc directly above it, and declared `number` in the schema's own `QueryMetadata` — three spellings of one field",
    anchor:
      "`anchor` is `any`. The pinned unit test passes a bare SAID string, every integration caller passes a Seal (`{i, s, d}`), and the schema's `QueryMetadata.anchor` is an `Anchor` (`{pre, sn, d}`) — three shapes, and only the integration ones ever reach a live KERIA",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. Corroboration for the sequence number's base, from outside signify-ts.
// ---------------------------------------------------------------------------
//
// Every `sn` the reference's own callers pass is a single digit, where decimal and hexadecimal
// agree — so signify-ts cannot settle which base KERIA reads. ADR `0009` scopes keripy as a
// *governing* reference only for capabilities signify-ts cannot emit, and this is not one of
// those; what follows is corroborating evidence, recorded as such.

function keripyLines(relativePath, needle) {
  const url = new URL(`../../reference/keripy/${relativePath}`, import.meta.url);
  let text;
  try {
    text = readFileSync(url, "utf8");
  } catch {
    return [];
  }
  return text
    .split("\n")
    .map((line, index) => ({ line: index + 1, text: line.trim() }))
    .filter((entry) => entry.text.includes(needle));
}

/** Lines of one pinned signify-ts file containing a needle. */
function referenceLines(relativePath, needle) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return text
    .split("\n")
    .map((line, index) => ({ line: index + 1, text: line.trim() }))
    .filter((entry) => entry.text.includes(needle));
}

const sequenceNumberBase = {
  reference_call_sites: queryCallSites(),
  every_recorded_sn_is_one_digit: null,
  dynamic_call_sites: {
    note: "two call sites pass something other than a literal. One forwards a helper's own `sn` parameter, itself always a one-digit literal; the other passes a key state's `s` field straight through — and that field is a KERI sequence number, which the protocol writes in **hexadecimal**.",
    key_state_field: referenceLines("test-integration/singlesig-ixn.test.ts", "keystate1.s"),
    parsed_as_decimal: referenceLines("test-integration/singlesig-ixn.test.ts", "parseInt(keystate1.s)"),
    parse_note: "the same file reads that field back with `parseInt`, which without a radix parses base ten — so the reference's own test treats a hexadecimal protocol field as decimal. Below ten the two agree, which is why nothing upstream has ever noticed.",
  },
  keripy: {
    commit: keripySha,
    file: "src/keri/app/indirecting.py",
    lines: keripyLines("src/keri/app/indirecting.py", 'get_param_as_int("sn")'),
    note: "keripy's own HTTP surface reads an `sn` query parameter with falcon's `get_param_as_int`, which parses base ten. KERIA is a different service, so this is corroboration rather than proof.",
  },
  note: "the reference passes whatever string it is handed straight into the body, so its own evidence cannot distinguish the base",
  rust_decision:
    "**not guessed.** The Rust request takes a two-variant `QuerySequence` — `Decimal(u64)` or `Hexadecimal(u64)` — so the caller chooses the rendering and the ambiguity is visible in the type rather than hidden behind a default. Both variants reproduce every recorded call byte for byte, because every one of them is below ten. Roadmap 9.2 owes this a live confirmation; `PORTING.md` §10 carries it as an open question.",
};
sequenceNumberBase.every_recorded_sn_is_one_digit = sequenceNumberBase.reference_call_sites
  .flatMap((site) => site.arguments.slice(1, 2))
  .filter((argument) => argument !== "undefined")
  .every((argument) => /^'[0-9]'$/.test(argument));

// ---------------------------------------------------------------------------
// 3. A KERIA agent, answering and signing as Roadmap 6.4's fixture did.
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

/** One key state of the shape KERIA answers `/states` with. */
function keyState(prefix) {
  return { ...agentState, i: prefix, d: prefix, et: "icp", di: "" };
}

/** One key-event record of the shape KERIA answers `/events` with. */
const KEY_EVENT_RECORD = {
  ked: {
    v: "KERI10JSON00012b_",
    t: "icp",
    d: PREFIX_ONE,
    i: PREFIX_ONE,
    s: "0",
    kt: "1",
    k: ["DGBw7C7AfC7jbD3jLLRS3SzIWFndM947TyNWKQ52iQx5"],
    nt: "1",
    n: ["EML5FrjCpz8SEl4dh0U15l8bMRhV_O5iDcR1opLJGBSH"],
    bt: "0",
    b: [],
    c: [],
    a: [],
  },
  atc: "-VAn-AABAAB0mGa6DKRLR6-1DXBlvIP0DEHkTLQtNQqHqPTLTUdMBBB0mGa6DKRLR6",
};

/** One pending query operation of the shape KERIA answers `/queries` with. */
const QUERY_OPERATION = {
  name: `query.${PREFIX_ONE}`,
  metadata: { pre: PREFIX_ONE, sn: 1 },
  done: false,
};

const recorded = [];
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
  const headers = [];
  const raw = init.headers;
  if (raw instanceof Headers) {
    raw.forEach((value, name) => headers.push({ name, value }));
  } else if (raw && typeof raw === "object") {
    for (const [name, value] of Object.entries(raw)) {
      headers.push({ name, value });
    }
  }
  recorded.push({
    url: text,
    path: text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length),
    method: httpMethod,
    headers,
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

const keyEvents = client.keyEvents();
const keyStates = client.keyStates();

const calls = [];

/** Runs one call, recording the request it produced and what it returned. */
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
  const request = recorded[before] ?? null;
  calls.push({
    name,
    note,
    request:
      request === null
        ? null
        : {
            path: request.path,
            method: request.method,
            body: request.body,
          },
    result,
    error,
  });
  nextPayload = {};
}

// --- key events -------------------------------------------------------------

await drive("events_get", "the pinned unit test's own key-event read", [KEY_EVENT_RECORD], () =>
  keyEvents.get(PREFIX_ONE),
);

await drive(
  "events_get_prefix_needing_encoding",
  "a prefix carrying query delimiters, which the reference interpolates raw",
  [],
  () => keyEvents.get("E&pre=EOTHER#x"),
);

// --- key states -------------------------------------------------------------

await drive("states_get", "the pinned unit test's own key-state read", [keyState(PREFIX_ONE)], () =>
  keyStates.get(PREFIX_ONE),
);

await drive(
  "states_list",
  "the pinned unit test's two-prefix listing, whose repeated parameter is joined with an ampersand",
  [keyState(PREFIX_ONE), keyState(PREFIX_TWO)],
  () => keyStates.list([PREFIX_ONE, PREFIX_TWO]),
);

await drive("states_list_one", "a single-prefix listing, identical to a read", [keyState(PREFIX_ONE)], () =>
  keyStates.list([PREFIX_ONE]),
);

await drive("states_list_empty", "an empty listing, which produces a bare question mark", [], () =>
  keyStates.list([]),
);

// --- queries ----------------------------------------------------------------

await drive(
  "query_pinned",
  "the pinned unit test's own query: a sequence number and a bare SAID as the anchor",
  QUERY_OPERATION,
  () => keyStates.query(PREFIX_ONE, "1", ANCHOR_SAID),
);

await drive("query_prefix_only", "a query with neither a sequence number nor an anchor", QUERY_OPERATION, () =>
  keyStates.query(PREFIX_ONE),
);

await drive("query_sequence_only", "a query naming only a sequence number, as every integration caller does", QUERY_OPERATION, () =>
  keyStates.query(PREFIX_ONE, "1"),
);

await drive(
  "query_seal_anchor",
  "a query naming only an anchor, in the Seal shape the integration tests pass and a live KERIA accepts",
  QUERY_OPERATION,
  () => keyStates.query(PREFIX_ONE, undefined, { i: PREFIX_TWO, s: "0", d: PREFIX_TWO }),
);

await drive(
  "query_two_digit_sequence",
  "a sequence number above nine, where decimal and hexadecimal stop agreeing — the reference passes the string through untouched",
  QUERY_OPERATION,
  () => keyStates.query(PREFIX_ONE, "10"),
);

// ---------------------------------------------------------------------------
// 4. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

const coringTest = parse("test/app/coring.test.ts");

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

const publishedPaths = [
  ...new Set(
    publishedStrings(coringTest.source, (text) => text.startsWith("/events") || text.startsWith("/states") || text === "/queries"),
  ),
].sort();
const drivenPaths = calls.filter((call) => call.request !== null).map((call) => call.request.path);

const REQUIRED_PATHS = [
  `/events?pre=${PREFIX_ONE}`,
  `/states?pre=${PREFIX_ONE}`,
  `/states?pre=${PREFIX_ONE}&pre=${PREFIX_TWO}`,
  "/queries",
];

const pinnedConfirmations = {
  published_paths: publishedPaths,
  driven_paths: [...new Set(drivenPaths)].sort(),
  every_pinned_path_is_driven: REQUIRED_PATHS.every(
    (path) => publishedPaths.includes(path) && drivenPaths.includes(path),
  ),
  pinned_query_body: calls.find((call) => call.name === "query_pinned")?.request?.body ?? null,
  note: "the four paths the pinned `coring.test.ts` asserts are all produced here by the reference's own classes, and the query body is the one it inspects field by field",
};
if (!pinnedConfirmations.every_pinned_path_is_driven) {
  throw new Error("the pinned key-event and key-state paths no longer reproduce");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  query_values_are_not_encoded: {
    path: calls.find((call) => call.name === "events_get_prefix_needing_encoding")?.request?.path ?? null,
    expressions: {
      events: declarations.events_path,
      states: declarations.states_path,
      list: declarations.states_list_path,
    },
    note: "all three read paths interpolate their prefix straight into the query with no encoding, so a prefix carrying `&` or `#` adds parameters or truncates the query — the fourth such family Roadmap 5.3 counted",
    rust_decision:
      "refused twice over: the parameter is a validated `IdentifierPrefix` rather than a string, and Roadmap 5.3's builder would encode it exactly once even if it were not",
  },
  an_empty_listing_addresses_a_bare_question_mark: {
    path: calls.find((call) => call.name === "states_list_empty")?.request?.path ?? null,
    expression: declarations.states_list_path,
    note: "`list([])` joins nothing and still interpolates `?`, so an empty listing addresses `/states?` — the same defect Roadmap 6.5 recorded for `/operations?`",
    rust_decision:
      "not reproduced, on Roadmap 6.5's own three grounds: the signed path is identical because Roadmap 3.10 strips the query, an empty query is not a distinguishable resource, and Roadmap 5.3's builder cannot spell it. An empty listing is refused outright here, because asking for no key states is a caller mistake rather than a request.",
  },
  a_listing_is_unbounded: {
    note: "`list` maps and joins however many prefixes it is handed, so a caller can build a query no server will accept",
    rust_decision:
      "Roadmap 5.3's builder bounds a query at 32 parameters and 1,024 bytes, so a listing of more than about twenty prefixes is a typed refusal rather than a request that fails remotely",
  },
  the_sequence_number_has_three_spellings: {
    parameter: declarations.query_signature,
    jsdoc: declarations.query_sn_doc,
    schema: declarations.query_metadata_sn,
    body: calls.find((call) => call.name === "query_pinned")?.request?.body ?? null,
    two_digit_body: calls.find((call) => call.name === "query_two_digit_sequence")?.request?.body ?? null,
    base: sequenceNumberBase,
    note: "the parameter is declared `string`, the JSDoc directly above it says `number`, and the schema's own `QueryMetadata.sn` is a `number` — while the value actually sent is a string",
    rust_decision:
      "a `u64` rendered in base ten, which is the string every recorded caller sends. The request writes text because that is what the reference sends and what the pinned test asserts.",
  },
  the_anchor_has_three_shapes: {
    unit_test_body: calls.find((call) => call.name === "query_pinned")?.request?.body ?? null,
    integration_body: calls.find((call) => call.name === "query_seal_anchor")?.request?.body ?? null,
    schema_anchor: declarations.query_metadata_anchor,
    anchor_first_field: declarations.anchor_schema,
    seal_first_field: declarations.seal_schema,
    call_sites: sequenceNumberBase.reference_call_sites,
    jsdoc: declarations.query_anchor_doc,
    note: "`anchor` is `any`. The pinned unit test passes a bare SAID string; every integration caller passes a Seal (`{i, s, d}`); the schema's `QueryMetadata.anchor` is an `Anchor` (`{pre, sn, d}`). Only the integration shape ever reaches a live KERIA.",
    rust_decision:
      "the request takes a `Seal`, which is the shape proven against a running agent. The unit test's bare string is recorded verbatim here and is unrepresentable in Rust; the schema's `Anchor` stays what it always was — the *response* metadata's type, which Roadmap 4.1 already carries.",
  },
  a_query_body_omits_what_it_was_not_given: {
    expression: declarations.query_body,
    prefix_only: calls.find((call) => call.name === "query_prefix_only")?.request?.body ?? null,
    sequence_only: calls.find((call) => call.name === "query_sequence_only")?.request?.body ?? null,
    note: "`query` writes `pre` always and adds `sn` and `anchor` only when defined, so an absent one is not written rather than written as null",
    rust_decision: "reproduced exactly: the body is an ordered `Sad` and an absent value is not written",
  },
  both_families_take_the_whole_client: {
    scan: scan("new KeyStates("),
    note: "`KeyEvents` and `KeyStates` each hold a whole `SignifyClient`, where `Operations` takes a narrow `OperationsDeps` and `Identifier` an `IdentifierDeps` — so neither can be unit-tested without a full client",
    rust_decision:
      "both are borrowed handles over a `ConnectedClient`, as Roadmap 6.5 settled; a family knows paths and shapes and nothing else",
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
  sources: ["src/keri/app/coring.ts", "src/types/keria-api-schema.ts", "test/app/coring.test.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    prefix_one: PREFIX_ONE,
    prefix_two: PREFIX_TWO,
    anchor_said: ANCHOR_SAID,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    note: "`KeyEvents` and `KeyStates` each take a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would — the arrangement Roadmap 6.4's fixture established. The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: the passcode is the one `coring.test.ts` publishes and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-key-state/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-key-state fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
