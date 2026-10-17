// Records the pinned signify-ts checkout's notifications endpoint.
//
// This port covers `Notifications.{list,mark,delete}` from `src/keri/app/notifying.ts`: three
// methods, one of which is the second windowed listing in the port (the identifiers listing being
// the first) and the only one that reads a `Content-Range` back.
//
// The interesting evidence here is not a path. It is **what a notification's identifier actually
// is**: `mark(said)` and `delete(said)` name their parameter `said` and document it as "SAID of the
// notification", and it is not one. `notification_identifier` below records the whole chain —
// `randomNonce`'s own declaration in `app/coring.ts`, the derivation code it uses, and keripy's
// `Dicter`, which fills an empty `i` with exactly that — so the finding is read out of both
// references rather than asserted.
//
// The pinned `notifying.test.ts` case asserts all three paths, all three methods, and the `Range`
// header; the generator drives the reference's own class through them.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { Matter, MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const keripySha = "4ce4cc79e06653f77342be1bf604086b89b1f090";

/** The passcode and URLs the pinned `notifying.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

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

function readKeripy(relativePath) {
  return readFileSync(new URL(`../../reference/keripy/${relativePath}`, import.meta.url), "utf8");
}

const notifying = parse("src/keri/app/notifying.ts");
const coring = parse("src/keri/app/coring.ts");
const schema = parse("src/types/keria-api-schema.ts");
const notifyingTest = parse("test/app/notifying.test.ts");
const testUtil = parse("test-integration/utils/test-util.ts");

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

function parameters(node) {
  return node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " "));
}

/** One whole exported function, by name. */
function functionText(source, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.getText() === name && node.body !== undefined) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The JSDoc attached to one method, which is where a wrong claim lives. */
function documentation(node) {
  const full = node.getFullText();
  const body = node.getText();
  return full.slice(0, full.length - body.length).replace(/\s+/g, " ").trim();
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

/** The whole text of one schema entry. */
function schemaEntry(typeName) {
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

function scan(needle, { normalizeWhitespace = false } = {}) {
  const hits = [];
  let total = 0;
  for (const file of PINNED_FILES) {
    let body = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    if (normalizeWhitespace) {
      body = body.replace(/\s+/g, "");
    }
    const count = body.split(needle).length - 1;
    if (count > 0) {
      hits.push({ file, count });
      total += count;
    }
  }
  return { needle, total, files: hits, scanned_files: PINNED_FILES.length, normalized: normalizeWhitespace };
}

const listMethod = method(notifying.source, "Notifications", "list");
const markMethod = method(notifying.source, "Notifications", "mark");
const deleteMethod = method(notifying.source, "Notifications", "delete");

const declarations = {
  list_parameters: parameters(listMethod),
  list_range_header: firstText(
    listMethod,
    (node) => ts.isExpressionStatement(node) && node.getText().includes("extraHeaders.append"),
  ),
  list_path: localDeclaration(listMethod, "path"),
  list_method: localDeclaration(listMethod, "method"),
  list_content_range: localDeclaration(listMethod, "cr"),
  list_range_parse: localDeclaration(listMethod, "range"),
  list_return: firstText(listMethod, (node) => ts.isReturnStatement(node)),
  mark_parameters: parameters(markMethod),
  mark_path: localDeclaration(markMethod, "path"),
  mark_method: localDeclaration(markMethod, "method"),
  mark_return: firstText(markMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.text()")),
  delete_parameters: parameters(deleteMethod),
  delete_path: localDeclaration(deleteMethod, "path"),
  delete_method: localDeclaration(deleteMethod, "method"),
  delete_fetch: firstText(deleteMethod, (node) => ts.isCallExpression(node) && node.getText().includes("client.fetch(")),
  class_members: classMembers(notifying.source, "Notifications"),
  notification_type: schemaEntry("Notification"),
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

const NOTIFICATIONS_MEMBERS = ["client", "<constructor>", "list", "mark", "delete"];
if (JSON.stringify(declarations.class_members) !== JSON.stringify(NOTIFICATIONS_MEMBERS)) {
  throw new Error(`the Notifications class no longer declares ${NOTIFICATIONS_MEMBERS.join(", ")}`);
}

// ---------------------------------------------------------------------------
// 1b. What a notification's identifier actually is.
// ---------------------------------------------------------------------------
//
// Both methods call their parameter `said` and document it as a SAID. It is not one. A notice's `i`
// is built empty and filled by a random nonce — and the two references do not even agree on which
// code that nonce carries: signify-ts's `randomNonce` qualifies thirty-two bytes under the Ed25519
// **seed** code (`A`), while keripy's qualifies sixteen under the **salt** code (`0A`). Neither is a
// digest code, so reading the field as a SAID would refuse every identifier a real agent produces,
// whichever implementation wrote it.

/** Fixed bytes, so every sample below is deterministic. */
const NONCE_SEED = new Uint8Array(Array.from({ length: 32 }, (_, index) => (index * 7 + 3) % 256));

/** A nonce as signify-ts's own `randomNonce` builds one: Ed25519 seed code. */
const SIGNIFY_NONCE = new Matter({ raw: NONCE_SEED, code: MtrDex.Ed25519_Seed }).qb64;
/** A nonce as keripy's builds one: 128-bit salt code, which is what fills a notice's `i`. */
const KERIPY_NONCE = new Matter({ raw: NONCE_SEED.slice(0, 16), code: MtrDex.Salt_128 }).qb64;
/** A Blake3 digest of the same bytes, which is what a real SAID looks like. */
const SAMPLE_SAID = new Diger({}, NONCE_SEED).qb64;

/** The identifier this fixture drives the reference with: the shape a KERIA agent produces. */
const SAMPLE_NONCE = KERIPY_NONCE;

const keripyNotifying = readKeripy("src/keri/app/notifying.py");
const keripyCoring = readKeripy("src/keri/core/coring.py");

/** One line of keripy, skipping comments: the claim is about code, not about what it says. */
function keripyLine(text, needle) {
  const line = text.split("\n").find((entry) => entry.includes(needle) && !entry.trim().startsWith("#"));
  return line === undefined ? null : line.trim();
}

/** How many non-comment lines match, so "the only place" is a count rather than a claim. */
function keripyLineCount(text, needle) {
  return text.split("\n").filter((entry) => entry.includes(needle) && !entry.trim().startsWith("#")).length;
}

const notificationIdentifier = {
  parameter: declarations.mark_parameters,
  documentation: documentation(markMethod),
  signify_random_nonce: functionText(coring.source, "randomNonce"),
  signify_nonce_code: MtrDex.Ed25519_Seed,
  signify_nonce: SIGNIFY_NONCE,
  signify_nonce_leading: SIGNIFY_NONCE.slice(0, 1),
  keripy_random_nonce_code: keripyLine(keripyCoring, "code=MtrDex.Salt_128"),
  keripy_nonce_code: MtrDex.Salt_128,
  keripy_nonce: KERIPY_NONCE,
  keripy_nonce_leading: KERIPY_NONCE.slice(0, 2),
  keripy_notice_leaves_it_empty: keripyLine(keripyNotifying, 'pad = dict(i="",'),
  keripy_dicter_fills_it: keripyLine(keripyCoring, "self._pad[self._label] = randomNonce()"),
  keripy_dicter_fill_sites: keripyLineCount(keripyCoring, "self._pad[self._label] = randomNonce()"),
  sample_said: SAMPLE_SAID,
  sample_said_leading: SAMPLE_SAID.slice(0, 1),
  keripy_sha: keripySha,
  note: "`mark(said)` and `delete(said)` name the parameter `said` and the JSDoc says \"SAID of the notification\". It is not one: keripy's `notice()` builds the record with `i=\"\"` and its `Dicter` fills an empty identifier with `randomNonce()`. The two references disagree about that nonce's code — signify-ts's `randomNonce` uses the Ed25519 seed code `A` over thirty-two bytes, keripy's the 128-bit salt code `0A` over sixteen — and **neither is a digest code**, so the field is not a SAID under either. KERIA is built on keripy, so what a real agent writes is the `0A` form.",
  rust_decision:
    "the argument is **not** typed as `Said`, which would refuse every identifier a real agent produces. It stays borrowed text encoded exactly once by the request builder — the shape the operations endpoint gave an operation name — which is enough to close the path injection this fixture records. keripy is corroboration for what fills the field, not a governing reference.",
};

for (const [name, value] of Object.entries(notificationIdentifier)) {
  if (value === null || value === undefined) {
    throw new Error(`the identifier record's ${name} is no longer where this generator expects it`);
  }
}
// The finding rests on three facts; check each rather than asserting the conclusion.
if (!notificationIdentifier.signify_random_nonce.includes("Ed25519_Seed")) {
  throw new Error("signify-ts's `randomNonce` no longer qualifies under the Ed25519 seed code");
}
if (notificationIdentifier.keripy_dicter_fill_sites === 0) {
  throw new Error("keripy's `Dicter` no longer fills an empty identifier with a nonce");
}
for (const nonce of [SIGNIFY_NONCE, KERIPY_NONCE]) {
  if (SAMPLE_SAID.startsWith(nonce.slice(0, 1))) {
    throw new Error("a nonce and a digest now share a derivation code; the finding no longer holds");
  }
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
let nextPayload = {};
let nextContentRange = null;

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
  const full = String(url);
  const httpMethod = init.method ?? "GET";
  const path = full.startsWith(ADMIN_URL) ? full.slice(ADMIN_URL.length) : full.slice(BOOT_URL.length);
  // The `Range` header is the whole point of `list`, so every request's headers are recorded.
  const sent = {};
  if (init.headers !== undefined) {
    for (const [name, value] of new Headers(init.headers).entries()) {
      sent[name] = value;
    }
  }
  recorded.push({
    path,
    method: httpMethod,
    headers: sent,
    body: init.body === undefined ? undefined : init.body === null ? null : String(init.body),
    body_is_undefined: init.body === undefined,
  });

  const payload =
    path.startsWith("/agent/") && httpMethod === "GET"
      ? { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 }
      : nextPayload;
  const responseHeaders = signedHeaders(httpMethod, path);
  responseHeaders.set("Content-Type", "application/json");
  if (nextContentRange !== null && !path.startsWith("/agent/")) {
    responseHeaders.set("Content-Range", nextContentRange);
  }
  return new Response(JSON.stringify(payload), { status: 202, headers: responseHeaders });
};

await client.boot();
await client.connect();

const notifications = client.notifications();

// ---------------------------------------------------------------------------
// 3. Drive every call.
// ---------------------------------------------------------------------------

/** One notification of the shape KERIA answers with, identified by a nonce. */
function notification(id, read) {
  return {
    i: id,
    dt: "2023-11-14T22:13:20.123000+00:00",
    r: read,
    a: { r: "/multisig/icp", d: SAMPLE_SAID, m: "" },
  };
}

const calls = [];

async function drive(name, note, payload, contentRange, run) {
  nextPayload = payload;
  nextContentRange = contentRange;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    const returned = await run();
    result = returned === undefined ? null : returned;
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const request = recorded[before] ?? null;
  calls.push({
    name,
    note,
    // What the agent was made to answer with, which for `list` is the page itself — the `result`
    // below is the wrapper the reference builds around it.
    payload,
    request:
      request === null
        ? null
        : {
            path: request.path,
            method: request.method,
            headers: request.headers,
            body: request.body === undefined ? null : request.body,
            body_is_undefined: request.body_is_undefined,
          },
    content_range: contentRange,
    result,
    error,
  });
  nextPayload = {};
  nextContentRange = null;
}

await drive(
  "list_windowed",
  "the pinned unit test's own call, which asserts the `Range` header exactly",
  [notification(SAMPLE_NONCE, false)],
  "notes 20-40/100",
  () => notifications.list(20, 40),
);

await drive(
  "list_default_window",
  "no arguments at all, which writes the `= 0` and `= 24` defaults into the header — an omitted window is still an observable request",
  [notification(SAMPLE_NONCE, false)],
  "notes 0-24/100",
  () => notifications.list(),
);

await drive(
  "list_no_content_range",
  "an agent that answers without a `Content-Range` at all, which the reference reads as a window of three zeroes",
  [notification(SAMPLE_NONCE, true)],
  null,
  () => notifications.list(0, 24),
);

await drive(
  "list_empty",
  "an empty page, which still carries a window",
  [],
  "notes 0-0/0",
  () => notifications.list(0, 24),
);

await drive(
  "list_fractional_window",
  "a window that is not a whole number of items: both bounds are stringified into the header unchanged",
  [],
  "notes 0-24/100",
  () => notifications.list(1.5, 2.5),
);

await drive(
  "list_reversed_window",
  "an end before its start, which the reference sends as `notes=40-20`",
  [],
  "notes 0-24/100",
  () => notifications.list(40, 20),
);

await drive(
  "mark",
  "the pinned unit test's own call — note that its argument is not a qualified identifier at all",
  {},
  null,
  () => notifications.mark("notificationSAID"),
);

await drive(
  "mark_nonce",
  "the same call with the identifier a real agent produces: a `randomNonce` under the Ed25519 seed code",
  {},
  null,
  () => notifications.mark(SAMPLE_NONCE),
);

await drive(
  "mark_needing_encoding",
  "an identifier carrying a query delimiter, which the reference concatenates raw — the case the `http-request-response` fixture already recorded turning a path into a query",
  {},
  null,
  () => notifications.mark("a?b=c"),
);

await drive(
  "delete",
  "the pinned unit test's own delete",
  {},
  null,
  () => notifications.delete("notificationSAID"),
);

await drive(
  "delete_nonce",
  "the same, with a real identifier",
  {},
  null,
  () => notifications.delete(SAMPLE_NONCE),
);

await drive(
  "list_wrong_shape",
  "a page whose entries are missing declared fields — the reference returns `res.json()` with no typing at all",
  [{ i: SAMPLE_NONCE }],
  "notes 0-24/100",
  () => notifications.list(0, 24),
);

// ---------------------------------------------------------------------------
// 4. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const UNIT_TEST_ASSERTIONS = [
  "url + '/notifications'",
  "assert.equal(lastHeaders.get('Range'), 'notes=20-40')",
  "url + '/notifications/notificationSAID'",
];
const normalizedTest = notifyingTest.text.replace(/\s+/g, " ");
const unitTestAssertions = UNIT_TEST_ASSERTIONS.filter((line) => normalizedTest.includes(line.replace(/\s+/g, " ")));
if (unitTestAssertions.length !== UNIT_TEST_ASSERTIONS.length) {
  throw new Error("an assertion this fixture reproduces is no longer in the pinned unit test");
}

const INTEGRATION_LINES = [
  "const res = await client.notifications().list();",
  "await client.notifications().mark(note.i);",
  "await client.notifications().delete(note.i);",
];
const normalizedUtil = testUtil.text.replace(/\s+/g, " ");
const integrationLines = INTEGRATION_LINES.filter((line) => normalizedUtil.includes(line.replace(/\s+/g, " ")));
if (integrationLines.length !== INTEGRATION_LINES.length) {
  throw new Error("an integration usage this fixture records has moved");
}

const pinnedConfirmations = {
  unit_test_assertions: unitTestAssertions,
  unit_test_identifier: "notificationSAID",
  unit_test_range_header: "notes=20-40",
  unit_test_paths: ["/notifications", "/notifications/notificationSAID"],
  integration_usage: integrationLines,
  every_mark_argument_is_a_field: scan("notifications().mark(note.i)", { normalizeWhitespace: true }),
  call_sites: scan("notifications().", { normalizeWhitespace: true }),
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "the pinned case asserts all three paths, all three methods, and the `Range` header exactly. What it does **not** provide is a real notification identifier: its literal is the string `notificationSAID`, and every integration call site passes a runtime `note.i` read back from a live agent — so the shape of that field is established from `randomNonce` and keripy rather than from any pinned literal.",
};

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function call(name) {
  return calls.find((entry) => entry.name === name) ?? null;
}

const quirks = {
  the_identifier_is_not_a_said: notificationIdentifier,
  the_window_defaults_are_observable: {
    parameters: declarations.list_parameters,
    header: call("list_default_window")?.request?.headers?.range ?? null,
    note: "`list(start = 0, end = 24)` writes both defaults into the `Range` header, so an omitted window is still a request that names one",
    rust_decision:
      "the window is a required `ItemRange` and `DEFAULT_WINDOW` names the reference's values, so what is asked for is visible at the call site — the identifier listing already takes its window the same way",
  },
  a_window_bound_is_not_an_integer: {
    fractional: call("list_fractional_window")?.request?.headers?.range ?? null,
    reversed: call("list_reversed_window")?.request?.headers?.range ?? null,
    note: "both bounds are `number` and reach the header through template interpolation, so `list(1.5, 2.5)` sends `notes=1.5-2.5` and `list(40, 20)` sends a window whose end precedes its start",
    rust_decision:
      "**refused**: `ItemRange` takes two `u64` and validates that the start does not exceed the end, so neither is representable. A fraction is not a count of items and a reversed window asks for nothing.",
  },
  an_absent_content_range_becomes_three_zeroes: {
    declaration: declarations.list_range_parse,
    result: call("list_no_content_range")?.result ?? null,
    note: "`parseRangeHeaders(null, 'notes')` returns `{start: 0, end: 0, total: 0}`, so a page of real notifications is reported as an empty window rather than as an unknown one",
    rust_decision:
      "reproduced as the response decoder already decided and the identifier listing already applied: the window is an `Option`, so an unreported one is `None` and stays distinguishable from a genuinely empty one",
  },
  the_identifier_is_not_encoded: {
    path: call("mark_needing_encoding")?.request?.path ?? null,
    expression: declarations.mark_path,
    note: "both single-notification paths are `'/notifications/' + said`, so a value carrying `?` turns the path into a query — the `http-request-response` fixture recorded `notifications().mark('a?b=c')` doing exactly that, and request authentication signs `@path`",
    rust_decision:
      "closed by the request builder, which encodes every path component exactly once and offers no way to skip it",
  },
  mark_returns_its_body_as_text: {
    declaration: declarations.mark_return,
    result: call("mark")?.result ?? null,
    note: "`mark` is the only method here that reads its answer, and it reads it with `res.text()` — which replaces any byte that is not valid UTF-8 with U+FFFD rather than failing",
    rust_decision:
      "the text is returned, because the reference genuinely offers it, but decoded **strictly**: a body that is not valid UTF-8 is `ClientError::Decode` where `res.text()` silently repairs it. That is the decision the credentials endpoint made for a CESR answer read the same way.",
  },
  a_delete_carries_no_body: {
    fetch: declarations.delete_fetch,
    body_is_undefined: call("delete")?.request?.body_is_undefined ?? null,
    note: "`delete` passes `undefined` where `list` and `mark` pass `null`, so the request carries no body at all",
    rust_decision: "reproduced: no body is set on the request, as the operations, contacts, and challenges deletes already do",
  },
  the_page_is_never_typed: {
    declaration: declarations.list_return,
    wrong_shape: call("list_wrong_shape")?.result ?? null,
    note: "`list` returns `Promise<any>` and its `notes` field is `await res.json()` with no cast at all — not even the compile-time claim the other families make",
    rust_decision:
      "decoded into `signify_types::api::Notification`, so an entry missing the fields the schema declares is refused; the recorded wrong-shaped page is proven refused",
  },
  the_window_is_returned_flattened: {
    declaration: declarations.list_return,
    result: call("list_windowed")?.result ?? null,
    note: "the three window numbers are spread into the returned object beside `notes`, so a caller cannot tell the window apart from the page",
    rust_decision:
      "`NotificationListing` keeps them apart — an optional `window` and the notifications — which is the shape the identifiers endpoint gave its listing for the same reason",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  keripy_sha: keripySha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/notifying.ts",
    "src/keri/app/coring.ts",
    "src/types/keria-api-schema.ts",
    "test/app/notifying.test.ts",
    "test-integration/utils/test-util.ts",
  ],
  keripy_sources: ["src/keri/app/notifying.py", "src/keri/core/coring.py"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    sample_nonce: SAMPLE_NONCE,
    sample_said: SAMPLE_SAID,
    note: "`Notifications` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would and can set a `Content-Range`. The clock and the agent's key are pinned, and the sample nonce is built from fixed bytes by the reference's own `Matter` under the code `randomNonce` uses. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything; the nonce is derived from a counting pattern and identifies nothing.",
  },
  declarations,
  notification_identifier: notificationIdentifier,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-notifications/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-notifications fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
