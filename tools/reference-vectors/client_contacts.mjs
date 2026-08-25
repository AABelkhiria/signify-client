// Records the pinned signify-ts checkout's contacts endpoint.
//
// Roadmap 7.3 ports `Contacts` from `src/keri/app/contacting.ts`: five methods over one resource,
// two of which write an open bag of caller-chosen fields as the request body.
//
// The pinned `test/app/contacting.test.ts` has one `Contacts` case, and it is unusually complete —
// it asserts all five paths, all five methods, both write bodies, and that a delete carries no body
// at all. So the generator drives the reference's own class through exactly those calls, as Roadmap
// 6.5's and 7.2's fixtures do, and `pinned_confirmations` recomputes every one of those assertions.
//
// `Contacts` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch`
// replaced by a recorder and the clock and the agent's key pinned — Roadmap 6.4's arrangement.
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

/** The passcode and URLs the pinned `contacting.test.ts` publishes. */
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

const contacting = parse("src/keri/app/contacting.ts");
const schema = parse("src/types/keria-api-schema.ts");
const contactingTest = parse("test/app/contacting.test.ts");
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

function text(node) {
  return node === null || node === undefined ? null : node.getText().replace(/\s+/g, " ");
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

/** A method's whole parameter list, which is where the optionality lives. */
function parameters(node) {
  return node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " "));
}

/** The body argument each method hands to `client.fetch`, positionally. */
function fetchArguments(node) {
  return firstText(node, (child) => ts.isCallExpression(child) && child.getText().includes("this.client.fetch("));
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

/** The whole text of one schema entry, or of one exported interface. */
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

function interfaceText(source, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isInterfaceDeclaration(node) && node.name?.getText() === name) {
      found = node.getText().replace(/\s+/g, " ");
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

const listMethod = method(contacting.source, "Contacts", "list");
const getMethod = method(contacting.source, "Contacts", "get");
const addMethod = method(contacting.source, "Contacts", "add");
const deleteMethod = method(contacting.source, "Contacts", "delete");
const updateMethod = method(contacting.source, "Contacts", "update");

const declarations = {
  list_parameters: parameters(listMethod),
  list_group_guard: firstText(listMethod, (node) => ts.isIfStatement(node) && node.getText().includes("group")),
  list_filter_guard: firstText(listMethod, (node) => ts.isIfStatement(node) && node.getText().includes("filterField")),
  list_path: localDeclaration(listMethod, "path"),
  get_path: localDeclaration(getMethod, "path"),
  get_method: localDeclaration(getMethod, "method"),
  add_path: localDeclaration(addMethod, "path"),
  add_method: localDeclaration(addMethod, "method"),
  add_fetch: fetchArguments(addMethod),
  delete_path: localDeclaration(deleteMethod, "path"),
  delete_method: localDeclaration(deleteMethod, "method"),
  delete_fetch: fetchArguments(deleteMethod),
  update_path: localDeclaration(updateMethod, "path"),
  update_method: localDeclaration(updateMethod, "method"),
  update_fetch: fetchArguments(updateMethod),
  get_return: firstText(getMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  class_members: classMembers(contacting.source, "Contacts"),
  contact_info_interface: interfaceText(contacting.source, "ContactInfo"),
  contact_type: schemaEntry("Contact"),
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// The two halves of this file belong to two roadmap items; naming the class members proves which
// capabilities 7.3 owns and which stay with 7.4.
const CONTACTS_MEMBERS = ["client", "<constructor>", "list", "get", "add", "delete", "update"];
if (JSON.stringify(declarations.class_members) !== JSON.stringify(CONTACTS_MEMBERS)) {
  throw new Error(`the Contacts class no longer declares ${CONTACTS_MEMBERS.join(", ")}`);
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
  const full = String(url);
  const httpMethod = init.method ?? "GET";
  const path = full.startsWith(ADMIN_URL) ? full.slice(ADMIN_URL.length) : full.slice(BOOT_URL.length);
  recorded.push({
    path,
    method: httpMethod,
    // `undefined` and `null` are told apart: `delete` passes the first and the reference's own
    // test asserts the request carries no body at all.
    body: init.body === undefined ? undefined : init.body === null ? null : String(init.body),
    body_is_undefined: init.body === undefined,
  });

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

const contacts = client.contacts();

// ---------------------------------------------------------------------------
// 3. Drive every call.
// ---------------------------------------------------------------------------

/** The contact prefix the pinned unit test uses. */
const CONTACT = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
/** A second one, so a listing carries more than one entry. */
const OTHER = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";

/** One contact record of the shape KERIA answers with. */
function contactRecord(id, alias) {
  return {
    id,
    alias,
    oobi: `${ADMIN_URL}/oobi/${id}/agent/${agentPrefix}`,
    challenges: [],
    wellKnowns: [],
  };
}

/** The `ContactInfo` the pinned unit test sends, in its own field order. */
const PINNED_INFO = { name: "John Doe", company: "My Company" };

const calls = [];

async function drive(name, note, payload, run) {
  nextPayload = payload;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    // `delete` returns `void`, so its result is `undefined`; recorded as null rather than omitted.
    const returned = await run();
    result = returned === undefined ? null : returned;
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
            body: request.body === undefined ? null : request.body,
            body_is_undefined: request.body_is_undefined,
          },
    result,
    error,
  });
  nextPayload = {};
}

await drive(
  "list_filtered",
  "the pinned unit test's own call: a group and both halves of a filter",
  [contactRecord(CONTACT, "John Doe")],
  () => contacts.list("mygroup", "company", "mycompany"),
);

await drive(
  "list_unfiltered",
  "no arguments at all, which appends a bare question mark to the path — the same shape Roadmap 6.5 recorded for an unfiltered `/operations?`",
  [contactRecord(CONTACT, "John Doe"), contactRecord(OTHER, "Jane Roe")],
  () => contacts.list(),
);

await drive(
  "list_group_only",
  "a group with no filter, which is a real call shape and writes one parameter",
  [],
  () => contacts.list("mygroup"),
);

await drive(
  "list_filter_only",
  "`getOrCreateContact` in the reference's own integration helper: no group, both filter halves, and a value that is a regular expression",
  [contactRecord(CONTACT, "alice")],
  () => contacts.list(undefined, "alias", "^alice$"),
);

await drive(
  "list_half_a_filter",
  "a filter field with no value: the guard tests both, so **the whole filter is silently dropped** and the listing comes back unfiltered",
  [contactRecord(CONTACT, "John Doe")],
  () => contacts.list(undefined, "alias"),
);

await drive(
  "list_half_a_filter_value_only",
  "the other half, dropped the same way",
  [],
  () => contacts.list(undefined, undefined, "^alice$"),
);

await drive(
  "list_filter_needing_encoding",
  "a filter value carrying a query delimiter, which `URLSearchParams` **does** encode — one of the few dynamic values the reference encodes at all",
  [],
  () => contacts.list(undefined, "alias", "a&b=c"),
);

await drive("get", "the pinned unit test's own read", contactRecord(CONTACT, "John Doe"), () => contacts.get(CONTACT));

await drive(
  "get_prefix_needing_encoding",
  "a prefix carrying path and query delimiters, which the reference concatenates raw",
  {},
  () => contacts.get("a/b?c=d"),
);

await drive(
  "add",
  "the pinned unit test's own write, with the two-field info it sends",
  contactRecord(CONTACT, "John Doe"),
  () => contacts.add(CONTACT, PINNED_INFO),
);

await drive(
  "add_empty_info",
  "an empty info object, which is written as `{}` rather than omitted",
  contactRecord(CONTACT, "John Doe"),
  () => contacts.add(CONTACT, {}),
);

await drive(
  "add_nested_info",
  "a nested and ordered info block, which reaches the wire in the caller's own field order",
  contactRecord(CONTACT, "John Doe"),
  () => contacts.add(CONTACT, { z: 1, a: { nested: true }, list: [1, 2, 3] }),
);

await drive(
  "update",
  "the pinned unit test's own update, with the same info",
  contactRecord(CONTACT, "John Doe"),
  () => contacts.update(CONTACT, PINNED_INFO),
);

await drive(
  "delete",
  "the pinned unit test's own delete, which the test asserts carries **no body at all**",
  {},
  () => contacts.delete(CONTACT),
);

await drive(
  "get_wrong_shape",
  "an answer that is not a contact — the reference casts it to `Contact` and returns it",
  { unexpected: true },
  () => contacts.get(CONTACT),
);

await drive(
  "list_wrong_shape",
  "a listing whose entries are missing the one field the schema requires",
  [{ alias: "John Doe" }],
  () => contacts.list(),
);

// ---------------------------------------------------------------------------
// 4. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const UNIT_TEST_ASSERTIONS = [
  "url + '/contacts?group=mygroup&filter_field=company&filter_value=mycompany'",
  "url + '/contacts/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao'",
  "assert.deepEqual(lastBody, info)",
  "assert.equal(lastCall[1]!.body, undefined)",
];
const normalizedTest = contactingTest.text.replace(/\s+/g, " ");
const unitTestAssertions = UNIT_TEST_ASSERTIONS.filter((line) => normalizedTest.includes(line.replace(/\s+/g, " ")));
if (unitTestAssertions.length !== UNIT_TEST_ASSERTIONS.length) {
  throw new Error("an assertion this fixture reproduces is no longer in the pinned unit test");
}

const INTEGRATION_LINE = "const list = await client.contacts().list(undefined, 'alias', `^${name}$`);";
if (!testUtil.text.replace(/\s+/g, " ").includes(INTEGRATION_LINE.replace(/\s+/g, " "))) {
  throw new Error("the integration helper's own listing call has moved");
}

const pinnedConfirmations = {
  unit_test_assertions: unitTestAssertions,
  unit_test_paths: [
    "/contacts?group=mygroup&filter_field=company&filter_value=mycompany",
    `/contacts/${CONTACT}`,
  ],
  unit_test_info: PINNED_INFO,
  unit_test_methods: ["GET", "GET", "POST", "PUT", "DELETE"],
  integration_helper_call: INTEGRATION_LINE,
  call_sites: scan("contacts().", { normalizeWhitespace: true }),
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "the pinned `Contacts` case is unusually complete for this port: it asserts all five paths, all five HTTP methods, both write bodies field for field, and that a delete carries no body at all. Every one of those is recomputed here from the reference's own driven output. Outside that case the family is used three times in the whole tree, all of them `list` — twice with no arguments and once through the integration helper with a filter whose value is a regular expression.",
};

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function call(name) {
  return calls.find((entry) => entry.name === name) ?? null;
}

const quirks = {
  an_unfiltered_listing_addresses_a_bare_question_mark: {
    path: call("list_unfiltered")?.request?.path ?? null,
    expression: declarations.list_path,
    note: "`path` is `'/contacts' + '?' + params.toString()`, concatenated unconditionally, so a listing with no arguments addresses `/contacts?`",
    rust_decision:
      "this port sends `/contacts`, on ADR `0028`'s three grounds applied again: Roadmap 3.10 strips the query before signing so the **signed path is identical**, an empty query is not a distinguishable resource, and Roadmap 5.3's builder cannot spell a bare `?` without a knob whose only users would be this call and `Operations.list`. Roadmap 9.2 owes it a live confirmation, as it does 6.5's.",
  },
  half_a_filter_is_silently_dropped: {
    guard: declarations.list_filter_guard,
    field_only: call("list_half_a_filter")?.request?.path ?? null,
    value_only: call("list_half_a_filter_value_only")?.request?.path ?? null,
    note: "the guard is `filterField !== undefined && filterValue !== undefined`, so naming one half without the other drops **both** — the caller asks for a filtered listing and is answered with an unfiltered one, which is the worst kind of wrong because it succeeds",
    rust_decision:
      "**unrepresentable**: the two are one `ContactFilter` value, so there is no way to name a field without a value. The group stays independent, because it genuinely is.",
  },
  the_prefix_is_not_encoded: {
    path: call("get_prefix_needing_encoding")?.request?.path ?? null,
    expression: declarations.get_path,
    note: "all four single-contact paths are `'/contacts/' + pre`, so a value carrying `/` or `?` addresses a different resource — and Roadmap 3.10 signs `@path`, so it changes what the signature commits to. Roadmap 5.3's own fixture already recorded `contacts().delete('a/b')` reaching two segments.",
    rust_decision:
      "refused twice over: the argument is Roadmap 3.4's validated `IdentifierPrefix` rather than a string, and Roadmap 5.3's builder would encode it exactly once regardless. A qualified prefix's alphabet is URL-safe Base64, so every real contact identifier reaches the path byte-identical.",
  },
  the_filter_value_is_encoded: {
    path: call("list_filter_needing_encoding")?.request?.path ?? null,
    expression: declarations.list_path,
    note: "the query is built with `URLSearchParams` rather than by interpolation, so a filter value holding `&` **is** encoded — one of the few dynamic values the reference encodes anywhere, and the opposite of what Roadmap 7.1 found in `Oobis.get`",
    rust_decision: "reproduced exactly; Roadmap 5.3's builder encodes every query value exactly once",
  },
  a_delete_carries_no_body: {
    fetch: declarations.delete_fetch,
    body_is_undefined: call("delete")?.request?.body_is_undefined ?? null,
    note: "`delete` passes `undefined` where the writes pass `info`, and the pinned test asserts the request's body is `undefined` rather than an empty object",
    rust_decision: "reproduced: no body is set on the request at all, which is what Roadmap 6.11's delete already does",
  },
  the_info_is_an_open_bag: {
    declaration: declarations.contact_info_interface,
    pinned: call("add")?.request?.body ?? null,
    ordered: call("add_nested_info")?.request?.body ?? null,
    empty: call("add_empty_info")?.request?.body ?? null,
    note: "`ContactInfo` is `{[key: string]: unknown}` handed straight to `JSON.stringify`, so the body's field order is the caller's object literal's and any shape at all is accepted",
    rust_decision:
      "an **ordered document** — Roadmap 3.2's `Sad`, which is what Roadmap 6.6 settled a request body is here, so a caller controls the bytes exactly. The one narrowing is ADR `0008`'s number space: an exact integer is representable and a float is not, which is recorded as a limitation rather than worked around.",
  },
  the_answers_are_cast_rather_than_decoded: {
    declaration: declarations.get_return,
    get_wrong_shape: call("get_wrong_shape")?.result ?? null,
    list_wrong_shape: call("list_wrong_shape")?.result ?? null,
    note: "all four reading methods return `res.json()` cast to `Contact` or `Contact[]`, so an answer of any shape reaches the caller as a contact",
    rust_decision:
      "decoded: both recorded wrong-shaped answers are proven refused, which is the rule Roadmap 6.8, 6.10, and 7.1 applied to their own answers. `id` is the one field the schema requires, and every other field the agent sends survives a round trip through Roadmap 4.1's open map.",
  },
  a_listing_has_no_paging: {
    parameters: declarations.list_parameters,
    note: "no range, no limit, no cursor: an agent holding many contacts answers with all of them in one body, where Roadmap 6.6's identifier listing at least accepts a `Range` header",
    rust_decision:
      "reproduced; the response is bounded only by Roadmap 5.1's transport limit, recorded as a limitation rather than a filter this port invents",
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
    "src/keri/app/contacting.ts",
    "src/types/keria-api-schema.ts",
    "test/app/contacting.test.ts",
    "test-integration/utils/test-util.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    contact_prefix: CONTACT,
    other_prefix: OTHER,
    note: "`Contacts` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-contacts/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-contacts fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
