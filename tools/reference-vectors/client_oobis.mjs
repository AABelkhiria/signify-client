// Records the pinned signify-ts checkout's OOBI endpoint.
//
// This port covers `Oobis.{get,resolve,endroles}` from `src/keri/app/coring.ts`: two reads and
// one write. `get` publishes the OOBIs a managed identifier advertises for a role, `resolve` asks
// the agent to go and fetch somebody else's, and `endroles` reads the endpoint authorizations an
// identifier has granted.
//
// Unlike the registries and schemas families, this one **does** have pinned unit coverage:
// `test/app/coring.test.ts` publishes three cases asserting five exact paths between them. So the
// generator drives the reference's own class through those calls and every integration call site
// besides, exactly as the `client-operations` generator did — `globalThis.fetch` is replaced with a
// recorder that answers and signs as a KERIA agent would, and the real client is walked through
// boot, connect, and every call.
//
// `Oobis` takes a whole `SignifyClient` rather than a narrow `fetch` dependency, so the whole
// client is driven with the clock and the agent's key pinned.
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

/** The passcode and URLs the pinned `coring.test.ts` publishes. */
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

/** A method's whole parameter list, which is where the reference's defaults live. */
function parameters(node) {
  return node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " "));
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

/** The members of one declared enum, in declaration order. */
function enumMembers(source, enumName) {
  let found = null;
  const visit = (node) => {
    if (ts.isEnumDeclaration(node) && node.name?.getText() === enumName) {
      found = node.members.map((member) => ({
        name: member.name.getText(),
        value: member.initializer?.getText().replace(/'/g, "") ?? null,
      }));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
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

/** Every literal role the pinned tree passes to `get`, so the default can be counted. */
function recordedGetCallSites() {
  const sites = [];
  const pattern = /oobis\(\)\s*\.\s*get\(([^)]*)\)/g;
  for (const file of PINNED_FILES) {
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    for (const found of text.matchAll(pattern)) {
      const argumentText = found[1].trim();
      const parts = argumentText.split(",").map((part) => part.trim());
      sites.push({
        file,
        call: `oobis().get(${argumentText})`,
        argument_count: parts.length,
        role: parts.length > 1 ? parts[1].replace(/'/g, "") : null,
      });
    }
  }
  return sites;
}

const getMethod = method(coring.source, "Oobis", "get");
const resolveMethod = method(coring.source, "Oobis", "resolve");
const endrolesMethod = method(coring.source, "Oobis", "endroles");

const declarations = {
  get_path: localDeclaration(getMethod, "path"),
  get_method: localDeclaration(getMethod, "method"),
  get_parameters: parameters(getMethod),
  get_return: firstText(getMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  resolve_path: localDeclaration(resolveMethod, "path"),
  resolve_method: localDeclaration(resolveMethod, "method"),
  resolve_parameters: parameters(resolveMethod),
  resolve_body: localDeclaration(resolveMethod, "data"),
  resolve_alias: firstText(resolveMethod, (node) => ts.isIfStatement(node)),
  endroles_path: localDeclaration(endrolesMethod, "path"),
  endroles_parameters: parameters(endrolesMethod),
  class_members: classMembers(coring.source, "Oobis"),
  oobi_type: schemaType("OOBI"),
  end_role_type: schemaType("EndRole"),
  oobi_role_enum: enumMembers(schema.source, "OOBIRole"),
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
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
    url: text,
    path,
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
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

const oobis = client.oobis();

// ---------------------------------------------------------------------------
// 3. Drive every call.
// ---------------------------------------------------------------------------

/** The AID both pinned `Endroles` cases use. */
const GROUP_AID = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
/**
 * The AID `endroles-by-aid.test.ts` asks about and expects nothing back for.
 *
 * It is **43 characters**, where a qualified `E` prefix is 44, so it is not a prefix at all —
 * the reference concatenates it into the path unchecked. See the `the_unknown_aid_is_not_a_prefix`
 * quirk.
 */
const UNKNOWN_AID = "EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
/** The same shape at the length a qualified prefix actually is, which this port can express. */
const UNKNOWN_VALID_AID = "EAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
/** The vLEI schema OOBI every multisig integration test resolves. */
const SCHEMA_OOBI = "http://vlei-server:7723/oobi/EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
/** A witness OOBI of the shape `resolve-env.ts` publishes. */
const WITNESS_OOBI = "http://witness-demo:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller";

/** One OOBI listing of the shape KERIA answers `get` with. */
function oobiAnswer(role, urls) {
  return { role, oobis: urls };
}

/** One end-role record of the shape KERIA answers `endroles` with. */
function endRole(cid, role, eid) {
  return { cid, role, eid };
}

/** One OOBI resolution operation of the shape KERIA answers `resolve` with. */
function oobiOperation(oobi, done) {
  const operation = { name: `oobi.${oobi}`, metadata: { oobi }, done };
  if (done) {
    operation.response = { ...agentState, i: GROUP_AID, d: GROUP_AID, et: "icp", di: "" };
  }
  return operation;
}

const calls = [];

/** Runs one call and records the request it produced with whatever came back. */
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
    request: request === null ? null : { path: request.path, method: request.method, body: request.body },
    result,
    error,
  });
  nextPayload = {};
}

await drive(
  "get_agent",
  "the pinned unit test's own call: `oobis.get('aid', 'agent')`",
  oobiAnswer("agent", [`${ADMIN_URL}/oobi/${GROUP_AID}/agent/${agentPrefix}`]),
  () => oobis.get("aid", "agent"),
);

await drive(
  "get_default_role",
  "`singlesig-drt.test.ts` calls `get('delegate')` with no role at all, which is the only pinned call site that takes the `= 'agent'` default",
  oobiAnswer("agent", [`${ADMIN_URL}/oobi/${GROUP_AID}/agent/${agentPrefix}`]),
  () => oobis.get("delegate"),
);

await drive(
  "get_witness_role",
  "`test-setup-single-client.test.ts` reads the witness role",
  oobiAnswer("witness", [WITNESS_OOBI]),
  () => oobis.get("name1", "witness"),
);

await drive(
  "get_mailbox_role",
  "`singlesig-drt.test.ts` reads the mailbox role",
  oobiAnswer("mailbox", [`${ADMIN_URL}/oobi/${GROUP_AID}/mailbox/${agentPrefix}`]),
  () => oobis.get("aid1", "mailbox"),
);

await drive(
  "get_name_needing_encoding",
  "an alias carrying path and query delimiters, which the reference concatenates raw",
  oobiAnswer("agent", []),
  () => oobis.get("a/b?c=d", "agent"),
);

await drive(
  "get_role_injecting_a_parameter",
  "a role carrying a query delimiter, which the reference interpolates raw into the query string",
  oobiAnswer("agent", []),
  () => oobis.get("aid", "agent&extra=1"),
);

await drive(
  "get_wrong_shape",
  "an answer that is not an OOBI listing at all — the reference casts it to `OOBI` and returns it",
  { unexpected: true },
  () => oobis.get("aid", "agent"),
);

await drive(
  "resolve_without_alias",
  "the pinned unit test's own call: `oobis.resolve('http://oobiurl.com')`",
  oobiOperation("http://oobiurl.com", false),
  () => oobis.resolve("http://oobiurl.com"),
);

await drive(
  "resolve_with_alias",
  "the pinned unit test's second call, naming a contact alias",
  oobiOperation("http://oobiurl.com", false),
  () => oobis.resolve("http://oobiurl.com", "witness"),
);

await drive(
  "resolve_schema_oobi",
  "the vLEI schema OOBI every multisig integration test resolves, aliased `schema`",
  oobiOperation(SCHEMA_OOBI, true),
  () => oobis.resolve(SCHEMA_OOBI, "schema"),
);

await drive(
  "resolve_witness_oobi",
  "a controller OOBI of the shape another agent's `get` answers with",
  oobiOperation(WITNESS_OOBI, false),
  () => oobis.resolve(WITNESS_OOBI, "member1"),
);

await drive(
  "resolve_empty_url",
  "an empty OOBI, which the reference sends as `{\"url\":\"\"}` and asks the agent to fetch",
  oobiOperation("", false),
  () => oobis.resolve(""),
);

await drive(
  "resolve_not_a_url",
  "an OOBI that is not a URL at all, which the reference also sends unchallenged",
  oobiOperation("not a url at all", false),
  () => oobis.resolve("not a url at all"),
);

await drive(
  "resolve_url_with_newline",
  "an OOBI carrying a newline and a control byte",
  oobiOperation("bad", false),
  () => oobis.resolve("http://oobiurl.com/\n\r x"),
);

await drive(
  "resolve_empty_alias",
  "an explicitly empty alias, which is written rather than dropped because only `undefined` is dropped",
  oobiOperation("http://oobiurl.com", false),
  () => oobis.resolve("http://oobiurl.com", ""),
);

await drive(
  "endroles_without_role",
  "the pinned `Endroles without role filter` case",
  [endRole(GROUP_AID, "agent", agentPrefix), endRole(GROUP_AID, "mailbox", agentPrefix)],
  () => oobis.endroles(GROUP_AID),
);

await drive(
  "endroles_with_role",
  "the pinned `Endroles with role filter` case",
  [endRole(GROUP_AID, "agent", agentPrefix)],
  () => oobis.endroles(GROUP_AID, "agent"),
);

await drive(
  "endroles_mailbox",
  "`endroles-by-aid.test.ts` filters by a role the identifier has not granted and expects an empty list back",
  [],
  () => oobis.endroles(GROUP_AID, "mailbox"),
);

await drive(
  "endroles_unknown_aid",
  "`endroles-by-aid.test.ts` asks about an AID the agent knows nothing about and expects an empty list",
  [],
  () => oobis.endroles(UNKNOWN_AID),
);

await drive(
  "endroles_unknown_valid_aid",
  "the same question asked with an AID of the length a qualified prefix actually is, which is what this port sends",
  [],
  () => oobis.endroles(UNKNOWN_VALID_AID),
);

await drive(
  "endroles_aid_needing_encoding",
  "an AID carrying path and query delimiters, which the reference concatenates raw",
  [],
  () => oobis.endroles("a/b?c=d"),
);

await drive(
  "endroles_role_needing_encoding",
  "a role that climbs out of its own path segment, which the reference concatenates raw",
  [],
  () => oobis.endroles(GROUP_AID, "../identifiers"),
);

await drive(
  "endroles_wrong_shape",
  "an answer whose records are missing declared fields — the reference casts it to `EndRole[]`",
  [{ cid: GROUP_AID }],
  () => oobis.endroles(GROUP_AID),
);

// ---------------------------------------------------------------------------
// 4. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const coringTest = parse("test/app/coring.test.ts");
const endrolesIntegration = parse("test-integration/endroles-by-aid.test.ts");

const UNIT_TEST_ASSERTIONS = [
  "url + '/identifiers/aid/oobis?role=agent'",
  "url + '/oobis'",
  "lastBody.url, 'http://oobiurl.com'",
  "lastBody.oobialias, 'witness'",
  "url + `/endroles/${aid}`",
  "url + `/endroles/${aid}/agent`",
];
const unitTestAssertions = UNIT_TEST_ASSERTIONS.filter((line) => coringTest.text.includes(line));
if (unitTestAssertions.length !== UNIT_TEST_ASSERTIONS.length) {
  throw new Error("an assertion this fixture reproduces is no longer in the pinned unit test");
}

const INTEGRATION_EXPECTATION_LINES = [
  "await aliceClient.oobis().endroles(groupAid)",
  ".endroles(groupAid, 'agent')",
  ".endroles(groupAid, 'mailbox')",
  ".endroles('EXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')",
  "expect(result).not.toHaveLength(0)",
  "expect(result).toHaveLength(0)",
  "expect(result).toHaveLength(1)",
  "expect(result.every((r: EndRole) => r.cid === groupAid)).toBe(true)",
  "expect(result.every((r: EndRole) => r.role === 'agent')).toBe(true)",
  "const oobiUrl = groupOobi.oobis[0].split('/agent/')[0]",
];
const INTEGRATION_EXPECTATIONS = INTEGRATION_EXPECTATION_LINES.filter((line) =>
  endrolesIntegration.text.replace(/\s+/g, " ").includes(line.replace(/\s+/g, " ")),
);
if (INTEGRATION_EXPECTATIONS.length !== INTEGRATION_EXPECTATION_LINES.length) {
  throw new Error("an assertion this fixture records has moved in `endroles-by-aid.test.ts`");
}

const getCallSites = recordedGetCallSites();
const defaultedGetCallSites = getCallSites.filter((site) => site.role === null);

const pinnedConfirmations = {
  unit_test_assertions: unitTestAssertions,
  unit_test_paths: [
    `/identifiers/aid/oobis?role=agent`,
    `/oobis`,
    `/endroles/${GROUP_AID}`,
    `/endroles/${GROUP_AID}/agent`,
  ],
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  get_call_sites: getCallSites,
  get_call_sites_taking_the_default: defaultedGetCallSites,
  resolve_call_count: scan("oobis().resolve(").total,
  endroles_call_sites: scan(".endroles(").files,
  integration_expectations: INTEGRATION_EXPECTATIONS,
  note: "unlike the registries and schemas families this one has real pinned unit coverage: three cases in `test/app/coring.test.ts` assert five exact paths, both `resolve` body fields, and both HTTP methods. Every one of those assertions is recomputed here from the reference's own driven output. `endroles-by-aid.test.ts` supplies the rest: the unknown-AID case that must answer with an empty list, and the role filter.",
};

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function callPath(name) {
  return calls.find((call) => call.name === name)?.request?.path ?? null;
}

function callBody(name) {
  return calls.find((call) => call.name === name)?.request?.body ?? null;
}

const quirks = {
  the_name_is_not_encoded: {
    path: callPath("get_name_needing_encoding"),
    expression: declarations.get_path,
    note: "`get` concatenates the alias straight into the path, so `get('a/b?c=d', 'agent')` addresses `/identifiers/a/b?c=d/oobis?role=agent` — a different resource, and a different `@path` for request authentication to sign",
    rust_decision:
      "refused by construction: the request builder encodes every path component exactly once and offers no way to skip it, which is the rule the identifiers endpoint applied to the same alias in the same path",
  },
  the_role_is_interpolated_into_the_query: {
    path: callPath("get_role_injecting_a_parameter"),
    expression: declarations.get_path,
    note: "`get` builds its query by string interpolation rather than with `URLSearchParams`, so a role holding `&` adds a query parameter of the caller's choosing — `get('aid', 'agent&extra=1')` sends `?role=agent&extra=1`",
    rust_decision:
      "refused by construction: the role is written through the request builder's `parameter`, which percent-encodes the value exactly once, so a role can never introduce a second parameter whatever it holds",
  },
  the_role_defaults_to_agent: {
    parameters: declarations.get_parameters,
    default_call: callPath("get_default_role"),
    call_sites_taking_the_default: defaultedGetCallSites,
    note: "`get(name, role = 'agent')` writes the default into the query, so an omitted role is still an observable request — `oobis().get('delegate')` sends `?role=agent`",
    rust_decision:
      "the role is a required argument and `DEFAULT_ROLE` names the reference's value, so what reaches the query is visible at the call site. The key states endpoint made the same choice for `QuerySequence`, and the reply event builder for a reply's timestamp.",
  },
  the_oobi_is_never_validated: {
    empty: callBody("resolve_empty_url"),
    not_a_url: callBody("resolve_not_a_url"),
    with_control_bytes: callBody("resolve_url_with_newline"),
    expression: declarations.resolve_body,
    note: "`resolve` takes `oobi: string` and sends it unchallenged, so an empty string, a sentence, or a value carrying a newline all become `{\"url\":…}` and the agent is asked to fetch them",
    rust_decision:
      "**refused**: the argument is `signify_http::transport::RequestUrl`, the same non-normalizing validator the transport uses — an absolute `http`/`https` URL of visible ASCII, no fragment, bounded at 2 KiB — so an OOBI that could not resolve is a caller error rather than a request. It preserves its bytes exactly, which matters because the agent fetches what it is given. Every OOBI the pinned tree resolves is accepted.",
  },
  an_empty_alias_is_written: {
    body: callBody("resolve_empty_alias"),
    absent: callBody("resolve_without_alias"),
    expression: declarations.resolve_alias,
    note: "the alias is dropped only when it is `undefined`; an explicitly empty one is written as `\"oobialias\":\"\"`, which names a contact with no name",
    rust_decision:
      "reproduced: `Option<&str>` tells the two apart exactly as `undefined` does, and an empty alias is written rather than dropped",
  },
  the_aid_is_not_encoded: {
    path: callPath("endroles_aid_needing_encoding"),
    expression: declarations.endroles_path,
    note: "`endroles` concatenates its AID into the path with no encoding, so `endroles('a/b?c=d')` addresses `/endroles/a/b?c=d`",
    rust_decision:
      "refused twice over: the argument is a validated `IdentifierPrefix` rather than a string, and the builder would encode it exactly once regardless. A qualified prefix's alphabet is URL-safe Base64, so every real AID reaches the path byte-identical — including the `EXXXX…` the integration test asks about.",
  },
  the_unknown_aid_is_not_a_prefix: {
    literal: UNKNOWN_AID,
    length: UNKNOWN_AID.length,
    qualified_length: GROUP_AID.length,
    path: callPath("endroles_unknown_aid"),
    valid_path: callPath("endroles_unknown_valid_aid"),
    note: "`endroles-by-aid.test.ts` asks about `EXXX…X`, which is 43 characters where a qualified `E` prefix is 44 — so the value the reference's own integration test sends is not an identifier prefix at all, and it reaches the path unchecked",
    rust_decision:
      "recorded verbatim and proven refused, which is what exchange message construction and the registries endpoint did with the same situation. The case that test is actually making — an AID the agent has never heard of answers with an empty list rather than a failure — is reproduced with `EAXXX…X`, one character longer and a valid prefix, whose recorded path is here beside it.",
  },
  the_endrole_role_is_a_raw_path_segment: {
    path: callPath("endroles_role_needing_encoding"),
    expression: declarations.endroles_path,
    note: "the role filter is concatenated as a path segment, so `endroles(aid, '../identifiers')` addresses a resource two levels up",
    rust_decision: "refused by construction, as every other dynamic component in this crate is",
  },
  the_answers_are_cast_rather_than_decoded: {
    get_wrong_shape: calls.find((call) => call.name === "get_wrong_shape")?.result ?? null,
    endroles_wrong_shape: calls.find((call) => call.name === "endroles_wrong_shape")?.result ?? null,
    declaration: declarations.get_return,
    note: "all three methods return `res.json()` cast to a declared type, so an answer of any shape reaches the caller as an `OOBI`, an `OOBIOperation`, or an `EndRole[]`",
    rust_decision:
      "decoded: each recorded wrong-shaped answer is proven refused, which is the rule the config and schemas endpoints applied to their own answers",
  },
  resolve_does_not_wait: {
    declaration: declarations.resolve_method,
    scan: scan("resolveOobi("),
    note: "`resolve` returns the operation the agent created and never polls it; every caller in the pinned tree immediately hands it to `waitOperation`, which is `Operations.wait`",
    rust_decision:
      "reproduced exactly. Polling is operation waiting's concern — the retry policy already built and pinned the schedule `Operations.wait` uses — so `resolve` returns the typed operation and the caller drives it.",
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
    "src/keri/app/coring.ts",
    "src/types/keria-api-schema.ts",
    "test/app/coring.test.ts",
    "test-integration/endroles-by-aid.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    group_aid: GROUP_AID,
    unknown_aid: UNKNOWN_AID,
    unknown_valid_aid: UNKNOWN_VALID_AID,
    schema_oobi: SCHEMA_OOBI,
    witness_oobi: WITNESS_OOBI,
    note: "`Oobis` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-oobis/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-oobis fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
