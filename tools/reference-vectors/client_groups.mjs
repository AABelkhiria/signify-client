// Records the pinned signify-ts checkout's group endpoint family.
//
// The Rust port covers the whole `Groups` class of `src/keri/app/grouping.ts`: `getRequest`,
// `sendRequest`, and `join`. It is the family a multisig member reads its peers' proposals through,
// and the first consumer of the exchange-route classifiers — `getRequest` returns exactly the
// `ExnMultisig` list those classify.
//
// `Groups` takes a whole `SignifyClient`, so this generator drives the real client the way the
// `client-exchanges` generator did: `globalThis.fetch` is replaced with a recorder that answers and
// signs as a KERIA agent would, with the clock and the agent's key pinned.
//
// Three things make the evidence here unusual.
//
// **Two of the three methods have no consumer.** `getRequest` is called twenty-one times across the
// integration tree; `sendRequest` and `join` are called nowhere outside the single pinned unit
// case. So for those two the only evidence of shape is their own declarations.
//
// **And that pinned case passes junk in every argument.** The SAID it reads by is forty-six
// characters where a qualified digest is forty-four; the rotation it joins with is `{ sad: {} }`;
// the signature is the string `'sig'`; the members are `['1','2','3']` and `['a','b','c']`; and the
// request it sends carries an empty signature list. Every one is recorded verbatim and proven
// refused, which is the pattern exchange-message construction and the registries and OOBI
// endpoints used.
//
// **The two POSTs disagree about their answers.** `sendRequest` declares `Promise<Exn>` and `join`
// declares `Promise<GroupOperation>`, for two writes to two paths under the same resource — the
// same disagreement the `client-exchanges` fixture recorded between `sendFromEvents` and
// `Ipex.submit*`, now inside one class.
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

/** The passcode and URLs the pinned `grouping.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

/** A genuine 44-character qualified digest, for the calls the pinned test cannot make. */
const REAL_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const GROUP_PREFIX = "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK";
const MEMBER = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SECOND_MEMBER = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

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

const grouping = parse("src/keri/app/grouping.ts");
const groupingTest = parse("test/app/grouping.test.ts");
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

function returnType(node) {
  return node?.type === undefined ? null : node.type.getText().replace(/\s+/g, " ");
}

function signature(node) {
  return node?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null;
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

/** Counts uses of a method outside the two files that declare and unit-test it. */
function consumers(name) {
  const hit = scan(`${name}(`);
  const own = ["src/keri/app/grouping.ts", "test/app/grouping.test.ts"];
  const outside = hit.files.filter((entry) => !own.includes(entry.file));
  return {
    needle: hit.needle,
    total: hit.total,
    consumer_files: outside,
    consumer_total: outside.reduce((sum, entry) => sum + entry.count, 0),
    scanned_files: hit.scanned_files,
  };
}

const getRequest = method(grouping.source, "Groups", "getRequest");
const sendRequest = method(grouping.source, "Groups", "sendRequest");
const joinMethod = method(grouping.source, "Groups", "join");

const declarations = {
  get_request_path: firstText(getRequest, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  get_request_method: firstText(getRequest, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  get_request_signature: signature(getRequest),
  get_request_return_type: returnType(getRequest),
  send_request_path: firstText(sendRequest, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  send_request_data: firstText(sendRequest, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "data"),
  send_request_method: firstText(sendRequest, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  send_request_signature: signature(sendRequest),
  send_request_return_type: returnType(sendRequest),
  join_path: firstText(joinMethod, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  join_data: firstText(joinMethod, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "data"),
  join_method: firstText(joinMethod, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  join_signature: signature(joinMethod),
  join_return_type: returnType(joinMethod),
  groups_members: classMembers(grouping.source, "Groups"),
  schema_exn_multisig: schemaType("ExnMultisig"),
  schema_group_operation_metadata: schemaType("GroupOperationMetadata"),
  get_request_consumers: consumers("getRequest"),
  send_request_consumers: consumers("sendRequest"),
  groups_accessor_uses: scan(".groups()"),
  notes: {
    raw_interpolation:
      "`getRequest` concatenates `'/multisig/request/' + said` and both writes interpolate `${name}` into a template literal, so none of the three dynamic values is encoded",
    send_request_body:
      "`sendRequest` sends `{exn, sigs, atc}` — no topic and no recipient list, unlike `Exchanges.sendFromEvents`, which sends `{tpc, exn, sigs, atc, rec}` to a different path for what a member does with the same message",
    join_reads_a_serder:
      "`join` declares `rot: any` and writes `rot.sad`, so it takes a `Serder` rather than the rotation event its own JSDoc names; passing the event itself would send `undefined`",
    join_topic: "`join`'s `tpc` is the literal `'multisig'`, where `Exchanges.send` takes it as an argument",
    return_types:
      "`sendRequest` declares `Promise<Exn>` and `join` declares `Promise<GroupOperation>` — two writes under one resource, disagreeing about what a KERIA answers, which is the disagreement the `client-exchanges` fixture recorded between `sendFromEvents` and `Ipex.submit*`",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

if (declarations.groups_members.join(",") !== "client,<constructor>,getRequest,sendRequest,join") {
  throw new Error(`the Groups class no longer has exactly three methods: ${declarations.groups_members}`);
}
if (declarations.send_request_consumers.consumer_total !== 0) {
  throw new Error("sendRequest gained a consumer; the recorded note is stale");
}
if (declarations.get_request_consumers.consumer_total === 0) {
  throw new Error("getRequest lost every consumer; the recorded note is stale");
}

// ---------------------------------------------------------------------------
// 2. The literals the pinned unit test passes, read from its own source.
// ---------------------------------------------------------------------------

/** Every string literal the pinned test writes, so its junk arguments are not transcribed. */
function testLiterals() {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node)) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(groupingTest.source, visit);
  return found;
}

const literals = testLiterals();
const PINNED_SAID = literals.find((text) => text.startsWith("ELI7pg979") && text.length !== 44);
if (PINNED_SAID === undefined) {
  throw new Error("the pinned test no longer reads by a non-SAID literal");
}

const pinnedArguments = {
  said: PINNED_SAID,
  said_length: PINNED_SAID.length,
  qualified_digest_length: REAL_SAID.length,
  said_is_a_digest: PINNED_SAID.length === 44,
  rotation: "{ sad: {} }",
  signatures: ["sig"],
  signing_members: ["1", "2", "3"],
  rotation_members: ["a", "b", "c"],
  send_request_signatures: [],
  note: "every argument the pinned `Groups` case passes is a value the protocol cannot hold: a forty-six-character SAID, a rotation whose event is `{}`, the signature `'sig'`, members named `1` and `a`, and — for `sendRequest` — no signature at all.",
};
if (pinnedArguments.said_is_a_digest) {
  throw new Error("the pinned SAID is now the right length; the recorded observation is stale");
}

// ---------------------------------------------------------------------------
// 3. A connected client, answering and signing as the `client-lifecycle` fixture did.
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
  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
  const httpMethod = init.method ?? "GET";
  recorded.push({
    path,
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });

  const payload = path.startsWith("/agent/")
    ? {
        agent: agentState,
        controller: {
          state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
          ee: { ...client.controller.serder.sad },
        },
        ridx: 0,
        pidx: 0,
      }
    : nextPayload;
  const responseHeaders = signedHeaders(httpMethod, path);
  responseHeaders.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status: 200, headers: responseHeaders });
};

await client.boot();
await client.connect();

const groups = client.groups();

// ---------------------------------------------------------------------------
// 4. The messages and answers the calls carry.
// ---------------------------------------------------------------------------

/** The exchange message the pinned test sends, read out of its own source. */
const PINNED_EXN = {
  v: "KERI10JSON0000bf_",
  t: "exn",
  d: "EPWm8LWxxQXmXlB8gbTZKDy7NIwXxpx49N_ZYTa5QkJV",
  i: "test",
  rp: "",
  p: "",
  dt: "2023-08-30T17:22:54.183Z",
  r: "/multisig/request",
  q: {},
  a: { i: "" },
  e: {},
};

/** A well-formed multisig inception proposal, of the shape a real member sends. */
const PROPOSAL_EXN = {
  v: "KERI10JSON000200_",
  t: "exn",
  d: REAL_SAID,
  i: MEMBER,
  rp: SECOND_MEMBER,
  p: "",
  dt: "2023-11-14T22:13:20.123000+00:00",
  r: "/multisig/icp",
  q: {},
  a: { gid: GROUP_PREFIX, smids: [MEMBER, SECOND_MEMBER], rmids: [MEMBER, SECOND_MEMBER] },
  e: {
    d: "EEMBED",
    icp: {
      v: "KERI10JSON000_",
      t: "icp",
      d: GROUP_PREFIX,
      i: GROUP_PREFIX,
      s: "0",
      kt: "2",
      k: ["DAA", "DBB"],
      nt: "2",
      n: ["EAA", "EBB"],
      bt: "0",
      b: [],
      c: [],
      a: [],
    },
  },
};

/** The rotation a real join contributes to. */
const ROTATION = {
  v: "KERI10JSON000_",
  t: "rot",
  d: "EROT",
  i: GROUP_PREFIX,
  s: "1",
  p: GROUP_PREFIX,
  kt: "2",
  k: ["DAA", "DBB"],
  nt: "2",
  n: ["EAA", "EBB"],
  bt: "0",
  br: [],
  ba: [],
  a: [],
};

/** A qualified indexed signature, of the shape a keeper produces. */
const SIGNATURE = `AAB${"A".repeat(85)}`;

/** The listing a real `getRequest` is answered with: one member's copy of a proposal. */
const REQUEST_LISTING = [
  {
    exn: PROPOSAL_EXN,
    paths: { "-e-icp": "-AABAA" },
    groupName: "multisig",
    memberName: "member1",
    sender: MEMBER,
  },
];

/** The operation a real `join` is answered with. */
const GROUP_OPERATION = {
  name: `group.${GROUP_PREFIX}`,
  metadata: { pre: GROUP_PREFIX, sn: 1 },
  done: false,
};

// ---------------------------------------------------------------------------
// 5. Drive the reference.
// ---------------------------------------------------------------------------

const calls = [];

async function drive(name, note, run, payload = {}) {
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
    answer: payload,
    request: request === null ? null : { path: request.path, method: request.method, body: request.body },
    result,
    error,
  });
  nextPayload = {};
}

await drive(
  "send_request_pinned",
  "the pinned unit test's own call: an unsigned exchange whose sender is the word `test`",
  async () => await groups.sendRequest("aid1", PINNED_EXN, pinnedArguments.send_request_signatures, ""),
  {},
);

await drive(
  "send_request_signed",
  "a real multisig proposal with one qualified signature and a transposed attachment",
  async () => await groups.sendRequest("aid1", PROPOSAL_EXN, [SIGNATURE], "-LAZ5AACAA-e-icp"),
  {},
);

await drive(
  "send_request_escaping_alias",
  "an alias holding path delimiters, which the reference interpolates raw into the address",
  async () => await groups.sendRequest("a/b?c=d", PROPOSAL_EXN, [SIGNATURE], ""),
  {},
);

await drive(
  "get_request_pinned",
  "the pinned unit test's own read, by a forty-six-character value where a qualified digest is forty-four",
  async () => await groups.getRequest(PINNED_SAID),
  REQUEST_LISTING,
);

await drive(
  "get_request_real_said",
  "the same read by a genuine qualified digest, answered with one member's copy of a proposal",
  async () => await groups.getRequest(REAL_SAID),
  REQUEST_LISTING,
);

await drive(
  "get_request_empty_said",
  "the empty string the reference's own `waitAndMarkNotification` falls back to when no notice arrived",
  async () => await groups.getRequest(""),
  [],
);

await drive(
  "get_request_escaping_said",
  "a SAID carrying path delimiters, which reaches the address unencoded",
  async () => await groups.getRequest("../identifiers/aid1?x=1"),
  [],
);

await drive(
  "get_request_wrong_shape",
  "an answer that is not a group request listing at all; the reference casts it to `ExnMultisig[]`",
  async () => await groups.getRequest(REAL_SAID),
  { notes: [] },
);

await drive(
  "join_pinned",
  "the pinned unit test's own join: an empty rotation, the signature `'sig'`, and members named `1` and `a`",
  async () =>
    await groups.join(
      "aid1",
      { sad: {} },
      pinnedArguments.signatures,
      PINNED_SAID,
      pinnedArguments.signing_members,
      pinnedArguments.rotation_members,
    ),
  GROUP_OPERATION,
);

await drive(
  "join_real",
  "a real join: a rotation event, one qualified signature, and two member prefixes",
  async () =>
    await groups.join("aid1", { sad: ROTATION }, [SIGNATURE], GROUP_PREFIX, [MEMBER, SECOND_MEMBER], [
      MEMBER,
      SECOND_MEMBER,
    ]),
  GROUP_OPERATION,
);

await drive(
  "join_no_members",
  "a join naming no members at all, which the reference sends unchallenged",
  async () => await groups.join("aid1", { sad: ROTATION }, [SIGNATURE], GROUP_PREFIX, [], []),
  GROUP_OPERATION,
);

await drive(
  "join_event_instead_of_serder",
  "the rotation event passed directly, which is what the method's own JSDoc names — `rot.sad` is then `undefined`",
  async () => await groups.join("aid1", ROTATION, [SIGNATURE], GROUP_PREFIX, [MEMBER], [MEMBER]),
  GROUP_OPERATION,
);

// ---------------------------------------------------------------------------
// 6. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

function called(name) {
  return calls.find((call) => call.name === name) ?? null;
}

/**
 * Every path the pinned test asserts, read as the literal half of a `url + '...'` expression.
 *
 * Taking only the asserted side keeps the exchange message's own `r: '/multisig/request'` — which
 * is a route rather than an address — out of the comparison.
 */
function assertedAddresses() {
  const found = [];
  const visit = (node) => {
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
      ts.isIdentifier(node.left) &&
      node.left.getText() === "url" &&
      ts.isStringLiteral(node.right)
    ) {
      found.push(node.right.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(groupingTest.source, visit);
  return [...new Set(found)];
}

const assertedPaths = assertedAddresses();
if (assertedPaths.length !== 3) {
  throw new Error(`the pinned test no longer asserts exactly three addresses: ${assertedPaths}`);
}

const pinnedConfirmations = {
  send_request_path: called("send_request_pinned")?.request?.path ?? null,
  send_request_method: called("send_request_pinned")?.request?.method ?? null,
  get_request_path: called("get_request_pinned")?.request?.path ?? null,
  get_request_method: called("get_request_pinned")?.request?.method ?? null,
  join_path: called("join_pinned")?.request?.path ?? null,
  join_method: called("join_pinned")?.request?.method ?? null,
  published_paths: assertedPaths,
  every_pinned_assertion_is_driven:
    called("send_request_pinned")?.request?.path === "/identifiers/aid1/multisig/request" &&
    called("send_request_pinned")?.request?.method === "POST" &&
    called("get_request_pinned")?.request?.path === `/multisig/request/${PINNED_SAID}` &&
    called("get_request_pinned")?.request?.method === "GET" &&
    called("join_pinned")?.request?.path === "/identifiers/aid1/multisig/join" &&
    called("join_pinned")?.request?.method === "POST",
  note: "the pinned `Groups` case asserts three addresses and three methods, and every one is recomputed here from the reference's own class. It asserts nothing about any body, which is why the bodies below are the reference's output rather than its expectations.",
};
pinnedConfirmations.every_published_path_is_driven = pinnedConfirmations.published_paths.every((published) =>
  calls.some((call) => call.request?.path === published),
);
if (!pinnedConfirmations.every_pinned_assertion_is_driven || !pinnedConfirmations.every_published_path_is_driven) {
  throw new Error("the pinned group assertions no longer reproduce");
}

// ---------------------------------------------------------------------------
// 7. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  the_pinned_case_passes_junk_in_every_argument: {
    arguments: pinnedArguments,
    send_request: called("send_request_pinned")?.request ?? null,
    get_request: called("get_request_pinned")?.request ?? null,
    join: called("join_pinned")?.request ?? null,
    note: "the only test of this class in the pinned tree passes a forty-six-character SAID, a rotation whose event is `{}`, the signature `'sig'`, members named `1` and `a`, and an empty signature list — and asserts only the three addresses, so none of it is checked",
    rust_decision:
      "each recorded request is reproduced in shape rather than byte for byte, and each argument is proven unrepresentable — the pattern exchange-message construction and the registries and OOBI endpoints used for a pinned vector the types cannot express. The three addresses, which are what the test actually asserts, reproduce exactly.",
  },
  a_request_may_carry_no_signature: {
    request: called("send_request_pinned")?.request ?? null,
    declaration: declarations.send_request_signature,
    note: "`sendRequest` declares `sigs: string[]` and sends whatever it is given; the pinned test sends `[]`, which asks the agent to relay to every group member a proposal nobody signed",
    rust_decision:
      "refused. A `SignedExchange` comes from `create_message`, which signs, and an empty signature set is checked before the body is built — the reasoning the IPEX submission endpoint applied to an empty recipient list.",
  },
  none_of_the_three_dynamic_values_is_encoded: {
    get_request_path: declarations.get_request_path,
    send_request_path: declarations.send_request_path,
    join_path: declarations.join_path,
    escaping_alias: called("send_request_escaping_alias")?.request?.path ?? null,
    escaping_said: called("get_request_escaping_said")?.request?.path ?? null,
    note: "`getRequest` concatenates its SAID and both writes interpolate their alias, so a value holding `/` or `?` addresses a different resource — and request authentication signs `@path`",
    rust_decision:
      "closed by the request builder and by typing: the SAID is a validated `Said` and the alias is encoded exactly once, so neither recorded input is representable.",
  },
  join_reads_a_serder_rather_than_an_event: {
    declaration: declarations.join_data,
    signature: declarations.join_signature,
    with_serder: JSON.parse(called("join_real")?.request?.body ?? "null")?.rot ?? null,
    with_event: JSON.parse(called("join_event_instead_of_serder")?.request?.body ?? "null")?.rot ?? null,
    note: "`join` declares `rot: any` and writes `rot.sad`, so passing the rotation event its own JSDoc names sends `rot: undefined` — recorded both ways round",
    rust_decision:
      "the argument is an `IdentifierArtifact`, which carries the event and the signatures that go with it, so there is no second thing to pass and nothing to read a field off.",
  },
  the_two_writes_disagree_about_their_answers: {
    send_request: declarations.send_request_return_type,
    join: declarations.join_return_type,
    note: "two writes under one resource, one declaring an exchange message and the other a long-running operation, both unchecked `res.json()` casts — the disagreement the `client-exchanges` fixture recorded between `sendFromEvents` and `Ipex.submit*`, now inside a single class",
    rust_decision:
      "`join`'s answer is decoded as the operation it declares, which is what every other write in this crate is answered with; `send_request` reuses `SentExchange`, which keeps the body and offers a decoder for each shape. The open question of which shape KERIA answers covers this path too.",
  },
  a_join_may_name_no_members: {
    request: called("join_no_members")?.request ?? null,
    note: "`join` sends whatever member lists it is given, including empty ones, which asks the agent to rotate a group into having no signers",
    rust_decision:
      "an empty signing-member list is refused; an empty rotation-member list is not, because the reference's own `Identifiers.rotate` writes an empty `rmids` for a single-signature identifier and the Rust `rotate` reproduces it.",
  },
  a_request_body_carries_no_topic_and_no_recipients: {
    declaration: declarations.send_request_data,
    note: "`sendRequest` sends `{exn, sigs, atc}` where `Exchanges.sendFromEvents` sends `{tpc, exn, sigs, atc, rec}` for the same kind of message; the agent is left to work out both from the message's own route",
    rust_decision:
      "reproduced exactly. The two are different endpoints with different bodies, and this one's is the shorter; `SignedExchange` supplies all three fields it does write.",
  },
};

// ---------------------------------------------------------------------------
// 8. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: [
    "src/keri/app/grouping.ts",
    "src/types/keria-api-schema.ts",
    "test/app/grouping.test.ts",
    "test-integration/utils/test-util.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    note: "`Groups` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would, with the clock and the agent's key pinned. Nothing here derives an identifier key. `PUBLIC TEST MATERIAL`: the passcode is the one `grouping.test.ts` publishes and has never protected anything.",
  },
  declarations,
  pinned_arguments: pinnedArguments,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-groups/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-groups fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
