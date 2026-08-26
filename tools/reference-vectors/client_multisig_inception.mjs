// Records the pinned signify-ts checkout's multisig inception workflow.
//
// Roadmap 8.3 ports `startMultisigIncept` and `acceptMultisigIncept` — the two halves of bringing a
// multisig group into existence. They are the third kind of unit this port has had to deal with,
// after a source file and a type system: **orchestration the reference only ever writes in its own
// test helpers**, in `test-integration/utils/multisig-utils.ts`. There is no `src` file to port, so
// `PORTING.md` §4.5 gets another Rust-only row.
//
// Those helpers are TypeScript that imports the package by name, so they are not importable from
// the built `dist`. This generator **transpiles the one file in memory** with the reference's own
// pinned compiler and evaluates it with a three-entry module shim — the built `dist` for
// `signify-ts`, a stub for the one helper it needs from `test-util.ts`, and node's `assert`. It
// writes nothing into the submodule, and what runs is the
// reference's own code rather than a re-expression of it.
//
// The stubbed helper is `getStates`, three lines long; its source is read and asserted against the
// stub, so the substitution is checked rather than trusted.
//
// Four things fall out of driving them.
//
//   1. **The initiator addresses its own proposal to itself.** `startMultisigIncept` passes
//      `participants` as the recipient list, and the local member is the first of them — so through
//      the loop Roadmap 7.7 recorded, the `exn` is addressed to the sender.
//   2. **The accepting member reads `rmids` and then discards it**, sending `rmids: smids` onward.
//   3. **The accepting member does not await its own exchange.** The `send` is a floating promise:
//      the helper returns the operation whether or not the message ever left.
//   4. **`toad` is read with a base-ten `parseInt` from a hexadecimal field.** Below ten they
//      agree; at ten or more the two members derive different group identifiers and the group
//      silently never forms.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as signifyModule from "../../reference/signify-ts/dist/index.js";
import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

/** The three witnesses the pinned scenario names. */
const WITNESSES = [
  "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
  "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
  "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
];

// ---------------------------------------------------------------------------
// 0. Pin the clock: an exchange message's `dt` is a clock reading.
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
// 1. The ported helpers, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const utils = parse("test-integration/utils/multisig-utils.ts");
const testUtil = parse("test-integration/utils/test-util.ts");
const scenario = parse("test-integration/multisig-inception.test.ts");

/** The whole text of one exported function declaration. */
function functionText(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The whole text of one exported interface. */
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

/** Whether a call expression is awaited, by walking up from it. */
function awaitedCalls(source, receiver, methodName) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === methodName &&
      node.getText().includes(receiver)
    ) {
      let parent = node.parent;
      let awaited = false;
      // `a.b().c()` chains put the await above the outermost call.
      while (parent !== undefined && (ts.isCallExpression(parent) || ts.isPropertyAccessExpression(parent))) {
        parent = parent.parent;
      }
      if (parent !== undefined && ts.isAwaitExpression(parent)) {
        awaited = true;
      }
      const enclosing = (() => {
        let scope = node.parent;
        while (scope !== undefined && !ts.isFunctionDeclaration(scope)) {
          scope = scope.parent;
        }
        return scope?.name?.getText() ?? "<top level>";
      })();
      found.push({ enclosing, awaited, text: node.getText().replace(/\s+/g, " ").slice(0, 120) });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
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

const START = functionText(utils.source, "startMultisigIncept");
const ACCEPT = functionText(utils.source, "acceptMultisigIncept");
const GET_STATES = functionText(testUtil.source, "getStates");

const declarations = {
  start_multisig_incept: START,
  accept_multisig_incept: ACCEPT,
  get_states: GET_STATES,
  start_args: interfaceText(utils.source, "StartMultisigInceptArgs"),
  accept_args: interfaceText(utils.source, "AcceptMultisigInceptArgs"),
  send_calls: awaitedCalls(utils.source, "exchanges()", "send"),
  scenario_witnesses: WITNESSES,
  start_uses: scan("startMultisigIncept("),
  accept_uses: scan("acceptMultisigIncept("),
  no_source_file: scan("startMultisigIncept").files.every((hit) => hit.file.startsWith("test-integration/")),
  notes: {
    no_upstream_file:
      "neither helper exists under `src`: the reference writes this orchestration only in its own integration utilities, which is why `PORTING.md` §4.5 gets a Rust-only row",
    initiator_addresses_itself:
      "`startMultisigIncept` passes `participants` as the recipient list, and the pinned scenario puts the local member first — so through the loop Roadmap 7.7 recorded, the message is addressed to its own sender",
    accepter_discards_rmids:
      "`acceptMultisigIncept` reads `exn.a.rmids ?? smids`, derives `rstates` from it, and then sends `{ gid, smids, rmids: smids }` — the rotation set it read never reaches the members it relays to",
    accepter_does_not_await:
      "the accepting member's `exchanges().send(...)` is not awaited and its result is not returned, so the helper reports success whether or not the message left",
    toad_is_parsed_base_ten:
      "`toad: parseInt(icp.bt)` reads a field the protocol writes in hexadecimal; below ten the two agree, and at ten or more the accepting member derives a different group identifier",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

if (!declarations.no_source_file) {
  throw new Error("the multisig helpers moved into `src`; this item is no longer a Rust-only row");
}
if (!ACCEPT.includes("rmids: smids")) {
  throw new Error("`acceptMultisigIncept` no longer relays smids as rmids; the recorded note is stale");
}
if (!ACCEPT.includes("parseInt(icp.bt)")) {
  throw new Error("`acceptMultisigIncept` no longer parses `bt` with parseInt; the recorded note is stale");
}

// The unawaited send is the finding that needs the syntax tree rather than a scan.
const sendCalls = declarations.send_calls.filter((call) =>
  ["startMultisigIncept", "acceptMultisigIncept"].includes(call.enclosing),
);
if (sendCalls.length !== 2) {
  throw new Error(`expected one send per helper, found ${sendCalls.length}`);
}
const unawaited = sendCalls.filter((call) => !call.awaited).map((call) => call.enclosing);
if (unawaited.join(",") !== "acceptMultisigIncept") {
  throw new Error(`the unawaited send moved: ${unawaited}`);
}

// ---------------------------------------------------------------------------
// 2. The helpers themselves, transpiled in memory and loaded with a shim.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);

/** The one helper `multisig-utils.ts` imports from `test-util.ts` and the two functions need. */
async function getStates(client, prefixes) {
  const participantStates = await Promise.all(prefixes.map((prefix) => client.keyStates().get(prefix)));
  return participantStates.map((state) => state[0]);
}

// The stub is checked against the source rather than trusted: same body, same shape.
const GET_STATES_BODY = "const participantStates = await Promise.all( prefixes.map((p) => client.keyStates().get(p)) ); return participantStates.map((s) => s[0]);";
if (GET_STATES === null || !GET_STATES.includes(GET_STATES_BODY)) {
  throw new Error("the `getStates` stub no longer matches the reference's own body");
}

const transpiled = ts.transpileModule(utils.text, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

const shimmedRequire = (specifier) => {
  if (specifier === "signify-ts") {
    return { ...signifyModule, default: signifyModule.default ?? signifyModule };
  }
  if (specifier === "./test-util.ts") {
    return { getStates, waitAndMarkNotification: async () => "" };
  }
  return nodeRequire(specifier);
};

const helperModule = { exports: {} };
// eslint-disable-next-line no-new-func -- the alternative is writing into the pinned submodule.
new Function("require", "exports", "module", transpiled)(shimmedRequire, helperModule.exports, helperModule);

const { startMultisigIncept, acceptMultisigIncept } = helperModule.exports;
if (typeof startMultisigIncept !== "function" || typeof acceptMultisigIncept !== "function") {
  throw new Error("the transpiled helpers did not export the two functions");
}

// ---------------------------------------------------------------------------
// 3. A connected client whose agent answers as a KERIA would.
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

/** Opens a sealed salty salt through the controller's own decrypter. */
function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

/** The reference's own `mockGetAID`, read out of its test helper. */
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

const testUtils = parse("test/app/test-utils.ts");
const MOCK_GET_AID = objectLiteral(testUtils.source, "mockGetAID");
if (MOCK_GET_AID === null) {
  throw new Error("mockGetAID is no longer where this generator expects it");
}
const ADDED_INCEPTION_STAMP = "2023-08-21T22:30:46.473545+00:00";
const LOCAL_MEMBER = { ...MOCK_GET_AID, name: "member1", icp_dt: MOCK_GET_AID.icp_dt ?? ADDED_INCEPTION_STAMP };
const LOCAL_PREFIX = LOCAL_MEMBER.prefix;
const PEER_PREFIX = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

/** The key state each participant is answered with; `getStates` reads `[0]`. */
function keyState(prefix) {
  return {
    vn: [1, 0],
    i: prefix,
    s: "0",
    p: "",
    d: prefix,
    f: "0",
    dt: "2023-08-21T22:30:46.473545+00:00",
    et: "icp",
    kt: "1",
    k: ["DPmhSfdhCPxr3EqjxzEtF8TVy0YX7ATo0Uc8oo2cnmY9"],
    nt: "1",
    n: ["EAORnRtObOgNiOlMolji-KijC_isa3lRDpHCsol79cOc"],
    bt: "0",
    b: [],
    c: [],
    ee: { s: "0", d: prefix, br: [], ba: [] },
    di: "",
  };
}

const recorded = [];
let groupRequestListing = [];

function signedHeaders(httpMethod, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
  ]);
  return authenticator.sign(headers, httpMethod, path.split("?")[0]);
}

function answer(path, httpMethod) {
  if (path.startsWith("/agent/")) {
    return {
      agent: agentState,
      controller: {
        state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
        ee: { ...client.controller.serder.sad },
      },
      ridx: 0,
      pidx: 0,
    };
  }
  if (path.startsWith("/states?")) {
    const prefixes = [...new URLSearchParams(path.slice(path.indexOf("?") + 1)).getAll("pre")];
    return prefixes.map(keyState);
  }
  if (path.startsWith("/multisig/request/")) {
    return groupRequestListing;
  }
  if (path.startsWith("/identifiers/") && httpMethod === "GET" && !path.includes("/")) {
    return LOCAL_MEMBER;
  }
  if (path.startsWith("/identifiers/") && httpMethod === "GET") {
    return LOCAL_MEMBER;
  }
  // Every write is answered with a long-running operation, as a KERIA does.
  return { name: "group.EGRP", metadata: { pre: "EGRP", sn: 0 }, done: false };
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
  const headers = signedHeaders(httpMethod, path);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(answer(path, httpMethod)), { status: 200, headers });
};

await client.boot();
await client.connect();

// ---------------------------------------------------------------------------
// 4. Drive the two helpers.
// ---------------------------------------------------------------------------

const calls = [];

async function drive(name, note, run) {
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    result = await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  // The accepting helper does not await its own send, so give the microtask queue a turn before
  // deciding what left — which is itself the evidence that it does not wait.
  await new Promise((resolve) => setTimeout(resolve, 0));
  calls.push({
    name,
    note,
    requests: recorded.slice(before).map((request) => ({ ...request })),
    result: result === null || result === undefined ? null : JSON.parse(JSON.stringify(result)),
    error,
  });
}

await drive(
  "start_multisig_incept",
  "the pinned scenario's own first step: member1 proposes a two-of-two group over three witnesses",
  async () =>
    await startMultisigIncept(client, {
      groupName: "multisig",
      localMemberName: "member1",
      participants: [LOCAL_PREFIX, PEER_PREFIX],
      toad: 2,
      isith: 2,
      nsith: 2,
      wits: WITNESSES,
    }),
);

await drive(
  "start_multisig_incept_no_witnesses",
  "the scenario's second group: the same proposal with no witnesses and a witness threshold of zero",
  async () =>
    await startMultisigIncept(client, {
      groupName: "multisig2",
      localMemberName: "member1",
      participants: [LOCAL_PREFIX, PEER_PREFIX],
      toad: 0,
      isith: 2,
      nsith: 2,
      wits: [],
    }),
);

// The proposal the accepting member reads back, built from what the initiator actually sent.
const proposalBody = JSON.parse(
  calls[0].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
if (proposalBody === null) {
  throw new Error("the initiator sent no exchange message");
}
groupRequestListing = [
  {
    exn: proposalBody.exn,
    paths: {},
    groupName: "multisig",
    memberName: "member1",
    sender: LOCAL_PREFIX,
  },
];

await drive(
  "accept_multisig_incept",
  "the second half: a member reads the proposal the initiator sent and joins the group it describes",
  async () =>
    await acceptMultisigIncept(client, {
      groupName: "multisig",
      localMemberName: "member1",
      msgSaid: proposalBody.exn.d,
    }),
);

// A proposal whose rotation set differs from its signing set, so the discard is observable.
const divergent = JSON.parse(JSON.stringify(proposalBody.exn));
divergent.a.rmids = [PEER_PREFIX];
groupRequestListing = [{ exn: divergent, paths: {}, groupName: "multisig", memberName: "member1", sender: LOCAL_PREFIX }];

await drive(
  "accept_with_divergent_rotation_members",
  "a proposal whose rmids differ from its smids: the accepting member reads them, uses them for rstates, and relays smids in their place",
  async () => await acceptMultisigIncept(client, { groupName: "multisig", localMemberName: "member1", msgSaid: divergent.d }),
);

// A proposal whose witness threshold is hexadecimal `a` — ten.
const hexToad = JSON.parse(JSON.stringify(proposalBody.exn));
hexToad.e.icp.bt = "a";
groupRequestListing = [{ exn: hexToad, paths: {}, groupName: "multisig", memberName: "member1", sender: LOCAL_PREFIX }];

await drive(
  "accept_with_hexadecimal_witness_threshold",
  "a proposal whose `bt` is the hexadecimal `a`, which `parseInt` reads as not-a-number",
  async () => await acceptMultisigIncept(client, { groupName: "multisig", localMemberName: "member1", msgSaid: hexToad.d }),
);

// A proposal whose witness threshold is the two-digit hexadecimal `10` — sixteen. This is the
// dangerous one: `parseInt` reads it as ten, so nothing throws and the accepting member simply
// derives a different group.
const silentToad = JSON.parse(JSON.stringify(proposalBody.exn));
silentToad.e.icp.bt = "10";
// Sixteen distinct witnesses, so a threshold of sixteen is a threshold the event can carry: the
// three the scenario names plus thirteen built from the first by varying its last character.
const SIXTEEN_WITNESSES = [
  ...WITNESSES,
  ..."ABCDEFGHIJKLM".split("").map((suffix) => `${WITNESSES[0].slice(0, 43)}${suffix}`),
];
silentToad.e.icp.b = SIXTEEN_WITNESSES;
groupRequestListing = [
  { exn: silentToad, paths: {}, groupName: "multisig", memberName: "member1", sender: LOCAL_PREFIX },
];

await drive(
  "accept_with_two_digit_hexadecimal_threshold",
  "a proposal whose `bt` is the hexadecimal `10` — sixteen — which `parseInt` reads as ten, so nothing fails and a different group is derived",
  async () =>
    await acceptMultisigIncept(client, { groupName: "multisig", localMemberName: "member1", msgSaid: silentToad.d }),
);

// ---------------------------------------------------------------------------
// 5. What the scenario asserts.
// ---------------------------------------------------------------------------

function scenarioLiterals(predicate) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && predicate(node.text)) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(scenario.source, visit);
  return [...new Set(found)];
}

const initiator = calls[0];
const proposal = JSON.parse(initiator.requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null");

const pinnedConfirmations = {
  scenario_group_names: scenarioLiterals((text) => text.startsWith("multisig")),
  scenario_member_names: scenarioLiterals((text) => text.startsWith("member")),
  scenario_route: scenarioLiterals((text) => text === "/multisig/icp"),
  initiator_paths: initiator.requests.map((request) => `${request.method} ${request.path}`),
  proposal_route: proposal?.exn?.r ?? null,
  proposal_addressed_to: proposal?.exn?.rp ?? null,
  proposal_sender: proposal?.exn?.i ?? null,
  proposal_delivered_to: proposal?.rec ?? null,
  group_prefix: proposal?.exn?.a?.gid ?? null,
  note: "the pinned scenario has no unit-test counterpart, so what it publishes is the shape of the workflow rather than an address: two group names, two member names, one route, and three witnesses. Each is driven here through the reference's own helpers.",
};
if (pinnedConfirmations.proposal_route !== "/multisig/icp") {
  throw new Error("the initiator no longer proposes on /multisig/icp");
}
if (pinnedConfirmations.proposal_addressed_to !== pinnedConfirmations.proposal_sender) {
  throw new Error("the initiator no longer addresses its proposal to itself; the recorded note is stale");
}

// ---------------------------------------------------------------------------
// 6. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function called(name) {
  return calls.find((call) => call.name === name) ?? null;
}

function submission(name) {
  return called(name)?.requests.find((request) => request.path.endsWith("/exchanges")) ?? null;
}

const accepted = JSON.parse(submission("accept_multisig_incept")?.body ?? "null");
const divergentSent = JSON.parse(submission("accept_with_divergent_rotation_members")?.body ?? "null");

const quirks = {
  the_initiator_addresses_its_proposal_to_itself: {
    declaration: declarations.notes.initiator_addresses_itself,
    sender: pinnedConfirmations.proposal_sender,
    addressed_to: pinnedConfirmations.proposal_addressed_to,
    delivered_to: pinnedConfirmations.proposal_delivered_to,
    note: "`startMultisigIncept` passes `participants` as the recipient list and the scenario puts the local member first, so `Exchanges.send` — which addresses the message to `recipients[0]` and delivers it to all of them — produces an `exn` whose `rp` is its own `i`. Every other member receives a proposal addressed to the proposer.",
    rust_decision:
      "the addressee is a separate argument from the delivery list (Roadmap 7.7), and the local member is removed from the delivery list here as the *accepting* helper already does — so a proposal is addressed to a peer and delivered to the peers.",
  },
  the_accepting_member_discards_the_rotation_set: {
    declaration: declarations.notes.accepter_discards_rmids,
    read_rmids: divergent.a.rmids,
    relayed_rmids: divergentSent?.exn?.a?.rmids ?? null,
    relayed_smids: divergentSent?.exn?.a?.smids ?? null,
    note: "`acceptMultisigIncept` computes `rmids` from the proposal and derives `rstates` from it, then relays `{ gid, smids, rmids: smids }` — so a third member joining from the accepter's message sees the signing set where the rotation set belongs",
    rust_decision:
      "the rotation set read from the proposal is the rotation set relayed. Nothing is silently substituted, and a proposal whose two sets differ survives the round.",
  },
  the_accepting_member_does_not_await_its_message: {
    send_calls: sendCalls,
    note: "the accepting helper's `exchanges().send(...)` is a floating promise whose result is discarded, so the helper returns its operation whether or not the message ever left — and a transport failure there is unobservable",
    rust_decision:
      "awaited. The proposal is part of joining, so `accept_inception` fails when it fails; a member that could not tell its peers has not joined.",
  },
  the_witness_threshold_is_read_in_the_wrong_base: {
    declaration: declarations.notes.toad_is_parsed_base_ten,
    hexadecimal_bt: hexToad.e.icp.bt,
    parsed_as: Number.parseInt(hexToad.e.icp.bt),
    correct_value: Number.parseInt(hexToad.e.icp.bt, 16),
    loud_failure: called("accept_with_hexadecimal_witness_threshold")?.error ?? null,
    silent: (() => {
      const proposed = silentToad.e.icp;
      const built = JSON.parse(submission("accept_with_two_digit_hexadecimal_threshold")?.body ?? "null")?.exn?.e?.icp
        ?? null;
      return {
        proposed_bt: proposed.bt,
        proposed_bt_means: Number.parseInt(proposed.bt, 16),
        rebuilt_bt: built?.bt ?? null,
        rebuilt_bt_means: built === null ? null : Number.parseInt(built.bt, 16),
        thresholds_agree: built !== null && built.bt === proposed.bt,
        // The group the accepting member derived from its rebuilt event. The `i` in the message it
        // was shown is the *original* proposal's, before this vector changed `bt`, so the number
        // that matters is the threshold above rather than a comparison with it.
        rebuilt_group: built?.i ?? null,
        error: called("accept_with_two_digit_hexadecimal_threshold")?.error ?? null,
      };
    })(),
    note: "`toad: parseInt(icp.bt)` reads a field the protocol writes in hexadecimal. Below ten the two agree. `'a'` is ten and parses to `NaN`, which throws — loudly, at least. `'10'` is sixteen and parses to ten, which throws nothing: the accepting member rebuilds the inception with a different witness threshold, derives a different group identifier, and the two members never converge on a group at all.",
    rust_decision:
      "the threshold is not re-parsed at all: the accepting member takes the proposal's own witness configuration as the typed value Roadmap 4.1 decoded, so there is no string to read in the wrong base. This is the same class of question Roadmap 6.7 raised about `KeyStates.query`, and unlike that one it is settled — `bt` is written by `toad.toString(16)` in the reference's own builder, so hexadecimal is not a guess.",
  },
  there_is_no_source_file: {
    scan: declarations.start_uses,
    note: "neither helper exists under `src`; the reference writes this orchestration only in its own integration utilities, so there is no exported API to port and no unit test to reproduce",
    rust_decision:
      "ported as a workflow in `signify-client::multisig`, and recorded in §4.5 as a Rust-only row — the fifth, after Roadmap 5.1, 5.2, 5.4, and 5.5.",
  },
};

// ---------------------------------------------------------------------------
// 7. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: [
    "test-integration/utils/multisig-utils.ts",
    "test-integration/utils/test-util.ts",
    "test-integration/multisig-inception.test.ts",
    "test/app/test-utils.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    local_member_prefix: LOCAL_PREFIX,
    peer_prefix: PEER_PREFIX,
    note: "The ported unit lives only in the reference's integration utilities, which import the package by name and are not built into `dist`. So `multisig-utils.ts` is **transpiled in memory** by the reference's own pinned TypeScript and evaluated with a three-entry module shim — the built `dist`, a checked stub for the one `test-util.ts` helper it needs, and node's `assert`. Nothing is written into the submodule, and what runs is the reference's own code. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
  },
  declarations,
  key_states: {
    [LOCAL_PREFIX]: keyState(LOCAL_PREFIX),
    [PEER_PREFIX]: keyState(PEER_PREFIX),
  },
  identifier_record: (() => {
    const copy = JSON.parse(JSON.stringify(LOCAL_MEMBER));
    copy.salty.sxlt_opens_to = openSealed(BRAN, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
    return copy;
  })(),
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-multisig-inception/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-multisig-inception fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
