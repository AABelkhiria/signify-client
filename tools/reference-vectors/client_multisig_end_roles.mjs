// Records the pinned signify-ts checkout's group end-role round.
//
// A group identifier has no agent endpoint until its members authorize one, so nothing addressed to
// the group reaches a member's agent before this round. The unit is `addEndRoleMultisig` in
// `test-integration/utils/multisig-utils.ts`, called by three integration scenarios. As in the
// other multisig rounds there is no source file, so the helper module is transpiled in memory and
// driven against a recording agent.
//
// What falls out:
//
//   1. **A joining member never reads the proposal.** `if (!isInitiator)` it waits for as many
//      `/multisig/rpy` notifications as there are signing members, **discards them**, and builds
//      its replies from its own `timestamp` argument. The scenarios agree only because one process
//      hands every member the same `stamp`; driven with another stamp the joining member signs
//      different replies and nothing fails.
//   2. **Every signing member's agent is authorized**, one reply and one announcement per agent,
//      reading `Object.keys(signing.ends.agent)[0]` out of the members listing.
//   3. **A member with no agent throws part way through the loop**, after the members before it
//      were already authorized and announced.
//   4. **The seal is the state the caller passed in**, not the group's state as the agent holds it,
//      so a caller holding a group record from before a rotation seals to a superseded event.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as signifyModule from "./node_modules/signify-ts/dist/index.js";
import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

/** The stamp every member is handed, as `endroles-by-aid.test.ts` hands one `stamp` to both. */
const STAMP = "2023-11-14T22:13:20.123000+00:00";
/** The stamp a member on another clock would use. */
const OTHER_STAMP = "2023-11-14T22:13:21.123000+00:00";

/** The three witnesses the multisig scenarios name. */
const WITNESSES = [
  "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
  "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
  "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
];

// ---------------------------------------------------------------------------
// 0. Pin the clock.
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
// 1. The helper, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const utils = parse("test-integration/utils/multisig-utils.ts");
const endroles = parse("test-integration/endroles-by-aid.test.ts");

/** The whole text of one function declaration, whitespace collapsed. */
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

/** Every call of `callee` inside `enclosing`, as whitespace-collapsed text. */
function callsIn(source, enclosing, callee) {
  const found = [];
  const visit = (node, inside) => {
    const now = inside || (ts.isFunctionDeclaration(node) && node.name?.getText() === enclosing);
    if (now && ts.isCallExpression(node) && node.expression.getText().endsWith(callee)) {
      found.push(node.getText().replace(/\s+/g, " "));
    }
    ts.forEachChild(node, (child) => visit(child, now));
  };
  ts.forEachChild(source, (child) => visit(child, false));
  return found;
}

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

const HELPER = functionText(utils.source, "addEndRoleMultisig");
if (HELPER === null) {
  throw new Error("addEndRoleMultisig is no longer where this generator expects it");
}
const WAITS = callsIn(utils.source, "addEndRoleMultisig", "waitAndMarkNotification");
const READS = callsIn(utils.source, "addEndRoleMultisig", "getRequest");
const SENDS = callsIn(utils.source, "addEndRoleMultisig", ".send");
const SCENARIO_CALLS = callsIn(endroles.source, "<none>", "addEndRoleMultisig");
if (WAITS.length !== 1 || READS.length !== 0 || SENDS.length !== 1) {
  throw new Error("the helper's waits, reads, or sends changed; re-read the premise");
}

const declarations = {
  add_end_role_multisig: HELPER,
  notification_waits: WAITS,
  proposal_reads: READS,
  sends: SENDS,
  agent_read: "const eid = Object.keys(agentEnds)[0];",
  seal_read: "i: multisigAID.prefix, s: ghabState1['ee']['s'], d: ghabState1['ee']['d']",
  shared_stamp: endroles.text.includes("const stamp = new Date().toISOString()"),
  helper_uses: scan("addEndRoleMultisig("),
  scanned_files: PINNED_FILES.length,
  notes: {
    joining: "`if (!isInitiator) { await waitAndMarkNotification(client, '/multisig/rpy', { minCount: signings.length }); }` — awaited as a statement, so the SAIDs are never bound",
    loop: "`for (const signing of signings)` — one `addEndRole` and one `send` per signing member's agent",
  },
};
if (!declarations.shared_stamp) {
  throw new Error("endroles-by-aid.test.ts no longer builds one stamp for both members");
}

// ---------------------------------------------------------------------------
// 2. The helper, transpiled in memory and loaded with a shim.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);
const waits = [];

async function getStates(client, prefixes) {
  const participantStates = await Promise.all(prefixes.map((prefix) => client.keyStates().get(prefix)));
  return participantStates.map((state) => state[0]);
}

const transpiled = ts.transpileModule(utils.text, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

const shimmedRequire = (specifier) => {
  if (specifier === "signify-ts") {
    return { ...signifyModule, default: signifyModule.default ?? signifyModule };
  }
  if (specifier === "./test-util.ts") {
    // Records what the joining half waits for. The SAID it returns is never read by the helper,
    // which this generator proves by never being asked for a group request.
    return {
      getStates,
      waitAndMarkNotification: async (_client, route, options = {}) => {
        waits.push({ route, min_count: options.minCount ?? 1 });
        return "EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF";
      },
    };
  }
  if (specifier === "assert") {
    const nodeAssert = nodeRequire("assert");
    return { ...nodeAssert, default: nodeAssert };
  }
  return nodeRequire(specifier);
};

const helperModule = { exports: {} };
// eslint-disable-next-line no-new-func -- the alternative is writing into the pinned submodule.
new Function("require", "exports", "module", transpiled)(shimmedRequire, helperModule.exports, helperModule);
const { startMultisigIncept, addEndRoleMultisig } = helperModule.exports;
if (typeof startMultisigIncept !== "function" || typeof addEndRoleMultisig !== "function") {
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

function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

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
/** Each member's own agent. */
const LOCAL_AGENT = agentPrefix;
const PEER_AGENT = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

function keyState(prefix) {
  return {
    vn: [1, 0],
    i: prefix,
    s: "0",
    p: "",
    d: prefix,
    f: "0",
    dt: ADDED_INCEPTION_STAMP,
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

/** The members listing a KERIA answers for the group: both members, each with its own agent. */
const MEMBERS = {
  signing: [
    { aid: LOCAL_PREFIX, ends: { agent: { [LOCAL_AGENT]: { http: "http://127.0.0.1:3902/" } } } },
    { aid: PEER_PREFIX, ends: { agent: { [PEER_AGENT]: { http: "http://127.0.0.1:3912/" } } } },
  ],
  rotation: [
    { aid: LOCAL_PREFIX, ends: { agent: { [LOCAL_AGENT]: { http: "http://127.0.0.1:3902/" } } } },
    { aid: PEER_PREFIX, ends: { agent: { [PEER_AGENT]: { http: "http://127.0.0.1:3912/" } } } },
  ],
};
/** The same listing with the second member authorizing no agent. */
const MEMBERS_WITHOUT_AN_AGENT = {
  signing: [MEMBERS.signing[0], { aid: PEER_PREFIX, ends: {} }],
  rotation: MEMBERS.rotation,
};

const recorded = [];
let groupRecord = null;
let membersListing = MEMBERS;

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
  if (path === "/identifiers/multisig/members") {
    return membersListing;
  }
  if (path.startsWith("/identifiers/multisig") && httpMethod === "GET") {
    if (groupRecord === null) {
      throw new Error("the group was read before it was incepted");
    }
    return groupRecord;
  }
  if (path.startsWith("/identifiers/") && httpMethod === "GET") {
    return LOCAL_MEMBER;
  }
  return { name: "endrole.EGRP", metadata: {}, done: true, response: {} };
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
// 4. Drive the round.
// ---------------------------------------------------------------------------

const calls = [];
const realLog = console.log;
console.log = () => {};

async function drive(name, note, run) {
  const before = recorded.length;
  const waitsBefore = waits.length;
  let result = null;
  let error = null;
  try {
    result = await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
    if (process.env.SHOW_ERRORS) {
      process.stderr.write(`${name}: ${thrown?.stack ?? error}\n`);
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 0));
  calls.push({
    name,
    note,
    requests: recorded.slice(before).map((request) => ({ ...request })),
    waits: waits.slice(waitsBefore),
    result: result === null || result === undefined ? null : JSON.parse(JSON.stringify(result)),
    error,
  });
  return result;
}

await drive(
  "incept_the_group",
  "the group whose agents are authorized, from the multisig inception helper",
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

const creation = JSON.parse(calls[0].requests.find((request) => request.path === "/identifiers")?.body ?? "null");
if (creation === null) {
  throw new Error("the group was not created");
}
const GROUP = creation.icp.i;

groupRecord = {
  name: "multisig",
  prefix: GROUP,
  transferable: true,
  windexes: [],
  icp_dt: ADDED_INCEPTION_STAMP,
  group: creation.group,
  state: {
    vn: [1, 0],
    i: GROUP,
    s: creation.icp.s,
    p: "",
    d: creation.icp.d,
    f: "0",
    dt: ADDED_INCEPTION_STAMP,
    et: "icp",
    kt: creation.icp.kt,
    k: creation.icp.k,
    nt: creation.icp.nt,
    n: creation.icp.n,
    bt: creation.icp.bt,
    b: creation.icp.b,
    c: [],
    ee: { s: creation.icp.s, d: creation.icp.d, br: [], ba: [] },
    di: "",
  },
};

const localMember = await client.identifiers().get("member1");
const peerMember = { ...LOCAL_MEMBER, name: "member2", prefix: PEER_PREFIX };

await drive(
  "propose_the_end_roles",
  "the first member authorizes every signing member's agent, announcing each on `/multisig/rpy`",
  async () => await addEndRoleMultisig(client, "multisig", localMember, [peerMember], groupRecord, STAMP, true),
);

await drive(
  "join_the_end_roles",
  "the second member waits for one notification per member, discards them, and signs from its own stamp",
  async () => await addEndRoleMultisig(client, "multisig", localMember, [peerMember], groupRecord, STAMP, false),
);

await drive(
  "join_the_end_roles_on_another_clock",
  "the same call a second later: it succeeds, and signs different replies",
  async () => await addEndRoleMultisig(client, "multisig", localMember, [peerMember], groupRecord, OTHER_STAMP, false),
);

await drive(
  "propose_with_a_stale_group_state",
  "the caller's group record names an establishment event the agent no longer holds; the seal follows the argument",
  async () =>
    await addEndRoleMultisig(
      client,
      "multisig",
      localMember,
      [peerMember],
      {
        ...groupRecord,
        state: { ...groupRecord.state, ee: { ...groupRecord.state.ee, s: "7", d: "EStaleEstablishmentEventDigest00000000000000" } },
      },
      STAMP,
      true,
    ),
);

membersListing = MEMBERS_WITHOUT_AN_AGENT;
await drive(
  "propose_with_a_member_without_an_agent",
  "the second signing member authorizes no agent: the loop throws after the first member's reply was submitted and announced",
  async () => await addEndRoleMultisig(client, "multisig", localMember, [peerMember], groupRecord, STAMP, true),
);
membersListing = MEMBERS;

console.log = realLog;

// ---------------------------------------------------------------------------
// 5. What the recording says.
// ---------------------------------------------------------------------------

const callNamed = (name) => {
  const call = calls.find((entry) => entry.name === name);
  if (call === undefined) {
    throw new Error(`no call named ${name}`);
  }
  return call;
};
const bodiesOf = (name, ending) =>
  callNamed(name)
    .requests.filter((request) => request.method === "POST" && request.path.endsWith(ending))
    .map((request) => JSON.parse(request.body));

const proposedReplies = bodiesOf("propose_the_end_roles", "/endroles");
const joinedReplies = bodiesOf("join_the_end_roles", "/endroles");
const divergentReplies = bodiesOf("join_the_end_roles_on_another_clock", "/endroles");
const proposedAnnouncements = bodiesOf("propose_the_end_roles", "/exchanges");
const staleAnnouncements = bodiesOf("propose_with_a_stale_group_state", "/exchanges");
const partial = callNamed("propose_with_a_member_without_an_agent");
if (proposedReplies.length !== 2 || proposedAnnouncements.length !== 2) {
  throw new Error("the proposing half no longer authorizes one agent per member");
}

const saids = (bodies) => bodies.map((body) => body.rpy.d);

const quirks = {
  a_joining_member_never_reads_the_proposal: {
    declaration: declarations.notes.joining,
    waits: callNamed("join_the_end_roles").waits,
    group_requests_made: calls.some((entry) =>
      entry.requests.some((request) => request.path.startsWith("/multisig/request/")),
    ),
    note: "the joining half waits for as many `/multisig/rpy` notifications as there are signing members and never binds what they carry. No group request is fetched in any driven call, so a joining member builds its replies from its own arguments and nothing compares them with what was proposed.",
    rust_decision:
      "`accept_end_role` reads the stamp, role, and endpoint out of the proposal's embedded reply and refuses with `ProposalMismatch` when the reply it builds has another SAID. It takes no timestamp.",
  },
  the_members_agree_only_on_a_shared_stamp: {
    declaration: "`const stamp = new Date().toISOString().replace('Z', '000+00:00');` handed to both members",
    proposed_replies: saids(proposedReplies),
    joined_replies: saids(joinedReplies),
    divergent_replies: saids(divergentReplies),
    agree: saids(proposedReplies).join() === saids(joinedReplies).join(),
    divergent_agrees: saids(proposedReplies).join() === saids(divergentReplies).join(),
    divergent_error: callNamed("join_the_end_roles_on_another_clock").error,
    note: "a reply's SAID covers its `dt`, so members sign the same reply only when they stamp it identically. The scenarios hand every member one `stamp` from one process; a member a second later signs different replies, the group reaches its threshold on none, and neither call fails.",
    rust_decision: "the stamp is read from the proposal, so every joining member signs the proposer's reply.",
  },
  every_members_agent_is_authorized: {
    declaration: declarations.agent_read,
    endpoints: proposedReplies.map((body) => body.rpy.a.eid),
    roles: proposedReplies.map((body) => body.rpy.a.role),
    announcements: proposedAnnouncements.length,
    announcement_route: proposedAnnouncements[0].exn.r,
    announcement_attributes: Object.keys(proposedAnnouncements[0].exn.a),
    announcement_slots: Object.keys(proposedAnnouncements[0].exn.e).filter((slot) => slot !== "d"),
    note: "one `addEndRole` and one `/multisig/rpy` per signing member, each authorizing that member's first agent for the group. This is the behaviour worth keeping: authorizing only the proposer's agent would leave every other member unreachable through the group.",
    rust_decision:
      "`propose_agent_end_roles` loops the same way, reading each member's agent from the members listing; the announcement names the members in `smids`/`rmids` beside `gid`, as every other round here does.",
  },
  a_member_without_an_agent_throws_part_way: {
    declaration: "`if (!agentEnds) { throw new Error('signing.ends.agent is null or undefined'); }` inside the loop",
    error: partial.error,
    replies_submitted_before: bodiesOf("propose_with_a_member_without_an_agent", "/endroles").length,
    announcements_sent_before: bodiesOf("propose_with_a_member_without_an_agent", "/exchanges").length,
    note: "the check sits inside the loop, so the members listed before the agentless one are authorized and announced first, and the round is left half done.",
    rust_decision:
      "`member_agents` reads every member's agent before anything is submitted and refuses with `MemberHasNoAgent`, so nothing is sent.",
  },
  the_seal_is_the_callers_group_state: {
    declaration: declarations.seal_read,
    stale_announcement_attachment_names_the_stale_digest: staleAnnouncements.every((body) =>
      body.atc.includes("EStaleEstablishmentEventDigest00000000000000"),
    ),
    note: "the seal is built from the `multisigAID` the caller passed in, not from the agent's record, so a caller still holding the group from before a rotation seals every reply to an establishment event the group no longer holds.",
    rust_decision: "the seal is read from the group's record as the agent reports it when the reply is announced.",
  },
};

const pinnedConfirmations = {
  group: GROUP,
  stamp: STAMP,
  agents: [LOCAL_AGENT, PEER_AGENT],
  members: [LOCAL_PREFIX, PEER_PREFIX],
  reply_route: "/end/role/add",
  announcement_route: "/multisig/rpy",
  announcement_topic: "multisig",
  announcement_slot: "rpy",
  propose_paths: callNamed("propose_the_end_roles").requests.map((request) => `${request.method} ${request.path}`),
  note: "each reply is `{rpy, sigs}` posted to the group's `endroles`, and each announcement carries the reply in `rpy` with the group's establishment seal in the attachment.",
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-09-17",
  sources: [
    "test-integration/utils/multisig-utils.ts",
    "test-integration/endroles-by-aid.test.ts",
    "test-integration/utils/test-util.ts",
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
    note: "The unit lives in the reference's integration utilities, so `multisig-utils.ts` is **transpiled in memory** by the reference's own pinned TypeScript and evaluated with a module shim, as the `client-multisig-inception` generator does. Nothing is written into the submodule. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`, and the members listing names one agent per member. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
  },
  declarations,
  key_states: {
    [LOCAL_PREFIX]: keyState(LOCAL_PREFIX),
    [PEER_PREFIX]: keyState(PEER_PREFIX),
  },
  members: MEMBERS,
  members_without_an_agent: MEMBERS_WITHOUT_AN_AGENT,
  identifier_record: (() => {
    const copy = JSON.parse(JSON.stringify(LOCAL_MEMBER));
    copy.salty.sxlt_opens_to = openSealed(BRAN, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
    return copy;
  })(),
  group_record: (() => {
    const copy = JSON.parse(JSON.stringify(groupRecord));
    copy.group.mhab.salty.sxlt_opens_to = openSealed(BRAN, copy.group.mhab.salty.sxlt);
    copy.group.mhab.salty.sxlt = "<SXLT>";
    return copy;
  })(),
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-multisig-end-roles/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-multisig-end-roles fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
