// Records the pinned signify-ts checkout's multisig registry, issuance, and revocation rounds.
//
// This port covers the three rounds a group runs over a credential registry: creating one,
// issuing a credential from it, and revoking that credential. The units are
// `createRegistryMultisig` and `issueCredentialMultisig` in
// `test-integration/utils/multisig-utils.ts`, and `multisigRevoke`, which is written inline in
// `test-integration/multisig.test.ts`. As for multisig inception, rotation and interaction, and
// delegated multisig, there is no source file, so the helper module is transpiled in memory and
// driven against a recording agent.
//
// Four things fall out, and the first is the largest defect in the multisig tree.
//
//   1. **A joining member never reads the proposal.** Both helpers do
//      `if (!isInitiator) await waitAndMarkNotification(client, route);` — they wait for a bell,
//      **discard the SAID it carries**, and then build from their own arguments. There is no
//      `getRequest`, no embed read, and no comparison anywhere. Two members handed a different
//      nonce create different registries; two handed different attributes issue different
//      credentials; and in both cases the group silently never reaches its threshold.
//   2. **A revocation travels in the issuance slot.** `multisigRevoke` builds
//      `{ iss: [rev, ''], anc: [...] }` and sends it on `/multisig/rev`, so a reader narrowing
//      through the reference's own `assertMultisigRev` finds no `rev` at all. The
//      `client-multisig-events` scan turned this up and left it here.
//   3. **The issuance result drops the signatures it computed.** `IssueCredentialResult` declares
//      `{ acdc, anc, iss, op }` and no `sigs`, so every multisig caller signs the same anchor bytes
//      a second time to build the attachment.
//   4. **One round is filed under a different topic.** A registry proposal uses `'registry'` where
//      every other round uses `'multisig'`.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as signifyModule from "./node_modules/signify-ts/dist/index.js";
import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { Siger } from "./node_modules/signify-ts/dist/keri/core/siger.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { b, d } from "./node_modules/signify-ts/dist/keri/core/core.js";
import { messagize } from "./node_modules/signify-ts/dist/keri/core/eventing.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

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
// 1. The three helpers, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const utils = parse("test-integration/utils/multisig-utils.ts");
const scenario = parse("test-integration/multisig.test.ts");
const vlei = parse("test-integration/multisig-vlei-issuance.test.ts");
const credentialing = parse("src/keri/app/credentialing.ts");

/** The whole text of one function declaration, wherever it is declared. */
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

/**
 * Every `waitAndMarkNotification` call, and whether its result is used for anything.
 *
 * A joining member that reads its proposal binds the SAID and fetches by it. One that does not
 * simply awaits the call as a statement — which is what both helpers here do.
 */
function notificationWaits(file, source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.getText() === "waitAndMarkNotification"
    ) {
      // Walk up past the `await` to see whether anything catches the value.
      let parent = node.parent;
      while (parent !== undefined && ts.isAwaitExpression(parent)) {
        parent = parent.parent;
      }
      const bound = parent !== undefined && ts.isVariableDeclaration(parent) ? parent.name.getText() : null;
      const enclosing = (() => {
        let scope = node.parent;
        while (scope !== undefined && !ts.isFunctionDeclaration(scope)) {
          scope = scope.parent;
        }
        return scope?.name?.getText() ?? "<top level>";
      })();
      found.push({
        file,
        enclosing,
        route: ts.isStringLiteralLike(node.arguments[1]) ? node.arguments[1].text : "<computed>",
        binds: bound,
        discarded: bound === null,
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `groups().getRequest(...)` call, which is how a proposal is actually read. */
function proposalReads(file, source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "getRequest"
    ) {
      const enclosing = (() => {
        let scope = node.parent;
        while (scope !== undefined && !ts.isFunctionDeclaration(scope)) {
          scope = scope.parent;
        }
        return scope?.name?.getText() ?? "<top level>";
      })();
      found.push({ file, enclosing });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `exchanges().send(...)` in one file: its route, its topic, and the embed it carries. */
function sendCalls(file, source) {
  const found = [];
  const embedSlots = (name, position) => {
    let best = null;
    const walk = (node) => {
      const isAssignment =
        ts.isVariableDeclaration(node) ||
        (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken);
      if (isAssignment) {
        const target = ts.isVariableDeclaration(node) ? node.name : node.left;
        const value = ts.isVariableDeclaration(node) ? node.initializer : node.right;
        if (
          value !== undefined &&
          target.getText() === name &&
          ts.isObjectLiteralExpression(value) &&
          node.getStart() < position &&
          (best === null || node.getStart() > best.at)
        ) {
          best = { at: node.getStart(), slots: value.properties.map((property) => property.name?.getText() ?? "") };
        }
      }
      ts.forEachChild(node, walk);
    };
    ts.forEachChild(source, walk);
    return best === null ? [] : best.slots;
  };
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "send" &&
      node.getText().includes("exchanges()") &&
      node.arguments.length >= 7
    ) {
      const route = ts.isStringLiteralLike(node.arguments[3]) ? node.arguments[3].text : "<computed>";
      const topic = ts.isStringLiteralLike(node.arguments[1]) ? node.arguments[1].text : "<computed>";
      const embeds = node.arguments[5];
      const slots = ts.isObjectLiteralExpression(embeds)
        ? embeds.properties.map((property) => property.name?.getText() ?? "")
        : embedSlots(embeds.getText(), node.getStart());
      found.push({ file, route, topic, embed_slots: slots });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** One interface's declared members, so a dropped field is visible. */
function interfaceMembers(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isInterfaceDeclaration(node) && node.name.getText() === name) {
      found = node.members.map((member) => ({
        name: member.name?.getText() ?? "",
        type: member.type?.getText().replace(/\s+/g, " ") ?? "<inferred>",
      }));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
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

const CREATE_REGISTRY = functionText(utils.source, "createRegistryMultisig");
const ISSUE_CREDENTIAL = functionText(utils.source, "issueCredentialMultisig");
const REVOKE = functionText(scenario.source, "multisigRevoke");
const WAITS = [
  ...notificationWaits("test-integration/utils/multisig-utils.ts", utils.source),
  ...notificationWaits("test-integration/multisig.test.ts", scenario.source),
];
const READS = [
  ...proposalReads("test-integration/utils/multisig-utils.ts", utils.source),
  ...proposalReads("test-integration/multisig.test.ts", scenario.source),
];
const SENDS = [
  ...sendCalls("test-integration/utils/multisig-utils.ts", utils.source),
  ...sendCalls("test-integration/multisig.test.ts", scenario.source),
];
const ISSUE_RESULT = interfaceMembers(credentialing.source, "IssueCredentialResult");
const REVOKE_RESULT = interfaceMembers(credentialing.source, "RevokeCredentialResult");

if (CREATE_REGISTRY === null || ISSUE_CREDENTIAL === null || REVOKE === null) {
  throw new Error("one of the three helpers is no longer where this generator expects it");
}

/** The two transaction helpers that wait for a notification and discard it. */
const discarding = WAITS.filter(
  (wait) => wait.discarded && ["createRegistryMultisig", "issueCredentialMultisig"].includes(wait.enclosing),
);
if (discarding.length !== 2) {
  throw new Error("the transaction helpers no longer discard their notifications; re-read the premise");
}
/** The send whose route names a revocation and whose embed carries an issuance. */
const misfiled = SENDS.filter(
  (call) => call.route === "/multisig/rev" && !call.embed_slots.includes("rev"),
);
if (misfiled.length === 0) {
  throw new Error("the revocation is no longer sent in the issuance slot; the finding is stale");
}
if (ISSUE_RESULT === null || ISSUE_RESULT.some((member) => member.name === "sigs")) {
  throw new Error("`IssueCredentialResult` now carries its signatures; the finding is stale");
}

const declarations = {
  create_registry_multisig: CREATE_REGISTRY,
  issue_credential_multisig: ISSUE_CREDENTIAL,
  multisig_revoke: REVOKE,
  notification_waits: WAITS,
  proposal_reads: READS,
  send_calls: SENDS,
  issue_credential_result: ISSUE_RESULT,
  revoke_credential_result: REVOKE_RESULT,
  registry_uses: scan("createRegistryMultisig("),
  issuance_uses: scan("issueCredentialMultisig("),
  scanned_files: PINNED_FILES.length,
  notes: {
    discarding: "`await waitAndMarkNotification(client, route);` as a statement — the SAID is never bound",
    slots: "an issuance embeds `{acdc, iss, anc}` and a revocation embeds `{iss, anc}`, so the two share a slot name",
  },
};

// ---------------------------------------------------------------------------
// 2. The helpers, transpiled in memory and loaded with a shim.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);

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
    // The stub returns a SAID that nothing reads — which is the point: both helpers here discard
    // it, and this generator proves that by never being asked for a group request.
    return { getStates, waitAndMarkNotification: async () => "EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF" };
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
const { startMultisigIncept, createRegistryMultisig, issueCredentialMultisig } = helperModule.exports;
if (
  typeof startMultisigIncept !== "function" ||
  typeof createRegistryMultisig !== "function" ||
  typeof issueCredentialMultisig !== "function"
) {
  throw new Error("the transpiled helpers did not export the three functions");
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

/** The nonce the vLEI scenario pins, so the registry identifier is reproducible. */
const NONCE = "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s";
/** The schema the vLEI scenario issues against. */
const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

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

const recorded = [];
/** The group's record, once it exists. */
let groupRecord = null;
/** The credential the group issued, once it has, so a revocation can read it back. */
let issuedCredential = null;

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
  if (path.startsWith("/credentials/") && httpMethod === "GET") {
    if (issuedCredential === null) {
      throw new Error("a credential was read before it was issued");
    }
    // `revoke` reads the credential to learn its registry and its current status digest.
    return {
      sad: issuedCredential,
      status: { i: issuedCredential.d, s: "0", d: issuedCredential.d, ri: issuedCredential.ri },
    };
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
  return { name: "registry.EGRP", metadata: { pre: "EGRP", sn: 1 }, done: false };
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
// 4. Drive the three rounds.
// ---------------------------------------------------------------------------

const calls = [];
const realLog = console.log;
console.log = () => {};

async function drive(name, note, run) {
  const before = recorded.length;
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
    result: result === null || result === undefined ? null : JSON.parse(JSON.stringify(result)),
    error,
  });
  return result;
}

await drive(
  "incept_the_group",
  "the group that will own the registry, from the multisig inception helper",
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
  "propose_the_registry",
  "the first member creates the registry and tells the other, on `/multisig/vcp` under the `registry` topic",
  async () =>
    await createRegistryMultisig(client, localMember, [peerMember], groupRecord, "vLEI Registry", NONCE, true),
);

await drive(
  "join_the_registry",
  "the second member waits for a notification, discards it, and creates a registry from its own arguments",
  async () =>
    await createRegistryMultisig(client, localMember, [peerMember], groupRecord, "vLEI Registry", NONCE, false),
);

await drive(
  "join_the_registry_with_a_different_nonce",
  "the same call with another nonce: it succeeds, and derives a different registry",
  async () =>
    await createRegistryMultisig(
      client,
      localMember,
      [peerMember],
      groupRecord,
      "vLEI Registry",
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
      false,
    ),
);

const registryBody = JSON.parse(
  calls[1].requests.find((request) => request.path.endsWith("/registries"))?.body ?? "null",
);
if (registryBody === null) {
  throw new Error("the registry was not created");
}
const REGISTRY = registryBody.vcp.i;

const credentialData = {
  i: GROUP,
  ri: REGISTRY,
  s: QVI_SCHEMA,
  a: { i: PEER_PREFIX, LEI: "5493001KJTIIGC8Y1R17", dt: "2023-11-14T22:13:20.123000+00:00" },
};

await drive(
  "propose_the_issuance",
  "the first member issues the credential and tells the other, on `/multisig/iss` under the `multisig` topic",
  async () => await issueCredentialMultisig(client, localMember, [peerMember], "multisig", credentialData, true),
);

await drive(
  "join_the_issuance",
  "the second member waits, discards the notification, and issues from its own credential data",
  async () => await issueCredentialMultisig(client, localMember, [peerMember], "multisig", credentialData, false),
);

await drive(
  "join_the_issuance_with_different_attributes",
  "the same call with another LEI: it succeeds, and issues a different credential",
  async () =>
    await issueCredentialMultisig(
      client,
      localMember,
      [peerMember],
      "multisig",
      { ...credentialData, a: { ...credentialData.a, LEI: "254900OPPU84GM83MG36" } },
      false,
    ),
);

const issuanceBody = JSON.parse(
  calls[4].requests.find((request) => request.path.endsWith("/credentials"))?.body ?? "null",
);
if (issuanceBody === null) {
  throw new Error("the credential was not issued");
}
issuedCredential = issuanceBody.acdc;

// `multisigRevoke` is written inline in the scenario rather than exported, so the round is driven
// through the reference's own `revoke` and `send` in the same order and with the same arguments.
await drive(
  "propose_the_revocation",
  "the revocation round, driven as `multisigRevoke` writes it: the `rev` event sent in the `iss` slot",
  async () => {
    const revoked = await client.credentials().revoke("multisig", issuanceBody.acdc.d);
    const keeper = client.manager.get(groupRecord);
    const signatures = await keeper.sign(b(revoked.anc.raw));
    const sigers = signatures.map((signature) => new Siger({ qb64: signature }));
    const attachment = d(messagize(revoked.anc, sigers)).substring(revoked.anc.size);
    await client
      .exchanges()
      .send(
        localMember.name,
        "multisig",
        localMember,
        "/multisig/rev",
        { gid: groupRecord.prefix },
        // The slot the reference uses: a revocation under the issuance label.
        { iss: [revoked.rev, ""], anc: [revoked.anc, attachment] },
        [peerMember.prefix],
      );
    return { revoked: revoked.rev.sad.d, ilk: revoked.rev.sad.t };
  },
);

console.log = realLog;

// ---------------------------------------------------------------------------
// 5. What the recording says.
// ---------------------------------------------------------------------------

const bodyOf = (name, ending) => {
  const call = calls.find((entry) => entry.name === name);
  const request = call?.requests.find((entry) => entry.path.endsWith(ending));
  return request?.body === undefined || request?.body === null ? null : JSON.parse(request.body);
};

const proposedRegistry = bodyOf("propose_the_registry", "/registries");
const joinedRegistry = bodyOf("join_the_registry", "/registries");
const divergentRegistry = bodyOf("join_the_registry_with_a_different_nonce", "/registries");
const proposedIssuance = bodyOf("propose_the_issuance", "/credentials");
const joinedIssuance = bodyOf("join_the_issuance", "/credentials");
const divergentIssuance = bodyOf("join_the_issuance_with_different_attributes", "/credentials");
const revocationAnnouncement = bodyOf("propose_the_revocation", "/exchanges");
if (
  proposedRegistry === null ||
  joinedRegistry === null ||
  divergentRegistry === null ||
  proposedIssuance === null ||
  joinedIssuance === null ||
  divergentIssuance === null ||
  revocationAnnouncement === null
) {
  throw new Error("a driven round posted nothing");
}

const quirks = {
  a_joining_member_never_reads_the_proposal: {
    declaration: "`if (!isInitiator) await waitAndMarkNotification(client, route);`",
    waits: discarding,
    group_requests_made: calls.some((entry) =>
      entry.requests.some((request) => request.path.startsWith("/multisig/request/")),
    ),
    proposal_reads_in_these_helpers: READS.filter((read) =>
      ["createRegistryMultisig", "issueCredentialMultisig"].includes(read.enclosing),
    ),
    note: "both helpers wait for a bell and discard the SAID it carries. No `getRequest` is ever made — driven here across six calls, none of which fetches a group request — so a joining member builds from its own arguments and nothing compares the result with what was proposed.",
    rust_decision:
      "the proposal is read and the value that decides the identifier is taken from it: `accept_registry` uses the nonce out of the proposed inception and `accept_issuance` compares the credential SAID it derived with the one it was shown. A mismatch is a typed error.",
  },
  a_different_nonce_is_a_different_registry: {
    declaration: "`createRegistryMultisig(..., nonce, ...)` — the nonce is the caller's, on both halves",
    proposed_registry: proposedRegistry.vcp.i,
    joined_registry: joinedRegistry.vcp.i,
    divergent_registry: divergentRegistry.vcp.i,
    agree: proposedRegistry.vcp.i === joinedRegistry.vcp.i,
    divergent_agrees: proposedRegistry.vcp.i === divergentRegistry.vcp.i,
    error: calls.find((entry) => entry.name === "join_the_registry_with_a_different_nonce").error,
    note: "a registry identifier is a digest over its inception and the nonce is inside it. Two members handed the same nonce derive the same registry; handed different ones they derive different registries and neither call fails. The group then holds two registries and agrees on none.",
    rust_decision:
      "the nonce is required on the proposing half — the endpoint beneath draws one from the operating system when it is absent, which for a group means every member deriving a different registry — and read from the proposal on the joining half.",
  },
  different_attributes_are_a_different_credential: {
    declaration: "`issueCredentialMultisig(..., kargsIss, ...)` — the credential data is the caller's, on both halves",
    proposed_credential: proposedIssuance.acdc.d,
    joined_credential: joinedIssuance.acdc.d,
    divergent_credential: divergentIssuance.acdc.d,
    agree: proposedIssuance.acdc.d === joinedIssuance.acdc.d,
    divergent_agrees: proposedIssuance.acdc.d === divergentIssuance.acdc.d,
    error: calls.find((entry) => entry.name === "join_the_issuance_with_different_attributes").error,
    note: "the same shape as the registry: every field of a credential is inside its SAID, so two members handed different attributes issue different credentials with no error on either side.",
    rust_decision: "the credential SAID this member derives is compared with the one the proposal carries.",
  },
  a_revocation_travels_in_the_issuance_slot: {
    declaration: "`const embeds = { iss: [rev, ''], anc: [anc, atc] };`",
    misfiled_sends: misfiled,
    announced_route: revocationAnnouncement.exn.r,
    announced_slots: Object.keys(revocationAnnouncement.exn.e).filter((slot) => slot !== "d"),
    embedded_ilk: revocationAnnouncement.exn.e.iss?.t ?? null,
    note: "the route says revocation and the embed carries the revocation event under the issuance label. A reader narrowing through the reference's own `assertMultisigRev` — which declares `e: { rev, d? }` — finds no `rev` at all. The `client-multisig-events` route-and-embed scan turned this up and left it here.",
    rust_decision:
      "the revocation travels in `rev`, which is the slot the exchange route table names for this route and the one the KERIA API schema declares. The reference's own pairing does not classify here.",
  },
  the_issuance_result_drops_its_signatures: {
    declaration: ISSUE_RESULT,
    revoke_declaration: REVOKE_RESULT,
    note: "`issue` computes the anchor's signatures and posts them, then returns `{ acdc, anc, iss, op }` without them — so `issueCredentialMultisig` fetches the group identifier again, rebuilds its keeper, and signs the same bytes a second time just to build the attachment. `revoke` returns `{ anc, rev, op }` and has the same gap.",
    rust_decision:
      "`IssuanceArtifacts.anchor` is an `IdentifierArtifact` — the event with its signatures — so the attachment is built from what the endpoint already returned and nothing is signed twice.",
  },
  one_round_is_filed_under_a_different_topic: {
    declaration: SENDS.filter((call) => call.route.startsWith("/multisig/")).map((call) => ({
      route: call.route,
      topic: call.topic,
    })),
    vcp_topics: SENDS.filter((call) => call.route === "/multisig/vcp").map((call) => call.topic),
    note: "a registry proposal is sent under the topic `registry` where every other multisig round uses `multisig` — and the pinned tree is not even consistent with itself: of its three `/multisig/vcp` sends, two use `registry` and one uses `multisig`. A member filtering notifications by topic therefore sees registry proposals in two places.",
    rust_decision:
      "the majority form is reproduced — the exchanges endpoint's own `REGISTRY_TOPIC` for this one route — because it is what `createRegistryMultisig`, the ported unit, sends. The disagreement is recorded rather than resolved, since nothing in the pinned tree settles which is intended.",
  },
};

const pinnedConfirmations = {
  group: GROUP,
  registry: REGISTRY,
  nonce: NONCE,
  schema: QVI_SCHEMA,
  credential: proposedIssuance.acdc.d,
  registry_paths: calls
    .find((entry) => entry.name === "propose_the_registry")
    .requests.map((request) => `${request.method} ${request.path}`),
  issuance_paths: calls
    .find((entry) => entry.name === "propose_the_issuance")
    .requests.map((request) => `${request.method} ${request.path}`),
  registry_route: "/multisig/vcp",
  registry_topic: "registry",
  issuance_route: "/multisig/iss",
  issuance_topic: "multisig",
  note: "a registry proposal embeds `{vcp, anc}` and an issuance embeds `{acdc, iss, anc}`; only the anchor carries an attachment, because its signature is what authorizes the rest.",
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: [
    "test-integration/utils/multisig-utils.ts",
    "test-integration/multisig.test.ts",
    "test-integration/multisig-vlei-issuance.test.ts",
    "src/keri/app/credentialing.ts",
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
    note: "Two of the three units live in the reference's integration utilities, so `multisig-utils.ts` is **transpiled in memory** by the reference's own pinned TypeScript and evaluated with a module shim, as the `client-multisig-inception` generator does. The third, `multisigRevoke`, is written inline in a test body and is driven through the reference's own `revoke` and `send` in the same order. Nothing is written into the submodule. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
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

const outputUrl = new URL("../../fixtures/client-multisig-credentials/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-multisig-credentials fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
