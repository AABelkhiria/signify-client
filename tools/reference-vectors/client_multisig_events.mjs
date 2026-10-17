// Records the pinned signify-ts checkout's multisig rotation and interaction rounds.
//
// This port covers the two rounds a multisig group runs *after* it exists: an interaction, which
// anchors data in the group's log, and a rotation, which changes who signs for it. Like multisig
// inception there is **no source file** — but this time there is not even a helper. Both rounds are
// written inline in `test-integration/multisig.test.ts`, and the only function-shaped counterpart
// is `delegateMultisig`, whose interaction anchors a delegation approval (the delegated multisig
// subject).
//
// So the evidence has two halves.
//
// The **syntax tree** supplies what cannot be driven: every `exchanges().send` in the multisig
// tree with the route it names and the embed slot it actually carries, and every
// `waitAndMarkNotification` with the route it waits on. Those two lists are what make the finding
// machine-checked rather than transcribed.
//
// The **recording agent** supplies the bytes: the reference's own `identifiers().interact`,
// `identifiers().rotate`, `exchanges().send`, and `groups().join` are driven against a group the
// reference itself incepted, so every recorded body is its own code's output.
//
// Three things fall out.
//
//   1. **Both joining members announce a rotation on the interaction route.** Only the initiator
//      sends `/multisig/rot`; members two and three send `/multisig/rot`'s embed — a `rot` — under
//      `/multisig/ixn`, while both peers are waiting on `/multisig/rot`. The route and the embed
//      disagree, which is exactly the mismatch the exchange route classifier refuses.
//   2. **A joining member never reads the rotation it is joining.** In `multisig.test.ts` it calls
//      `rotate` again with its own `states`/`rstates` and signs whatever that produces; the
//      proposal supplies only `smids`. `multisig-join.test.ts` does the opposite — it rebuilds the
//      proposed `Serder` and signs *that* — so the pinned tree contains two join styles that are
//      not equivalent, and nothing marks one as the right one.
//   3. **The two rotation call sites disagree about `rmids`.** One sends `rstates`, the other
//      sends `states` under the rotation-member label, which is multisig inception's conflation
//      again in a second place.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as signifyModule from "../../reference/signify-ts/dist/index.js";
import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { Siger } from "../../reference/signify-ts/dist/keri/core/siger.js";
import { Serder } from "../../reference/signify-ts/dist/keri/core/serder.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { SaltyIdentifierManager } from "../../reference/signify-ts/dist/keri/core/keeping.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import { b, d } from "../../reference/signify-ts/dist/keri/core/core.js";
import { messagize } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

/** The multisig inception scenario's three witnesses, reused so the group is the same one. */
const WITNESSES = [
  "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
  "BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM",
  "BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX",
];

/** The anchor the pinned interaction round writes, read from the scenario below. */
const SCENARIO_FILES = [
  "test-integration/multisig.test.ts",
  "test-integration/multisig-join.test.ts",
  "test-integration/utils/multisig-utils.ts",
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
// 1. The rounds, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const sources = new Map(SCENARIO_FILES.map((file) => [file, parse(file)]));

/** The nearest enclosing named function, arrow-assigned test, or `test(...)`/`describe(...)` title. */
function enclosingLabel(node) {
  let scope = node.parent;
  while (scope !== undefined) {
    if (ts.isFunctionDeclaration(scope) && scope.name !== undefined) {
      return scope.name.getText();
    }
    if (
      ts.isCallExpression(scope) &&
      ts.isIdentifier(scope.expression) &&
      (scope.expression.getText() === "test" || scope.expression.getText() === "it") &&
      scope.arguments.length > 0 &&
      ts.isStringLiteralLike(scope.arguments[0])
    ) {
      return scope.arguments[0].text;
    }
    scope = scope.parent;
  }
  return "<top level>";
}

/** The keys of the object literal most recently assigned to `name` before `position`. */
function embedSlots(source, name, position) {
  let best = null;
  const visit = (node) => {
    const initializer = ts.isVariableDeclaration(node)
      ? node.initializer
      : ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        ? node.right
        : undefined;
    const target = ts.isVariableDeclaration(node) ? node.name : ts.isBinaryExpression(node) ? node.left : undefined;
    if (
      initializer !== undefined &&
      target !== undefined &&
      target.getText() === name &&
      ts.isObjectLiteralExpression(initializer) &&
      node.getStart() < position &&
      (best === null || node.getStart() > best.at)
    ) {
      best = {
        at: node.getStart(),
        slots: initializer.properties
          .map((property) => property.name?.getText() ?? "")
          .filter((slot) => slot !== ""),
      };
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return best === null ? null : best.slots;
}

/**
 * Every `exchanges().send(...)` in one file: the route it names and the embed it carries.
 *
 * `send(name, topic, sender, route, payload, embeds, recipients)` — argument three is the route
 * and argument five is the embed block, so a route naming one message and an embed carrying
 * another is visible here without running anything.
 */
function sendCalls(file) {
  const { source } = sources.get(file);
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "send" &&
      node.getText().includes("exchanges()") &&
      node.arguments.length >= 7
    ) {
      const routeNode = node.arguments[3];
      const embedNode = node.arguments[5];
      const route = ts.isStringLiteralLike(routeNode) ? routeNode.text : `<${routeNode.getText()}>`;
      const slots = ts.isObjectLiteralExpression(embedNode)
        ? embedNode.properties.map((property) => property.name?.getText() ?? "")
        : embedSlots(source, embedNode.getText(), node.getStart());
      found.push({
        file,
        enclosing: enclosingLabel(node),
        route,
        embed_variable: ts.isObjectLiteralExpression(embedNode) ? null : embedNode.getText(),
        embed_slots: slots ?? [],
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `waitAndMarkNotification(client, route)` in one file, with the route it waits on. */
function waitCalls(file) {
  const { source } = sources.get(file);
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.getText() === "waitAndMarkNotification" &&
      node.arguments.length >= 2 &&
      ts.isStringLiteralLike(node.arguments[1])
    ) {
      found.push({ file, enclosing: enclosingLabel(node), route: node.arguments[1].text });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `identifiers().rotate(...)` whose second argument names group key states. */
function groupRotateCalls(file) {
  const { source } = sources.get(file);
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "rotate" &&
      node.getText().includes("identifiers()") &&
      node.arguments.length === 2 &&
      ts.isObjectLiteralExpression(node.arguments[1])
    ) {
      found.push({
        file,
        enclosing: enclosingLabel(node),
        arguments: node.arguments[1]
          .getText()
          .replace(/\s+/g, " ")
          .slice(0, 120),
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The `smids`/`rmids` expression each `send` payload names, so the two call sites can be compared. */
function memberExpressions(file) {
  const { source } = sources.get(file);
  const found = [];
  const visit = (node) => {
    const isMemberAssignment =
      (ts.isVariableDeclaration(node) || (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken));
    if (isMemberAssignment) {
      const target = ts.isVariableDeclaration(node) ? node.name : node.left;
      const value = ts.isVariableDeclaration(node) ? node.initializer : node.right;
      const label = target.getText();
      if ((label === "smids" || label === "rmids") && value !== undefined) {
        found.push({
          file,
          enclosing: enclosingLabel(node),
          label,
          expression: value.getText().replace(/\s+/g, " ").slice(0, 100),
        });
      }
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

const SENDS = SCENARIO_FILES.flatMap(sendCalls);
const WAITS = SCENARIO_FILES.flatMap(waitCalls);
const ROTATIONS = SCENARIO_FILES.flatMap(groupRotateCalls);
const MEMBER_EXPRESSIONS = SCENARIO_FILES.flatMap(memberExpressions);

/** The route constants, read from the reference's own `exchanging.ts` rather than transcribed. */
const exchanging = parse("src/keri/app/exchanging.ts");
function constantText(source, name) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      node.name.getText() === name &&
      node.initializer !== undefined &&
      ts.isStringLiteralLike(node.initializer)
    ) {
      found = node.initializer.text;
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}
const ROTATION_ROUTE = constantText(exchanging.source, "MULTISIG_ROT_ROUTE");
const INTERACTION_ROUTE = constantText(exchanging.source, "MULTISIG_IXN_ROUTE");
if (ROTATION_ROUTE !== "/multisig/rot" || INTERACTION_ROUTE !== "/multisig/ixn") {
  throw new Error("the multisig route constants moved; this generator's premise no longer holds");
}

/** Sends whose route and embed name different messages. */
const mismatched = SENDS.filter(
  (call) => call.embed_slots.length > 0 && !call.embed_slots.includes(call.route.split("/").pop()),
);

// A rotation announced on the interaction route is the whole finding; refuse to write a fixture
// that no longer records one, because then the item's premise has changed.
const rotationsOnInteractionRoute = mismatched.filter(
  (call) => call.route === INTERACTION_ROUTE && call.embed_slots.includes("rot"),
);
if (rotationsOnInteractionRoute.length === 0) {
  throw new Error("no rotation is announced on the interaction route any more; re-read the scenario");
}
if (!WAITS.some((call) => call.route === ROTATION_ROUTE)) {
  throw new Error("nobody waits on the rotation route any more; re-read the scenario");
}

// ---------------------------------------------------------------------------
// 2. The multisig inception helper, transpiled in memory, so the group is the real one.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);
const utils = sources.get("test-integration/utils/multisig-utils.ts");

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
    return { getStates, waitAndMarkNotification: async () => "" };
  }
  return nodeRequire(specifier);
};

const helperModule = { exports: {} };
// eslint-disable-next-line no-new-func -- the alternative is writing into the pinned submodule.
new Function("require", "exports", "module", transpiled)(shimmedRequire, helperModule.exports, helperModule);
const { startMultisigIncept } = helperModule.exports;
if (typeof startMultisigIncept !== "function") {
  throw new Error("the transpiled helper did not export `startMultisigIncept`");
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

// A group rotation only works if the members' key states chain: the group's prior next digests
// must contain the digest of the key each member rotates *to*. The pinned `mockGetAID` invents
// both, so the two keys after the mock's are derived here from the member's own salt through the
// reference's own keeper, and every digest below is computed rather than chosen.
const memberSalt = openSealed(BRAN, LOCAL_MEMBER.salty.sxlt);
const memberKeeper = new SaltyIdentifierManager(
  new Salter({ qb64: memberSalt, tier: Tier.low }),
  LOCAL_MEMBER.salty.pidx,
  LOCAL_MEMBER.salty.kidx,
  LOCAL_MEMBER.salty.tier,
  LOCAL_MEMBER.salty.transferable,
  LOCAL_MEMBER.salty.stem,
  undefined,
  undefined,
  LOCAL_MEMBER.salty.icodes,
  undefined,
  undefined,
  LOCAL_MEMBER.salty.ncodes,
  LOCAL_MEMBER.salty.dcode,
  // The member's own salt, so the keys below are the ones its keeper would derive rather than a
  // fresh random set — which is what the reference falls back to when neither this nor `sxlt` is
  // given, and what made an earlier draft of this generator non-deterministic.
  memberSalt.slice(3),
  undefined,
);
/** The key the member holds now, as the mock declares it. */
const CURRENT_KEY = LOCAL_MEMBER.state.k[0];
/** The key it rotates to, and the one after that, both derived from its own salt. */
const [[ROTATED_KEY], [NEXT_DIGEST]] = await (async () => {
  const [keys, digests] = await memberKeeper.rotate(LOCAL_MEMBER.salty.ncodes, true);
  return [keys, digests];
})();
const digestOf = (key) => new Diger({}, b(key)).qb64;
const ROTATED_DIGEST = digestOf(ROTATED_KEY);

/** The key state each participant is answered with before the members rotate. */
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
    k: [CURRENT_KEY],
    nt: "1",
    n: [ROTATED_DIGEST],
    bt: "0",
    b: [],
    c: [],
    ee: { s: "0", d: prefix, br: [], ba: [] },
    di: "",
  };
}

/** And the key state after it rotates, which is what a group rotation is built from. */
function rotatedKeyState(prefix) {
  return {
    ...keyState(prefix),
    s: "1",
    et: "rot",
    k: [ROTATED_KEY],
    n: [NEXT_DIGEST],
    ee: { s: "1", d: prefix, br: [], ba: [] },
  };
}

const recorded = [];
let groupRequestListing = [];
/** Flipped once the members rotate their own keys, as the scenario has them do. */
let membersRotated = false;
/** The member record the agent answers with, which the member's own rotation replaces. */
let localMemberRecord = LOCAL_MEMBER;
/** The group identifier record the agent answers `GET /identifiers/multisig` with. */
let groupRecord = null;

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
    return prefixes.map(membersRotated ? rotatedKeyState : keyState);
  }
  if (path.startsWith("/multisig/request/")) {
    return groupRequestListing;
  }
  if (path === "/identifiers/multisig" && httpMethod === "GET") {
    if (groupRecord === null) {
      throw new Error("the group was read before it was incepted");
    }
    return groupRecord;
  }
  if (path.startsWith("/identifiers/") && httpMethod === "GET") {
    return localMemberRecord;
  }
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
// 4. Incept the group, so both rounds run against a real one.
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
    // A failing call is evidence, so it is recorded rather than raised — but a later step reading
    // its result then fails somewhere unhelpful. `SHOW_ERRORS=1` prints the original stack.
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
  "multisig inception's own first step, run again so both rounds here act on a group the reference built",
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

const creationBody = JSON.parse(calls[0].requests.find((request) => request.path === "/identifiers")?.body ?? "null");
if (creationBody === null) {
  throw new Error("the inception created nothing");
}
const groupInception = creationBody.icp;

// The record a KERIA answers with once the group exists: the event that was created, plus the
// group key-manager block the creation itself sent.
groupRecord = {
  name: "multisig",
  prefix: groupInception.i,
  transferable: true,
  windexes: [],
  icp_dt: ADDED_INCEPTION_STAMP,
  group: creationBody.group,
  state: {
    vn: [1, 0],
    i: groupInception.i,
    s: groupInception.s,
    p: "",
    d: groupInception.d,
    f: "0",
    dt: ADDED_INCEPTION_STAMP,
    et: "icp",
    kt: groupInception.kt,
    k: groupInception.k,
    nt: groupInception.nt,
    n: groupInception.n,
    bt: groupInception.bt,
    b: groupInception.b,
    c: [],
    ee: { s: groupInception.s, d: groupInception.d, br: [], ba: [] },
    di: "",
  },
};

const localMember = await client.identifiers().get("member1");
const memberStates = await getStates(client, [LOCAL_PREFIX, PEER_PREFIX]);
const smids = memberStates.map((state) => state.i);

/** The attachment the scenario transposes beside an embedded event. */
function attachment(serder, sigs) {
  const sigers = sigs.map((sig) => new Siger({ qb64: sig }));
  return d(messagize(serder, sigers)).substring(serder.size);
}

// ---------------------------------------------------------------------------
// 5. The interaction round.
// ---------------------------------------------------------------------------

/** The anchor the pinned scenario's interaction writes, read from its own source. */
const scenarioAnchor = (() => {
  const { source } = sources.get("test-integration/multisig.test.ts");
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      node.name.getText() === "data" &&
      node.initializer !== undefined &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      const literal = node.initializer.getText();
      if (literal.includes("i:") && literal.includes("s:") && literal.includes("d:")) {
        found = JSON.parse(
          literal
            .replace(/'/g, '"')
            .replace(/,(\s*[}\]])/g, "$1")
            .replace(/([{,]\s*)([A-Za-z_$][A-Za-z0-9_$]*)\s*:/g, '$1"$2":'),
        );
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
})();
if (scenarioAnchor === null) {
  throw new Error("the interaction round's anchor is no longer where this generator expects it");
}

const interaction = await drive(
  "propose_interaction",
  "member1 anchors the scenario's own seal in the group's log",
  async () => await client.identifiers().interact("multisig", scenarioAnchor),
);

const interactionSerder = interaction.serder;
const interactionAtc = attachment(interactionSerder, interaction.sigs);

await drive(
  "announce_interaction",
  "and tells the other member, on the route whose name matches the embed it carries",
  async () =>
    await client
      .exchanges()
      .send(
        "member1",
        "multisig",
        localMember,
        INTERACTION_ROUTE,
        { gid: interactionSerder.pre, smids, rmids: smids },
        { ixn: [interactionSerder, interactionAtc] },
        [PEER_PREFIX],
      ),
);

// What a joining member reads: the announcement the initiator just sent.
const announcedInteraction = JSON.parse(
  calls[calls.length - 1].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
if (announcedInteraction === null) {
  throw new Error("the interaction announcement sent nothing");
}
groupRequestListing = [
  {
    exn: announcedInteraction.exn,
    paths: {},
    groupName: "multisig",
    memberName: "member1",
    sender: LOCAL_PREFIX,
  },
];

await drive(
  "accept_interaction",
  "the joining member reads the anchor out of the embedded event and interacts with the same data",
  async () => {
    const listing = await client.groups().getRequest("EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF");
    const anchors = listing[0].exn.e.ixn.a;
    return await client.identifiers().interact("multisig", anchors);
  },
);

// ---------------------------------------------------------------------------
// 6. The rotation round.
// ---------------------------------------------------------------------------

// The scenario has every member rotate its own keys before the group rotates, and then re-query
// each other's key states. Both are reproduced here: the member record and the answered key states
// move to the keys the group's prior next digests commit to.
membersRotated = true;
localMemberRecord = {
  ...LOCAL_MEMBER,
  state: { ...rotatedKeyState(LOCAL_PREFIX), i: LOCAL_PREFIX, d: LOCAL_PREFIX },
};
groupRecord.group.mhab = localMemberRecord;
const rotatedStates = [LOCAL_PREFIX, PEER_PREFIX].map(rotatedKeyState);

const rotation = await drive(
  "propose_rotation",
  "member1 rotates the group to the members' newly rotated key states",
  async () => await client.identifiers().rotate("multisig", { states: rotatedStates, rstates: rotatedStates }),
);

const rotationSerder = rotation.serder;
const rotationAtc = attachment(rotationSerder, rotation.sigs);

await drive(
  "announce_rotation_on_its_own_route",
  "the initiator announces it on `/multisig/rot`, which is the route the joining members wait on",
  async () =>
    await client
      .exchanges()
      .send(
        "member1",
        "multisig",
        localMember,
        ROTATION_ROUTE,
        { gid: rotationSerder.pre, smids, rmids: smids },
        { rot: [rotationSerder, rotationAtc] },
        [PEER_PREFIX],
      ),
);

await drive(
  "announce_rotation_on_the_interaction_route",
  "and what the joining members actually send: the same `rot` embed under `/multisig/ixn`, which is the finding",
  async () =>
    await client
      .exchanges()
      .send(
        "member2",
        "multisig",
        localMember,
        INTERACTION_ROUTE,
        { gid: rotationSerder.pre, smids, rmids: smids },
        { rot: [rotationSerder, rotationAtc] },
        [PEER_PREFIX],
      ),
);

// The two announcements, so a reader can compare them field by field.
const announcedOnRotationRoute = JSON.parse(
  calls[calls.length - 2].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
const announcedOnInteractionRoute = JSON.parse(
  calls[calls.length - 1].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
if (announcedOnRotationRoute === null || announcedOnInteractionRoute === null) {
  throw new Error("a rotation announcement sent nothing");
}

// The other join style: rebuild the proposed event and sign *that*, which is what
// `multisig-join.test.ts` does and `multisig.test.ts` does not.
groupRequestListing = [
  {
    exn: announcedOnRotationRoute.exn,
    paths: {},
    groupName: "multisig",
    memberName: "member1",
    sender: LOCAL_PREFIX,
  },
];

await drive(
  "join_the_proposed_rotation",
  "`multisig-join.test.ts`'s style: rebuild the proposed event, sign it, and post it to the join endpoint",
  async () => {
    const listing = await client.groups().getRequest("EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF");
    const proposed = new Serder(listing[0].exn.e.rot);
    const keeper = client.manager.get(localMember);
    const signatures = await keeper.sign(b(proposed.raw));
    return await client
      .groups()
      .join("multisig", proposed, signatures, listing[0].exn.a.gid, smids, smids);
  },
);

await drive(
  "rotate_the_group_again_without_reading_the_proposal",
  "`multisig.test.ts`'s style: the joining member rebuilds from its own key states and never reads the proposal",
  async () => await client.identifiers().rotate("multisig", { states: rotatedStates, rstates: rotatedStates }),
);

// The same style with a rotation set the proposal did not name — same size, so no threshold
// complains, and every digest in it is a real one. Only the *values* differ.
const divergentRotationStates = [
  rotatedKeyState(LOCAL_PREFIX),
  { ...rotatedKeyState(PEER_PREFIX), n: [ROTATED_DIGEST] },
];

await drive(
  "rebuild_from_a_rotation_set_the_proposal_did_not_name",
  "the same style over a rotation set of the same size whose digests differ: it succeeds and signs a different event",
  async () =>
    await client.identifiers().rotate("multisig", { states: rotatedStates, rstates: divergentRotationStates }),
);

// ---------------------------------------------------------------------------
// 7. What the two styles produce, compared.
// ---------------------------------------------------------------------------

const bodyOf = (name, predicate) =>
  JSON.parse(calls.find((call) => call.name === name)?.requests.find(predicate)?.body ?? "null");

const joinBody = bodyOf("join_the_proposed_rotation", (request) => request.path.endsWith("/multisig/join"));
const rebuiltBody = bodyOf(
  "rotate_the_group_again_without_reading_the_proposal",
  (request) => request.path === "/identifiers/multisig/events",
);
const divergentBody = bodyOf(
  "rebuild_from_a_rotation_set_the_proposal_did_not_name",
  (request) => request.path === "/identifiers/multisig/events",
);
if (joinBody === null || rebuiltBody === null || divergentBody === null) {
  throw new Error("a join style produced no body");
}

const quirks = {
  a_rotation_is_announced_on_the_interaction_route: {
    declaration:
      "in `multisig.test.ts` only the initiator sends `/multisig/rot`; both joining members send the same `rot` embed under `/multisig/ixn`, while both peers wait on `/multisig/rot`",
    sends_on_rotation_route: SENDS.filter((call) => call.route === ROTATION_ROUTE).length,
    rotations_sent_on_interaction_route: rotationsOnInteractionRoute,
    waits_on_rotation_route: WAITS.filter((call) => call.route === ROTATION_ROUTE).length,
    announced_route: announcedOnInteractionRoute.exn.r,
    announced_embed_slots: Object.keys(announcedOnInteractionRoute.exn.e).filter((slot) => slot !== "d"),
    note: "the route says interaction and the embed carries a rotation, so a member that trusts the route reads the wrong message and one that waits on the rotation route never sees the join at all. Nothing upstream compares the two, because nothing upstream looks inside the embed.",
    rust_decision:
      "the route decides the embed. The exchange route classifier refuses a message whose embed slot is not the one its route names, so this pair cannot be built here — `propose_rotation` and `accept_rotation` both send `/multisig/rot`.",
  },
  a_joining_member_never_reads_the_rotation_it_joins: {
    declaration:
      "`multisig.test.ts` calls `rotate` again with its own `states`/`rstates` and signs whatever that produces; `multisig-join.test.ts` rebuilds the proposed `Serder` and signs that",
    rebuilt_event_digest: rebuiltBody.rot.d,
    proposed_event_digest: announcedOnRotationRoute.exn.e.rot.d,
    styles_agree: rebuiltBody.rot.d === announcedOnRotationRoute.exn.e.rot.d,
    signed_by_the_join: joinBody.rot?.d ?? null,
    divergent: {
      rebuilt_from: "a rotation set of the same size whose next digests differ from the proposal's",
      rebuilt_event_digest: divergentBody.rot.d,
      matches_the_proposal: divergentBody.rot.d === announcedOnRotationRoute.exn.e.rot.d,
      rebuilt_next_digests: divergentBody.rot.n,
      proposed_next_digests: announcedOnRotationRoute.exn.e.rot.n,
      error: calls.find((call) => call.name === "rebuild_from_a_rotation_set_the_proposal_did_not_name").error,
    },
    note: "the two styles agree only while the members' key states do. Driven both ways: with the same states the digests match, and with one rotation member where the proposal named two the rebuilding member signs a different event — no error, no comparison, and the signature it contributes is over something nobody proposed. This is the multisig inception witness threshold defect in a second place.",
    rust_decision:
      "a joining member checks. `accept_rotation` rebuilds as the reference does and then compares what it built with the digest the proposal carries, refusing to sign a different event. A digest comparison rather than a byte one, because a decoded record cannot reproduce the bytes it arrived as — but an event's SAID is a digest over the event, so two events with one SAID are one event.",
  },
  the_two_rotation_call_sites_disagree_about_rmids: {
    declaration: "one rotation announcement maps `rstates` into `rmids` and the other maps `states`",
    expressions: MEMBER_EXPRESSIONS.filter((entry) => entry.label === "rmids"),
    note: "The `client-multisig-inception` fixture recorded the accepting member substituting the signing set for the rotation set. It is not a one-off: the rotation round does the same thing at one of its two call sites, so the two are inconsistent with each other as well as with the field's name.",
    rust_decision: "the rotation set is a separate argument from the signing set and neither defaults to the other.",
  },
  an_interaction_relays_the_data_it_read: {
    declaration:
      "`multisig.test.ts` reads `exn.e.ixn.a` and passes it straight back into `interact`, where `delegateMultisig` reads `ixn.a[0]`",
    proposed_anchors: announcedInteraction.exn.e.ixn.a,
    note: "this is the half the reference gets right: the joining member anchors the same seal the initiator did, because `createInteract` wraps a non-array and leaves an array alone. The two readers disagree about the shape — one takes the array, the other its first element — but both reach the same seal.",
    rust_decision: "reproduced. The anchors are read from the embedded event and passed through unchanged.",
  },
  there_is_no_source_file: {
    declaration: "neither round exists under `src`; both are written inline in the integration scenario",
    interact_scan: scan("identifiers().interact("),
    rotate_scan: scan(".rotate("),
    note: "Multisig inception had helpers to transpile. These rounds do not even have those: the rounds are statements in a test body, so what is ported is the shape the statements describe and the evidence is the reference's own primitives driven in that order.",
    rust_decision:
      "ported as workflows beside multisig inception's in `signify-client::multisig`.",
  },
};

const declarations = {
  send_calls: SENDS,
  wait_calls: WAITS,
  group_rotate_calls: ROTATIONS,
  member_expressions: MEMBER_EXPRESSIONS,
  mismatched_sends: mismatched,
  rotation_route: ROTATION_ROUTE,
  interaction_route: INTERACTION_ROUTE,
  scenario_anchor: scenarioAnchor,
  scenario_files: SCENARIO_FILES,
  scanned_files: PINNED_FILES.length,
  notes: {
    send_arguments: "send(name, topic, sender, route, payload, embeds, recipients) — argument three is the route and argument five is the embed block",
    embed_resolution: "an embed passed as a variable is resolved to the keys of the nearest object literal assigned to it before the call",
  },
};

const pinnedConfirmations = {
  interaction_paths: calls
    .find((call) => call.name === "propose_interaction")
    .requests.map((request) => `${request.method} ${request.path}`),
  rotation_paths: calls
    .find((call) => call.name === "propose_rotation")
    .requests.map((request) => `${request.method} ${request.path}`),
  join_path: calls
    .find((call) => call.name === "join_the_proposed_rotation")
    .requests.map((request) => `${request.method} ${request.path}`),
  group_prefix: groupInception.i,
  interaction_digest: interactionSerder.sad.d,
  rotation_digest: rotationSerder.sad.d,
  note: "both rounds act on a group the multisig inception helper incepted here. Its identifier differs from the `client-multisig-inception` fixture because the key states are different: a group rotation only works if the members' key states chain, so the next digests here are derived from the member's own salt where `mockGetAID` invents them.",
};

// ---------------------------------------------------------------------------
// 8. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: [...SCENARIO_FILES, "src/keri/app/exchanging.ts", "test/app/test-utils.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    local_member_prefix: LOCAL_PREFIX,
    peer_prefix: PEER_PREFIX,
    note: "Both rounds are written inline in the integration scenario rather than in a function, so there is nothing to transpile and call. The syntax tree supplies what cannot be driven — every `exchanges().send` with its route and its embed slot, and every `waitAndMarkNotification` with the route it waits on — and the reference's own `interact`, `rotate`, `send`, and `join` supply the bytes, driven against the group the multisig inception helper incepted. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
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

const outputUrl = new URL("../../fixtures/client-multisig-events/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-multisig-events fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
