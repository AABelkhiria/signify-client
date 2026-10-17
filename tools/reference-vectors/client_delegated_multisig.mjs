// Records the pinned signify-ts checkout's delegated-multisig round.
//
// This fixture ports the case where **both sides of a delegation are groups**: a delegatee group
// whose inception names a delegator, and a delegator group that approves it by each of its members
// anchoring the same seal and telling the others. It is the composition of the group inception, the
// interaction announcement, and the delegation approval address — and it is the first place a
// delegated inception is driven at all.
//
// The unit is `delegateMultisig` in `test-integration/utils/multisig-utils.ts`, so this generator
// transpiles that file in memory exactly as `client_multisig_inception.mjs` does and drives the
// reference's own helper against a recording agent. Nothing is written into the submodule.
//
// Four things fall out.
//
//   1. **The joining member takes only the first seal.** It reads `ixn.a[0]` where the plain
//      interaction round reads `ixn.a` whole — so a delegator group anchoring two delegations
//      in one event has its second silently dropped by every member but the initiator, and the
//      members then sign different events.
//   2. **`rmids: smids` a third time.** The same conflation `client-multisig-inception` recorded in
//      the accepting half of an inception and `client-multisig-events` found again at one of two
//      rotation call sites.
//   3. **The member list is hand-assembled**, `[aid.prefix, ...otherMembersAIDs]`, rather than read
//      from the group's own key states — so it is whatever the caller passed and its order is the
//      caller's.
//   4. **This is the one place the reference checks its own work.** `delegateMultisig` asserts the
//      anchor it read back out of the event it built equals the anchor it was given. Nothing else
//      in the multisig tree compares anything, and this check is in a test helper.
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
import { b, d } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Siger } from "../../reference/signify-ts/dist/keri/core/siger.js";
import { messagize } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

/** The three witnesses the delegated scenario names, the same three as `client-multisig-inception`'s. */
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
// 1. The helper and its scenario, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const utils = parse("test-integration/utils/multisig-utils.ts");
const scenario = parse("test-integration/delegation-multisig.test.ts");
const testUtil = parse("test-integration/utils/test-util.ts");

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

/** One function's parameter list, with each declared type and its default if any. */
function signature(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      found = {
        parameters: node.parameters.map((parameter) => ({
          name: parameter.name.getText(),
          type: parameter.type?.getText().replace(/\s+/g, " ") ?? "<inferred>",
          default: parameter.initializer?.getText() ?? null,
        })),
        returns: node.type?.getText() ?? "<inferred>",
      };
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/**
 * Every read of an embedded interaction's anchor block, and whether it takes one seal or all.
 *
 * `exn.e.ixn.a` is the seal list. The plain interaction round reads it whole; this one indexes
 * it.
 */
function anchorReads(file, source) {
  const found = [];
  const visit = (node) => {
    const isAssignment =
      ts.isVariableDeclaration(node) ||
      (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken);
    if (isAssignment) {
      const target = ts.isVariableDeclaration(node) ? node.name : node.left;
      const value = ts.isVariableDeclaration(node) ? node.initializer : node.right;
      if (value !== undefined) {
        const expression = value.getText().replace(/\s+/g, " ");
        // A read of an embedded interaction's seal list: `<something>ixn<something>.a`, with or
        // without a cast, and with or without an index after it.
        if (/\bixn\b[^;]*\.a\b/.test(expression) && !expression.includes("=>")) {
          found.push({
            file,
            binds: target.getText(),
            expression,
            takes: /\[\s*0\s*\]\s*$/.test(expression) ? "the first seal" : "the whole list",
          });
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The `smids`/`rmids` expression each multisig send names, so the call sites can be compared. */
function memberExpressions(file, source) {
  const found = [];
  const visit = (node) => {
    const isAssignment =
      ts.isVariableDeclaration(node) ||
      (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken);
    if (isAssignment) {
      const target = ts.isVariableDeclaration(node) ? node.name : node.left;
      const value = ts.isVariableDeclaration(node) ? node.initializer : node.right;
      const label = target.getText();
      if ((label === "smids" || label === "rmids" || label === "recp") && value !== undefined) {
        found.push({
          file,
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

/** Every `assert.equal`/`assert.strictEqual` inside one function. */
function assertionsIn(source, name) {
  const found = [];
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      const walk = (inner) => {
        if (
          ts.isCallExpression(inner) &&
          ts.isPropertyAccessExpression(inner.expression) &&
          inner.expression.expression.getText() === "assert"
        ) {
          found.push(inner.getText().replace(/\s+/g, " "));
        }
        ts.forEachChild(inner, walk);
      };
      walk(node);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `startMultisigIncept` argument object in the scenario, so the `delpre` is visible. */
function inceptionArguments(source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.getText() === "startMultisigIncept" &&
      node.arguments.length >= 2 &&
      ts.isObjectLiteralExpression(node.arguments[1])
    ) {
      const properties = node.arguments[1].properties.map((property) => property.name?.getText() ?? "");
      found.push({ properties, delegated: properties.includes("delpre") });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Where the scenario learns a group's own prefix. */
function prefixDiscoveries(source) {
  const found = [];
  const visit = (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const text = node.initializer.getText().replace(/\s+/g, " ");
      if (text.includes(".name.split(")) {
        found.push({ binds: node.name.getText(), from: text });
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

const DELEGATE_MULTISIG = functionText(utils.source, "delegateMultisig");
const SIGNATURE = signature(utils.source, "delegateMultisig");
const ANCHOR_READS = [
  ...anchorReads("test-integration/utils/multisig-utils.ts", utils.source),
  ...anchorReads("test-integration/multisig.test.ts", parse("test-integration/multisig.test.ts").source),
];
const MEMBER_EXPRESSIONS = memberExpressions("test-integration/utils/multisig-utils.ts", utils.source);
const ASSERTIONS = assertionsIn(utils.source, "delegateMultisig");
const INCEPTIONS = inceptionArguments(scenario.source);
const DISCOVERIES = prefixDiscoveries(scenario.source);

if (DELEGATE_MULTISIG === null || SIGNATURE === null) {
  throw new Error("`delegateMultisig` is no longer where this generator expects it");
}
// The premise: the joining half reads one seal, and the scenario incepts a delegated group.
const takesFirstSeal = ANCHOR_READS.filter((read) => read.takes === "the first seal");
if (takesFirstSeal.length === 0) {
  throw new Error("nothing indexes an embedded interaction's anchor list any more; re-read the premise");
}
if (!INCEPTIONS.some((call) => call.delegated)) {
  throw new Error("the scenario no longer incepts a delegated group");
}
if (ASSERTIONS.length === 0) {
  throw new Error("`delegateMultisig` no longer checks its own work; the finding below is stale");
}

const declarations = {
  delegate_multisig: DELEGATE_MULTISIG,
  signature: SIGNATURE,
  anchor_reads: ANCHOR_READS,
  member_expressions: MEMBER_EXPRESSIONS,
  assertions: ASSERTIONS,
  inception_arguments: INCEPTIONS,
  prefix_discoveries: DISCOVERIES,
  delegate_multisig_uses: scan("delegateMultisig("),
  delegated_inception_uses: scan("delpre"),
  scanned_files: PINNED_FILES.length,
  notes: {
    composition: "the group inception with a delegator, the interaction announcement, and the delegation approval address",
    one_seal: "the joining half reads `ixn.a[0]`; the plain interaction round reads `ixn.a`",
  },
};

// ---------------------------------------------------------------------------
// 2. The helpers themselves, transpiled in memory and loaded with a shim.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);

async function getStates(client, prefixes) {
  const participantStates = await Promise.all(prefixes.map((prefix) => client.keyStates().get(prefix)));
  return participantStates.map((state) => state[0]);
}

/** The notification SAID the joining half is handed; the shim answers with it. */
let pendingNotification = "EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF";

const transpiled = ts.transpileModule(utils.text, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

const shimmedRequire = (specifier) => {
  if (specifier === "signify-ts") {
    return { ...signifyModule, default: signifyModule.default ?? signifyModule };
  }
  if (specifier === "./test-util.ts") {
    return { getStates, waitAndMarkNotification: async () => pendingNotification };
  }
  if (specifier === "assert") {
    // `import assert from 'assert'` transpiles to `assert_1.default`, and node's CommonJS module
    // has no `default`. The group inception's two helpers never call it; this one does — and what
    // it asserts is the finding below, so it must be the real thing rather than a stub.
    const nodeAssert = nodeRequire("assert");
    return { ...nodeAssert, default: nodeAssert };
  }
  return nodeRequire(specifier);
};

const helperModule = { exports: {} };
// eslint-disable-next-line no-new-func -- the alternative is writing into the pinned submodule.
new Function("require", "exports", "module", transpiled)(shimmedRequire, helperModule.exports, helperModule);
const { startMultisigIncept, delegateMultisig } = helperModule.exports;
if (typeof startMultisigIncept !== "function" || typeof delegateMultisig !== "function") {
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
const LOCAL_MEMBER = { ...MOCK_GET_AID, name: "delegator1", icp_dt: MOCK_GET_AID.icp_dt ?? ADDED_INCEPTION_STAMP };
const LOCAL_PREFIX = LOCAL_MEMBER.prefix;
const PEER_PREFIX = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

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
let groupRequestListing = [];
/** The delegator group's record, once it exists. */
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
    return prefixes.map(keyState);
  }
  if (path.startsWith("/multisig/request/")) {
    return groupRequestListing;
  }
  if (path.startsWith("/identifiers/delegators") && httpMethod === "GET") {
    if (groupRecord === null) {
      throw new Error("the delegator group was read before it was incepted");
    }
    return groupRecord;
  }
  if (path.startsWith("/identifiers/") && httpMethod === "GET") {
    return LOCAL_MEMBER;
  }
  return { name: "delegation.EGRP", metadata: { pre: "EGRP", sn: 1 }, done: false };
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

// The helper narrates to `console.log`, and this generator's own output is the fixture, so the
// narration is captured rather than printed. Nothing else about the helper changes.
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

// The delegator group, which will do the approving.
await drive(
  "incept_the_delegator_group",
  "the scenario's first step: an undelegated two-of-two group, which will approve the delegatee",
  async () =>
    await startMultisigIncept(client, {
      groupName: "delegators",
      localMemberName: "delegator1",
      participants: [LOCAL_PREFIX, PEER_PREFIX],
      toad: 2,
      isith: 2,
      nsith: 2,
      wits: WITNESSES,
    }),
);

const delegatorCreation = JSON.parse(
  calls[0].requests.find((request) => request.path === "/identifiers")?.body ?? "null",
);
if (delegatorCreation === null) {
  throw new Error("the delegator group was not created");
}
const DELEGATOR_GROUP = delegatorCreation.icp.i;

groupRecord = {
  name: "delegators",
  prefix: DELEGATOR_GROUP,
  transferable: true,
  windexes: [],
  icp_dt: ADDED_INCEPTION_STAMP,
  group: delegatorCreation.group,
  state: {
    vn: [1, 0],
    i: DELEGATOR_GROUP,
    s: delegatorCreation.icp.s,
    p: "",
    d: delegatorCreation.icp.d,
    f: "0",
    dt: ADDED_INCEPTION_STAMP,
    et: "icp",
    kt: delegatorCreation.icp.kt,
    k: delegatorCreation.icp.k,
    nt: delegatorCreation.icp.nt,
    n: delegatorCreation.icp.n,
    bt: delegatorCreation.icp.bt,
    b: delegatorCreation.icp.b,
    c: [],
    ee: { s: delegatorCreation.icp.s, d: delegatorCreation.icp.d, br: [], ba: [] },
    di: "",
  },
};

// The delegatee group, whose inception names the delegator group.
await drive(
  "incept_the_delegatee_group",
  "the same helper with a `delpre`: a group whose inception names the delegator group and stays pending",
  async () =>
    await startMultisigIncept(client, {
      groupName: "delegatees",
      localMemberName: "delegator1",
      participants: [LOCAL_PREFIX, PEER_PREFIX],
      toad: 2,
      isith: 2,
      nsith: 2,
      delpre: DELEGATOR_GROUP,
      wits: WITNESSES,
    }),
);

const delegateeCreation = JSON.parse(
  calls[1].requests.find((request) => request.path === "/identifiers")?.body ?? "null",
);
if (delegateeCreation === null) {
  throw new Error("the delegatee group was not created");
}
const DELEGATEE_GROUP = delegateeCreation.icp.i;

/** The seal the delegator group anchors: the delegatee group's inception, named three ways. */
const SEAL = { i: DELEGATEE_GROUP, s: "0", d: DELEGATEE_GROUP };

const localMember = await client.identifiers().get("delegator1");
const peerMember = { ...LOCAL_MEMBER, name: "delegator2", prefix: PEER_PREFIX };

await drive(
  "approve_as_the_initiator",
  "the first delegator member approves with the seal it was given and tells the other",
  async () => await delegateMultisig(client, localMember, [peerMember], groupRecord, SEAL, true),
);

// What the joining member reads: the announcement the initiator just sent.
const announced = JSON.parse(
  calls[2].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
if (announced === null) {
  throw new Error("the initiator announced nothing");
}
groupRequestListing = [
  {
    exn: announced.exn,
    paths: {},
    groupName: "delegators",
    memberName: "delegator1",
    sender: LOCAL_PREFIX,
  },
];

await drive(
  "approve_as_a_joining_member",
  "the second member reads the announcement, takes the anchor out of it, and approves the same delegation",
  async () => await delegateMultisig(client, localMember, [peerMember], groupRecord, undefined, false),
);

// And the case the indexing makes observable: two delegations anchored in one event.
const SECOND_SEAL = { i: DELEGATOR_GROUP, s: "0", d: DELEGATOR_GROUP };

await drive(
  "approve_two_delegations_at_once",
  "the initiator anchors two seals in one event, which the endpoint and the event format both permit",
  async () => await delegateMultisig(client, localMember, [peerMember], groupRecord, [SEAL, SECOND_SEAL], true),
);

// `delegateMultisig` cannot produce a two-seal announcement — its own assertion refuses, above — so
// the announcement a joining member would read is built here from the reference's own primitives,
// in the same order and with the same arguments the helper uses.
const announcedTwo = await drive(
  "announce_two_delegations_by_hand",
  "the announcement the helper cannot send, built from the reference's own `interact` and `send`",
  async () => {
    const result = await client.identifiers().interact("delegators", [SEAL, SECOND_SEAL]);
    const serder = result.serder;
    const sigers = result.sigs.map((signature) => new Siger({ qb64: signature }));
    const attachment = d(messagize(serder, sigers)).substring(serder.size);
    const smids = [localMember.prefix, peerMember.prefix];
    await client
      .exchanges()
      .send(
        localMember.name,
        groupRecord.name,
        localMember,
        "/multisig/ixn",
        { gid: serder.pre, smids, rmids: smids },
        { ixn: [serder, attachment] },
        [peerMember.prefix],
      );
    return { anchored: serder.sad.a, digest: serder.sad.d };
  },
);

const announcedTwoBody = JSON.parse(
  calls[calls.length - 1].requests.find((request) => request.path.endsWith("/exchanges"))?.body ?? "null",
);
if (announcedTwoBody === null || announcedTwo === null) {
  throw new Error("the two-seal announcement sent nothing");
}
groupRequestListing = [
  {
    exn: announcedTwoBody.exn,
    paths: {},
    groupName: "delegators",
    memberName: "delegator1",
    sender: LOCAL_PREFIX,
  },
];

await drive(
  "join_an_announcement_carrying_two_seals",
  "and the joining member reads `ixn.a[0]`, so it approves only the first and signs a different event",
  async () => await delegateMultisig(client, localMember, [peerMember], groupRecord, undefined, false),
);

// ---------------------------------------------------------------------------
// 5. What the recording says.
// ---------------------------------------------------------------------------

const bodyOf = (name, predicate) => {
  const call = calls.find((entry) => entry.name === name);
  const request = call?.requests.find(predicate);
  return request?.body === undefined || request?.body === null ? null : JSON.parse(request.body);
};
const approvalOf = (name) => bodyOf(name, (request) => request.path.endsWith("/delegation"));
const announcementOf = (name) => bodyOf(name, (request) => request.path.endsWith("/exchanges"));

const initiatorApproval = approvalOf("approve_as_the_initiator");
const joinerApproval = approvalOf("approve_as_a_joining_member");
const twoSealApproval = approvalOf("approve_two_delegations_at_once");
const droppedApproval = approvalOf("join_an_announcement_carrying_two_seals");
if (initiatorApproval === null || joinerApproval === null || twoSealApproval === null || droppedApproval === null) {
  throw new Error("an approval posted nothing");
}

// The helper's own assertion refuses a two-seal anchor — after the approval has already been
// posted, so the delegator's log holds both and the peers are never told.
const twoSealCall = calls.find((entry) => entry.name === "approve_two_delegations_at_once");
if (twoSealCall.error === null) {
  throw new Error("`delegateMultisig` no longer refuses a two-seal anchor; the finding is stale");
}

const quirks = {
  the_joining_member_takes_only_the_first_seal: {
    declaration: "`anchor = (ixn.a as Array<{ i: string; s: string; d: string }>)[0]`",
    reads: ANCHOR_READS,
    initiator_anchored: announcedTwo.anchored,
    initiator_event: announcedTwo.digest,
    joiner_anchored: droppedApproval.ixn.a,
    joiner_event: droppedApproval.ixn.d,
    events_agree: announcedTwo.digest === droppedApproval.ixn.d,
    joiner_error: calls.find((entry) => entry.name === "join_an_announcement_carrying_two_seals").error,
    note: "the initiator anchors both seals; the joining member reads `ixn.a[0]` and anchors one. The two members sign different interaction events, the group never reaches its threshold, and the second delegation is never approved — with no error on either side. the plain interaction round reads the same field whole, so the pinned tree contains both readings of one shape.",
    rust_decision:
      "the whole seal list is read. `accept_delegation_approval` anchors every seal the proposal names, and then compares the event it built with the digest the proposal carries — so a disagreement is a typed error rather than a group that never converges.",
  },
  the_rotation_set_is_the_signing_set_a_third_time: {
    declaration: "`{ gid: serder.pre, smids: smids, rmids: smids }`",
    expressions: MEMBER_EXPRESSIONS,
    announced_smids: announced.exn.a.smids,
    announced_rmids: announced.exn.a.rmids,
    identical: JSON.stringify(announced.exn.a.smids) === JSON.stringify(announced.exn.a.rmids),
    note: "`client-multisig-inception` recorded this in the accepting half of an inception and `client-multisig-events` found it again at one of two rotation call sites. Here it is unconditional: the rotation set is written as the signing set with no rotation set consulted at all.",
    rust_decision: "the two sets are separate arguments and neither defaults to the other.",
  },
  the_member_list_is_hand_assembled: {
    declaration: "`const smids = [aid.prefix, ...otherMembersAIDs.map((aid) => aid.prefix)]`",
    announced_smids: announced.exn.a.smids,
    recipients: announced.rec,
    sender: announced.exn.i,
    sender_is_a_recipient: announced.rec.includes(announced.exn.i),
    note: "the members are whatever the caller passed, in the caller's order, rather than read from the group's own key states — so a member omitted from `otherMembersAIDs` is omitted from the message the group is agreeing on. The delivery list does exclude the sender here, which is what the group inception's *proposing* half fails to do.",
    rust_decision:
      "the members are read from the group's record and the delivery list is `delivery_list`, which excludes the sender and refuses a member that is not one.",
  },
  the_reference_checks_its_own_work_exactly_once: {
    declaration: ASSERTIONS,
    note: "`delegateMultisig` reads the anchor back out of the event it built and asserts it equals the anchor it was given. It is the only comparison of its kind in the multisig tree — `client-multisig-events` recorded that the rotation round compares nothing — and it lives in a test helper, so no consumer of the library gets it.",
    rust_decision:
      "reproduced and moved into the port: the joining half compares the event it built with the digest the proposal carries, on every round, and refuses rather than asserting.",
  },
  the_check_fires_after_the_approval_is_already_posted: {
    declaration:
      "`approve` is awaited, then `op()`, then `assert.equal(...)`, and only then `exchanges().send`",
    error: twoSealCall.error,
    anchored_anyway: twoSealApproval.ixn.a,
    requests_made: twoSealCall.requests.map((request) => `${request.method} ${request.path}`),
    announced: twoSealCall.requests.some((request) => request.path.endsWith("/exchanges")),
    note: "the assertion compares `serder.sad.a[0]` with the whole anchor argument, so a two-seal anchor fails it — but the approval has already been posted by then. The delegator's log holds both seals, the peers are never told, and the caller gets an exception instead of the operation it needs to wait on. The one check the reference performs is placed after the irreversible step and compares the wrong shape.",
    rust_decision:
      "checked before anything is written. `propose_delegation_approval` refuses an empty seal list before it reads the group, and the joining half compares the event it built with the digest it was shown before announcing — and a mismatch is a typed error, not an assertion.",
  },
  a_delegated_group_inception_is_a_dip: {
    declaration: INCEPTIONS,
    delegator: delegateeCreation.icp.di,
    ilk: delegateeCreation.icp.t,
    undelegated_ilk: delegatorCreation.icp.t,
    note: "the same helper builds both, and the only difference in the request is `delpre` — which becomes the event's `di` and changes its ilk from `icp` to `dip`. This is the first fixture in the port to drive a delegated group inception at all; `client-multisig-inception` drove only undelegated ones.",
    rust_decision:
      "reproduced. `GroupInceptionRequest` already carries a delegator, and the exchange-route inception embed accepts both ilks, so a delegated group proposal classifies as an inception like any other.",
  },
};

const pinnedConfirmations = {
  delegator_group: DELEGATOR_GROUP,
  delegatee_group: DELEGATEE_GROUP,
  seal: SEAL,
  approval_path: calls
    .find((entry) => entry.name === "approve_as_the_initiator")
    .requests.find((request) => request.path.endsWith("/delegation"))?.path,
  initiator_paths: calls
    .find((entry) => entry.name === "approve_as_the_initiator")
    .requests.map((request) => `${request.method} ${request.path}`),
  joiner_paths: calls
    .find((entry) => entry.name === "approve_as_a_joining_member")
    .requests.map((request) => `${request.method} ${request.path}`),
  announcement_route: announced.exn.r,
  announcement_topic: announced.tpc,
  note: "the delegatee group's inception is a `dip` naming the delegator group, and the approval is an interaction on the delegator group posted to the delegation address.",
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
    "test-integration/delegation-multisig.test.ts",
    "test-integration/utils/test-util.ts",
    "test-integration/multisig.test.ts",
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
    note: "The ported unit is `delegateMultisig`, which lives in the reference's integration utilities, so `multisig-utils.ts` is **transpiled in memory** by the reference's own pinned TypeScript and evaluated with a three-entry module shim exactly as the `client-multisig-inception` generator does. Nothing is written into the submodule, and what runs is the reference's own code. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
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

console.log = realLog;

const outputUrl = new URL("../../fixtures/client-delegated-multisig/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-delegated-multisig fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
