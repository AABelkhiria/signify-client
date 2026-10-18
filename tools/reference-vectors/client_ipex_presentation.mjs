// Records the pinned signify-ts checkout's IPEX presentation workflow.
//
// The Rust port covers the conversation that discloses a credential: apply, offer, agree, grant,
// and admit, plus the shorter issuer path where a grant opens the exchange and an admit closes it.
// The IPEX artifact builders build those five messages and the IPEX submitters send them; what this
// generator records is the part between — reading what arrived, checking it belongs to the
// conversation it claims to, and building the answer from it.
//
// There is no source file. The single-signature conversation is written inline in
// `test-integration/credentials.test.ts`, and the group rounds are `grantMultisig` and
// `admitMultisig` in `test-integration/utils/multisig-utils.ts`, with a third copy of the admit,
// `multisigAdmitCredential`, inline in `test-integration/multisig-holder.test.ts`.
//
// Five things fall out.
//
//   1. **A group's IPEX round agrees only because one process handed both members one clock.**
//      An IPEX message's SAID covers its `dt`, so two members stamping their own clocks build two
//      different messages. `grantMultisig` and `admitMultisig` take `timestamp` as a parameter, and
//      `multisig-holder.test.ts` reads a module-level `const TIME = createTimestamp()`. Its own
//      `assert.equal(admitResult1.admitSaid, admitResult2.admitSaid)` therefore passes in the test
//      process and would fail between two real members. Driven here both ways.
//   2. **A joining member never reads the proposal**, the same defect the
//      `client-multisig-credentials` fixture pinned for the transaction rounds:
//      `if (!isInitiator) await waitAndMarkNotification(client, '/multisig/exn')`
//      discards the SAID, and neither helper contains a `getRequest`.
//   3. **A notification's SAID is not required to exist.** `waitAndMarkNotification` ends
//      `return notes[notes.length - 1]?.a.d ?? '';`, so a notification carrying no `a.d` yields the
//      empty string — which `admitMultisig` passes straight into `grantSaid`. The integration test
//      that runs the same step by hand guards it with `assert(grantNotification.a.d)` first.
//   4. **And it reads only one.** The same helper marks *every* matching notification read and
//      returns the last one's SAID, so a holder with several grants outstanding answers one and
//      silently loses the rest. The parameter that would have said how many to expect is still in
//      the tree on `admitMultisig`, commented out.
//   5. **A grant's attachments are assembled three different ways in one tree** — all three, the
//      anchor's only, and none at all. Passing none sends `Ipex.grant` down the branch that
//      re-signs the anchoring event with the *sender's* keeper, whoever the sender is.
import { createRequire } from "node:module";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as signifyModule from "./node_modules/signify-ts/dist/index.js";
import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Serder } from "./node_modules/signify-ts/dist/keri/core/serder.js";
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

/** The stamp both members of a group are handed, and the one only one of them has. */
const SHARED_STAMP = "2023-11-14T22:13:20.123000+00:00";
const OTHER_STAMP = "2023-11-14T22:13:21.456000+00:00";

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
// 1. What the pinned tree declares, read from its own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const utils = parse("test-integration/utils/multisig-utils.ts");
const holder = parse("test-integration/multisig-holder.test.ts");
const credentials = parse("test-integration/credentials.test.ts");
const testUtil = parse("test-integration/utils/test-util.ts");
const credentialing = parse("src/keri/app/credentialing.ts");
const exchanging = parse("src/keri/app/exchanging.ts");
const multisigTest = parse("test-integration/multisig.test.ts");

/** The whole text of one type alias, whitespace collapsed. */
function typeText(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isTypeAliasDeclaration(node) && node.name.getText() === name) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  if (found === null) {
    throw new Error(`no type alias named ${name}`);
  }
  return found;
}

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

/** The enclosing function declaration's name, or `<top level>`. */
function enclosingOf(node) {
  let scope = node.parent;
  while (scope !== undefined && !ts.isFunctionDeclaration(scope)) {
    scope = scope.parent;
  }
  return scope?.name?.getText() ?? "<top level>";
}

/**
 * Every `waitAndMarkNotification` call, and whether its result is used for anything.
 *
 * A joining member that reads its proposal binds the SAID and fetches by it. One that does not
 * simply awaits the call as a statement.
 */
function notificationWaits(file, source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.expression.getText() === "waitAndMarkNotification"
    ) {
      let parent = node.parent;
      while (parent !== undefined && ts.isAwaitExpression(parent)) {
        parent = parent.parent;
      }
      const bound = parent !== undefined && ts.isVariableDeclaration(parent) ? parent.name.getText() : null;
      found.push({
        file,
        enclosing: enclosingOf(node),
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

/** Every `ipex().<step>(...)` call: which step, and which arguments it names. */
function ipexCalls(file, source) {
  const steps = ["apply", "offer", "agree", "grant", "admit"];
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      steps.includes(node.expression.name.getText()) &&
      node.expression.expression.getText().includes("ipex()")
    ) {
      const argument = node.arguments[0];
      const names = ts.isObjectLiteralExpression(argument)
        ? argument.properties.map((property) => property.name?.getText() ?? "")
        : ["<computed>"];
      found.push({
        file,
        step: node.expression.name.getText(),
        enclosing: enclosingOf(node),
        arguments: names,
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Whether a function guards a notification's SAID before using it. */
function guardsNotificationSaid(source, name) {
  let guarded = false;
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      guarded = /assert\([A-Za-z0-9_$.]*\.a\.d\)/.test(node.getText());
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return guarded;
}

/** The `return` statement of one function, verbatim. */
function returnText(source, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      const walk = (child) => {
        if (found === null && ts.isReturnStatement(child)) {
          found = child.getText().replace(/\s+/g, " ");
        }
        ts.forEachChild(child, walk);
      };
      ts.forEachChild(node, walk);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every parameter of one function, including the ones commented out beside them. */
function parameterList(source, name) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isFunctionDeclaration(node) && node.name?.getText() === name) {
      const declared = node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " "));
      const between = node.parameters.length === 0 ? "" : node.getText();
      const commented = [...between.matchAll(/\/\/\s*([A-Za-z_$][A-Za-z0-9_$]*\s*:\s*[A-Za-z<>[\]]+)/g)].map(
        (match) => match[1].replace(/\s+/g, " "),
      );
      found = { declared, commented_out: commented };
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The `atc === undefined` branch of `Ipex.grant`, which re-signs the anchor. */
function grantDefaults(source) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isMethodDeclaration(node) && node.name.getText() === "grant") {
      const text = node.getText().replace(/\s+/g, " ");
      found = {
        text,
        resigns_the_anchor: /atc === undefined \{? ?const keeper = this\.client\.manager!\.get\(hab\)/.test(text)
          ? true
          : /if \(atc === undefined\) \{ const keeper/.test(text),
        credential_attachment_default: /acdcAttachment === undefined \? d\(serializeACDCAttachment\(args\.iss\)\)/.test(
          text,
        ),
        issuance_attachment_default: /issAttachment === undefined \? d\(serializeIssExnAttachment\(args\.anc\)\)/.test(
          text,
        ),
      };
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

const GRANT_MULTISIG = functionText(utils.source, "grantMultisig");
const ADMIT_MULTISIG = functionText(utils.source, "admitMultisig");
const MULTISIG_ADMIT_CREDENTIAL = functionText(holder.source, "multisigAdmitCredential");
const WAITER_RETURN = returnText(testUtil.source, "waitAndMarkNotification");
const ADMIT_PARAMETERS = parameterList(utils.source, "admitMultisig");
const GRANT_DEFAULTS = grantDefaults(credentialing.source);

const WAITS = [
  ...notificationWaits("test-integration/utils/multisig-utils.ts", utils.source),
  ...notificationWaits("test-integration/multisig-holder.test.ts", holder.source),
  ...notificationWaits("test-integration/credentials.test.ts", credentials.source),
];
const IPEX_CALLS = [
  ...ipexCalls("test-integration/utils/multisig-utils.ts", utils.source),
  ...ipexCalls("test-integration/multisig-holder.test.ts", holder.source),
  ...ipexCalls("test-integration/credentials.test.ts", credentials.source),
];

if (GRANT_MULTISIG === null || ADMIT_MULTISIG === null || MULTISIG_ADMIT_CREDENTIAL === null) {
  throw new Error("one of the three group helpers is no longer where this generator expects it");
}
if (WAITER_RETURN === null || !WAITER_RETURN.includes("?? ''")) {
  throw new Error("`waitAndMarkNotification` no longer falls back to the empty string; the finding is stale");
}
if (GRANT_DEFAULTS === null || !GRANT_DEFAULTS.resigns_the_anchor) {
  throw new Error("`Ipex.grant` no longer re-signs the anchor when given no attachment; the finding is stale");
}

/** The three group helpers' `/multisig/exn` waits, every one of them discarded. */
const discarding = WAITS.filter(
  (wait) =>
    wait.route === "/multisig/exn" &&
    ["grantMultisig", "admitMultisig", "multisigAdmitCredential"].includes(wait.enclosing),
);
if (discarding.length !== 3 || discarding.some((wait) => !wait.discarded)) {
  throw new Error("the group helpers no longer discard their `/multisig/exn` notifications");
}

/** The one wait in the tree whose SAID *is* bound: the grant a group admit answers. */
const bound = WAITS.filter((wait) => !wait.discarded);

/** Every set of arguments a grant is built with, across the whole tree. */
const grantArguments = IPEX_CALLS.filter((call) => call.step === "grant").map((call) => ({
  file: call.file,
  enclosing: call.enclosing,
  attachments: call.arguments.filter((name) => name.endsWith("Attachment")),
}));

/** Whether the group admit helper checks the SAID it was handed, and whether the test beside it does. */
const guards = {
  admitMultisig: guardsNotificationSaid(utils.source, "admitMultisig"),
  multisigAdmitCredential: guardsNotificationSaid(holder.source, "multisigAdmitCredential"),
  credentials_test_inline: credentials.text.includes("assert(grantNotification.a.d)"),
};

const declarations = {
  grant_multisig: GRANT_MULTISIG,
  admit_multisig: ADMIT_MULTISIG,
  multisig_admit_credential: MULTISIG_ADMIT_CREDENTIAL,
  waiter_return: WAITER_RETURN,
  admit_parameters: ADMIT_PARAMETERS,
  grant_defaults: GRANT_DEFAULTS,
  notification_waits: WAITS,
  ipex_calls: IPEX_CALLS,
  grant_arguments: grantArguments,
  said_guards: guards,
  shared_clock: {
    declaration: holder.text.includes("const TIME = createTimestamp();"),
    text: "const TIME = createTimestamp();",
    file: "test-integration/multisig-holder.test.ts",
    asserted: holder.text.includes("assert.equal(admitResult1.admitSaid, admitResult2.admitSaid)"),
  },
  timestamp_uses: scan("datetime: TIME"),
  scanned_files: PINNED_FILES.length,
  notes: {
    waiter: "`return notes[notes.length - 1]?.a.d ?? '';` — marks every match read, returns the last, and yields the empty string when a notification names no message",
    stamp: "an IPEX message's SAID covers its `dt`, so two members must agree on a timestamp to build one message",
  },
};

// ---------------------------------------------------------------------------
// 2. The group helpers, transpiled in memory and loaded with a shim.
// ---------------------------------------------------------------------------

const nodeRequire = createRequire(import.meta.url);

async function getStates(client, prefixes) {
  const participantStates = await Promise.all(prefixes.map((prefix) => client.keyStates().get(prefix)));
  return participantStates.map((state) => state[0]);
}

/** The SAID the stubbed waiter hands back — a grant the group is admitting. */
const NOTIFIED_GRANT = "EL7y8q-Cc2MO8s4aiJX5MC05m2BTIYvoX5lgUhFo5ZYF";
/** How many times the stubbed waiter was asked for a notification, and on which routes. */
const waiterCalls = [];

const transpiled = ts.transpileModule(utils.text, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

const shimmedRequire = (specifier) => {
  if (specifier === "signify-ts") {
    return { ...signifyModule, default: signifyModule.default ?? signifyModule };
  }
  if (specifier === "./test-util.ts") {
    return {
      getStates,
      waitAndMarkNotification: async (_client, route) => {
        waiterCalls.push(route);
        return NOTIFIED_GRANT;
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
const { startMultisigIncept, grantMultisig, admitMultisig } = helperModule.exports;
if (
  typeof startMultisigIncept !== "function" ||
  typeof grantMultisig !== "function" ||
  typeof admitMultisig !== "function"
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
/** Who the credential is about, and who a presentation is disclosed to. */
const SUBJECT_PREFIX = "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei";
const VERIFIER_PREFIX = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";

const NONCE = "AHSNDV3ABI6U8OIgKaj3aky91ZpNL54I5_7-qwtC6q2s";
const QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LEI = "5493001KJTIIGC8Y1R17";

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
let groupRecord = null;
/** The credential the issuer issued, once it has, so the holder can read it back with attachments. */
let heldCredential = null;

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
    if (heldCredential === null) {
      throw new Error("a credential was read before it was issued");
    }
    return heldCredential;
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
  return { name: "exn.EEXN", metadata: { pre: "EEXN", sn: 0 }, done: false };
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
// 4. Drive the conversation.
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

// The single-signature half first: one identifier issues, discloses, and is asked to disclose
// again. Each step is driven through the reference's own `Ipex` method with the reference's own
// arguments, in the order `credentials.test.ts` calls them.

const issued = await drive(
  "issue_the_credential",
  "the issuer issues a credential to its subject, so there is something to disclose",
  async () =>
    await client.credentials().issue("member1", {
      ri: "EJBglnT4bORqW6oF87S050gj5i1qBQSHwTj3bLPyMpbX",
      s: QVI_SCHEMA,
      u: NONCE,
      a: { i: SUBJECT_PREFIX, LEI, dt: SHARED_STAMP },
    }),
);
if (issued === null) {
  throw new Error("the credential was not issued");
}

// What the holder would read back: the credential with the three attachments it arrived with.
heldCredential = {
  sad: issued.acdc.sad,
  atc: "-IABEEXN0AAAAAAAAAAAAAAAAAAAAAAAEEXN",
  iss: issued.iss.sad,
  issatc: "-VAS-GAB0AAAAAAAAAAAAAAAAAAAAAAAEEXN",
  pre: LOCAL_PREFIX,
  schema: {
    $id: QVI_SCHEMA,
    $schema: "http://json-schema.org/draft-07/schema#",
    title: "Qualified vLEI Issuer Credential",
    description: "A vLEI Credential issued by GLEIF to Qualified vLEI Issuers",
    type: "object",
    credentialType: "QualifiedvLEIIssuervLEICredential",
    version: "1.0.0",
    properties: {},
    additionalProperties: false,
    required: ["i", "ri", "s", "d"],
  },
  chains: [],
  status: {
    vn: [1, 0],
    i: issued.acdc.sad.d,
    s: "0",
    d: issued.iss.sad.d,
    ri: issued.acdc.sad.ri,
    a: { s: "1", d: issued.anc.sad.d },
    dt: SHARED_STAMP,
    et: "iss",
    ra: {},
  },
  anchor: { pre: LOCAL_PREFIX, sn: 0, d: issued.anc.sad.d },
  anc: issued.anc.sad,
  ancatc: ["-AABAA" + "B".repeat(86)],
};

await drive(
  "issuer_grants_the_credential",
  "the grant that opens an issuance: it chains to nothing, and passes only the anchor's attachment",
  async () => {
    const [grant, sigs, end] = await client.ipex().grant({
      senderName: "member1",
      acdc: new Serder(heldCredential.sad),
      anc: new Serder(heldCredential.anc),
      iss: new Serder(heldCredential.iss),
      ancAttachment: heldCredential.ancatc.join(""),
      recipient: SUBJECT_PREFIX,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitGrant("member1", grant, sigs, end, [SUBJECT_PREFIX]);
    return { said: grant.said, prior: grant.sad.p, slots: Object.keys(grant.sad.e).filter((slot) => slot !== "d") };
  },
);

await drive(
  "issuer_grants_with_no_attachments",
  "the same grant with no attachments at all — the shape `multisig-holder.test.ts` sends, which re-signs the anchor",
  async () => {
    const [grant, sigs, end] = await client.ipex().grant({
      senderName: "member1",
      acdc: new Serder(heldCredential.sad),
      anc: new Serder(heldCredential.anc),
      iss: new Serder(heldCredential.iss),
      recipient: SUBJECT_PREFIX,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitGrant("member1", grant, sigs, end, [SUBJECT_PREFIX]);
    return { said: grant.said, attachment_length: end.length };
  },
);

await drive(
  "holder_admits_the_grant",
  "the admit that closes an issuance, chained to the grant it answers",
  async () => {
    const [admit, sigs, end] = await client.ipex().admit({
      senderName: "member1",
      message: "",
      grantSaid: NOTIFIED_GRANT,
      recipient: LOCAL_PREFIX,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitAdmit("member1", admit, sigs, end, [LOCAL_PREFIX]);
    return { said: admit.said, prior: admit.sad.p };
  },
);

await drive(
  "holder_admits_an_unnamed_grant",
  "the same admit given the empty string the waiter returns when a notification names no message",
  async () => {
    const [admit, sigs, end] = await client.ipex().admit({
      senderName: "member1",
      message: "",
      grantSaid: "",
      recipient: LOCAL_PREFIX,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitAdmit("member1", admit, sigs, end, [LOCAL_PREFIX]);
    return { said: admit.said, prior: admit.sad.p };
  },
);

const applied = await drive(
  "verifier_applies",
  "the apply that opens a presentation: a schema and the attributes it must carry",
  async () => {
    const [apply, sigs] = await client.ipex().apply({
      senderName: "member1",
      schemaSaid: QVI_SCHEMA,
      attributes: { LEI },
      recipient: SUBJECT_PREFIX,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitApply("member1", apply, sigs, [SUBJECT_PREFIX]);
    return { said: apply.said, attributes: apply.sad.a, slots: Object.keys(apply.sad.e ?? {}) };
  },
);
if (applied === null) {
  throw new Error("the apply was not built");
}

const offered = await drive(
  "holder_offers",
  "the offer that answers it, chained to the apply and embedding the credential alone",
  async () => {
    const [offer, sigs, end] = await client.ipex().offer({
      senderName: "member1",
      recipient: VERIFIER_PREFIX,
      acdc: new Serder(heldCredential.sad),
      applySaid: applied.said,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitOffer("member1", offer, sigs, end, [VERIFIER_PREFIX]);
    return { said: offer.said, prior: offer.sad.p, slots: Object.keys(offer.sad.e).filter((slot) => slot !== "d") };
  },
);
if (offered === null) {
  throw new Error("the offer was not built");
}

const agreed = await drive(
  "verifier_agrees",
  "the agree, chained to the offer and embedding nothing",
  async () => {
    const [agree, sigs] = await client.ipex().agree({
      senderName: "member1",
      recipient: SUBJECT_PREFIX,
      offerSaid: offered.said,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitAgree("member1", agree, sigs, [SUBJECT_PREFIX]);
    return { said: agree.said, prior: agree.sad.p };
  },
);
if (agreed === null) {
  throw new Error("the agree was not built");
}

await drive(
  "holder_discloses",
  "the presentation grant, chained to the agree and passing all three attachments",
  async () => {
    const [grant, sigs, end] = await client.ipex().grant({
      senderName: "member1",
      recipient: VERIFIER_PREFIX,
      acdc: new Serder(heldCredential.sad),
      anc: new Serder(heldCredential.anc),
      iss: new Serder(heldCredential.iss),
      acdcAttachment: heldCredential.atc,
      ancAttachment: heldCredential.ancatc.join(""),
      issAttachment: heldCredential.issatc,
      agreeSaid: agreed.said,
      datetime: SHARED_STAMP,
    });
    await client.ipex().submitGrant("member1", grant, sigs, end, [VERIFIER_PREFIX]);
    return { said: grant.said, prior: grant.sad.p, slots: Object.keys(grant.sad.e).filter((slot) => slot !== "d") };
  },
);

// The group half. `grantMultisig` and `admitMultisig` are the reference's own, transpiled above.

await drive(
  "incept_the_group",
  "the group that will disclose and admit, from the same helper the `client-multisig-inception` fixture drives",
  async () =>
    await startMultisigIncept(client, {
      groupName: "multisig",
      localMemberName: "member1",
      participants: [LOCAL_PREFIX, PEER_PREFIX],
      toad: 0,
      isith: 2,
      nsith: 2,
      wits: [],
    }),
);

const creation = JSON.parse(
  calls.find((entry) => entry.name === "incept_the_group").requests.find((request) => request.path === "/identifiers")
    ?.body ?? "null",
);
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
const recipientRecord = { ...LOCAL_MEMBER, name: "recipient", prefix: VERIFIER_PREFIX };
const credentialForGrant = { sad: heldCredential.sad, anc: heldCredential.anc, iss: heldCredential.iss };

await drive(
  "group_proposes_the_disclosure",
  "the initiator grants under the group's alias, submits it to the recipient, and tells the other member",
  async () =>
    await grantMultisig(
      client,
      localMember,
      [peerMember],
      groupRecord,
      recipientRecord,
      credentialForGrant,
      SHARED_STAMP,
      true,
    ),
);

await drive(
  "group_joins_the_disclosure",
  "the joining member waits for `/multisig/exn`, discards it, and grants from its own arguments",
  async () =>
    await grantMultisig(
      client,
      localMember,
      [peerMember],
      groupRecord,
      recipientRecord,
      credentialForGrant,
      SHARED_STAMP,
      false,
    ),
);

await drive(
  "group_joins_the_disclosure_on_another_clock",
  "the same call one second later: it succeeds, and builds a different grant",
  async () =>
    await grantMultisig(
      client,
      localMember,
      [peerMember],
      groupRecord,
      recipientRecord,
      credentialForGrant,
      OTHER_STAMP,
      false,
    ),
);

await drive(
  "group_proposes_the_admittance",
  "the initiator admits the grant it was notified of, under the group's alias",
  async () =>
    await admitMultisig(client, localMember, [peerMember], groupRecord, recipientRecord, SHARED_STAMP, true),
);

await drive(
  "group_joins_the_admittance",
  "the joining member, handed the same stamp: the same admit",
  async () =>
    await admitMultisig(client, localMember, [peerMember], groupRecord, recipientRecord, SHARED_STAMP, false),
);

await drive(
  "group_joins_the_admittance_on_another_clock",
  "and handed its own clock: a different admit, with no error",
  async () =>
    await admitMultisig(client, localMember, [peerMember], groupRecord, recipientRecord, OTHER_STAMP, false),
);

console.log = realLog;

// ---------------------------------------------------------------------------
// 5. What the recording says.
// ---------------------------------------------------------------------------

const resultOf = (name) => calls.find((entry) => entry.name === name)?.result ?? null;
const errorOf = (name) => calls.find((entry) => entry.name === name)?.error ?? null;
const bodyOf = (name, ending) => {
  const call = calls.find((entry) => entry.name === name);
  const request = call?.requests.find((entry) => entry.path.endsWith(ending));
  return request?.body === undefined || request?.body === null ? null : JSON.parse(request.body);
};

const proposedGrant = bodyOf("group_proposes_the_disclosure", "/ipex/grant");
const joinedGrant = bodyOf("group_joins_the_disclosure", "/ipex/grant");
const divergentGrant = bodyOf("group_joins_the_disclosure_on_another_clock", "/ipex/grant");
const proposedAdmit = bodyOf("group_proposes_the_admittance", "/ipex/admit");
const joinedAdmit = bodyOf("group_joins_the_admittance", "/ipex/admit");
const divergentAdmit = bodyOf("group_joins_the_admittance_on_another_clock", "/ipex/admit");
const announcement = bodyOf("group_proposes_the_admittance", "/exchanges");

if (
  proposedGrant === null ||
  joinedGrant === null ||
  divergentGrant === null ||
  proposedAdmit === null ||
  joinedAdmit === null ||
  divergentAdmit === null ||
  announcement === null
) {
  throw new Error("a driven group round posted nothing");
}

const anonymous = resultOf("holder_admits_an_unnamed_grant");
const attached = resultOf("issuer_grants_the_credential");
const unattached = resultOf("issuer_grants_with_no_attachments");

const quirks = {
  a_group_round_agrees_only_on_a_shared_clock: {
    declaration: "`datetime: timestamp` on both halves; `const TIME = createTimestamp()` in the holder test",
    proposed_grant: proposedGrant.exn.d,
    joined_grant: joinedGrant.exn.d,
    divergent_grant: divergentGrant.exn.d,
    grants_agree: proposedGrant.exn.d === joinedGrant.exn.d,
    divergent_grant_agrees: proposedGrant.exn.d === divergentGrant.exn.d,
    proposed_admit: proposedAdmit.exn.d,
    joined_admit: joinedAdmit.exn.d,
    divergent_admit: divergentAdmit.exn.d,
    admits_agree: proposedAdmit.exn.d === joinedAdmit.exn.d,
    divergent_admit_agrees: proposedAdmit.exn.d === divergentAdmit.exn.d,
    divergent_errors: [
      errorOf("group_joins_the_disclosure_on_another_clock"),
      errorOf("group_joins_the_admittance_on_another_clock"),
    ],
    asserted_upstream: "assert.equal(admitResult1.admitSaid, admitResult2.admitSaid)",
    note: "an IPEX message's SAID covers its `dt`. Both helpers take the stamp as a parameter and the holder test reads one module-level constant, so the members agree only because one process handed both the same value. One second apart they build different messages, the group never reaches its threshold on either, and neither call fails. The reference's own equality assertion is the only thing that would notice, and it lives inside the process that made them equal.",
    rust_decision:
      "`accept_admittance` takes no timestamp at all: the stamp, the recipient, the text, and the grant being acknowledged are read out of the proposal, and the SAID this member derives is compared with the one it was shown. `accept_disclosure` does the same.",
  },
  a_joining_member_never_reads_the_proposal: {
    declaration: "`if (!isInitiator) await waitAndMarkNotification(client, '/multisig/exn');`",
    waits: discarding,
    routes_waited_on: waiterCalls,
    group_requests_made: calls.some((entry) =>
      entry.requests.some((request) => request.path.startsWith("/multisig/request/")),
    ),
    note: "the same shape the `client-multisig-credentials` fixture pinned for the transaction rounds, in all three group IPEX helpers. Driven across six group rounds, not one fetches a group request.",
    rust_decision: "the proposed message is read out of the `/multisig/exn` proposal and rebuilt from its own fields.",
  },
  a_notification_need_not_name_a_message: {
    declaration: WAITER_RETURN,
    guards,
    admit_prior: anonymous === null ? null : anonymous.prior,
    admit_said: anonymous === null ? null : anonymous.said,
    error: errorOf("holder_admits_an_unnamed_grant"),
    note: "the waiter yields the empty string when a notification carries no `a.d`, and `admitMultisig` passes it straight into `grantSaid`. Driven: the admit is built and posted with an empty `p`, acknowledging nothing, with no error. The inline step in `credentials.test.ts` guards the same value with `assert(grantNotification.a.d)` first; the helper beside it does not.",
    rust_decision:
      "`Presentation::read` requires the notification to name a SAID and refuses with `UnaddressedNotification`, so no step can be built from a notification that announces nothing.",
  },
  only_the_last_notification_survives: {
    declaration: WAITER_RETURN,
    commented_out_parameter: ADMIT_PARAMETERS.commented_out,
    note: "`waitAndMarkNotification` marks every matching notification read and returns only the last one's SAID. A holder group admitting from a multisig issuer receives one grant per issuer member; it answers one and silently marks the rest read. The parameter that would have said how many to expect — `numGrantMsgs: number` — is still in the tree, commented out.",
    rust_decision: "`Presentation::waiting` returns every unread notification on the route, and the caller answers each.",
  },
  a_grant_assembles_its_attachments_three_ways: {
    call_sites: grantArguments,
    defaults: GRANT_DEFAULTS,
    with_attachment: attached === null ? null : attached.said,
    without_attachment: unattached === null ? null : unattached.said,
    note: "the presentation grant passes all three attachments, the issuance grant passes the anchor's only, and `multisig-holder.test.ts` passes none. Passing none reaches the branch that signs `args.anc.raw` with the *sender's* keeper — correct only when the sender is the issuer, and reached in the tree where it is not.",
    rust_decision:
      "the credentials endpoint refused that branch: a `Disclosure` carries its own three attachments, derived from the issuance artifacts or read off the credential. `presentation::disclosure_of` assembles them from a credential in hand, and re-serializes each of the three events to check its bytes still reproduce the SAID that names it.",
  },
  an_announcement_names_only_the_group: {
    declaration: typeText(exchanging.source, "MultisigExnExchange"),
    announcement_attributes: Object.keys(announcement.exn.a),
    helpers_take_recipients_from_caller: ["grantMultisig", "admitMultisig"],
    recipients_source: functionText(multisigTest.source, "multisigIssue").match(/const recipients = [^;]+;/)?.[0] ?? null,
    members_endpoint_uses: scan("client.identifiers().members("),
    note: "a `/multisig/exn` proposal carries `{ gid }` and nothing else — `MultisigExnExchange` declares no `smids` — and both group IPEX helpers take the peers as an argument, so a joining member is told who to answer by its caller rather than by the message. Where the reference's own tests derive the members themselves (`multisigIssue`, `multisigRevoke`) they ask the agent's members endpoint for `signing[].aid`; the group record's `keys` are the members' signing keys and never stand in for them.",
    rust_decision:
      "the IPEX rounds announce `smids` and `rmids` exactly as the six event rounds do, so a joining member reads its peers from the proposal it was shown; a proposal that names nobody — the reference's — is answered by `identifiers().members(group)`, never by the record's keys. The classifier accepts both shapes on `/multisig/exn`.",
  },
};

const pinnedConfirmations = {
  group: GROUP,
  schema: QVI_SCHEMA,
  credential: heldCredential.sad.d,
  apply: applied.said,
  offer: offered.said,
  agree: agreed.said,
  chain: [
    { step: "apply", said: applied.said, prior: "" },
    { step: "offer", said: offered.said, prior: offered.prior },
    { step: "agree", said: agreed.said, prior: agreed.prior },
    { step: "grant", said: resultOf("holder_discloses")?.said ?? null, prior: resultOf("holder_discloses")?.prior ?? null },
  ],
  apply_slots: applied.slots,
  offer_slots: offered.slots,
  grant_slots: resultOf("holder_discloses")?.slots ?? null,
  issuance_grant_slots: attached === null ? null : attached.slots,
  announcement_route: announcement.exn.r,
  announcement_topic: announcement.tpc,
  announcement_slots: Object.keys(announcement.exn.e).filter((slot) => slot !== "d"),
  announcement_attributes: Object.keys(announcement.exn.a),
  presentation_paths: calls
    .find((entry) => entry.name === "verifier_applies")
    .requests.map((request) => `${request.method} ${request.path}`),
  note: "an apply and an agree embed nothing, an offer embeds `acdc` alone, and a grant embeds `{acdc, iss, anc}`. A group announces the whole message under `exn` on `/multisig/exn`.",
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-09-16",
  sources: [
    "test-integration/credentials.test.ts",
    "test-integration/multisig-holder.test.ts",
    "test-integration/utils/multisig-utils.ts",
    "test-integration/utils/test-util.ts",
    "src/keri/app/credentialing.ts",
    "test/app/test-utils.ts",
    "src/keri/app/exchanging.ts",
    "test-integration/multisig.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    shared_stamp: SHARED_STAMP,
    other_stamp: OTHER_STAMP,
    agent_prefix: agentPrefix,
    local_member_prefix: LOCAL_PREFIX,
    peer_prefix: PEER_PREFIX,
    subject_prefix: SUBJECT_PREFIX,
    verifier_prefix: VERIFIER_PREFIX,
    notified_grant: NOTIFIED_GRANT,
    note: "The single-signature conversation is written inline in `credentials.test.ts`, so each step is driven through the reference's own `Ipex` method with the same arguments in the same order. The group rounds live in `multisig-utils.ts`, which is **transpiled in memory** by the reference's own pinned TypeScript and evaluated with a module shim, as the `client-multisig-inception` generator does. Nothing is written into the submodule. The clock and the agent's key are pinned; the local member is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
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
  held_credential: heldCredential,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-ipex-presentation/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-ipex-presentation fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
