// Records the pinned signify-ts checkout's delegation endpoint.
//
// This fixture ports the whole of `src/keri/app/delegating.ts`: one class with one method,
// `Delegations.approve`, in thirty-three lines including its documentation. It is the smallest
// application module in the port, three lines shorter than `escrowing.ts`.
//
// A delegated identifier cannot come into existence alone. Its inception names a delegator and
// stays pending until that delegator anchors a **seal of it** in its own key event log. This one
// call is that anchoring, and it is an ordinary interaction event posted to a different address.
//
// `Delegations` takes a whole `SignifyClient`, so this generator drives the real client the way
// `client_escrows.mjs` does: `globalThis.fetch` is replaced with a recorder that answers and signs
// as a KERIA agent would, the clock is pinned, and every recorded byte is the reference's own.
//
// Three things fall out.
//
//   1. **The pinned unit test approves nothing.** `approve` declares `data?: any` and
//      `createInteract` wraps a non-array in one, so calling it with no anchor sends `"a": [null]`
//      — an interaction whose seal list holds a JSON null, whose SAID is computed over it, and
//      whose signature covers it. That is the only body the pinned tree publishes for this
//      endpoint, and it is what the test asserts byte for byte.
//   2. **The address is the whole of the difference.** The body `approve` sends and the body
//      `identifiers().interact` sends are byte-identical for the same anchor; only the last path
//      segment differs. Driven both ways and compared here.
//   3. **The delegate reads its own prefix out of an operation's name.** The integration test does
//      `op2.name.split('.')[1]` to learn the identifier it just created, and then hand-assembles
//      the seal from it. The prefix is in the inception event the same call returned.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

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

/** The passcode and URLs the pinned `delegating.test.ts` publishes. */
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
// 1. The class and its one test, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const delegating = parse("src/keri/app/delegating.ts");
const unitTest = parse("test/app/delegating.test.ts");
const integration = parse("test-integration/delegation.test.ts");
const aiding = parse("src/keri/app/aiding.ts");

/** Every method name a class declares, in source order. */
function classMembers(source, className) {
  const found = [];
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        const name = member.name?.getText();
        if (name !== undefined) {
          found.push(name);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The whole text of one method of one class. */
function methodText(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name.getText() === methodName) {
          found = member.getText().replace(/\s+/g, " ");
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** One method's parameter list, with each declared type and whether it is optional. */
function methodSignature(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name.getText() === methodName) {
          found = {
            parameters: member.parameters.map((parameter) => ({
              name: parameter.name.getText(),
              type: parameter.type?.getText() ?? "<inferred>",
              optional: parameter.questionToken !== undefined,
            })),
            returns: member.type?.getText() ?? "<inferred>",
          };
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The path expression a `fetch` call in one method addresses. */
function fetchPaths(source, className, methodName) {
  const found = [];
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name.getText() === methodName) {
          const walk = (inner) => {
            if (
              ts.isCallExpression(inner) &&
              ts.isPropertyAccessExpression(inner.expression) &&
              inner.expression.name.getText() === "fetch" &&
              inner.arguments.length >= 2
            ) {
              found.push({
                path: inner.arguments[0].getText().replace(/\s+/g, " "),
                method: ts.isStringLiteralLike(inner.arguments[1]) ? inner.arguments[1].text : "<computed>",
              });
            }
            ts.forEachChild(inner, walk);
          };
          walk(member);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `delegations().approve(...)` call in one file, with its arguments as written. */
function approveCalls(file, source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "approve" &&
      // Either `client.delegations().approve(...)` or a `delegations` binding held first, which
      // is what the pinned unit test does.
      (node.getText().includes("delegations()") || node.expression.expression.getText() === "delegations")
    ) {
      found.push({
        file,
        arguments: node.arguments.map((argument) => argument.getText().replace(/\s+/g, " ")),
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The line where the integration test learns the delegate's own prefix. */
function prefixDiscovery(source) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isVariableDeclaration(node) && node.initializer !== undefined) {
      const text = node.initializer.getText().replace(/\s+/g, " ");
      if (text.includes(".name.split(")) {
        found = { binds: node.name.getText(), from: text };
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The `createInteract` line that turns an absent anchor into a one-element list. */
function wrappingLine() {
  const line = aiding.text
    .split("\n")
    .map((text) => text.trim())
    .find((text) => text.startsWith("data = Array.isArray(data)"));
  if (line === undefined) {
    throw new Error("`createInteract` no longer wraps its anchor; re-read the premise");
  }
  return line;
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

const MEMBERS = classMembers(delegating.source, "Delegations");
const APPROVE = methodText(delegating.source, "Delegations", "approve");
const SIGNATURE = methodSignature(delegating.source, "Delegations", "approve");
const PATHS = fetchPaths(delegating.source, "Delegations", "approve");
const CALLS = [
  ...approveCalls("test/app/delegating.test.ts", unitTest.source),
  ...approveCalls("test-integration/delegation.test.ts", integration.source),
  ...approveCalls("test-integration/utils/multisig-utils.ts", parse("test-integration/utils/multisig-utils.ts").source),
];
const DISCOVERY = prefixDiscovery(integration.source);
const WRAPPING = wrappingLine();

// The premise of this fixture: one class, one method, one address.
if (MEMBERS.length !== 2 || !MEMBERS.includes("approve")) {
  throw new Error(`Delegations no longer has a constructor and one method: ${MEMBERS.join(", ")}`);
}
if (PATHS.length !== 1 || PATHS[0].method !== "POST") {
  throw new Error("`approve` no longer performs exactly one POST");
}
if (!PATHS[0].path.includes("/delegation")) {
  throw new Error("`approve` no longer posts to the delegation segment");
}
// And the finding: the anchor is optional.
const anchorParameter = SIGNATURE?.parameters.find((parameter) => parameter.name === "data");
if (anchorParameter === undefined || !anchorParameter.optional) {
  throw new Error("`approve`'s anchor is no longer optional; the finding below is stale");
}

const declarations = {
  approve: APPROVE,
  members: MEMBERS,
  signature: SIGNATURE,
  fetch_calls: PATHS,
  approve_calls: CALLS,
  prefix_discovery: DISCOVERY,
  anchor_wrapping: WRAPPING,
  delegations_accessor_uses: scan("delegations()"),
  delegation_segment_uses: scan("/delegation"),
  // `wc -l` semantics: the number of newlines, so a trailing one is not a line.
  file_lines: delegating.text.split("\n").length - 1,
  notes: {
    address: "the only difference between an approval and an ordinary interaction is the last path segment",
    anchor: "`data?: any` with `createInteract` wrapping a non-array, so an omitted anchor reaches the wire as `[null]`",
  },
};

// ---------------------------------------------------------------------------
// 2. A connected client whose agent answers as a KERIA would.
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
// `mockGetAID` carries no `icp_dt`, which the reference never reads and the typed identifier record
// requires. The `client-multisig-inception` fixture added it the same way: the field is supplied
// here so the record is decodable on both sides, and nothing upstream behaves differently for it.
const ADDED_INCEPTION_STAMP = "2023-08-21T22:30:46.473545+00:00";
const DELEGATOR = { ...MOCK_GET_AID, name: "delegator", icp_dt: MOCK_GET_AID.icp_dt ?? ADDED_INCEPTION_STAMP };
const DELEGATOR_PREFIX = DELEGATOR.prefix;

/** The identifier the pinned unit test names — a SAID-shaped value used as an alias. */
const PINNED_NAME = (() => {
  const call = CALLS.find((entry) => entry.file === "test/app/delegating.test.ts");
  if (call === undefined || call.arguments.length === 0) {
    throw new Error("the pinned unit test no longer calls `approve`");
  }
  return call.arguments[0].replace(/^'|'$/g, "");
})();

const recorded = [];

function signedHeaders(httpMethod, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
  ]);
  return authenticator.sign(headers, httpMethod, path.split("?")[0]);
}

function answer(path) {
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
  if (path.startsWith("/identifiers/") && !path.includes("/delegation") && !path.includes("/events")) {
    return DELEGATOR;
  }
  // A write is answered with a long-running operation, as a KERIA does.
  return {
    name: `delegation.${DELEGATOR_PREFIX}`,
    metadata: { pre: DELEGATOR_PREFIX, sn: 1 },
    done: false,
  };
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
  return new Response(JSON.stringify(answer(path)), { status: 200, headers });
};

await client.boot();
await client.connect();

// ---------------------------------------------------------------------------
// 3. Drive the one method.
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
  calls.push({
    name,
    note,
    requests: recorded.slice(before).map((request) => ({ ...request })),
    result: result === null || result === undefined ? null : JSON.parse(JSON.stringify(result)),
    error,
  });
  return result;
}

/** The seal a real approval anchors: the delegate's inception, named three ways. */
const DELEGATE_PREFIX = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const SEAL = { i: DELEGATE_PREFIX, s: "0", d: DELEGATE_PREFIX };

await drive(
  "approve_with_no_anchor",
  "the pinned unit test's own call: `approve(name)` with no anchor at all, which sends `a: [null]`",
  async () => await client.delegations().approve(PINNED_NAME),
);

await drive(
  "approve_a_delegate",
  "what an approval is for: the delegator anchors a seal of the delegate's inception",
  async () => await client.delegations().approve("delegator", SEAL),
);

await drive(
  "approve_with_a_seal_list",
  "the same seal already wrapped, since `createInteract` leaves an array alone",
  async () => await client.delegations().approve("delegator", [SEAL]),
);

await drive(
  "approve_two_delegates_at_once",
  "two seals in one event, which the wrapping permits and nothing upstream forbids",
  async () => await client.delegations().approve("delegator", [SEAL, { ...SEAL, i: DELEGATOR_PREFIX }]),
);

await drive(
  "approve_a_seal_that_is_not_one",
  "an anchor that is a bare string: `data?: any`, so it is wrapped and signed like any other",
  async () => await client.delegations().approve("delegator", "not a seal"),
);

await drive(
  "interact_with_the_same_seal",
  "the sibling call: the identical body, posted to `events` instead of `delegation`",
  async () => await client.identifiers().interact("delegator", SEAL),
);

await drive(
  "approve_under_an_alias_holding_delimiters",
  "the alias reaches the path raw, as everywhere in the reference",
  async () => await client.delegations().approve("a/b?c=d", SEAL),
);

// ---------------------------------------------------------------------------
// 4. What the recording says.
// ---------------------------------------------------------------------------

const bodyOf = (name, predicate = () => true) => {
  const call = calls.find((entry) => entry.name === name);
  const request = call?.requests.find((entry) => entry.method === "POST" && predicate(entry));
  return request?.body === undefined || request?.body === null ? null : JSON.parse(request.body);
};
const pathOf = (name) => {
  const call = calls.find((entry) => entry.name === name);
  return call?.requests.find((entry) => entry.method === "POST")?.path ?? null;
};

const noAnchor = bodyOf("approve_with_no_anchor");
const approved = bodyOf("approve_a_delegate");
const interacted = bodyOf("interact_with_the_same_seal");
if (noAnchor === null || approved === null || interacted === null) {
  throw new Error("a driven call posted nothing");
}

const quirks = {
  the_pinned_test_approves_nothing: {
    declaration: "`approve(name: string, data?: any)` — the anchor is optional, and the one pinned test omits it",
    pinned_call: CALLS.find((entry) => entry.file === "test/app/delegating.test.ts"),
    wrapping: WRAPPING,
    anchored: noAnchor.ixn.a,
    said: noAnchor.ixn.d,
    signatures: noAnchor.sigs.length,
    note: "`createInteract` wraps a non-array, so an absent anchor becomes `[undefined]` and serializes as `[null]`. The event's SAID is computed over that list and the signature covers it, so the only body the pinned tree publishes for this endpoint is a signed approval of nothing. A delegate waiting on this seal waits forever.",
    rust_decision:
      "the seals are a required argument and an empty list is refused with `ClientError::NoDelegationSeals`. There is no way to spell an approval of nothing.",
  },
  the_address_is_the_whole_difference: {
    declaration: "`approve` calls `createInteract` and posts the result to `/delegation`; `interact` posts it to `/events`",
    approval_path: pathOf("approve_a_delegate"),
    interaction_path: pathOf("interact_with_the_same_seal"),
    bodies_identical: JSON.stringify(approved) === JSON.stringify(interacted),
    note: "driven both ways with the same seal: the event, its SAID, its signature, and the key-manager block are byte for byte the same, and only the last path segment differs.",
    rust_decision:
      "one builder serves both, as one serves both upstream. `Identifiers::submit_interaction` takes the segment, and `Delegations::approve` is that call with `delegation` in it.",
  },
  the_delegate_reads_its_prefix_from_an_operations_name: {
    declaration: DISCOVERY,
    note: "the integration test learns the identifier it just created by splitting a long-running operation's *name* on a full stop, and then hand-assembles the seal from the result. The prefix is in the inception event the same call returned.",
    rust_decision:
      "`InceptionSeal::of` takes the delegate's own artifact and reads the identifier and the digest out of the event, so the three seal fields cannot disagree with each other or with what they claim to anchor.",
  },
  an_anchor_may_be_anything: {
    declaration: "`data?: any`",
    string_anchor: bodyOf("approve_a_seal_that_is_not_one")?.ixn.a ?? null,
    two_seals: bodyOf("approve_two_delegates_at_once")?.ixn.a ?? null,
    note: "a bare string is wrapped, anchored, and signed exactly as a seal would be; two seals in one event are equally accepted. Nothing upstream looks at the shape.",
    rust_decision:
      "a seal is a `Sad`, so an anchor is a block rather than anything at all; `InceptionSeal` names the three fields a delegated inception's seal carries. A list of more than one is still permitted, because the event format permits it.",
  },
  one_alias_is_encoded_on_the_read_and_raw_on_the_write: {
    declaration: PATHS[0].path,
    read_path: (() => {
      const call = calls.find((entry) => entry.name === "approve_under_an_alias_holding_delimiters");
      return call?.requests.find((entry) => entry.method === "GET")?.path ?? null;
    })(),
    write_path: pathOf("approve_under_an_alias_holding_delimiters"),
    note: "one call, one alias, two treatments. `approve` reads the identifier first through `identifiers().get`, which encodes its path component, and then writes to `'/identifiers/' + name + '/delegation'`, which concatenates — so `a/b?c=d` is one segment on the read and two segments and a query on the write. The reference disagrees with itself inside a single method, which is a sharper form of the raw interpolation `client-oobis` and `client-groups` recorded.",
    rust_decision: "closed by `ResourcePathBuilder`, which percent-encodes every component of both addresses; the read and the write cannot diverge because they are built the same way.",
  },
};

const pinnedConfirmations = {
  pinned_name: PINNED_NAME,
  pinned_path: pathOf("approve_with_no_anchor"),
  pinned_body: calls.find((entry) => entry.name === "approve_with_no_anchor")?.requests.find((entry) => entry.method === "POST")?.body ?? null,
  approval_path: pathOf("approve_a_delegate"),
  delegator_prefix: DELEGATOR_PREFIX,
  delegate_prefix: DELEGATE_PREFIX,
  seal: SEAL,
  note: "the pinned test asserts one address, one method, and one body; all three are reproduced here, and the body is the one that approves nothing.",
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: [
    "src/keri/app/delegating.ts",
    "src/keri/app/aiding.ts",
    "test/app/delegating.test.ts",
    "test-integration/delegation.test.ts",
    "test/app/test-utils.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    delegator_prefix: DELEGATOR_PREFIX,
    note: "`Delegations` takes a whole `SignifyClient`, so the real client is walked through boot, connect, and each call with `globalThis.fetch` replaced by a recorder that signs as a KERIA agent would. The clock is pinned because a signed request's timestamp is a clock reading; the identifier is the reference's own `mockGetAID`. `PUBLIC TEST MATERIAL`: the passcode and sealed salt are the pinned tests' own.",
  },
  declarations,
  identifier_record: (() => {
    const copy = JSON.parse(JSON.stringify(DELEGATOR));
    copy.salty.sxlt_opens_to = openSealed(BRAN, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
    return copy;
  })(),
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-delegations/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-delegations fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
