// Records the pinned signify-ts checkout's whole client lifecycle, driven through `SignifyClient`.
//
// This port covers what a client does before any endpoint family exists: validate its
// configuration, boot an agent, read that agent's state, connect — which rebuilds the controller
// against the returned state, validates the agent's commitment, approves the delegation, and
// builds the key manager and the authenticator — and then send signed requests. It also ports
// `randomPasscode` and `randomNonce` from `app/coring.ts`, and settles what `src/ready.ts` becomes.
//
// As with keri-acdc's `ipex` fixture, this one **drives the reference rather than re-expressing
// it**: `globalThis.fetch` is replaced with a recorder that answers exactly as a KERIA agent would,
// and the real `SignifyClient` is walked through `boot`, `state`, `connect`, `fetch`,
// `saveOldPasscode`, and `deletePasscode`. Every request it makes is recorded with its method, URL,
// headers, and body.
//
// Two things are pinned that no earlier fixture pinned: the **clock**, as the `http-auth` fixture's
// was, so the signed request reproduces byte for byte including its signature; and the agent's
// **own key**, so its response signatures are reproducible too.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Agent, Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { randomPasscode, randomNonce } from "./node_modules/signify-ts/dist/keri/app/coring.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The passcode and URLs the pinned `clienting.test.ts` publishes. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// 0. Pin the clock, so the signed request and its signature are deterministic.
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
// 1. The lifecycle's own declarations, read from the reference's syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const clienting = parse("src/keri/app/clienting.ts");
const coring = parse("src/keri/app/coring.ts");
const ready = parse("src/ready.ts");

function method(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name?.getText() === methodName) {
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

function functionText(source, name) {
  return firstText(source, (node) => ts.isFunctionDeclaration(node) && node.name?.getText() === name);
}

/** Every `.ts` file in the pinned trees, so an absence can be scanned rather than asserted. */
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

const declarations = {
  default_boot_url: firstText(clienting.source, (node) =>
    ts.isVariableDeclaration(node) && node.name.getText() === "DEFAULT_BOOT_URL",
  ),
  passcode_length_check: firstText(
    method(clienting.source, "SignifyClient", "constructor") ?? clienting.source,
    (node) => ts.isIfStatement(node) && node.getText().includes("bran.length"),
  ),
  boot_body: firstText(
    method(clienting.source, "SignifyClient", "boot"),
    (node) => ts.isVariableDeclaration(node) && node.name.getText() === "data",
  ),
  state_path: firstText(
    method(clienting.source, "SignifyClient", "state"),
    (node) => ts.isTemplateExpression(node) && node.getText().includes("/agent/"),
  ),
  connect_anchor_check: firstText(
    method(clienting.source, "SignifyClient", "connect"),
    (node) => ts.isIfStatement(node) && node.getText().includes("agent.anchor"),
  ),
  connect_delegation_check: firstText(
    method(clienting.source, "SignifyClient", "connect"),
    (node) => ts.isIfStatement(node) && node.getText().includes("serder.sad.s == 0"),
  ),
  approve_delegation_url: firstText(
    method(clienting.source, "SignifyClient", "approveDelegation"),
    (node) => ts.isBinaryExpression(node) && node.getText().includes("?type=ixn"),
  ),
  fetch_error_message: firstText(
    method(clienting.source, "SignifyClient", "fetch"),
    (node) => ts.isTemplateExpression(node) && node.getText().includes("res.status"),
  ),
  random_passcode: functionText(coring.source, "randomPasscode"),
  random_nonce: functionText(coring.source, "randomNonce"),
  ready: ready.text.trim(),
  notes: {
    boot: "boot posts the controller's inception event, its signature, the derivation stem, a hardcoded `pidx: 1`, and the tier — to the *boot* URL, unauthenticated, because no agent exists yet to authenticate to",
    connect:
      "connect reads the agent state, rebuilds the controller against the returned establishment event, refuses an agent whose inception does not anchor this controller, approves the delegation when the controller is still at sequence zero, and only then builds the key manager and the authenticator",
    fetch: "the signed pipeline is the authenticated transport's; what the client adds is the controller prefix it stamps and the agent key it verifies against",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. A KERIA agent, answering exactly as the pinned test's mock does.
// ---------------------------------------------------------------------------

const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
const controllerPrefix = client.controller.pre;
// Captured before `connect`, which advances the controller to the delegation-approving `ixn`.
const inceptionRaw = client.controller.serder.raw;

/** The agent's own key, fixed so its prefix and response signatures are reproducible. */
const agentSigner = new Signer({
  raw: new Uint8Array([
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122,
    87, 143, 109, 39, 98, 153, 192, 148,
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

/** Signs a response the way a KERIA agent would. */
function signedHeaders(method, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
  ]);
  return authenticator.sign(headers, method, path.split("?")[0]);
}

let nextStatus = 200;

globalThis.fetch = async (url, init = {}) => {
  const text = String(url);
  const method = init.method ?? "GET";
  const headers = [];
  const raw = init.headers;
  if (raw instanceof Headers) {
    raw.forEach((value, key) => headers.push([key, value]));
  } else if (raw && typeof raw === "object") {
    for (const [key, value] of Object.entries(raw)) {
      headers.push([key, value]);
    }
  }
  recorded.push({
    url: text,
    method,
    headers: headers.map(([name, value]) => ({ name, value })),
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });

  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
  const status = nextStatus;
  nextStatus = 200;
  if (status !== 200) {
    return new Response("Error info", { status, statusText: "Bad Request" });
  }
  const payload = path.startsWith("/agent/") && method === "GET"
    ? { agent: agentState, controller: controllerState, ridx: 0, pidx: 0 }
    : {};
  const responseHeaders = signedHeaders(method, path);
  responseHeaders.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status: 202, headers: responseHeaders });
};

// ---------------------------------------------------------------------------
// 3. Walk the lifecycle and record every request.
// ---------------------------------------------------------------------------

/** Runs one lifecycle step and records the requests it produced. */
async function step(name, note, run) {
  const before = recorded.length;
  let error = null;
  try {
    await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  return { name, note, error, requests: recorded.slice(before) };
}

const lifecycle = [];

lifecycle.push(
  await step("boot", "the first call any client makes: the controller's inception, posted to the boot URL", () =>
    client.boot(),
  ),
);
lifecycle.push(
  await step("state", "reading the agent resource, which names both the agent and the controller", async () => {
    const state = await client.state();
    if (state.agent.i !== agentPrefix) {
      throw new Error("the agent state did not round trip");
    }
  }),
);
lifecycle.push(
  await step(
    "connect",
    "rebuilds the controller against the returned state, validates the agent's anchor, and approves the delegation because the controller is still at sequence zero",
    () => client.connect(),
  ),
);

const connected = {
  controller_prefix: client.controller.pre,
  controller_sequence_number: client.controller.serder.sad.s,
  controller_kind: client.controller.serder.sad.t,
  controller_event_raw: client.controller.serder.raw,
  agent_prefix: client.agent.pre,
  agent_anchor: client.agent.anchor,
  agent_verification_key: client.agent.verfer.qb64,
  pidx: client.pidx,
  note: "after connect the controller has advanced to the interaction event approving the delegation, and its anchor names the agent",
};

lifecycle.push(
  await step("fetch_get", "one signed request, with the clock pinned so its signature is exact", () =>
    client.fetch("/contacts", "GET", undefined),
  ),
);
lifecycle.push(
  await step("fetch_post", "a signed request carrying a JSON body", () =>
    client.fetch("/identifiers", "POST", { name: "aid1" }),
  ),
);
lifecycle.push(
  await step("save_old_passcode", "storing a superseded passcode with the agent, unauthenticated", () =>
    client.saveOldPasscode("1234"),
  ),
);
lifecycle.push(
  await step("delete_passcode", "deleting it again, also unauthenticated", () => client.deletePasscode()),
);
lifecycle.push(
  await step("fetch_error", "a non-success status, whose message the reference builds from the response", async () => {
    nextStatus = 400;
    await client.fetch("/somepath", "GET", undefined);
  }),
);

// ---------------------------------------------------------------------------
// 4. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

const clientingTest = parse("test/app/clienting.test.ts");

/** Collects every long string literal the pinned test asserts. */
function publishedStrings(source, minimumLength) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && node.text.length >= minimumLength) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const published = publishedStrings(clientingTest.source, 40);
const bootRequest = lifecycle[0].requests[0] ?? null;
if (bootRequest === null) {
  throw new Error("boot made no request");
}

const pinnedConfirmations = {
  controller_prefix: controllerPrefix,
  controller_prefix_is_published: published.includes(controllerPrefix),
  inception_raw: inceptionRaw,
  boot_body: bootRequest.body,
  boot_body_is_published: published.includes(bootRequest.body ?? ""),
  passcode_error: (() => {
    try {
      const bad = new SignifyClient(ADMIN_URL, "short", Tier.low, BOOT_URL);
      throw new Error(`the reference accepted a short passcode: ${bad.bran}`);
    } catch (error) {
      return String(error?.message ?? error);
    }
  })(),
  note: "the controller prefix and the exact boot body are looked for among the literals the pinned `clienting.test.ts` asserts; the inception event is recorded beside them",
};
if (!pinnedConfirmations.controller_prefix_is_published || !pinnedConfirmations.boot_body_is_published) {
  throw new Error("the pinned client lifecycle no longer reproduces");
}

// ---------------------------------------------------------------------------
// 5. The two random helpers, recorded by shape.
// ---------------------------------------------------------------------------

const randomShapes = (() => {
  const passcodes = Array.from({ length: 64 }, () => randomPasscode());
  const nonces = Array.from({ length: 64 }, () => randomNonce());
  const alphabet = new Set();
  for (const passcode of passcodes) {
    for (const character of passcode) {
      alphabet.add(character);
    }
  }
  return {
    passcode_length: passcodes[0].length,
    passcode_lengths_all_equal: passcodes.every((value) => value.length === passcodes[0].length),
    passcode_alphabet: [...alphabet].sort().join(""),
    passcode_distinct: new Set(passcodes).size,
    passcode_note:
      "`randomPasscode` builds a `Salter` from 16 random bytes and slices `qb64.substring(2, 23)` — dropping the two-character derivation code and taking 21 of the 22 remaining characters, which is the length the constructor requires",
    nonce_length: nonces[0].length,
    nonce_lengths_all_equal: nonces.every((value) => value.length === nonces[0].length),
    nonce_code: nonces[0].slice(0, 1),
    nonce_codes_all_equal: nonces.every((value) => value.slice(0, 1) === nonces[0].slice(0, 1)),
    nonce_distinct: new Set(nonces).size,
    nonce_note: "`randomNonce` is 32 random bytes under the Ed25519 seed code, qualified",
    samples: 64,
  };
})();

// ---------------------------------------------------------------------------
// 6. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  boot_hardcodes_pidx_one: {
    expression: declarations.boot_body,
    recorded_pidx: JSON.parse(bootRequest.body ?? "{}").pidx,
    client_pidx: 0,
    note: "the client's own `pidx` is zero at boot, but the body hardcodes `pidx: 1`; the two are never reconciled and nothing reads the field back",
    rust_decision: "reproduced verbatim, because the value is what a KERIA agent receives; it is a constant here rather than a field, so the two cannot disagree",
  },
  approve_delegation_is_unauthenticated: {
    url: declarations.approve_delegation_url,
    request: lifecycle[2].requests.find((request) => request.method === "PUT") ?? null,
    note: "the PUT that anchors the agent's delegation carries no HTTP signature at all — it bypasses `fetch` and calls the global directly, which the `http-transport` fixture also recorded",
    rust_decision: "reproduced: the call is made on the unsigned transport, and the API says so. Changing it would produce a request KERIA does not expect.",
  },
  passcode_save_and_delete_are_unauthenticated: {
    requests: [
      lifecycle[5].requests[0] ?? null,
      lifecycle[6].requests[0] ?? null,
    ],
    note: "`saveOldPasscode` and `deletePasscode` also bypass `fetch`, so a passcode is written to the agent over an unsigned request",
    rust_decision: "reproduced, and named: both methods are documented as unauthenticated so a caller cannot mistake them for signed calls.",
  },
  state_reports_404_as_a_message: {
    expression: firstText(
      method(clienting.source, "SignifyClient", "state"),
      (node) => ts.isIfStatement(node) && node.getText().includes("404"),
    ),
    note: "a missing agent is reported as a thrown string naming the controller; every other status falls through and is parsed as if it were the state",
    rust_decision: "typed: a 404 is `ClientError::AgentNotFound` and any other non-success status is `ClientError::Status`, so a 500 is never parsed as state.",
  },
  connect_assigns_ridx_without_rederiving: {
    expression: firstText(
      method(clienting.source, "SignifyClient", "connect"),
      (node) => ts.isBinaryExpression(node) && node.getText().includes("controller.ridx ="),
    ),
    note: "connect assigns `controller.ridx` after construction without re-deriving any key, so the field and the keys it names can disagree",
    rust_decision: "unrepresentable: the controller fixes the rotation index at construction, so the controller is rebuilt with the returned index rather than mutated after the fact.",
  },
  ready_is_libsodium_initialization: {
    source: declarations.ready,
    scan: scan("ready.ts"),
    note: "`src/ready.ts` is four lines that await libsodium's WebAssembly initialization; there is nothing protocol-level in it. The scan counts where the module is imported from, which is the export surface alone",
    rust_decision: "`N/A`: the Rust cryptographic stack needs no asynchronous initialization, so there is nothing to port. Recorded against the file's own text.",
  },
  fetch_requires_connect_at_run_time: {
    expression: firstText(
      method(clienting.source, "SignifyClient", "fetch"),
      (node) => ts.isThrowStatement(node) && node.getText().includes("connect first"),
    ),
    note: "`fetch` throws `client need to call connect first` when the authenticator is still null, which is a run-time check on a state the type system could have carried",
    rust_decision: "unrepresentable: connecting consumes the unconnected client and returns a connected one, so there is no `fetch` to call before connecting.",
  },
};

// ---------------------------------------------------------------------------
// 7. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: ["src/keri/app/clienting.ts", "src/keri/app/coring.ts", "src/ready.ts", "test/app/clienting.test.ts"],
  provenance: {
    passcode: BRAN,
    passcode_note: "PUBLIC TEST MATERIAL: the passcode the pinned `clienting.test.ts` publishes; it has never protected anything",
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    agent_prefix: agentPrefix,
    agent_verification_key: agentSigner.verfer.qb64,
    agent_seed_note: "PUBLIC TEST MATERIAL: the agent's seed is the fixed array in this generator, as the `http-auth` fixture used",
    fixed_clock_ms: FIXED_MS,
    fixed_clock_iso: new Date().toISOString(),
    note: "the clock is pinned as the `http-auth` fixture pinned it, so the signed requests reproduce byte for byte including their signatures; the agent's key is fixed so its response signatures do too",
  },
  declarations,
  lifecycle,
  connected,
  pinned_confirmations: pinnedConfirmations,
  random_shapes: randomShapes,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-lifecycle/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-lifecycle fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
