// Records the pinned signify-ts checkout's agent-configuration endpoint.
//
// Roadmap 6.8 ports `Config.get` from `src/keri/app/coring.ts`. It is the smallest capability in
// the file and the last one that file owes before Roadmap 7.1 and 7.2: one constant path, one
// method, no body, and a response of a single optional field.
//
// `Config` takes a whole `SignifyClient`, as `KeyEvents` and `KeyStates` do, so this generator
// drives the reference the way Roadmap 6.7's did: `globalThis.fetch` is replaced with a recorder
// that answers and signs as a KERIA agent would, and the real client is walked through boot,
// connect, and the call itself.
//
// Because the path carries no dynamic value at all, the interesting evidence here is not the
// request — it is the *response*: what `AgentConfig` is declared to be, and what the reference
// does with an answer that does not match.
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

const configGet = method(coring.source, "Config", "get");

const declarations = {
  config_path: firstText(configGet, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  config_method: firstText(configGet, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  config_fetch: firstText(configGet, (node) => ts.isCallExpression(node) && node.getText().startsWith("this.client.fetch(")),
  config_return: firstText(configGet, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  config_members: classMembers(coring.source, "Config"),
  agent_config_schema: schemaType("AgentConfig"),
  agent_config_uses: scan("AgentConfig"),
  config_accessor_uses: scan(".config()"),
  notes: {
    path: "the path is a template literal with nothing interpolated into it, so this is the only endpoint in the port whose address carries no caller input at all",
    body: "the reference passes `null` as the request data and `SignifyClient.fetch` sends `null` for a GET regardless, so no body is written either way",
    response:
      "`AgentConfig` declares exactly one optional field, `iurls`, and the reference returns `res.json()` with no validation — so any JSON at all is accepted and typed as an `AgentConfig` at compile time only",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. A KERIA agent, answering and signing as Roadmap 6.4's fixture did.
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
  recorded.push({
    url: text,
    path: text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length),
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });

  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
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

const config = client.config();

const calls = [];

/** Runs one call, recording the request it produced and what it returned. */
async function drive(name, note, payload) {
  nextPayload = payload;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    result = await config.get();
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

await drive("config_with_introductions", "the ordinary answer: a list of introduction OOBIs", {
  iurls: [
    "http://127.0.0.1:5642/oobi/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha/controller?name=Wan&tag=witness",
    "http://127.0.0.1:5643/oobi/BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM/controller?name=Wes&tag=witness",
  ],
});

await drive("config_empty_list", "an agent configured with no introductions at all", { iurls: [] });

await drive(
  "config_absent_field",
  "an answer omitting the field entirely, which the schema permits and which is not the same as an empty list",
  {},
);

await drive(
  "config_unknown_fields",
  "an answer carrying fields the schema does not declare, which the reference keeps and this port ignores",
  { iurls: [], curls: ["http://127.0.0.1:3902/oobi"], unknown: 7 },
);

await drive(
  "config_wrong_shape",
  "an answer whose `iurls` is not a list of strings — the reference types this `AgentConfig` at compile time and returns it unchecked",
  { iurls: "not-a-list" },
);

// ---------------------------------------------------------------------------
// 3. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

const coringTest = parse("test/app/coring.test.ts");

function publishedStrings(source, predicate) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && predicate(node.text)) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const publishedPaths = [...new Set(publishedStrings(coringTest.source, (text) => text === "/config"))];
const drivenPaths = [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))];

const pinnedConfirmations = {
  published_paths: publishedPaths,
  driven_paths: drivenPaths,
  every_pinned_path_is_driven: publishedPaths.length === 1 && drivenPaths.length === 1 && drivenPaths[0] === "/config",
  note: "the one path `coring.test.ts` asserts is produced here by the reference's own class, and every one of the five answers produces the same request — the address carries no caller input at all",
};
if (!pinnedConfirmations.every_pinned_path_is_driven) {
  throw new Error("the pinned config path no longer reproduces");
}

// ---------------------------------------------------------------------------
// 4. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  the_answer_is_never_validated: {
    declaration: declarations.config_return,
    wrong_shape: calls.find((call) => call.name === "config_wrong_shape")?.result ?? null,
    note: "`get` returns `res.json()` cast to `AgentConfig`, so an answer whose `iurls` is a string — or is not an object at all — is handed to the caller as though it were configuration. The type exists only at compile time.",
    rust_decision:
      "decoded: an answer that is not an `AgentConfig` is `ClientError::Api` rather than a value a caller will misread. The wrong-shaped answer recorded here is proven refused.",
  },
  unknown_fields_are_kept: {
    answer: calls.find((call) => call.name === "config_unknown_fields")?.answer ?? null,
    result: calls.find((call) => call.name === "config_unknown_fields")?.result ?? null,
    note: "`res.json()` returns whatever the agent sent, so undeclared fields survive into the value a caller holds",
    rust_decision:
      "ignored, which is Roadmap 4.1's rule for a schema without an index signature (ADR `0012`): `AgentConfig` declares one field and captures nothing else. A caller who needs an undeclared field is reading a schema this port does not have.",
  },
  an_absent_list_is_not_an_empty_one: {
    absent: calls.find((call) => call.name === "config_absent_field")?.result ?? null,
    empty: calls.find((call) => call.name === "config_empty_list")?.result ?? null,
    schema: declarations.agent_config_schema,
    note: "the schema marks `iurls` optional, so an agent may omit it; the reference hands back `undefined` in one case and `[]` in the other, and nothing in its own code tells them apart",
    rust_decision:
      "reproduced as `Option<Vec<String>>`, so the two stay distinguishable — an agent that has not been configured is not an agent configured with nothing",
  },
  the_path_carries_no_input: {
    declaration: declarations.config_path,
    scan: declarations.config_accessor_uses,
    note: "the path is a template literal with nothing interpolated, which makes this the only endpoint in the port with no dynamic component — and so the only one where the reference's unencoded interpolation cannot bite",
    rust_decision: "reproduced exactly; there is nothing to encode and nothing to validate",
  },
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-24",
  sources: ["src/keri/app/coring.ts", "src/types/keria-api-schema.ts", "test/app/coring.test.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    note: "`Config` takes a whole `SignifyClient`, as `KeyEvents` and `KeyStates` do, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: the passcode is the one `coring.test.ts` publishes and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-config/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-config fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
