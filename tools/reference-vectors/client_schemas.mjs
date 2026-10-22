// Records the pinned signify-ts checkout's schema endpoint.
//
// This port covers `Schemas.{get,list}` from `src/keri/app/credentialing.ts`: two reads, one
// addressing a SAID and one a constant path.
//
// A scan of every pinned `.ts` file finds this family in exactly two of them —
// `test/app/clienting.test.ts`, which asserts only that `client.schemas()` is a `Schemas`, and
// `test-integration/credentials.test.ts`, which calls both methods against a live KERIA. So the
// evidence here is the reference driven directly, as the key-state, config, and registries fixtures
// do: `globalThis.fetch` is replaced with a recorder that answers and signs as a KERIA agent would,
// and the real client is walked through boot, connect, and every call.
//
// The two schema SAIDs are the vLEI ones the integration tests use, so the recorded paths are the
// ones a real deployment sees.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
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
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");
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

// ---------------------------------------------------------------------------
// 2. A KERIA agent, answering and signing as the `client-lifecycle` fixture did.
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

const getMethod = method(credentialing.source, "Schemas", "get");
const listMethod = method(credentialing.source, "Schemas", "list");

function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

/** Which pinned files name this family at all. */
function schemaFiles() {
  return PINNED_FILES.filter((file) => {
    const text = readFileSync(upstreamUrl(file), "utf8");
    return text.includes("schemas()") || text.includes("Schemas");
  });
}

const declarations = {
  get_path: localDeclaration(getMethod, "path"),
  get_method: localDeclaration(getMethod, "method"),
  list_path: localDeclaration(listMethod, "path"),
  list_method: localDeclaration(listMethod, "method"),
  get_return: firstText(getMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  class_members: classMembers(credentialing.source, "Schemas"),
  schema_type: schemaType("Schema"),
  files_naming_schemas: schemaFiles(),
  notes: {
    segment:
      "both paths use the **singular** `/schema`, not `/schemas`, while the accessor and the class are plural — an easy thing to get wrong and the reason this port pins the segment as a constant",
    encoding: "`get` interpolates the SAID straight into the path with no encoding, as every other family in this file does",
    list: "`list` addresses a constant path, so it is the second endpoint in the port whose address carries no caller input",
    response: "both return `res.json()` with no validation, typed as `Schema` at compile time only",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

await client.boot();
await client.connect();

const schemas = client.schemas();

/** The two vLEI schema SAIDs the integration tests use. */
const QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";

/** One schema document of the shape KERIA answers with, in the schema's own field order. */
function schemaDocument(said, title, credentialType) {
  return {
    $id: said,
    $schema: "http://json-schema.org/draft-07/schema#",
    title,
    description: `${title} credential`,
    type: "object",
    credentialType,
    version: "1.0.0",
    properties: {
      v: { description: "Version", type: "string" },
      d: { description: "Credential SAID", type: "string" },
      i: { description: "Issuer", type: "string" },
      a: {
        oneOf: [
          { description: "Attributes block SAID", type: "string" },
          {
            $id: "ELGgI0fkloqKWREXgqUfgS0bJybP1LChxCO3sqPSFHCj",
            description: "Attributes block",
            type: "object",
            properties: { LEI: { description: "Legal Entity Identifier", type: "string" } },
            additionalProperties: false,
            required: ["i", "dt", "LEI"],
          },
        ],
      },
    },
    additionalProperties: false,
    required: ["i", "ri", "s", "d"],
  };
}

const QVI_SCHEMA = schemaDocument(QVI_SCHEMA_SAID, "Qualified vLEI Issuer", "QualifiedvLEIIssuervLEICredential");
const LE_SCHEMA = schemaDocument(LE_SCHEMA_SAID, "Legal Entity", "LegalEntityvLEICredential");

const calls = [];

/** Runs one call and records the request it produced with whatever came back. */
async function drive(name, note, payload, run) {
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
    request: request === null ? null : { path: request.path, method: request.method, body: request.body },
    result,
    error,
  });
  nextPayload = {};
}

await drive("get_qvi", "the QVI schema the integration tests read, by its own SAID", QVI_SCHEMA, () =>
  schemas.get(QVI_SCHEMA_SAID),
);

await drive("get_legal_entity", "the legal-entity schema, the second one those tests read", LE_SCHEMA, () =>
  schemas.get(LE_SCHEMA_SAID),
);

await drive(
  "get_said_needing_encoding",
  "a SAID carrying path and query delimiters, which the reference interpolates raw",
  {},
  () => schemas.get("E/../schema?x=1#y"),
);

await drive("list", "the listing the integration tests read, whose address carries no input", [QVI_SCHEMA, LE_SCHEMA], () =>
  schemas.list(),
);

await drive("list_empty", "an agent holding no schemas at all", [], () => schemas.list());

await drive(
  "get_wrong_shape",
  "an answer missing fields the schema declares required — the reference types it `Schema` and returns it unchecked",
  { $id: QVI_SCHEMA_SAID },
  () => schemas.get(QVI_SCHEMA_SAID),
);

// ---------------------------------------------------------------------------
// 4. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const clientingTest = parse("test/app/clienting.test.ts");
const credentialsIntegration = parse("test-integration/credentials.test.ts");

const pinnedConfirmations = {
  files_naming_schemas: declarations.files_naming_schemas,
  assertions: {
    "test/app/clienting.test.ts": [
      "assert.equal(client.schemas() instanceof Schemas, true)",
    ].filter((line) => clientingTest.text.includes(line.slice(line.indexOf("(") + 1, line.lastIndexOf(",")))),
    "test-integration/credentials.test.ts": [
      ".get(QVI_SCHEMA_SAID)",
      ".get(LE_SCHEMA_SAID)",
      "schemas().list()",
      "issuerQviSchema.$id, QVI_SCHEMA_SAID",
      "issuerLeSchema.$id, LE_SCHEMA_SAID",
      "holderSchemas.length, 2",
    ].filter((line) => credentialsIntegration.text.includes(line)),
  },
  qvi_schema_said: QVI_SCHEMA_SAID,
  le_schema_said: LE_SCHEMA_SAID,
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "no pinned unit test exercises either call: `clienting.test.ts` asserts the accessor's type and nothing else. The only real usage is `test-integration/credentials.test.ts`, which reads both vLEI schemas by SAID and asserts each answer's `$id`, then lists and asserts a count — so what upstream actually checks is that a schema comes back under the SAID it was asked for. Both SAIDs are recorded here and both are valid qualified digests, which is what lets this port take a `Said` rather than a string.",
};
if (pinnedConfirmations.assertions["test/app/clienting.test.ts"].length !== 1) {
  throw new Error("the accessor assertion this fixture records is no longer where it was");
}
if (pinnedConfirmations.assertions["test-integration/credentials.test.ts"].length !== 6) {
  throw new Error("the integration usage this fixture records has moved");
}
const EXPECTED_FILES = [
  "src/keri/app/clienting.ts",
  "src/keri/app/credentialing.ts",
  "test-integration/credentials.test.ts",
  "test/app/clienting.test.ts",
];
if (JSON.stringify(pinnedConfirmations.files_naming_schemas) !== JSON.stringify(EXPECTED_FILES)) {
  throw new Error("the set of files naming this family changed; re-read them before trusting the evidence");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  the_said_is_not_encoded: {
    path: calls.find((call) => call.name === "get_said_needing_encoding")?.request?.path ?? null,
    expression: declarations.get_path,
    note: "`get` interpolates its SAID straight into the path, so a value carrying `/`, `?`, or `#` addresses a different resource — and request authentication signs `@path`, so it changes what a signature commits to",
    rust_decision:
      "refused twice over: the argument is a validated `Said` rather than a string, and the request builder would encode it exactly once even if it were not. A qualified digest's alphabet is URL-safe Base64, so every real SAID reaches the path byte-identical.",
  },
  the_segment_is_singular: {
    get: declarations.get_path,
    list: declarations.list_path,
    note: "both paths address `/schema`, singular, while the class, the accessor, and the module are all plural — the one place in this file where the resource name and its accessor disagree",
    rust_decision: "reproduced exactly, and pinned as a named constant so the plural module name cannot drift into the path",
  },
  the_answer_is_never_validated: {
    declaration: declarations.get_return,
    wrong_shape: calls.find((call) => call.name === "get_wrong_shape")?.result ?? null,
    error: calls.find((call) => call.name === "get_wrong_shape")?.error ?? null,
    note: "`get` returns `res.json()` cast to `Schema`, so an answer carrying only `$id` — missing all nine other required fields — is handed to the caller as a schema. The type exists at compile time only.",
    rust_decision:
      "decoded: an answer that is not a `Schema` is `ClientError::Api`. The wrong-shaped answer recorded here is proven refused.",
  },
  a_listing_carries_no_input: {
    declaration: declarations.list_path,
    empty: calls.find((call) => call.name === "list_empty")?.result ?? null,
    note: "`list` addresses a constant path with no filter, range, or paging of any kind, so an agent holding many schemas returns all of them in one body",
    rust_decision:
      "reproduced; the response is bounded only by the transport's limit, which is recorded as a limitation rather than a filter this port invents",
  },
  nothing_checks_the_said_came_back: {
    scan: scan("$id, QVI_SCHEMA_SAID"),
    note: "the reference's own integration test asserts `schema.$id` equals the SAID it asked for, which is the check that matters — but `Schemas.get` itself does not make it, so a misrouted or substituted answer is returned unchallenged",
    rust_decision:
      "reproduced rather than fixed: `get` returns what the agent sent and a caller compares. Inventing the check would diverge from the reference for a guarantee only a digest verification can actually give, which is SAID verification's job and not an endpoint's.",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-24",
  sources: [
    "src/keri/app/credentialing.ts",
    "src/types/keria-api-schema.ts",
    "test/app/clienting.test.ts",
    "test-integration/credentials.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    qvi_schema_said: QVI_SCHEMA_SAID,
    le_schema_said: LE_SCHEMA_SAID,
    note: "`Schemas` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned. The two schema SAIDs are the vLEI ones the integration tests use, so the recorded paths are the ones a real deployment sees. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-schemas/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-schemas fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
