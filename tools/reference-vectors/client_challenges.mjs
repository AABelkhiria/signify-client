// Records the pinned signify-ts checkout's challenges endpoint.
//
// Roadmap 7.4 ports `Challenges.{generate,verify,responded}` from `src/keri/app/contacting.ts`.
//
// **`respond` is not here, and its absence is the first thing this fixture records.** It is a
// five-line wrapper — read the habitat, then call
// `exchanges.send(name, 'challenge', hab, '/challenge/response', {words}, {}, [recipient])` — so it
// needs `Exchanges.{createExchangeMessage,send,sendFromEvents}` whole, which `PORTING.md` §5.10
// assigns to Roadmap 7.7. `deferred_capability` below reads that call out of the reference's own
// syntax tree and asserts the three methods it reaches, so the deferral is a machine-checked fact
// rather than a claim.
//
// The pinned `contacting.test.ts` `Challenges` case covers all four methods; the three in scope
// here are driven through the reference's own class, exactly as Roadmap 7.3's fixture drives
// `Contacts`.
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

/** The passcode and URLs the pinned `contacting.test.ts` publishes. */
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

const contacting = parse("src/keri/app/contacting.ts");
const exchanging = parse("src/keri/app/exchanging.ts");
const schema = parse("src/types/keria-api-schema.ts");
const contactingTest = parse("test/app/contacting.test.ts");
const challengeIntegration = parse("test-integration/challenge.test.ts");

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

function text(node) {
  return node === null || node === undefined ? null : node.getText().replace(/\s+/g, " ");
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

function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

function parameters(node) {
  return node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " "));
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

/** The whole text of one schema entry. */
function schemaEntry(typeName) {
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

function scan(needle, { normalizeWhitespace = false } = {}) {
  const hits = [];
  let total = 0;
  for (const file of PINNED_FILES) {
    let body = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    if (normalizeWhitespace) {
      body = body.replace(/\s+/g, "");
    }
    const count = body.split(needle).length - 1;
    if (count > 0) {
      hits.push({ file, count });
      total += count;
    }
  }
  return { needle, total, files: hits, scanned_files: PINNED_FILES.length, normalized: normalizeWhitespace };
}

const generateMethod = method(contacting.source, "Challenges", "generate");
const respondMethod = method(contacting.source, "Challenges", "respond");
const verifyMethod = method(contacting.source, "Challenges", "verify");
const respondedMethod = method(contacting.source, "Challenges", "responded");

const declarations = {
  generate_parameters: parameters(generateMethod),
  generate_path: localDeclaration(generateMethod, "path"),
  generate_method: localDeclaration(generateMethod, "method"),
  verify_parameters: parameters(verifyMethod),
  verify_path: localDeclaration(verifyMethod, "path"),
  verify_method: localDeclaration(verifyMethod, "method"),
  verify_body: localDeclaration(verifyMethod, "data"),
  responded_parameters: parameters(respondedMethod),
  responded_path: localDeclaration(respondedMethod, "path"),
  responded_method: localDeclaration(respondedMethod, "method"),
  responded_body: localDeclaration(respondedMethod, "data"),
  responded_return: firstText(respondedMethod, (node) => ts.isReturnStatement(node)),
  verify_return: firstText(verifyMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  class_members: classMembers(contacting.source, "Challenges"),
  challenge_type: schemaEntry("Challenge"),
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

const CHALLENGES_MEMBERS = ["client", "<constructor>", "generate", "respond", "verify", "responded"];
if (JSON.stringify(declarations.class_members) !== JSON.stringify(CHALLENGES_MEMBERS)) {
  throw new Error(`the Challenges class no longer declares ${CHALLENGES_MEMBERS.join(", ")}`);
}

// ---------------------------------------------------------------------------
// 1b. Why `respond` is not in this item, read from the reference itself.
// ---------------------------------------------------------------------------

const respondBody = text(respondMethod.body);
const exchangesSend = method(exchanging.source, "Exchanges", "send");
const exchangesCreate = method(exchanging.source, "Exchanges", "createExchangeMessage");
const exchangesSendFromEvents = method(exchanging.source, "Exchanges", "sendFromEvents");

const deferredCapability = {
  capability: "Challenges.respond",
  deferred_to: "Roadmap 7.7 — Exchange endpoint retrieval and submission",
  body: respondBody,
  reaches: ["Exchanges.send", "Exchanges.createExchangeMessage", "Exchanges.sendFromEvents"],
  send_body: text(exchangesSend?.body ?? null),
  create_body: text(exchangesCreate?.body ?? null),
  send_from_events_path: localDeclaration(exchangesSendFromEvents, "path"),
  send_from_events_body: localDeclaration(exchangesSendFromEvents, "data"),
  topic: "challenge",
  route: "/challenge/response",
  note: "`respond` reads the habitat and calls `exchanges.send(...)`; `send` calls `createExchangeMessage`, which signs with the identifier's keeper, and then `sendFromEvents`, which POSTs `{tpc, exn, sigs, atc, rec}` to `/identifiers/{name}/exchanges`. All three are `Exchanges` methods, which `PORTING.md` §5.10 assigns to Roadmap 7.7 and which Roadmap 7.4 does not list as a prerequisite.",
  rust_decision:
    "moved to Roadmap 7.7 in §5.13 rather than duplicated here. Reproducing `sendFromEvents` would mean implementing the next roadmap item alongside this one: the generic exchange submission is 7.7's whole write half, not scaffolding for this single caller.",
};

for (const [name, value] of Object.entries(deferredCapability)) {
  if (value === null || value === undefined) {
    throw new Error(`the deferral record's ${name} is no longer where this generator expects it`);
  }
}
// The claim is that `respond` reaches nothing but `Exchanges`; check it rather than assert it.
if (!respondBody.includes("exchanges.send(")) {
  throw new Error("`respond` no longer delegates to `Exchanges.send`");
}
for (const expected of ["'challenge'", "'/challenge/response'", "words: words", "[recipient]"]) {
  if (!respondBody.includes(expected)) {
    throw new Error(`\`respond\` no longer passes ${expected}`);
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
  const full = String(url);
  const httpMethod = init.method ?? "GET";
  const path = full.startsWith(ADMIN_URL) ? full.slice(ADMIN_URL.length) : full.slice(BOOT_URL.length);
  recorded.push({
    path,
    method: httpMethod,
    body: init.body === undefined ? undefined : init.body === null ? null : String(init.body),
    body_is_undefined: init.body === undefined,
  });

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

const challenges = client.challenges();

// ---------------------------------------------------------------------------
// 3. Drive every call in scope.
// ---------------------------------------------------------------------------

/** The identifier the pinned unit test challenges. */
const SOURCE = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
/** The exchange SAID the pinned unit test marks as accepted. */
const SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/** The twelve words the pinned unit test uses — a 128-bit BIP39 mnemonic. */
const WORDS = [
  "shell",
  "gloom",
  "mimic",
  "cereal",
  "stool",
  "furnace",
  "nominee",
  "nation",
  "sauce",
  "sausage",
  "rather",
  "venue",
];

/** Twenty-four words, which is what a 256-bit strength produces. */
const BIG_WORDS = [...WORDS, ...WORDS];

const calls = [];

async function drive(name, note, payload, run) {
  nextPayload = payload;
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    const returned = await run();
    // `responded` returns the platform `Response` itself, which is not JSON-serializable; its
    // status is what a caller could actually read.
    result =
      returned instanceof Response
        ? { kind: "Response", status: returned.status, body_already_read: returned.bodyUsed }
        : returned === undefined
          ? null
          : returned;
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const request = recorded[before] ?? null;
  calls.push({
    name,
    note,
    request:
      request === null
        ? null
        : {
            path: request.path,
            method: request.method,
            body: request.body === undefined ? null : request.body,
            body_is_undefined: request.body_is_undefined,
          },
    result,
    error,
  });
  nextPayload = {};
}

await drive(
  "generate_128",
  "the pinned unit test's own call, and the strength both integration suites use",
  { words: WORDS },
  () => challenges.generate(128),
);

await drive(
  "generate_256",
  "`challenge.test.ts` also generates at 256, which produces twenty-four words",
  { words: BIG_WORDS },
  () => challenges.generate(256),
);

await drive(
  "generate_default",
  "no argument at all, which writes the `= 128` default into the query — an omitted strength is still an observable request",
  { words: WORDS },
  () => challenges.generate(),
);

await drive(
  "generate_fractional",
  "a strength that is not a whole number: `strength.toString()` is interpolated, so `1.5` reaches the wire and no BIP39 generator accepts it",
  {},
  () => challenges.generate(1.5),
);

await drive(
  "generate_not_a_number",
  "`NaN` stringifies to `NaN`, which the reference sends as the strength",
  {},
  () => challenges.generate(Number.NaN),
);

await drive(
  "generate_negative",
  "a negative strength, sent unchallenged",
  {},
  () => challenges.generate(-1),
);

await drive(
  "verify",
  "the pinned unit test's own verification",
  { name: `challenge.${SOURCE}`, metadata: { words: WORDS }, done: false },
  () => challenges.verify(SOURCE, WORDS),
);

await drive(
  "verify_empty_words",
  "an empty word list, which asks the agent to verify that nothing was signed",
  { name: `challenge.${SOURCE}`, metadata: { words: [] }, done: false },
  () => challenges.verify(SOURCE, []),
);

await drive(
  "verify_source_needing_encoding",
  "a source carrying path and query delimiters, which the reference interpolates raw",
  {},
  () => challenges.verify("a/b?c=d", WORDS),
);

await drive(
  "responded",
  "the pinned unit test's own acceptance",
  {},
  () => challenges.responded(SOURCE, SAID),
);

await drive(
  "responded_said_needing_encoding",
  "the SAID reaches the *body* rather than the path, so a delimiter in it changes no address — only the source does",
  {},
  () => challenges.responded(SOURCE, "E/../x?y=1"),
);

await drive(
  "verify_wrong_shape",
  "an answer that is not a challenge operation — the reference casts it and returns it",
  { unexpected: true },
  () => challenges.verify(SOURCE, WORDS),
);

await drive(
  "generate_wrong_shape",
  "an answer carrying no word list at all, cast to `Challenge` and handed to the caller",
  { unexpected: true },
  () => challenges.generate(128),
);

// ---------------------------------------------------------------------------
// 4. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const UNIT_TEST_ASSERTIONS = [
  "url + '/challenges?strength=128'",
  "url + '/challenges_verify/EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p'",
  "assert.deepEqual(lastBody.words, words)",
  "assert.equal( lastBody.said, 'EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao' )",
];
const normalizedTest = contactingTest.text.replace(/\s+/g, " ");
const unitTestAssertions = UNIT_TEST_ASSERTIONS.filter((line) => normalizedTest.includes(line.replace(/\s+/g, " ")));
if (unitTestAssertions.length !== UNIT_TEST_ASSERTIONS.length) {
  throw new Error("an assertion this fixture reproduces is no longer in the pinned unit test");
}

const INTEGRATION_LINES = [
  "await client1.challenges().generate(128)",
  "await client1.challenges().generate(256)",
  "await client1.challenges().verify(aid2.i, challenge1_small.words)",
  "await client1.challenges().responded(aid2.i, exn.sad.d)",
  "assert.strictEqual(bobContact.challenges.length, 0)",
];
const normalizedIntegration = challengeIntegration.text.replace(/\s+/g, " ");
const integrationLines = INTEGRATION_LINES.filter((line) =>
  normalizedIntegration.includes(line.replace(/\s+/g, " ")),
);
if (integrationLines.length !== INTEGRATION_LINES.length) {
  throw new Error("an integration usage this fixture records has moved");
}

const pinnedConfirmations = {
  unit_test_assertions: unitTestAssertions,
  unit_test_paths: ["/challenges?strength=128", `/challenges_verify/${SOURCE}`],
  unit_test_words: WORDS,
  unit_test_said: SAID,
  integration_usage: integrationLines,
  strengths_used: scan("challenges().generate(", { normalizeWhitespace: true }),
  call_sites: scan("challenges().", { normalizeWhitespace: true }),
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "the pinned `Challenges` case covers all four methods; the three in scope here are driven directly. It asserts the generated path, both verification paths, the word list in `verify`'s body, and the SAID in `responded`'s. The integration suites add the second strength, the operation `verify` returns, and the fact that a contact's challenge list starts empty — which is what `responded` is for.",
};

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function call(name) {
  return calls.find((entry) => entry.name === name) ?? null;
}

const quirks = {
  the_strength_is_interpolated_not_validated: {
    expression: declarations.generate_path,
    fractional: call("generate_fractional")?.request?.path ?? null,
    not_a_number: call("generate_not_a_number")?.request?.path ?? null,
    negative: call("generate_negative")?.request?.path ?? null,
    note: "`strength: number` is stringified straight into the query, so a fraction reaches the wire as `1.5`, `NaN` as `NaN`, and a negative as `-1` — none of which any BIP39 generator accepts, and all of which the agent is asked for",
    rust_decision:
      "**refused**: `ChallengeStrength` accepts only the five entropy sizes BIP39 defines, so a request that could not produce a mnemonic cannot be written. keripy's own generator is the corroboration — it hands the value to `mnemonic.Mnemonic.generate(strength=…)`, which raises outside that set — recorded as corroboration rather than as a governing reference (ADR `0009`).",
  },
  the_strength_default_is_observable: {
    parameters: declarations.generate_parameters,
    path: call("generate_default")?.request?.path ?? null,
    note: "`generate(strength = 128)` writes the default into the query, so an omitted strength is still a request that names one",
    rust_decision:
      "the strength is a required argument and `ChallengeStrength::BITS_128` names the reference's value, so what reaches the query is visible at the call site — Roadmap 7.1's `DEFAULT_ROLE` decision applied again",
  },
  the_source_is_not_encoded: {
    path: call("verify_source_needing_encoding")?.request?.path ?? null,
    expression: declarations.verify_path,
    note: "both verification paths are `/challenges_verify/${source}`, so a value carrying `/` or `?` addresses a different resource — and Roadmap 3.10 signs `@path`",
    rust_decision:
      "refused twice over: the argument is Roadmap 3.4's validated `IdentifierPrefix`, and Roadmap 5.3's builder would encode it exactly once regardless",
  },
  the_two_verification_calls_share_one_address: {
    verify: declarations.verify_path,
    responded: declarations.responded_path,
    note: "`verify` and `responded` address the identical path and differ only in method and body — `POST` asks the agent to check, `PUT` records that a caller accepted the answer",
    rust_decision:
      "reproduced, with the segment pinned as one constant so the two cannot drift apart",
  },
  responded_returns_the_raw_response: {
    declaration: declarations.responded_return,
    result: call("responded")?.result ?? null,
    note: "`responded` is the only method in the family that does not call `res.json()`: it returns the platform `Response` object itself, so a caller receives an unread body and a transport type",
    rust_decision:
      "returns `()`, which is what Roadmap 6.5's `delete` and Roadmap 7.3's do for the same reason — a non-success status is already `ClientError::Status`, and leaking a transport type across the SDK boundary is what `ARCHITECTURE.md` §4.7 exists to prevent",
  },
  an_empty_word_list_is_accepted: {
    path: call("verify_empty_words")?.request?.path ?? null,
    body: call("verify_empty_words")?.request?.body ?? null,
    note: "`verify(source, [])` sends `{\"words\":[]}`, asking the agent to confirm that an identifier signed nothing",
    rust_decision:
      "**refused**, which is what Roadmap 6.12 did for an empty recipient list on the same reasoning: it is a caller mistake rather than a request, and a verification that trivially matches is worse than one that fails",
  },
  the_answers_are_cast_rather_than_decoded: {
    declaration: declarations.verify_return,
    verify_wrong_shape: call("verify_wrong_shape")?.result ?? null,
    generate_wrong_shape: call("generate_wrong_shape")?.result ?? null,
    note: "`generate` and `verify` return `res.json()` cast to `Challenge` and `ChallengeOperation`, so an answer of any shape reaches the caller — including one carrying no words at all",
    rust_decision:
      "decoded: both recorded wrong-shaped answers are proven refused, which is the rule Roadmap 6.8, 6.10, 7.1, and 7.3 applied to their own answers",
  },
  the_said_reaches_the_body_not_the_path: {
    body: call("responded_said_needing_encoding")?.request?.body ?? null,
    expression: declarations.responded_body,
    note: "`responded`'s `said` is written into the JSON body rather than the path, so unlike the source it cannot change an address whatever it holds",
    rust_decision:
      "still typed as Roadmap 3.3's validated `Said`, because what it names is a specific exchange message and an unparseable one records an acceptance of nothing — the narrowing costs nothing the reference can usefully send",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/contacting.ts",
    "src/keri/app/exchanging.ts",
    "src/types/keria-api-schema.ts",
    "test/app/contacting.test.ts",
    "test-integration/challenge.test.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    source_prefix: SOURCE,
    exchange_said: SAID,
    words: WORDS,
    note: "`Challenges` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned. `PUBLIC TEST MATERIAL`: the passcode and the word list are the pinned tests' own and have never protected anything.",
  },
  declarations,
  deferred_capability: deferredCapability,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-challenges/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-challenges fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
