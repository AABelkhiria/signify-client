// Records the pinned signify-ts checkout's exchange endpoint family.
//
// This fixture ports the `Exchanges` class of `src/keri/app/exchanging.ts` —
// `createExchangeMessage`, `send`, `sendFromEvents`, and `get` — plus `Challenges.respond` of
// `src/keri/app/contacting.ts`, which `client-challenges` moved here on evidence because it is a
// five-line wrapper over `send` and nothing else. Delivering these closes `contacting.ts`;
// `exchanging.ts` stays open for the route table, resource variants, and type guards that
// `client-exchange-routes` covers.
//
// The pure `exchange(...)` function this class wraps is already byte-exact; what is new here is
// the signing, the request body, and the two addresses.
//
// `Exchanges` takes a whole `SignifyClient`, so this generator drives the real client the way
// `client_credentials.mjs` does: `globalThis.fetch` is replaced with a recorder that answers and
// signs as a KERIA agent would, and the identifier is the reference's own `mockGetAID`, read out of
// `test/app/test-utils.ts` by its own compiler — which is what makes `exn.i` here the very literal
// the pinned `contacting.test.ts` asserts.
//
// The **clock is pinned**, because `send` passes no datetime and `exchange(...)` then reads the
// system clock; without pinning it, nothing this class sends is reproducible at all.
//
// Three things make the evidence here worth recording rather than assuming.
//
// `send` contains a **loop that returns on its first iteration**. It builds one message addressed
// to `recipients[0]` and posts it to every recipient, so with two recipients the second is handed a
// message addressed to the first. The reference's own `multisig.test.ts` calls it that way
// eighteen times. The generator drives it and records both the `rp` it produced and the `rec` it
// sent.
//
// `send` takes the alias and the sending identifier as **two independent arguments**, so the
// resource a message is posted under and the identifier whose keeper signs it need not agree. The
// generator drives one call where they do not.
//
// And `sendFromEvents` declares `Promise<Exn>` where the sibling `Ipex.submit*` methods declare
// `Promise<ExchangeOperation>` for the same shape of POST. Both are unchecked casts. The generator
// records the same submission answered both ways.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "./node_modules/signify-ts/dist/keri/core/cipher.js";
import { Decrypter } from "./node_modules/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Controller } from "./node_modules/signify-ts/dist/keri/app/controller.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { Salter, Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { Serder } from "./node_modules/signify-ts/dist/keri/core/serder.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { b, Ilks } from "./node_modules/signify-ts/dist/keri/core/core.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The passcode and URLs the pinned `exchanging.test.ts` and `contacting.test.ts` publish. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** The recipient the pinned `contacting.test.ts` responds to. */
const PINNED_RECIPIENT = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

/** The SAID the pinned `exchanging.test.ts` reads an exchange by. */
const PINNED_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";

/** A second recipient, so the dead loop in `send` can be observed. */
const SECOND_RECIPIENT = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// 0. Pin the clock. `send` reads it for the message's own `dt`.
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

const exchanging = parse("src/keri/app/exchanging.ts");
const contacting = parse("src/keri/app/contacting.ts");
const credentialing = parse("src/keri/app/credentialing.ts");
const schema = parse("src/types/keria-api-schema.ts");
const testUtils = parse("test/app/test-utils.ts");

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

function wholeText(node) {
  return node === null ? null : node.getText().replace(/\s+/g, " ");
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

/** The declared return type of one method. */
function returnType(node) {
  return node?.type === undefined ? null : node.type.getText().replace(/\s+/g, " ");
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

/** Every exported `const` whose initializer is a string literal, as a name/value map. */
function exportedStringConstants(source) {
  const found = {};
  const visit = (node) => {
    if (ts.isVariableStatement(node)) {
      const exported = (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
      if (exported) {
        for (const declaration of node.declarationList.declarations) {
          if (declaration.initializer !== undefined && ts.isStringLiteral(declaration.initializer)) {
            found[declaration.name.getText()] = declaration.initializer.text;
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
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

/** One object literal declared as a `const`, parsed as JSON. */
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

/** One array of string literals declared as a `const`, read from source. */
function stringArrayLiteral(source, name) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      node.name.getText() === name &&
      node.initializer !== undefined &&
      ts.isArrayLiteralExpression(node.initializer) &&
      node.initializer.elements.every((element) => ts.isStringLiteral(element))
    ) {
      found = node.initializer.elements.map((element) => element.text);
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

const contactingTest = parse("test/app/contacting.test.ts");

/** The word list the pinned `contacting.test.ts` responds with, read from its own source. */
const PINNED_WORDS = stringArrayLiteral(contactingTest.source, "words");
if (PINNED_WORDS === null || PINNED_WORDS.length !== 12) {
  throw new Error(`the pinned challenge word list is no longer twelve literals: ${PINNED_WORDS}`);
}

const createExchangeMessage = method(exchanging.source, "Exchanges", "createExchangeMessage");
const sendMethod = method(exchanging.source, "Exchanges", "send");
const sendFromEvents = method(exchanging.source, "Exchanges", "sendFromEvents");
const getMethod = method(exchanging.source, "Exchanges", "get");
const respondMethod = method(contacting.source, "Challenges", "respond");
const submitGrant = method(credentialing.source, "Ipex", "submitGrant");

const declarations = {
  create_signature: createExchangeMessage?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null,
  create_keeper: firstText(createExchangeMessage, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "keeper"),
  create_exchange_call: firstText(createExchangeMessage, (node) => ts.isCallExpression(node) && node.expression.getText() === "exchange"),
  create_sign: firstText(createExchangeMessage, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "sigs"),
  create_return: firstText(createExchangeMessage, (node) => ts.isReturnStatement(node)),
  send_signature: sendMethod?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null,
  send_body: wholeText(sendMethod?.body ?? null),
  send_loop: firstText(sendMethod, (node) => ts.isForOfStatement(node)),
  send_throw: firstText(sendMethod, (node) => ts.isThrowStatement(node)),
  send_return_type: returnType(sendMethod),
  send_from_events_signature: sendFromEvents?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null,
  send_from_events_path: firstText(sendFromEvents, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  send_from_events_data: firstText(sendFromEvents, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "data"),
  send_from_events_method: firstText(sendFromEvents, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "method"),
  send_from_events_return_type: returnType(sendFromEvents),
  get_path: firstText(getMethod, (node) => ts.isVariableDeclaration(node) && node.name.getText() === "path"),
  get_signature: getMethod?.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")) ?? null,
  get_return_type: returnType(getMethod),
  get_return: firstText(getMethod, (node) => ts.isAwaitExpression(node) && node.getText().includes("res.json()")),
  exchanges_members: classMembers(exchanging.source, "Exchanges"),
  respond_body: wholeText(respondMethod?.body ?? null),
  respond_return_type: returnType(respondMethod),
  submit_grant_return_type: returnType(submitGrant),
  route_constants: exportedStringConstants(exchanging.source),
  exn_schema: schemaType("Exn"),
  exchange_resource_schema: schemaType("ExchangeResource"),
  exchanges_accessor_uses: scan(".exchanges()"),
  send_uses: scan(".send("),
  send_from_events_uses: scan("sendFromEvents"),
  pinned_words: PINNED_WORDS,
  notes: {
    dead_loop:
      "`send` iterates `recipients` and `return`s inside the loop, so only the first iteration ever runs: the message is addressed to `recipients[0]` and delivered to all of them. The `throw` after the loop is reachable only for an empty list.",
    clock:
      "`send` calls `createExchangeMessage` with five arguments, so `datetime` and `dig` are `undefined` and `exchange(...)` falls back to `nowUTC()` — the message's `dt`, and therefore its SAID and every signature over it, depend on when it was built",
    two_identifiers:
      "`send(name, topic, sender, ...)` takes the alias that addresses the resource and the identifier whose keeper signs as two independent arguments; nothing compares them",
    return_types:
      "`sendFromEvents` declares `Promise<Exn>` while the sibling `Ipex.submit*` methods declare `Promise<ExchangeOperation>` for the same shape of POST to the same agent. Both are `res.json()` casts, so at most one can be right and neither is checked.",
    routes:
      "the thirteen exported route constants are `client-exchange-routes`'s, not this fixture's: they are recorded here to pin the split, and because `send`'s route argument is the plain `string` they are values of",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

if (declarations.exchanges_members.join(",") !== "client,<constructor>,createExchangeMessage,send,sendFromEvents,get") {
  throw new Error(`the Exchanges class no longer has exactly four methods: ${declarations.exchanges_members}`);
}
if (declarations.send_return_type === declarations.send_from_events_return_type &&
    declarations.send_from_events_return_type === declarations.submit_grant_return_type) {
  throw new Error("the submission return types now agree; the recorded divergence is stale");
}

// ---------------------------------------------------------------------------
// 2. The reference's own mock identifier, read from its test helper.
// ---------------------------------------------------------------------------

const MOCK_GET_AID = objectLiteral(testUtils.source, "mockGetAID");
if (MOCK_GET_AID === null) {
  throw new Error("mockGetAID is no longer where this generator expects it");
}

// `mockGetAID` carries no `icp_dt`, which its own generated schema declares required, so the Rust
// side would refuse the record. `client-credentials` recorded the same shortfall and added the same
// field; nothing derived reads it, so no recorded byte changes.
const ADDED_INCEPTION_STAMP = "2023-08-21T22:30:46.473545+00:00";
const HAB = { ...MOCK_GET_AID, icp_dt: MOCK_GET_AID.icp_dt ?? ADDED_INCEPTION_STAMP };

/** Opens a sealed salty salt through the controller's own decrypter. */
function openSealed(bran, sealed) {
  const controller = new Controller(bran, Tier.low);
  const signer = controller.salter.signer(MtrDex.Ed25519_Seed, false);
  const decrypter = new Decrypter({}, signer.qb64b);
  return decrypter.decrypt(null, new Cipher({ qb64: sealed })).qb64;
}

/**
 * Replaces a record's sealed salt with what it opens to, so a Rust test can re-seal it under its
 * own key rather than transcribing a blob that only this controller can open.
 * `client_credentials.mjs` does the same.
 */
function sanitizeRecord(record) {
  const copy = JSON.parse(JSON.stringify(record));
  if (copy.salty?.sxlt) {
    copy.salty.sxlt_opens_to = openSealed(BRAN, copy.salty.sxlt);
    copy.salty.sxlt = "<SXLT>";
  }
  return copy;
}

const mockShortfall = {
  identifier_record: sanitizeRecord(HAB),
  identifier_record_fields: Object.keys(MOCK_GET_AID),
  identifier_record_missing: ["icp_dt"].filter((field) => !(field in MOCK_GET_AID)),
  added_inception_stamp: ADDED_INCEPTION_STAMP,
  note: "`mockGetAID` omits `icp_dt`, which the generated `HabState` schema declares required. The field is added here so the record decodes on the Rust side; nothing derived reads it. `client-credentials` recorded the same omission.",
};

// ---------------------------------------------------------------------------
// 3. A connected client, answering and signing as the `client-lifecycle` fixture did.
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

/** The exchange operation an accepted submission is answered with, as `Ipex.submit*` declares. */
const EXCHANGE_OPERATION = {
  name: "exchange.EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-",
  metadata: { said: "EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-" },
  done: true,
  response: { said: "EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-" },
};

const recorded = [];
let nextPayload = null;

function signedHeaders(httpMethod, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
  ]);
  return authenticator.sign(headers, httpMethod, path.split("?")[0]);
}

function jsonResponse(payload, httpMethod, path, status = 200) {
  const headers = signedHeaders(httpMethod, path);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status, headers });
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

  if (path.startsWith("/agent/")) {
    return jsonResponse(
      {
        agent: agentState,
        controller: {
          state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
          ee: { ...client.controller.serder.sad },
        },
        ridx: 0,
        pidx: 0,
      },
      httpMethod,
      path,
    );
  }
  if (path.startsWith("/identifiers/") && !path.endsWith("/exchanges")) {
    return jsonResponse(HAB, httpMethod, path);
  }
  return jsonResponse(nextPayload ?? EXCHANGE_OPERATION, httpMethod, path);
};

await client.boot();
await client.connect();

if (client.manager === null) {
  throw new Error("the client did not build a key manager");
}

const exchanges = client.exchanges();
const challenges = client.challenges();

// ---------------------------------------------------------------------------
// 4. The embedded event one driven message carries, built as the pinned test builds it.
// ---------------------------------------------------------------------------

const embedSalter = new Salter({
  raw: new Uint8Array([5, 170, 143, 45, 83, 154, 233, 250, 85, 156, 2, 156, 155, 8, 72, 117]),
});
const embedSigner = embedSalter.signer(MtrDex.Ed25519_Seed, true, "A", Tier.low, true);
const nextSigner = embedSalter.signer(MtrDex.Ed25519_Seed, true, "N", Tier.low, true);
const embeddedInception = new Serder({
  v: "KERI10JSON000000_",
  t: Ilks.icp,
  d: "",
  i: "",
  s: "0",
  kt: "1",
  k: [embedSigner.verfer.qb64],
  nt: "1",
  n: [new Diger({}, nextSigner.verfer.qb64b).qb64],
  bt: "0",
  b: [],
  c: [],
  a: [],
});
const embeddedSignature = embedSigner.sign(b(embeddedInception.raw), 0).qb64;

// ---------------------------------------------------------------------------
// 5. Drive the reference.
// ---------------------------------------------------------------------------

const calls = [];

/** Runs one driven call, recording every request it produced and what it returned. */
async function drive(name, note, run, payload = null) {
  nextPayload = payload;
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
  nextPayload = null;
}

/** `createExchangeMessage` returns a `Serder` plus two strings; record all three. */
function createdShape([exn, sigs, atc]) {
  return { exn: exn.sad, raw: exn.raw, sigs, atc };
}

await drive(
  "create_challenge_response",
  "the message `Challenges.respond` builds: a challenge response with a word list and no embeds",
  async () =>
    createdShape(
      await exchanges.createExchangeMessage(
        HAB,
        "/challenge/response",
        { words: PINNED_WORDS },
        {},
        PINNED_RECIPIENT,
      ),
    ),
);

await drive(
  "create_multisig_icp_with_embed",
  "a multisig inception proposal carrying an embedded inception and its signature, so the pathed attachment stream is non-empty",
  async () =>
    createdShape(
      await exchanges.createExchangeMessage(
        HAB,
        "/multisig/icp",
        { gid: HAB.prefix, smids: [HAB.prefix], rmids: [HAB.prefix] },
        { icp: [embeddedInception, embeddedSignature] },
        PINNED_RECIPIENT,
      ),
    ),
);

await drive(
  "create_with_explicit_datetime_and_prior",
  "the two arguments `send` never passes: an explicit timestamp and a prior message digest",
  async () =>
    createdShape(
      await exchanges.createExchangeMessage(
        HAB,
        "/multisig/vcp",
        { gid: HAB.prefix },
        {},
        PINNED_RECIPIENT,
        "2023-08-30T17:22:54.183000+00:00",
        PINNED_SAID,
      ),
    ),
);

await drive(
  "send_from_events_pinned",
  "the pinned unit test's own call: an empty topic, one empty signature, an empty attachment, and an empty recipient list",
  async () => await exchanges.sendFromEvents("aid1", "", embeddedInception, [""], "", []),
);

await drive(
  "send_single_recipient",
  "one recipient: the ordinary case, and the shape `Challenges.respond` produces",
  async () =>
    await exchanges.send("aid1", "multisig", HAB, "/multisig/icp", { gid: HAB.prefix }, {}, [PINNED_RECIPIENT]),
);

await drive(
  "send_two_recipients",
  "two recipients, which is how `multisig.test.ts` calls it eighteen times: the loop returns on its first pass, so the message is addressed to the first and delivered to both",
  async () =>
    await exchanges.send("aid1", "multisig", HAB, "/multisig/icp", { gid: HAB.prefix }, {}, [
      PINNED_RECIPIENT,
      SECOND_RECIPIENT,
    ]),
);

await drive(
  "send_alias_disagrees_with_sender",
  "the alias that addresses the resource and the identifier whose keeper signs are two arguments, and nothing compares them",
  async () =>
    await exchanges.send("some-other-alias", "multisig", HAB, "/multisig/icp", { gid: HAB.prefix }, {}, [
      PINNED_RECIPIENT,
    ]),
);

await drive(
  "send_empty_recipients",
  "an empty recipient list, which is the only way the `throw` after the loop is reached",
  async () => await exchanges.send("aid1", "multisig", HAB, "/multisig/icp", {}, {}, []),
);

await drive(
  "send_answered_with_an_exchange",
  "the same submission answered with an `exn`, which is what `sendFromEvents` declares it returns",
  async () => await exchanges.send("aid1", "multisig", HAB, "/multisig/icp", { gid: HAB.prefix }, {}, [PINNED_RECIPIENT]),
  { v: "KERI10JSON0000bf_", t: "exn", d: PINNED_SAID, i: HAB.prefix, rp: PINNED_RECIPIENT, p: "", dt: "2023-11-14T22:13:20.123000+00:00", r: "/multisig/icp", q: {}, a: { i: PINNED_RECIPIENT }, e: {} },
);

await drive(
  "get_pinned_said",
  "the SAID the pinned unit test reads an exchange by",
  async () => await exchanges.get(PINNED_SAID),
  {
    exn: { v: "KERI10JSON0000bf_", t: "exn", d: PINNED_SAID, i: HAB.prefix, rp: PINNED_RECIPIENT, p: "", dt: "2023-11-14T22:13:20.123000+00:00", r: "/multisig/icp", q: {}, a: { i: PINNED_RECIPIENT }, e: {} },
    pathed: {},
  },
);

await drive(
  "get_escaping_said",
  "a SAID carrying path delimiters, which the reference interpolates raw into the address",
  async () => await exchanges.get("../identifiers/aid1?x=1"),
  { exn: {}, pathed: {} },
);

await drive(
  "respond_pinned",
  "the pinned `contacting.test.ts` call, which is the capability `client-challenges` deferred to this fixture",
  async () => await challenges.respond("aid1", PINNED_RECIPIENT, PINNED_WORDS),
);

// ---------------------------------------------------------------------------
// 6. The values the pinned unit tests publish.
// ---------------------------------------------------------------------------

function called(name) {
  return calls.find((call) => call.name === name) ?? null;
}

/** The last request one driven call produced — the submission, after any identifier read. */
function submission(name) {
  const requests = called(name)?.requests ?? [];
  return requests.length === 0 ? null : requests[requests.length - 1];
}

const respondBody = JSON.parse(submission("respond_pinned")?.body ?? "null");
const sendFromEventsRequest = submission("send_from_events_pinned");
const getRequest = submission("get_pinned_said");

const pinnedConfirmations = {
  exchanging_test: {
    send_from_events_path: sendFromEventsRequest?.path ?? null,
    send_from_events_method: sendFromEventsRequest?.method ?? null,
    get_path: getRequest?.path ?? null,
    get_method: getRequest?.method ?? null,
  },
  contacting_test: {
    path: submission("respond_pinned")?.path ?? null,
    method: submission("respond_pinned")?.method ?? null,
    tpc: respondBody?.tpc ?? null,
    exn_route: respondBody?.exn?.r ?? null,
    exn_sender: respondBody?.exn?.i ?? null,
    exn_words: respondBody?.exn?.a?.words ?? null,
    first_signature_length: respondBody?.sigs?.[0]?.length ?? null,
  },
  every_pinned_assertion_is_driven:
    sendFromEventsRequest?.path === "/identifiers/aid1/exchanges" &&
    sendFromEventsRequest?.method === "POST" &&
    getRequest?.path === `/exchanges/${PINNED_SAID}` &&
    getRequest?.method === "GET" &&
    respondBody?.tpc === "challenge" &&
    respondBody?.exn?.r === "/challenge/response" &&
    respondBody?.exn?.i === "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK" &&
    JSON.stringify(respondBody?.exn?.a?.words) === JSON.stringify(PINNED_WORDS) &&
    respondBody?.sigs?.[0]?.length === 88,
  note: "`exchanging.test.ts` asserts two addresses and two methods; `contacting.test.ts`'s `respond` case asserts an address, a method, the topic, the message's route, its sender, its word list, and the length of its first signature. All eleven are recomputed here from the reference's own classes.",
};
if (!pinnedConfirmations.every_pinned_assertion_is_driven) {
  throw new Error("the pinned exchange assertions no longer reproduce");
}

// ---------------------------------------------------------------------------
// 7. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const twoRecipients = JSON.parse(submission("send_two_recipients")?.body ?? "null");

const quirks = {
  send_addresses_only_the_first_recipient: {
    loop: declarations.send_loop,
    recipients: [PINNED_RECIPIENT, SECOND_RECIPIENT],
    message_addressed_to: twoRecipients?.exn?.rp ?? null,
    attribute_addressed_to: twoRecipients?.exn?.a?.i ?? null,
    delivered_to: twoRecipients?.rec ?? null,
    call_sites: declarations.send_uses,
    note: "`send` iterates `recipients` and returns inside the loop, so only the first pass runs: `createExchangeMessage` is called with `recipients[0]` and the resulting message — whose `rp` and `a.i` name that one identifier — is then delivered to every recipient. `multisig.test.ts` calls it with two recipients eighteen times, so every member but the first receives a message addressed to somebody else.",
    rust_decision:
      "the addressee is a separate, explicit argument from the delivery list, so the port cannot silently pick one recipient out of many. The reference's own behaviour is still expressible — address the message to the first and deliver to all — but it has to be written down.",
  },
  the_alias_and_the_signer_are_two_arguments: {
    signature: declarations.send_signature,
    request: submission("send_alias_disagrees_with_sender"),
    sender_prefix: HAB.prefix,
    note: "`send(name, topic, sender, ...)` posts under `/identifiers/{name}/exchanges` while signing with `sender`'s keeper; nothing compares them, so a message signed by one identifier can be posted under another's resource — and request signing covers `@path`, so the two also disagree about what the HTTP signature covers.",
    rust_decision:
      "one alias. The sending identifier's record is looked up from the alias the message is posted under, so the resource, the signer, and the message's own `i` field are the same identifier by construction.",
  },
  the_timestamp_is_a_clock_reading: {
    declaration: declarations.create_exchange_call,
    note: declarations.notes.clock,
    rust_decision:
      "a required parameter, which is the decision taken for `exchange(...)` itself and for the authorization replies. A caller that wants `now` says so.",
  },
  the_submission_answer_has_two_declared_types: {
    send_from_events: declarations.send_from_events_return_type,
    send: declarations.send_return_type,
    ipex_submit_grant: declarations.submit_grant_return_type,
    operation_answer: called("send_single_recipient")?.result ?? null,
    exchange_answer: called("send_answered_with_an_exchange")?.result ?? null,
    note: "`sendFromEvents` declares `Promise<Exn>` and `Ipex.submitGrant` declares `Promise<ExchangeOperation>` for the same shape of POST to the same agent, and both are unchecked `res.json()` casts. At most one is right; the pinned tree contains no assertion either way, because its only unit case ignores the answer.",
    rust_decision:
      "the answer is kept as owned bytes with a decoder for each shape, so neither reading is imposed and a wrong-shaped answer is refused rather than cast. The question of which one a live KERIA sends is left for a live run to settle, as `client-key-state` left the sequence-number base.",
  },
  the_said_is_interpolated_raw: {
    declaration: declarations.get_path,
    request: submission("get_escaping_said"),
    note: "`get(said)` concatenates its argument into the path, so a value carrying `/` or `?` addresses a different resource — and changes the signed path",
    rust_decision:
      "the argument is the validated `Said`, which cannot hold a delimiter, and the request builder would encode it exactly once even if it could. The recorded input is proven refused.",
  },
  the_pinned_unit_call_is_three_empty_values: {
    request: sendFromEventsRequest,
    body: JSON.parse(sendFromEventsRequest?.body ?? "null"),
    note: "`sendFromEvents('aid1', '', serder, [''], '', [])` sends an empty topic, a single empty string where a qualified signature belongs, and an empty recipient list — asking the agent to file a notification under no topic and deliver it to nobody. The reference validates none of the three; its own `send` refuses only the last, and only because the loop cannot run.",
    rust_decision:
      "all three are unrepresentable: the topic is refused when empty, the signatures come from a keeper rather than from the caller, and an empty recipient list is refused as `client-ipex` refuses it. The recorded request is therefore reproduced in shape rather than byte for byte, and each input is proven refused — the pattern used for `exchange(...)` and in `client-registries` and `client-oobis` for a pinned vector their types cannot express.",
  },
  the_route_table_belongs_to_client_exchange_routes: {
    constants: declarations.route_constants,
    note: "thirteen exported route constants and the resource variants and type guards over them are `client-exchange-routes`'s, not this fixture's; `send`'s route parameter is the bare `string` they are values of",
    rust_decision:
      "the route stays borrowed text here, exactly as `ExchangeBuilder` left it and `client-escrows` left the escrow filter. `client-exchange-routes` owns the typed table.",
  },
};

// ---------------------------------------------------------------------------
// 8. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/exchanging.ts",
    "src/keri/app/contacting.ts",
    "src/keri/app/credentialing.ts",
    "src/types/keria-api-schema.ts",
    "test/app/exchanging.test.ts",
    "test/app/contacting.test.ts",
    "test/app/test-utils.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    identifier_prefix: HAB.prefix,
    recipient: PINNED_RECIPIENT,
    second_recipient: SECOND_RECIPIENT,
    note: "`Exchanges` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The clock and the agent's key are pinned, and the identifier is the reference's own `mockGetAID` read out of `test/app/test-utils.ts` — which is why `exn.i` here is the literal `contacting.test.ts` asserts. Signing uses a real keeper at the reference's production Argon2 profile, so this generator takes several seconds. `PUBLIC TEST MATERIAL`: the passcode and the encrypted salt are the pinned tests' own and have never protected anything.",
  },
  declarations,
  mock_shortfall: mockShortfall,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-exchanges/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-exchanges fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
