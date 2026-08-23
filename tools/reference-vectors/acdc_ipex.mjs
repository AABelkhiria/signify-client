// Records the pinned signify-ts checkout's five IPEX messages, driven through its own `Ipex` class.
//
// Roadmap 6.3 ports the pure half of `Ipex.apply`, `.offer`, `.agree`, `.grant`, and `.admit`:
// each builds a routed exchange message with a payload, an optional prior, and — for offer and
// grant — embedded messages with their CESR attachments, then signs it with the sender's keeper.
// The five `submit*` methods that POST the result are Roadmap 6.12.
//
// Unlike Roadmap 6.1's and 6.2's fixtures, this one does **not** re-express the ported code: it
// drives the reference's own `Ipex` methods end to end. `globalThis.fetch` is replaced so the
// client's `identifiers().get(...)` returns a habitat state this generator derives with the
// reference's own `Controller`, `IdentifierManagerFactory`, and `incept` — exactly as the pinned
// `test/app/test-utils.ts` derives its mock — which means the recorded `exn` bytes, signatures,
// and attachment streams are the reference's real output rather than a paraphrase of it.
//
// Everything is deterministic: every message's timestamp is supplied, and the sender's keys derive
// from the passcode the pinned tests publish. The keeper runs at the reference's **production**
// Argon2 cost, as Roadmap 4.4 through 4.6 did, so the signatures are the real ones.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import { IdentifierManagerFactory } from "../../reference/signify-ts/dist/keri/core/keeping.js";
import { incept } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import { interact } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import { Saider } from "../../reference/signify-ts/dist/keri/core/saider.js";
import { Serder } from "../../reference/signify-ts/dist/keri/core/serder.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { b, versify, Protocols, Serials, Ilks, Vrsn_1_0 } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// ---------------------------------------------------------------------------
// 1. The routes and payload shapes, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");
const exchanging = parse("src/keri/app/exchanging.ts");

/** Returns the declaration node of one named method of one named class. */
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

/** Returns the source text of the first node inside `node` matching `predicate`, on one line. */
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

/** Reads one IPEX method's route, payload literal, and embed literal. */
function ipexShape(name) {
  const node = method(credentialing.source, "Ipex", name);
  if (node === null) {
    throw new Error(`Ipex.${name} is no longer where this generator expects it`);
  }
  const call = firstText(node, (child) =>
    ts.isCallExpression(child) && child.expression.getText().endsWith("createExchangeMessage"),
  );
  const payload = firstText(
    node,
    (child) => ts.isVariableDeclaration(child) && child.name.getText() === "data",
  );
  const declaredEmbeds = firstText(
    node,
    (child) => ts.isVariableDeclaration(child) && child.name.getText() === "embeds",
  );
  // `createExchangeMessage(hab, route, data, embeds, recipient, datetime, dig)`: the fourth
  // argument is the embed map, written inline by offer and as a variable by grant.
  let embedsArgument = null;
  const visit = (child) => {
    if (
      embedsArgument === null &&
      ts.isCallExpression(child) &&
      child.expression.getText().endsWith("createExchangeMessage") &&
      child.arguments.length >= 4
    ) {
      embedsArgument = child.arguments[3].getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return { call, payload, embeds_argument: embedsArgument, embeds_declaration: declaredEmbeds };
}

const shapes = {
  apply: ipexShape("apply"),
  offer: ipexShape("offer"),
  agree: ipexShape("agree"),
  grant: ipexShape("grant"),
  admit: ipexShape("admit"),
};

/** Every route string the five methods pass. */
const routes = Object.fromEntries(
  Object.entries(shapes).map(([name, shape]) => {
    const match = shape.call.match(/'(\/ipex\/[a-z]+)'/);
    if (match === null) {
      throw new Error(`the route for Ipex.${name} is no longer a literal`);
    }
    return [name, match[1]];
  }),
);

const createExchangeMessage = method(exchanging.source, "Exchanges", "createExchangeMessage");
if (createExchangeMessage === null) {
  throw new Error("Exchanges.createExchangeMessage is no longer where this generator expects it");
}

const declarations = {
  routes,
  shapes,
  create_exchange_message: createExchangeMessage.getText().replace(/\s+/g, " "),
  notes: {
    payloads:
      "apply carries the schema and its selective-disclosure attributes beside the message; offer, agree, and grant carry the message alone; admit passes `args.message` through with no default, so an admit with no message emits an attribute block carrying no `m` at all",
    embeds:
      "only offer and grant embed anything: offer embeds the credential with no attachment, grant embeds the credential, its issuance event, and the anchoring key event, each with the attachment that authenticates the next",
    signing:
      "`createExchangeMessage` is `exchange(...)` — Roadmap 3.8 — followed by one keeper signature over the serialized message; the attachment stream it returns is the transposed embed material, not the signature",
  },
};

// ---------------------------------------------------------------------------
// 2. A connected client whose habitat the reference itself derives.
// ---------------------------------------------------------------------------

const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";

/** Derives the habitat state the pinned `test/app/test-utils.ts` mocks, by the same route. */
async function mockIdentifierState(name, bran) {
  const controller = new Controller(bran, Tier.low);
  const manager = new IdentifierManagerFactory(controller.salter);
  const keeper = manager.new("salty", 0, {
    transferable: true,
    isith: "1",
    nsith: "1",
    wits: [],
    toad: 0,
    dcode: MtrDex.Blake3_256,
    data: [],
    algo: "salty",
    bran,
    count: undefined,
    ncount: undefined,
    tier: undefined,
  });
  const [keys, ndigs] = await keeper.incept(true);
  const serder = incept({
    keys,
    isith: "1",
    ndigs,
    nsith: "1",
    toad: 0,
    wits: [],
    cnfg: [],
    data: [],
    version: Vrsn_1_0,
    kind: Serials.JSON,
    code: MtrDex.Blake3_256,
    intive: false,
  });
  return {
    name,
    prefix: serder.pre,
    salty: keeper.params(),
    transferable: true,
    windexes: [],
    extern: {},
    state: {
      vn: [serder.version.major, serder.version.minor],
      s: serder.sad.s,
      d: serder.sad.d,
      i: serder.pre,
      ee: serder.sad,
      kt: serder.sad.kt,
      k: serder.sad.k,
      nt: serder.sad.nt,
      n: serder.sad.n,
      bt: serder.sad.bt,
      b: serder.sad.b,
      p: serder.sad.p ?? "",
      f: "",
      dt: "2023-08-23T15:16:07.553000+00:00",
      et: serder.sad.t,
      c: [],
      di: "",
    },
    icp_dt: "2023-08-23T15:16:07.553000+00:00",
  };
}

const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
const controllerPrefix = client.controller.pre;

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

const hab = await mockIdentifierState("multisig", BRAN);

const recorded = [];

/** Signs a response the way a KERIA agent would, so `SignifyClient.fetch` accepts it. */
function signedHeaders(method, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", "2023-08-23T15:16:07.553000+00:00"],
  ]);
  return authenticator.sign(headers, method, path.split("?")[0]);
}

function jsonResponse(payload, method, path, status = 200) {
  const headers = signedHeaders(method, path);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status, headers });
}

/** Answers every request the driven code makes, and records the submissions. */
globalThis.fetch = async (url, init = {}) => {
  const path = String(url).slice(ADMIN_URL.length);
  recorded.push({
    url: String(url),
    method: init.method ?? "GET",
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });
  // An identifier lookup returns the habitat; an IPEX submission returns nothing; everything
  // else is the agent/controller state the client's `connect` reads.
  const method = init.method ?? "GET";
  if (path.startsWith("/identifiers/") && !path.includes("/ipex/")) {
    return jsonResponse(hab, method, path);
  }
  if (path.includes("/ipex/")) {
    return jsonResponse({}, method, path);
  }
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
    method,
    path,
  );
};

await client.state();
try {
  await client.connect();
} catch (error) {
  const message = String(error?.message ?? error);
  if (!message.includes("remote agent") && !message.includes("verification failed")) {
    throw error;
  }
}
if (client.manager === null) {
  throw new Error("the client did not build a key manager");
}

// ---------------------------------------------------------------------------
// 3. The artifacts the IPEX messages carry, built the way Roadmap 6.2 builds them.
// ---------------------------------------------------------------------------

const MOCK_CREDENTIAL_SAD = {
  v: "ACDC10JSON000197_",
  d: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo",
  i: "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1",
  ri: "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df",
  s: "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
  a: {
    d: "EK0GOjijKd8_RLYz9qDuuG29YbbXjU8yJuTQanf07b6P",
    i: "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby",
    dt: "2023-08-23T15:16:07.553000+00:00",
    LEI: "5493001KJTIIGC8Y1R17",
  },
};
const DT = MOCK_CREDENTIAL_SAD.a.dt;
const HOLDER = "ELjSFdrTdCebJlmvbFNX9-TLhR2PO0_60al1kQp5_e6k";

const [, acdcSad] = Saider.saidify(MOCK_CREDENTIAL_SAD);
const acdc = new Serder(acdcSad);

const [, issSad] = Saider.saidify({
  v: versify(Protocols.KERI, undefined, Serials.JSON, 0),
  t: Ilks.iss,
  d: "",
  i: MOCK_CREDENTIAL_SAD.d,
  s: "0",
  ri: MOCK_CREDENTIAL_SAD.ri,
  dt: DT,
});
const iss = new Serder(issSad);

// The pinned test's own anchor, which deliberately seals `[{}]` because it is testing the grant.
const anc = interact({
  pre: MOCK_CREDENTIAL_SAD.i,
  sn: 1,
  data: [{}],
  dig: MOCK_CREDENTIAL_SAD.d,
  version: undefined,
  kind: undefined,
});
const ANC_ATTACHMENT =
  "-AABAADMtDfNihvCSXJNp1VronVojcPGo--0YZ4Kh6CAnowRnn4Or4FgZQqaqCEv6XVS413qfZoVp8j2uxTTPkItO7ED";

// ---------------------------------------------------------------------------
// 4. Drive the reference's own IPEX methods and record everything they return.
// ---------------------------------------------------------------------------

const ipex = client.ipex();

/** Records one IPEX message: its exact bytes, its signatures, and its attachment stream. */
async function record(name, note, run) {
  const [exn, sigs, atc] = await run();
  return {
    note,
    raw: exn.raw,
    said: exn.sad.d,
    size: exn.size,
    route: exn.sad.r,
    prior: exn.sad.p,
    payload: exn.sad.a,
    embed_labels: Object.keys(exn.sad.e),
    attachment: atc,
    signatures: sigs,
  };
}

const messages = {};

messages.apply = await record(
  "apply",
  "the pinned unit test's apply: a schema request with selective-disclosure attributes and no prior",
  () =>
    ipex.apply({
      senderName: "multisig",
      recipient: HOLDER,
      message: "Applying",
      schemaSaid: MOCK_CREDENTIAL_SAD.s,
      attributes: { LEI: MOCK_CREDENTIAL_SAD.a.LEI },
      datetime: DT,
    }),
);

messages.apply_defaults = await record(
  "apply_defaults",
  "an apply with neither message nor attributes, which default to the empty string and the empty block",
  () =>
    ipex.apply({
      senderName: "multisig",
      recipient: HOLDER,
      schemaSaid: MOCK_CREDENTIAL_SAD.s,
      datetime: DT,
    }),
);

messages.offer = await record(
  "offer",
  "the pinned unit test's offer: the credential embedded with no attachment, answering the apply above",
  () =>
    ipex.offer({
      senderName: "multisig",
      recipient: HOLDER,
      message: "How about this",
      acdc,
      datetime: DT,
      applySaid: messages.apply.said,
    }),
);

messages.offer_without_apply = await record(
  "offer_without_apply",
  "an offer with no prior, which the pinned suite's third IPEX case exercises",
  () =>
    ipex.offer({
      senderName: "multisig",
      recipient: HOLDER,
      message: "How about this",
      acdc,
      datetime: DT,
    }),
);

messages.agree = await record(
  "agree",
  "the pinned unit test's agree: a message alone, answering the offer above",
  () =>
    ipex.agree({
      senderName: "multisig",
      recipient: HOLDER,
      message: "OK!",
      datetime: DT,
      offerSaid: messages.offer.said,
    }),
);

messages.grant = await record(
  "grant",
  "the pinned unit test's grant: three embedded messages, each with the attachment authenticating the next",
  () =>
    ipex.grant({
      senderName: "multisig",
      recipient: HOLDER,
      message: "",
      acdc,
      iss,
      anc,
      ancAttachment: ANC_ATTACHMENT,
      datetime: DT,
      agreeSaid: messages.agree.said,
    }),
);

messages.grant_without_agree = await record(
  "grant_without_agree",
  "a grant with no prior, which the discloser-initiated flow produces",
  () =>
    ipex.grant({
      senderName: "multisig",
      recipient: HOLDER,
      message: "",
      acdc,
      iss,
      anc,
      ancAttachment: ANC_ATTACHMENT,
      datetime: DT,
    }),
);

messages.admit = await record(
  "admit",
  "the pinned unit test's admit: a message alone, answering the grant above",
  () =>
    ipex.admit({
      senderName: "multisig",
      recipient: HOLDER,
      message: "",
      grantSaid: messages.grant.said,
      datetime: DT,
    }),
);

// ---------------------------------------------------------------------------
// 5. The values the pinned unit tests publish, read from their own syntax tree.
// ---------------------------------------------------------------------------

const credentialingTest = parse("test/app/credentialing.test.ts");

/** Collects every `assert.deepStrictEqual(x.sad, {...})` literal, keyed by its route. */
function publishedMessages(source) {
  const found = {};
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      node.expression.getText() === "assert.deepStrictEqual" &&
      node.arguments.length === 2 &&
      node.arguments[1] !== undefined &&
      ts.isObjectLiteralExpression(node.arguments[1])
    ) {
      const text = node.arguments[1].getText();
      const route = text.match(/r: '(\/ipex\/[a-z]+)'/);
      const said = text.match(/d: '(E[A-Za-z0-9_-]{43})'/);
      const version = text.match(/v: '(KERI10JSON[0-9a-f]{6}_)'/);
      if (route !== null && said !== null && version !== null) {
        (found[route[1]] ??= []).push({ said: said[1], version: version[1] });
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Collects every signature literal the pinned tests assert. */
function publishedSignatures(source) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && /^A[A-Za-z0-9_-]{87}$/.test(node.text)) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const published = publishedMessages(credentialingTest.source);
const publishedSigs = publishedSignatures(credentialingTest.source);

/** Confirms one driven message appears among the values the pinned test publishes. */
function confirm(name, route) {
  const message = messages[name];
  const candidates = published[route] ?? [];
  return {
    route,
    said: message.said,
    version: message.raw.slice(5, 22),
    published_saids: candidates.map((candidate) => candidate.said),
    said_is_published: candidates.some((candidate) => candidate.said === message.said),
    signature_is_published: message.signatures.every((signature) => publishedSigs.includes(signature)),
  };
}

const pinnedConfirmations = {
  apply: confirm("apply", "/ipex/apply"),
  offer: confirm("offer", "/ipex/offer"),
  agree: confirm("agree", "/ipex/agree"),
  grant: confirm("grant", "/ipex/grant"),
  admit: confirm("admit", "/ipex/admit"),
  note: "each driven message's identifier and signature are looked for among the literals the pinned `credentialing.test.ts` asserts; the sender's keys derive from the passcode that file publishes, at the reference's production Argon2 cost",
};
for (const [name, confirmation] of Object.entries(pinnedConfirmations)) {
  if (name === "note") {
    continue;
  }
  if (!confirmation.said_is_published || !confirmation.signature_is_published) {
    throw new Error(`the pinned ${name} message no longer reproduces: ${JSON.stringify(confirmation)}`);
  }
}

// ---------------------------------------------------------------------------
// 6. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

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

const quirks = {
  admit_message_has_no_default: await (async () => {
    const [exn] = await ipex.admit({
      senderName: "multisig",
      recipient: HOLDER,
      grantSaid: messages.grant.said,
      datetime: DT,
    });
    // Read back from the serialization: `exn.sad.a` holds `m: undefined` as an own property,
    // which `JSON.stringify` drops, so the in-memory object and the bytes disagree.
    const serialized = JSON.parse(exn.raw);
    return {
      raw: exn.raw,
      said: exn.sad.d,
      payload: serialized.a,
      payload_labels: Object.keys(serialized.a),
      carries_message_field: Object.hasOwn(serialized.a, "m"),
      differs_from_empty_message: exn.sad.d !== messages.admit.said,
      note: "the other four routes write `m: args.message ?? ''`; admit writes `m: args.message`, so an admit with no message emits an attribute block with no `m` at all — a different message, with a different identifier, from one carrying an empty string",
      rust_decision:
        "refused: the message is a required parameter on every route, because whether the field exists at all should not depend on which argument a caller happened to omit. The empty string is spelled explicitly.",
    };
  })(),
  offer_embeds_an_undefined_attachment: {
    embed_expression: shapes.offer.embeds_argument,
    attachment: messages.offer.attachment,
    note: "an offer embeds `[args.acdc, undefined]`, and the transposed stream for an embed with no attachment is the empty string — the label is written into the exchange's `e` block but nothing follows it in the attachment stream",
    rust_decision: "reproduced: Roadmap 3.8's `ExchangeEmbed::new` without `with_attachment` is exactly this case, and it is distinct from an explicitly empty attachment, which still writes its path.",
  },
  grant_signs_the_anchor_when_no_attachment_is_given: {
    expression: firstText(
      method(credentialing.source, "Ipex", "grant"),
      (node) => ts.isIfStatement(node) && node.getText().includes("atc === undefined"),
    ),
    note: "a grant with no `ancAttachment` signs the anchoring key event with the sender's keeper and takes the attachment off the resulting message — which means the *sender* signs an event belonging to the credential's issuer, whoever that is",
    rust_decision:
      "the anchor attachment is a required input. Roadmap 6.2 produces the issuer's own signed anchor, and a discloser who is not the issuer cannot produce a valid one; making it required means the caller must supply what it actually has.",
  },
  routes_are_string_literals: {
    scan: scan("/ipex/"),
    note: "the five routes appear as bare string literals at their call sites; the pinned `app/exchanging.ts` declares a route table for multisig but none for IPEX",
    rust_decision: "a typed `IpexRoute` enum, whose `as_str` is asserted against the literals read from the reference's own syntax tree. The general exchange route table is Roadmap 8.1.",
  },
  sender_and_recipient_are_unvalidated: {
    note: "`senderName` is an alias looked up remotely and `recipient` is free text interpolated into the message; neither is checked, so a typo becomes part of the exchange's identifier",
    rust_decision: "the recipient is an `IdentifierPrefix` and the sender is the habitat's own prefix, as Roadmap 3.8 already types them.",
  },
  attributes_are_an_untyped_record: {
    payload_expression: shapes.apply.payload,
    note: "an apply's `attributes` is `Record<string, unknown>`, spread into the payload with no bound and no label check",
    rust_decision: "an ordered `Sad`, bounded and label-checked exactly as Roadmap 6.1 bounds a credential's attribute block, because it is committed into the exchange's identifier the same way.",
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
  sources: ["src/keri/app/credentialing.ts", "src/keri/app/exchanging.ts", "test/app/credentialing.test.ts"],
  provenance: {
    passcode: BRAN,
    passcode_note: "PUBLIC TEST MATERIAL: the passcode the pinned `credentialing.test.ts` publishes; it has never protected anything",
    sender: hab.prefix,
    recipient: HOLDER,
    timestamp: DT,
    credential: acdcSad.d,
    issuance: issSad.d,
    anchor: anc.sad.d,
    anchor_attachment: ANC_ATTACHMENT,
    note: "the sender's habitat is derived here by the same route the pinned `test/app/test-utils.ts` derives its mock, at the reference's production Argon2 cost, and the reference's own `Ipex` methods are driven end to end against it",
  },
  declarations,
  embedded_artifacts: {
    acdc_raw: acdc.raw,
    iss_raw: iss.raw,
    anc_raw: anc.raw,
    note: "the credential, its issuance event, and the anchoring key event a grant embeds; the first two are Roadmap 6.1's and 6.2's own output and the third is the pinned test's, which deliberately seals `[{}]`",
  },
  messages,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/acdc-ipex/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("acdc-ipex fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
