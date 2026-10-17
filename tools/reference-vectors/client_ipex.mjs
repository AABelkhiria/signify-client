// Records the pinned signify-ts checkout's five IPEX submissions.
//
// The Rust port covers `Ipex.{submitApply,submitOffer,submitAgree,submitGrant,submitAdmit}` from
// `src/keri/app/credentialing.ts`. The five artifact builders beside them are the `acdc-ipex`
// fixture's and are already `VERIFIED`, so this generator builds each message through the
// reference's own builder and then submits it through the reference's own submitter, recording
// the request that leaves.
//
// The pinned unit tree exercises **all five**: the three IPEX cases in
// `test/app/credentialing.test.ts` call every submitter and assert each path. Those messages are
// the ones rebuilt here, from the same `mockCredential`-derived artifacts the
// `acdc-ipex` fixture uses, so each recorded body carries an `exn` that fixture has already proven
// byte-exact.
//
// Everything is deterministic: every message's timestamp is supplied and the sender's keys derive
// from the passcode the pinned tests publish, at the reference's **production** Argon2 cost, so the
// signatures in each body are the real ones.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import { IdentifierManagerFactory } from "../../reference/signify-ts/dist/keri/core/keeping.js";
import { incept, interact } from "../../reference/signify-ts/dist/keri/core/eventing.js";
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
// 1. The five submitters, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");
const credentialingTest = parse("test/app/credentialing.test.ts");
const clientingTest = parse("test/app/clienting.test.ts");

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

function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

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

/** Reads one submitter's parameter list, its body literal, and its path. */
function submitter(name) {
  const node = method(credentialing.source, "Ipex", name);
  if (node === null) {
    throw new Error(`Ipex.${name} is no longer where this generator expects it`);
  }
  return {
    parameters: node.parameters.map((parameter) => parameter.getText().replace(/\s+/g, " ")),
    body: localDeclaration(node, "body"),
    path: firstText(node, (child) => ts.isTemplateExpression(child) && child.getText().includes("/ipex/")),
    returns: firstText(node, (child) => ts.isReturnStatement(child) && child.getText().includes("response.json()")),
  };
}

const declarations = {
  class_members: classMembers(credentialing.source, "Ipex"),
  submit_apply: submitter("submitApply"),
  submit_offer: submitter("submitOffer"),
  submit_agree: submitter("submitAgree"),
  submit_grant: submitter("submitGrant"),
  submit_admit: submitter("submitAdmit"),
  usage_scan: scan(".ipex()"),
  notes: {
    attachment:
      "`submitApply` and `submitAgree` take **no** `atc` parameter and write none, although their own builders return an attachment as the third element of the tuple — so two of the five submitters discard a value the builder produced",
    recipients:
      "every submitter takes a `recp: string[]` and copies it into the body as `rec`; nothing compares it with the recipient the message itself names in `rp` and `a.i`",
    path: "each path interpolates the sender's alias raw and appends a route segment the method chooses, so the route and the resource can only agree by the caller picking the matching method",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

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

const hab = await mockIdentifierState("multisig", BRAN);

const recorded = [];

/** Signs a response the way a KERIA agent would, so `SignifyClient.fetch` accepts it. */
function signedHeaders(httpMethod, path) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", "2023-08-23T15:16:07.553000+00:00"],
  ]);
  return authenticator.sign(headers, httpMethod, path.split("?")[0]);
}

function jsonResponse(payload, httpMethod, path, status = 200) {
  const headers = signedHeaders(httpMethod, path);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify(payload), { status, headers });
}

/** The exchange operation an accepted submission is answered with. */
const EXCHANGE_OPERATION = {
  name: "exchange.EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-",
  metadata: { said: "EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-" },
  done: true,
  response: { said: "EGpSjqjavdzgjQiyt0AtrOutWfKrj5gR63lOUUq-1sL-" },
};

globalThis.fetch = async (url, init = {}) => {
  const path = String(url).slice(ADMIN_URL.length);
  const httpMethod = init.method ?? "GET";
  recorded.push({
    path,
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
  });
  if (path.startsWith("/identifiers/") && !path.includes("/ipex/")) {
    return jsonResponse(hab, httpMethod, path);
  }
  if (path.includes("/ipex/")) {
    return jsonResponse(EXCHANGE_OPERATION, httpMethod, path);
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
    httpMethod,
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
// 3. The artifacts the IPEX messages carry, exactly as the `acdc-ipex` fixture builds them.
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
/** A second recipient, used only to record a multi-recipient submission. */
const SECOND_RECIPIENT = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";

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
// 4. Build the five messages, then submit each through the reference's own submitter.
// ---------------------------------------------------------------------------

const ipex = client.ipex();

const built = {};
built.apply = await ipex.apply({
  senderName: "multisig",
  recipient: HOLDER,
  message: "Applying",
  schemaSaid: MOCK_CREDENTIAL_SAD.s,
  attributes: { LEI: MOCK_CREDENTIAL_SAD.a.LEI },
  datetime: DT,
});
built.offer = await ipex.offer({
  senderName: "multisig",
  recipient: HOLDER,
  message: "How about this",
  acdc,
  datetime: DT,
  applySaid: built.apply[0].sad.d,
});
built.agree = await ipex.agree({
  senderName: "multisig",
  recipient: HOLDER,
  message: "OK!",
  datetime: DT,
  offerSaid: built.offer[0].sad.d,
});
built.grant = await ipex.grant({
  senderName: "multisig",
  recipient: HOLDER,
  message: "",
  acdc,
  iss,
  anc,
  ancAttachment: ANC_ATTACHMENT,
  datetime: DT,
  agreeSaid: built.agree[0].sad.d,
});
built.admit = await ipex.admit({
  senderName: "multisig",
  message: "",
  grantSaid: built.grant[0].sad.d,
  recipient: HOLDER,
  datetime: DT,
});

const calls = [];

/** Runs one submission, recording the request it produced with whatever came back. */
async function drive(name, note, run) {
  const before = recorded.length;
  let result = null;
  let error = null;
  try {
    result = await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const request = recorded[recorded.length - 1] ?? null;
  calls.push({
    name,
    note,
    request:
      request === null || recorded.length === before
        ? null
        : { path: request.path, method: request.method, body: request.body },
    requests: recorded.length - before,
    result,
    error,
  });
}

// --- the five the pinned unit test performs ---------------------------------

await drive("apply", "the pinned unit test's apply submission, which sends no attachment at all", () =>
  ipex.submitApply("multisig", built.apply[0], built.apply[1], [HOLDER]),
);

await drive("offer", "the pinned unit test's offer submission, whose attachment is the empty string", () =>
  ipex.submitOffer("multisig", built.offer[0], built.offer[1], built.offer[2], [HOLDER]),
);

await drive("agree", "the pinned unit test's agree submission, which sends no attachment at all", () =>
  ipex.submitAgree("multisig", built.agree[0], built.agree[1], [HOLDER]),
);

await drive("grant", "the pinned unit test's grant submission, the only one carrying a real attachment", () =>
  ipex.submitGrant("multisig", built.grant[0], built.grant[1], built.grant[2], [HOLDER]),
);

await drive("admit", "the pinned unit test's admit submission, whose attachment is the empty string", () =>
  ipex.submitAdmit("multisig", built.admit[0], built.admit[1], built.admit[2], [HOLDER]),
);

// --- the shapes the pinned tree never sends ---------------------------------

await drive("grant_two_recipients", "a grant submitted to two recipients, which the body carries as a list", () =>
  ipex.submitGrant("multisig", built.grant[0], built.grant[1], built.grant[2], [HOLDER, SECOND_RECIPIENT]),
);

await drive("grant_no_recipients", "a grant submitted to nobody, which the reference sends as an empty list", () =>
  ipex.submitGrant("multisig", built.grant[0], built.grant[1], built.grant[2], []),
);

await drive(
  "grant_recipient_is_not_the_addressee",
  "a grant addressed to one identifier and submitted to another, which nothing compares",
  () => ipex.submitGrant("multisig", built.grant[0], built.grant[1], built.grant[2], [SECOND_RECIPIENT]),
);

await drive("apply_alias_needing_encoding", "an alias carrying a slash, which the path does not encode", () =>
  ipex.submitApply("a/b", built.apply[0], built.apply[1], [HOLDER]),
);

await drive(
  "grant_through_the_apply_submitter",
  "a grant message posted to the apply resource, which the reference permits because the caller picks the method",
  () => ipex.submitApply("multisig", built.grant[0], built.grant[1], [HOLDER]),
);

await drive(
  "apply_through_the_grant_submitter",
  "an apply message posted to the grant resource with an attachment it never had",
  () => ipex.submitGrant("multisig", built.apply[0], built.apply[1], built.apply[2], [HOLDER]),
);

// ---------------------------------------------------------------------------
// 5. What the pinned unit tree does and does not contain.
// ---------------------------------------------------------------------------

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

function ipexTestFiles() {
  return PINNED_FILES.filter((file) => {
    if (!file.startsWith("test/")) {
      return false;
    }
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    return text.includes("ipex()") || text.includes("new Ipex");
  });
}

const pinnedConfirmations = {
  unit_test_file: "test/app/credentialing.test.ts",
  unit_test_files_naming_ipex: ipexTestFiles(),
  // The full URLs the test asserts each submission against, and the route literals beside them.
  published_submission_urls: publishedStrings(
    credentialingTest.source,
    (text) => text.startsWith("http") && text.includes("/ipex/"),
  ),
  published_routes: [
    ...new Set(publishedStrings(credentialingTest.source, (text) => text.startsWith("/ipex/"))),
  ].sort(),
  // Unlike `credentials()`, `registries()`, and `schemas()`, the `ipex()` accessor has **no**
  // type assertion in `clienting.test.ts` — recorded as a scan rather than claimed.
  accessor_assertion: clientingTest.text.includes("client.ipex()"),
  accessor_assertions_that_do_exist: ["credentials", "registries", "schemas", "operations", "identifiers"].filter(
    (name) => clientingTest.text.includes(`client.${name}() instanceof`),
  ),
  submitter_call_sites: {
    apply: scan("submitApply("),
    offer: scan("submitOffer("),
    agree: scan("submitAgree("),
    grant: scan("submitGrant("),
    admit: scan("submitAdmit("),
  },
  driven_paths: [...new Set(calls.filter((call) => call.request !== null).map((call) => call.request.path))].sort(),
  note: "the pinned `credentialing.test.ts` calls all five submitters across its three IPEX cases and asserts each one's full URL, which is the whole of what it checks about them — no body is asserted anywhere. `clienting.test.ts` asserts the type of five other endpoint accessors and **not** this one, which is recorded as a scan rather than claimed. Every real call site in the pinned tree, unit and integration alike, passes exactly one recipient and it is the one the message itself addresses; nothing in the reference compares the two.",
};
if (pinnedConfirmations.accessor_assertion) {
  throw new Error("`clienting.test.ts` now names `client.ipex()`; fold it into the evidence");
}
if (pinnedConfirmations.accessor_assertions_that_do_exist.length === 0) {
  throw new Error("no accessor assertions remain, so the absence above is no longer notable");
}
const distinctSubmissionUrls = [...new Set(pinnedConfirmations.published_submission_urls)].sort();
if (distinctSubmissionUrls.length !== 5) {
  throw new Error(`the pinned unit test publishes ${distinctSubmissionUrls.length} distinct submission URLs, not five`);
}
if (pinnedConfirmations.published_routes.length !== 5) {
  throw new Error("the pinned unit test no longer publishes exactly five IPEX routes");
}
pinnedConfirmations.distinct_submission_urls = distinctSubmissionUrls;

/** Every recipient list the pinned tree passes, so "always one, always the addressee" is evidence. */
const recipientListShapes = (() => {
  const lists = [];
  for (const file of PINNED_FILES) {
    const text = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    for (const match of text.matchAll(/submit(?:Apply|Offer|Agree|Grant|Admit)\([\s\S]{0,400?}?\)/g)) {
      const tail = match[0].slice(match[0].lastIndexOf("["));
      if (tail.startsWith("[")) {
        lists.push({ file, list: tail.replace(/\s+/g, " ") });
      }
    }
  }
  return {
    total: lists.length,
    single_element: lists.filter((entry) => !entry.list.includes(",")).length,
    lists,
    note: "read from the pinned source text rather than executed, because most call sites are integration tests needing a live KERIA; every one passes a single-element list",
  };
})();

// ---------------------------------------------------------------------------
// 6. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  two_submitters_discard_their_own_attachment: {
    apply_parameters: declarations.submit_apply.parameters,
    agree_parameters: declarations.submit_agree.parameters,
    apply_attachment: built.apply[2],
    agree_attachment: built.agree[2],
    apply_body: calls.find((call) => call.name === "apply")?.request?.body ?? null,
    agree_body: calls.find((call) => call.name === "agree")?.request?.body ?? null,
    note: "`Ipex.apply` and `Ipex.agree` each return an attachment as the third element of their tuple, and `submitApply` and `submitAgree` take no `atc` parameter and write no `atc` field — so the value is built and dropped. It is always the empty string, because neither route embeds anything, so nothing is actually lost; the asymmetry is in the API rather than in the bytes.",
    rust_decision:
      "reproduced exactly: the route decides whether the body carries `atc`, so an apply and an agree write three fields and the other three write four. A property asserts an apply's and an agree's attachment is always empty, which is what makes the omission lossless.",
  },
  the_route_and_the_resource_agree_only_by_convention: {
    grant_to_apply: calls.find((call) => call.name === "grant_through_the_apply_submitter")?.request ?? null,
    apply_to_grant: calls.find((call) => call.name === "apply_through_the_grant_submitter")?.request ?? null,
    note: "each submitter appends its own route segment and accepts any `exn`, so posting a grant through `submitApply` addresses `/ipex/apply` with a message whose own `r` says `/ipex/grant` — and posting an apply through `submitGrant` adds an `atc` the message never had. Nothing checks either.",
    rust_decision:
      "unrepresentable: there is one `submit`, and the path segment is read from the message's own route, so the resource and the `r` field cannot disagree.",
  },
  nothing_compares_the_recipients_with_the_addressee: {
    detail: recipientListShapes,
    addressed_to: built.grant[0].sad.rp,
    submitted_to: calls.find((call) => call.name === "grant_recipient_is_not_the_addressee")?.request?.body ?? null,
    note: "the recipient list is copied into the body as `rec` and is never compared with the `rp` and `a.i` the message itself carries, so a grant addressed to one identifier can be handed to the agent for delivery to another. Every call site in the pinned tree passes exactly one recipient and it is the addressee, so the reference has no evidence either way about fanning out.",
    rust_decision:
      "the list is kept as upstream and **not** narrowed to the addressee, because a multisig sender plausibly needs more than one and the pinned tree proves nothing either way; the method documents that it does not check. What is refused is an **empty** list, which asks the agent to deliver to nobody.",
  },
  an_empty_recipient_list_is_sent: {
    request: calls.find((call) => call.name === "grant_no_recipients")?.request ?? null,
    note: "`recp: []` reaches the wire as `\"rec\":[]`, a submission the agent is asked to deliver to no one; the reference neither refuses it nor reports it",
    rust_decision: "a typed refusal before anything is sent",
  },
  the_alias_is_not_encoded: {
    request: calls.find((call) => call.name === "apply_alias_needing_encoding")?.request ?? null,
    paths: {
      apply: declarations.submit_apply.path,
      offer: declarations.submit_offer.path,
      agree: declarations.submit_agree.path,
      grant: declarations.submit_grant.path,
      admit: declarations.submit_admit.path,
    },
    note: "all five paths interpolate the sender's alias raw, so an alias holding a slash addresses a different identifier's IPEX resource — and request authentication signs `@path`, so it changes what the signature covers",
    rust_decision: "refused by construction: the request builder's `ResourcePath` encodes the alias exactly once",
  },
  the_answer_is_cast_rather_than_decoded: {
    returns: declarations.submit_apply.returns,
    recorded_answer: EXCHANGE_OPERATION,
    note: "every submitter returns `response.json()` cast to `ExchangeOperation`, so whatever the agent sends is read as an operation",
    rust_decision: "decoded rather than cast, as the config, schemas, and credentials endpoints decided",
  },
};

// ---------------------------------------------------------------------------
// 7. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: ["src/keri/app/credentialing.ts", "test/app/credentialing.test.ts", "test/app/clienting.test.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    stamp: DT,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    sender_alias: "multisig",
    sender: hab.prefix,
    recipient: HOLDER,
    second_recipient: SECOND_RECIPIENT,
    note: "`Ipex` takes a whole `SignifyClient`, so the real client is driven with `globalThis.fetch` replaced by a recorder that signs its answers as a KERIA agent would. The sender's habitat is derived by the same route the pinned `test/app/test-utils.ts` derives its mock, at the reference's production Argon2 cost, so every signature in a recorded body is real. Each message is built by the reference's own IPEX artifact builder before being submitted, so every recorded `exn` is one `fixtures/acdc-ipex/v1.json` has already proven byte-exact. `PUBLIC TEST MATERIAL`: the passcode is the pinned tests' own and has never protected anything.",
  },
  declarations,
  // The three artifacts a grant embeds, so the Rust side can rebuild the same messages.
  embedded_artifacts: {
    acdc_raw: acdc.raw,
    iss_raw: iss.raw,
    anc_raw: anc.raw,
    anchor_attachment: ANC_ATTACHMENT,
    schema: MOCK_CREDENTIAL_SAD.s,
    lei: MOCK_CREDENTIAL_SAD.a.LEI,
    note: "the same three the `acdc-ipex` fixture embeds, rebuilt here from `mockCredential` by the reference's own `Saider` and `interact`",
  },
  messages: Object.fromEntries(
    Object.entries(built).map(([name, [exn, sigs, atc]]) => [
      name,
      { raw: exn.raw, said: exn.sad.d, route: exn.sad.r, addressed_to: exn.sad.rp, attachment: atc, signatures: sigs },
    ]),
  ),
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-ipex/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-ipex fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
