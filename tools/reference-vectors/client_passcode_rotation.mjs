// Records the pinned signify-ts checkout's passcode-rotation workflow, against keripy's.
//
// This port covers `SignifyClient.rotate` — the client half of moving to a new passcode. The
// artifact half is `Controller.rotate`, already recorded in `fixtures/keri-controller/v1.json`;
// what this fixture adds is the request that carries it and the comparison that decides what the
// port should do.
//
// The finding is one variable.
//
//   const nbran = MtrDex.Salt_128 + 'A' + bran.substring(0, 21);   // the NEW salt
//   const nsalter = new Salter({ qb64: nbran, tier: this.tier });  // the NEW salter
//   const nsigner = this.salter.signer(undefined, false);          // ...the OLD salter
//   const encrypter = new Encrypter({}, b(nsigner.verfer.qb64));
//   const decrypter = new Decrypter({}, nsigner.qb64b);
//
// Every `n`-prefixed name beside it is the new passcode's; `nsigner` is the old one's. It feeds
// the decrypter, which is right, and the encrypter, which is not — so the payload the rotation
// produces is sealed to the passcode being left behind, and the sealed controller salt is the old
// salt as well. Driven here: the payload does not open under the new passcode at all.
//
// keripy does it the other way. `Manager.updateAeid` builds its encrypter from the **new** key,
// checks that the new seed belongs to it, then opens each secret with the old decrypter and seals
// it with the new encrypter. This port follows keripy.
//
// Nothing upstream exercises any of this: the one test that calls `rotate` passes an **empty**
// identifier list, so the whole re-encryption loop, both its branches, and its key-state check
// never run.
import { readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "../../reference/signify-ts/dist/keri/core/authing.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Controller } from "../../reference/signify-ts/dist/keri/app/controller.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { rotate } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import { Encrypter } from "../../reference/signify-ts/dist/keri/core/encrypter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { SaltyCreator } from "../../reference/signify-ts/dist/keri/core/manager.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const keripySha = "4ce4cc79e06653f77342be1bf604086b89b1f090";

const PASSCODE = "0123456789abcdefghijk";
const SECOND_PASSCODE = "abcdefghijk0123456789";
const ADMIN_URL = "http://127.0.0.1:3901";
const BOOT_URL = "http://127.0.0.1:3903";
const FIXED_MS = 1_700_000_000_123;

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
// 1. What both trees declare.
// ---------------------------------------------------------------------------

function parse(root, relativePath) {
  const url = new URL(`../../reference/${root}/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const clienting = parse("signify-ts", "src/keri/app/clienting.ts");
const controllerFile = parse("signify-ts", "src/keri/app/controller.ts");
const clientingTest = parse("signify-ts", "test/app/clienting.test.ts");

/** One method's text, however it is declared. */
function methodText(source, className, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name.getText() === name) {
          found = member.getText().replace(/\s+/g, " ");
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every `new Encrypter(...)`/`new Decrypter(...)` in one method, with the argument it is given. */
function cipherConstruction(text) {
  const found = [];
  for (const match of text.matchAll(/new (Encrypter|Decrypter)\(\{\}, ([^)]*)\)/g)) {
    found.push({ kind: match[1], argument: match[2].trim() });
  }
  return found;
}

/** The declaration of one local variable inside a method's text. */
function localDeclaration(text, name) {
  const match = text.match(new RegExp(`const ${name} = ([^;]*);`));
  return match === null ? null : `const ${name} = ${match[1].trim()};`;
}

const CLIENT_ROTATE = methodText(clienting.source, "SignifyClient", "rotate");
const CONTROLLER_ROTATE = methodText(controllerFile.source, "Controller", "rotate");
if (CLIENT_ROTATE === null || CONTROLLER_ROTATE === null) {
  throw new Error("rotate is no longer where this generator expects it");
}

const NSIGNER = localDeclaration(CONTROLLER_ROTATE, "nsigner");
const NSALTER = localDeclaration(CONTROLLER_ROTATE, "nsalter");
const NBRAN = localDeclaration(CONTROLLER_ROTATE, "nbran");
const SXLT_LINE = localDeclaration(CONTROLLER_ROTATE, "sxlt");
if (NSIGNER === null || !NSIGNER.includes("this.salter")) {
  throw new Error("`nsigner` no longer derives from the old salter; the finding is stale");
}

/** Every `.rotate(` call in the pinned unit test, with the arguments it passes. */
function rotateCalls(source) {
  const found = [];
  const visit = (node) => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.getText() === "rotate" &&
      node.expression.expression.getText() === "client"
    ) {
      found.push({
        text: node.getText().replace(/\s+/g, " "),
        identifiers: node.arguments[1]?.getText() ?? "<absent>",
        identifier_count:
          node.arguments[1] !== undefined && ts.isArrayLiteralExpression(node.arguments[1])
            ? node.arguments[1].elements.length
            : null,
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const TEST_CALLS = rotateCalls(clientingTest.source);
if (TEST_CALLS.length !== 1 || TEST_CALLS[0].identifier_count !== 0) {
  throw new Error("the pinned test no longer rotates with an empty identifier list");
}

// keripy's contrasting implementation, read from its own pinned checkout.
const keeping = readFileSync(new URL("../../reference/keripy/src/keri/app/keeping.py", import.meta.url), "utf8");
const updateAeid = (() => {
  const start = keeping.indexOf("    def updateAeid(self, aeid, seed):");
  if (start < 0) {
    throw new Error("keripy's updateAeid is no longer where this generator expects it");
  }
  const next = keeping.indexOf("\n    def ", start + 10);
  return keeping.slice(start, next < 0 ? undefined : next);
})();
const keripyLines = updateAeid
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line.includes("Encrypter(") || line.includes("encrypt(") || line.includes("decrypt("));
if (!updateAeid.includes("self.encrypter = core.Encrypter(verkey=aeid)")) {
  throw new Error("keripy no longer builds its encrypter from the new aeid; the comparison is stale");
}

const declarations = {
  client_rotate: CLIENT_ROTATE,
  controller_rotate: CONTROLLER_ROTATE,
  nbran_declaration: NBRAN,
  nsalter_declaration: NSALTER,
  nsigner_declaration: NSIGNER,
  sealed_salt_declaration: SXLT_LINE,
  cipher_construction: cipherConstruction(CONTROLLER_ROTATE),
  unit_test_calls: TEST_CALLS,
  keripy: {
    commit: keripySha,
    file: "src/keri/app/keeping.py",
    symbol: "Manager.updateAeid",
    encrypter_from_new_key: "self.encrypter = core.Encrypter(verkey=aeid)",
    verifies_new_seed: updateAeid.includes("self.encrypter.verifySeed(seed)"),
    docstring_claim: "aeid may be different not empty which reencrypts",
    cipher_lines: keripyLines,
  },
  notes: {
    finding:
      "`nsigner` derives from `this.salter` — the old salt — while `nbran` and `nsalter` beside it are the new passcode's. It feeds both the decrypter (right) and the encrypter (wrong).",
    coverage: "the one pinned call passes an empty identifier list, so the re-encryption loop never runs",
  },
};

// ---------------------------------------------------------------------------
// 2. A connected client whose agent answers as a KERIA would.
// ---------------------------------------------------------------------------

/** The key a passcode seals its stored material under, as every keeper derives it. */
function encryption(passcode) {
  const salter = new Salter({ qb64: MtrDex.Salt_128 + "A" + passcode.substring(0, 21), tier: Tier.low });
  const signer = salter.signer(MtrDex.Ed25519_Seed, false);
  return {
    encrypter: new Encrypter({}, b(signer.verfer.qb64)),
    decrypter: new Decrypter({}, signer.qb64b),
  };
}

/** A deterministic salty identifier, sealed to the prior passcode's key. */
function saltyAid(encrypter) {
  const salter = new Salter({ qb64: "0ABmZWRjYmE5ODc2NTQzMjEw", tier: Tier.low });
  const creator = new SaltyCreator(salter.qb64, Tier.low, "signify:aid");
  const keys = creator.create(["A"], undefined, MtrDex.Ed25519_Seed, true, 0, 0, 0, false).signers.map((s) => s.verfer.qb64);
  return {
    salt: salter.qb64,
    record: {
      prefix: keys[0],
      salty: {
        sxlt: encrypter.encrypt(b(salter.qb64)).qb64,
        pidx: 0,
        kidx: 0,
        stem: "signify:aid",
        tier: Tier.low,
        icodes: ["A"],
        ncodes: ["A"],
        transferable: true,
        dcode: MtrDex.Blake3_256,
      },
      state: { k: keys },
    },
  };
}

/** A deterministic randy identifier, sealed to the prior passcode's key. */
function randyAid(encrypter) {
  const seeds = [new Uint8Array(32).fill(7), new Uint8Array(32).fill(11)];
  const signers = seeds.map((raw) => new Signer({ raw, code: MtrDex.Ed25519_Seed, transferable: true }));
  const next = new Signer({ raw: new Uint8Array(32).fill(13), code: MtrDex.Ed25519_Seed, transferable: true });
  return {
    seeds: signers.map((signer) => signer.qb64),
    next_seed: next.qb64,
    record: {
      prefix: signers[0].verfer.qb64,
      randy: {
        prxs: signers.map((signer) => encrypter.encrypt(b(signer.qb64)).qb64),
        nxts: [encrypter.encrypt(b(next.qb64)).qb64],
      },
      state: { k: signers.map((signer) => signer.verfer.qb64) },
    },
  };
}

const client = new SignifyClient(ADMIN_URL, PASSCODE, Tier.low, BOOT_URL);
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

const recorded = [];

globalThis.fetch = async (url, init = {}) => {
  const text = String(url);
  const path = text.startsWith(ADMIN_URL) ? text.slice(ADMIN_URL.length) : text.slice(BOOT_URL.length);
  const httpMethod = init.method ?? "GET";
  const headers = new Headers(init.headers ?? {});
  recorded.push({
    path,
    method: httpMethod,
    body: init.body === undefined || init.body === null ? null : String(init.body),
    // The reference calls the global `fetch` directly here, so no signature header is attached.
    signed: headers.has("Signature") || headers.has("Signature-Input"),
  });
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const answered = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", new Date().toISOString().replace("Z", "000+00:00")],
  ]);
  const signed = authenticator.sign(answered, httpMethod, path.split("?")[0]);
  signed.set("Content-Type", "application/json");
  const body = path.startsWith("/agent/")
    ? {
        agent: agentState,
        controller: {
          state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
          ee: { ...client.controller.serder.sad },
        },
        ridx: 0,
        pidx: 0,
      }
    : {};
  return new Response(JSON.stringify(body), { status: 200, headers: signed });
};

await client.boot();
await client.connect();

// ---------------------------------------------------------------------------
// 3. Drive the rotation.
// ---------------------------------------------------------------------------

const prior = encryption(PASSCODE);
const salty = saltyAid(prior.encrypter);
const randy = randyAid(prior.encrypter);

const before = recorded.length;
await client.rotate(SECOND_PASSCODE, [salty.record, randy.record]);
const requests = recorded.slice(before).map((request) => ({ ...request }));
if (requests.length !== 1) {
  throw new Error(`the rotation made ${requests.length} requests, not one`);
}
const [sent] = requests;
const payload = JSON.parse(sent.body);

// ---------------------------------------------------------------------------
// 3b. The log the rotation lands on, and the rotation keripy accepts there.
// ---------------------------------------------------------------------------
//
// Connecting approves the agent's delegation with an interaction at sequence one, so the
// reference's rotation — always `s = "1"`, prior the current event — names that interaction as
// its prior at its own sequence number. keripy reads a `rot` at the log's current sequence number
// as a recovery and requires the prior to be the event before it. The corrected rotation is the
// same event at the next sequence number, built by the reference's own `rotate` and signed by the
// same two keys in the same placements; a third, at the next sequence number but naming the
// inception as prior, is refused for the other reason. `client_passcode_rotation_keripy.py` feeds
// all of them to keripy; this port's rotation must equal the corrected one byte for byte.

const bootRequest = recorded.find((request) => request.path === "/boot");
const approval = recorded.find((request) => request.path.includes("?type=ixn"));
if (bootRequest === undefined || approval === undefined) {
  throw new Error("the connection did not record its inception and its approval");
}
const booted = JSON.parse(bootRequest.body);
const approved = JSON.parse(approval.body);

const original = new Controller(PASSCODE, Tier.low);
const replacement = new Controller(SECOND_PASSCODE, Tier.low);
const oldCommitted = original.nsigner;
const newSigner = replacement.signer;
if (newSigner.verfer.qb64 !== payload.rot.k[0] || oldCommitted.verfer.qb64 !== payload.rot.k[1]) {
  throw new Error("the recorded rotation's keys are no longer the two controllers' keys");
}

const rebuilt = (sn, dig) => {
  const event = rotate({
    pre: controllerPrefix,
    keys: payload.rot.k,
    dig,
    sn,
    isith: ["1", "0"],
    nsith: "1",
    ndigs: payload.rot.n,
  });
  return {
    raw: event.raw,
    sigs: [oldCommitted.sign(b(event.raw), 1, false, 0).qb64, newSigner.sign(event.raw, 0).qb64],
  };
};

const referenceRotation = { raw: JSON.stringify(payload.rot), sigs: payload.sigs };
const sameAsRecorded = rebuilt(1, approved.ixn.d);
if (sameAsRecorded.raw !== referenceRotation.raw || sameAsRecorded.sigs.join() !== payload.sigs.join()) {
  throw new Error("rebuilding the recorded rotation no longer reproduces it; the comparison is stale");
}

const kel = {
  note: "Every event as raw text, signatures as qualified Base64. `inception` and `interaction` are what the connection sent; `reference_rotation` is the recorded request's; `corrected_rotation` and `inception_prior_rotation` are rebuilt by the reference's own `rotate` and signed by the same keys, the first of them proven to reproduce the recorded one at `s = 1`.",
  inception: { raw: JSON.stringify(booted.icp), sigs: [booted.sig] },
  interaction: { raw: JSON.stringify(approved.ixn), sigs: approved.sigs },
  reference_rotation: referenceRotation,
  corrected_rotation: rebuilt(2, approved.ixn.d),
  inception_prior_rotation: rebuilt(2, booted.icp.d),
};

// The same call again, with the empty list the pinned test passes: the loop never runs.
const emptyBefore = recorded.length;
await client.rotate(SECOND_PASSCODE, []);
const emptyPayload = JSON.parse(recorded.slice(emptyBefore)[0].body);

// ---------------------------------------------------------------------------
// 4. What the payload turns out to be sealed to.
// ---------------------------------------------------------------------------

const next = encryption(SECOND_PASSCODE);
const opens = (decrypter, qb64, transferable = false) => {
  try {
    return decrypter.decrypt(null, new Cipher({ qb64 }), transferable).qb64;
  } catch {
    return null;
  }
};

const saltySealed = payload.keys[salty.record.prefix].sxlt;
const randySealed = payload.keys[randy.record.prefix].prxs[0];

const sealing = {
  controller_salt: {
    opens_under_old: opens(prior.decrypter, payload.sxlt),
    opens_under_new: opens(next.decrypter, payload.sxlt),
  },
  salty_identifier: {
    opens_under_old: opens(prior.decrypter, saltySealed),
    opens_under_new: opens(next.decrypter, saltySealed),
  },
  randy_identifier: {
    opens_under_old: opens(prior.decrypter, randySealed, true),
    opens_under_new: opens(next.decrypter, randySealed, true),
  },
};

const oldSalt = MtrDex.Salt_128 + "A" + PASSCODE.substring(0, 21);
const newSalt = MtrDex.Salt_128 + "A" + SECOND_PASSCODE.substring(0, 21);
if (sealing.controller_salt.opens_under_new !== null) {
  throw new Error("the payload now opens under the new passcode; the finding is stale");
}
if (sealing.controller_salt.opens_under_old !== oldSalt) {
  throw new Error("the sealed controller salt is no longer the old salt");
}

// And a second rotation from the same client: the controller's salt never moved, so it derives
// its "old" committed key from the original passcode again.
const twice = (() => {
  const fresh = new Controller(PASSCODE, Tier.low);
  const first = fresh.rotate(SECOND_PASSCODE, []);
  const second = fresh.rotate("zyxwvutsrq9876543210k", []);
  return {
    first_old_key: first.rot.k[1],
    second_old_key: second.rot.k[1],
    identical: first.rot.k[1] === second.rot.k[1],
    bran_moved: fresh.bran !== oldSalt,
  };
})();

const quirks = {
  the_payload_is_sealed_to_the_passcode_being_left_behind: {
    declaration: NSIGNER,
    beside_it: [NBRAN, NSALTER],
    cipher_construction: declarations.cipher_construction,
    sealing,
    old_salt: oldSalt,
    new_salt: newSalt,
    note: "`nsigner` derives from `this.salter`, the old salt, where `nbran` and `nsalter` beside it are the new passcode's. It feeds the decrypter, which is right, and the encrypter, which is not. Driven: the controller salt and both identifiers' key material open under the old passcode and under the new one not at all — so a client that rotated and reconnected could not read its own identifiers, and whoever holds the old passcode still can. Rotating the signing keys does not rotate the encryption.",
    keripy: declarations.keripy,
    rust_decision:
      "this port follows keripy: the encrypter derives from the new salt, `sxlt` carries the new salt, and the controller's stored salt moves with its keys — which the fix requires, since material sealed to the new passcode cannot be opened by the old one a second time.",
  },
  the_sealed_salt_is_the_old_one: {
    declaration: SXLT_LINE,
    opens_to: sealing.controller_salt.opens_under_old,
    is_the_old_salt: sealing.controller_salt.opens_under_old === oldSalt,
    note: "`encrypter.encrypt(b(this.bran))` seals `this.bran`, which the rotation never updates — so the payload records the passcode being replaced rather than the one replacing it.",
    rust_decision:
      "`sealed_salt` carries the **new** salt under the new passcode's key, so the payload records the passcode now in force rather than the one it replaced, and the controller's stored salt moves with its keys.",
  },
  a_second_rotation_derives_from_the_original_salt: {
    ...twice,
    note: "`rotate` moves the signers, keys, and digests and leaves `bran`, `salter`, `ridx`, and `serder` behind, so the controller's salt and its keys disagree from the first rotation on, and every later rotation commits to the original passcode's key again.",
    rust_decision:
      "the salt moves with the keys, so a second rotation reveals the key the first one pre-committed to — which is what the chain requires and what the sealing fix depends on.",
  },
  nothing_upstream_exercises_the_re_encryption: {
    unit_test_calls: TEST_CALLS,
    identifier_count: TEST_CALLS[0].identifier_count,
    empty_payload_keys: Object.keys(emptyPayload.keys),
    note: "the one pinned call is `client.rotate('abcdefghijk0123456789', [])`. With an empty list the loop, both its branches, the key-state check, and every re-seal are skipped, and the recorded payload's `keys` map is empty. Four assertions cover the rotation event and nothing else.",
    rust_decision: "both branches, the key-state check, and the re-sealing are driven here and property-tested.",
  },
  the_rotation_travels_unsigned: {
    signed: sent.signed,
    path: sent.path,
    method: sent.method,
    note: "`rotate` calls the global `fetch` directly rather than the client's signed pipeline, so the request carrying every re-sealed secret has no HTTP signature — the same bypass the `client-lifecycle` fixture recorded for the delegation approval and both passcode calls. A KERIA agent applies the rotation and only then checks the request's signature against the controller's keys as they now stand: WebOfTrust KERIA 0.4.0 refuses an unsigned request there with 403 after it has already rotated.",
    rust_decision:
      "the request is signed with the key the rotation introduces, and the client signs everything afterwards with it (`fixtures/client-passcode-rotation-keripy/`).",
  },
  the_rotation_always_claims_sequence_one: {
    declaration: "export function rotate({ ..., sn = 1, ... })",
    rotate_call: "rotate({ pre: this.pre, keys: this.keys, dig: this.serder.sad['d'], isith: ['1', '0'], nsith: '1', ndigs: this.ndigs })",
    controller_sequence_before: approved.ixn.s,
    rotation_sequence: payload.rot.s,
    rotation_prior: payload.rot.p,
    prior_is_interaction_said: payload.rot.p === approved.ixn.d,
    keripy_verdicts: "fixtures/client-passcode-rotation-keripy/v1.json",
    note: "`Controller.rotate` never passes `sn`, so the builder's default of one is written whatever the log holds, and the prior is the controller's current event. A connected client's log holds the delegation-approval interaction at sequence one, so the rotation is a `rot` at sequence one over that interaction — which keripy's `Kever.rotate` reads as a recovery whose prior must be the inception, and refuses. A live KERIA answers 500. The only upstream test mocks the agent.",
    rust_decision:
      "built at the current sequence number plus one with the current event as prior — keripy's ordinary rotation — and the accepted rotation becomes the controller's current event so the next one chains.",
  },
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  secondary_reference: { upstream: "https://github.com/WebOfTrust/keripy.git", commit: keripySha },
  generated_on: "2026-09-16",
  sources: [
    "src/keri/app/clienting.ts",
    "src/keri/app/controller.ts",
    "test/app/clienting.test.ts",
    "keripy: src/keri/app/keeping.py",
    "src/keri/core/eventing.ts",
  ],
  provenance: {
    passcode: PASSCODE,
    second_passcode: SECOND_PASSCODE,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    fixed_clock_ms: FIXED_MS,
    agent_prefix: agentPrefix,
    controller_prefix: controllerPrefix,
    note: "The client is driven against a recording agent with its clock and the agent's key pinned. Sealed boxes draw a fresh ephemeral key per call, so ciphertexts cannot be compared byte for byte; this fixture records **what each sealed value opens to and under which passcode**, which is the property the finding is about. `PUBLIC TEST MATERIAL`: both passcodes are the pinned tests' own.",
  },
  declarations,
  request: {
    path: sent.path,
    method: sent.method,
    signed: sent.signed,
    body_fields: Object.keys(payload),
    key_entries: Object.keys(payload.keys),
    salty_entry_fields: Object.keys(payload.keys[salty.record.prefix]),
    randy_entry_fields: Object.keys(payload.keys[randy.record.prefix]),
    rotation: payload.rot,
    signature_count: payload.sigs.length,
  },
  identifiers: {
    salty: { prefix: salty.record.prefix, salt: salty.salt, state_keys: salty.record.state.k },
    randy: { prefix: randy.record.prefix, seeds: randy.seeds, next_seed: randy.next_seed, state_keys: randy.record.state.k },
  },
  sealing,
  kel,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-passcode-rotation/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-passcode-rotation fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
