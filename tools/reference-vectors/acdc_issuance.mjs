// Records the pinned signify-ts checkout's credential issuance and revocation artifacts.
//
// Roadmap 6.1 ported the two `Saider.saidify(...)` expressions that build a credential. What is
// left of the *pure* half of `Credentials.issue` and `Credentials.revoke` is the rest of what they
// construct before anything is sent: the `iss` transaction event, the `rev` transaction event, the
// interaction event that anchors either in the issuer's key event log, and the two CESR
// attachments an IPEX grant later carries. Everything after that — the keeper signatures' place in
// a request body, the path, the `POST`/`DELETE` — is Roadmap 6.11.
//
// The evidence has the same two halves as Roadmap 6.1's, for the same reason: the ported unit is a
// set of expressions rather than an exported function.
//
//   1. The **expressions themselves**, read from the reference's own syntax tree by its own pinned
//      TypeScript, so what this generator executes is provably production code.
//   2. The **outputs**, produced by the reference's own compiled `Saider`, `interact`, and the two
//      `core/utils.ts` serializers — and anchored against values the reference's own test suite
//      asserts against: `test/app/credentialing.test.ts` publishes a complete `iss` event, a
//      complete `ixn`, and both attachment strings inside its IPEX grant assertion, and
//      `test/core/utils.test.ts` publishes both serializers' output directly.
//
// Everything is deterministic: none of these builders derives a key, and the one clock reading —
// the revocation timestamp — is supplied instead, with its default expression recorded by text.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { Saider } from "../../reference/signify-ts/dist/keri/core/saider.js";
import { Serder } from "../../reference/signify-ts/dist/keri/core/serder.js";
import { interact } from "../../reference/signify-ts/dist/keri/core/eventing.js";
import {
  serializeACDCAttachment,
  serializeIssExnAttachment,
} from "../../reference/signify-ts/dist/keri/core/utils.js";
import { versify, Protocols, Serials, Ilks, d } from "../../reference/signify-ts/dist/keri/core/core.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// ---------------------------------------------------------------------------
// 1. The ported expressions, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");
const utils = parse("src/keri/core/utils.ts");

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

/** Every `.ts` file in the pinned source and test trees, so an absence can be scanned. */
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

const issueMethod = method(credentialing.source, "Credentials", "issue");
const revokeMethod = method(credentialing.source, "Credentials", "revoke");
if (issueMethod === null || revokeMethod === null) {
  throw new Error("Credentials.issue or .revoke is no longer where this generator expects it");
}

const isSaidify = (node) =>
  ts.isCallExpression(node) &&
  ts.isPropertyAccessExpression(node.expression) &&
  node.expression.expression.getText() === "Saider" &&
  node.expression.name.getText() === "saidify";
const isInteract = (node) => ts.isCallExpression(node) && node.expression.getText() === "interact";

/** The `_rev` object literal, which `revoke` saidifies through a variable rather than inline. */
const revocationLiteral = firstText(
  revokeMethod,
  (node) => ts.isVariableDeclaration(node) && node.name.getText() === "_rev",
);

const declarations = {
  issuance_saidify_expression: firstText(
    issueMethod,
    (node) => isSaidify(node) && node.getText().includes("Ilks.iss"),
  ),
  issuance_anchor_expression: firstText(issueMethod, isInteract),
  revocation_literal: revocationLiteral,
  revocation_saidify_expression: firstText(revokeMethod, isSaidify),
  revocation_anchor_expression: firstText(revokeMethod, isInteract),
  revocation_registry_fallback: firstText(
    revokeMethod,
    (node) => ts.isIfStatement(node) && node.getText().includes("'ri' in cred.sad"),
  ),
  acdc_attachment_body: firstText(
    utils.source,
    (node) => ts.isFunctionDeclaration(node) && node.name?.getText() === "serializeACDCAttachment",
  ),
  iss_attachment_body: firstText(
    utils.source,
    (node) => ts.isFunctionDeclaration(node) && node.name?.getText() === "serializeIssExnAttachment",
  ),
  keri_version_string: versify(Protocols.KERI, undefined, Serials.JSON, 0),
  issuance_ilk: Ilks.iss,
  revocation_ilk: Ilks.rev,
  notes: {
    issuance:
      "the `iss` event's `dt` is the credential's *attribute* timestamp — `dt: subject.dt` — not a second clock reading, so issuing commits the credential and its transaction event to the same instant",
    issuance_anchor:
      "the anchoring interaction seals one `{i, s, d}` triple naming the transaction event, at the issuer's next sequence number, over the key state's digest",
    revocation:
      "the `rev` event's sequence number is the literal string '1' and its `p` is the credential's current status digest, so the reference can only revoke a credential whose transaction log holds exactly one prior event",
    attachments:
      "`serializeACDCAttachment` is passed the *issuance* event despite its parameter being named `anc`, so the triple names (credential SAID, 0, iss SAID); `serializeIssExnAttachment` is passed the anchor and produces a pipelined couple naming it",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null) {
    throw new Error(`the expression for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. The ported expressions, re-expressed exactly as the reference writes them.
// ---------------------------------------------------------------------------

const VS = versify(Protocols.KERI, undefined, Serials.JSON, 0);

/** `Credentials.issue`'s third `saidify`, with the credential's own attribute timestamp. */
function issuanceEvent({ credential, registry, timestamp }) {
  const [, iss] = Saider.saidify({
    v: VS,
    t: Ilks.iss,
    d: "",
    i: credential,
    s: "0",
    ri: registry,
    dt: timestamp,
  });
  return iss;
}

/** `Credentials.revoke`'s `_rev` literal and its `saidify`. */
function revocationEvent({ credential, registry, prior, timestamp }) {
  const [, rev] = Saider.saidify({
    v: VS,
    t: Ilks.rev,
    d: "",
    i: credential,
    s: "1",
    ri: registry,
    p: prior,
    dt: timestamp,
  });
  return rev;
}

/** The interaction both methods build to anchor a transaction event. */
function anchor({ issuer, sequenceNumber, prior, event }) {
  return interact({
    pre: issuer,
    sn: sequenceNumber,
    data: [{ i: event.i, s: event.s, d: event.d }],
    dig: prior,
    version: undefined,
    kind: undefined,
  });
}

/** Records one complete issuance: the transaction event, its anchor, and both attachments. */
function recordIssuance(note, args) {
  const iss = issuanceEvent(args);
  const serder = new Serder(iss);
  const anc = anchor({ ...args, event: iss });
  return {
    note,
    iss_raw: serder.raw,
    iss_said: iss.d,
    iss_size: serder.size,
    anchor_raw: anc.raw,
    anchor_said: anc.sad.d,
    anchor_size: anc.size,
    anchor_seal: anc.sad.a,
    credential_attachment: d(serializeACDCAttachment(serder)),
    issuance_attachment: d(serializeIssExnAttachment(anc)),
    reference_verifies: new Saider({ qb64: iss.d }).verify(iss, true, true) && new Saider({ qb64: anc.sad.d }).verify(anc.sad, true, true),
  };
}

/** Records one complete revocation: the transaction event and its anchor. */
function recordRevocation(note, args) {
  const rev = revocationEvent(args);
  const serder = new Serder(rev);
  const anc = anchor({ ...args, event: rev });
  return {
    note,
    rev_raw: serder.raw,
    rev_said: rev.d,
    rev_size: serder.size,
    anchor_raw: anc.raw,
    anchor_said: anc.sad.d,
    anchor_size: anc.size,
    anchor_seal: anc.sad.a,
    reference_verifies: new Saider({ qb64: rev.d }).verify(rev, true, true) && new Saider({ qb64: anc.sad.d }).verify(anc.sad, true, true),
  };
}

// The credential the pinned `test/app/test-utils.ts` checks in, which Roadmap 6.1 reproduces.
const MOCK_CREDENTIAL = "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo";
const MOCK_ISSUER = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const MOCK_REGISTRY = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const MOCK_TIMESTAMP = "2023-08-23T15:16:07.553000+00:00";
// The issuance event the pinned unit test publishes, and the credential's own status digest.
const MOCK_ISSUANCE = "ENf3IEYwYtFmlq5ZzoI-zFzeR7E3ZNRN2YH_0KAFbdJW";

// The vLEI identifiers, schema SAIDs, and registries the pinned integration suites issue against.
const QVI_REGISTRY = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const LE_CREDENTIAL = "EOAE2mCC8e2oNXbXPtiDFMMGrQ6N8iS7ZUAS2fWwqua0";
const ECR_CREDENTIAL = "ECV74hW2vMvUaBbpgbsoTyl79D5pRhyIXTpVXn4tn-bi";

const issuances = {
  pinned_mock_credential: recordIssuance(
    "the issuance of the credential the pinned `test-utils.ts` checks in, at the issuer's first interaction; its `iss` SAID is the one `credentialing.test.ts` publishes",
    {
      credential: MOCK_CREDENTIAL,
      registry: MOCK_REGISTRY,
      timestamp: MOCK_TIMESTAMP,
      issuer: MOCK_ISSUER,
      sequenceNumber: 1,
      prior: MOCK_CREDENTIAL,
    },
  ),
  later_in_the_log: recordIssuance("an issuance anchored well into the issuer's key event log", {
    credential: LE_CREDENTIAL,
    registry: QVI_REGISTRY,
    timestamp: MOCK_TIMESTAMP,
    issuer: MOCK_ISSUER,
    sequenceNumber: 42,
    prior: MOCK_ISSUANCE,
  }),
  hexadecimal_sequence_number: recordIssuance(
    "an anchor whose sequence number needs hexadecimal digits, which the event writes lowercase and unpadded",
    {
      credential: ECR_CREDENTIAL,
      registry: QVI_REGISTRY,
      timestamp: MOCK_TIMESTAMP,
      issuer: MOCK_ISSUER,
      sequenceNumber: 255,
      prior: MOCK_ISSUANCE,
    },
  ),
  large_sequence_number: recordIssuance("an anchor at a sequence number past 32 bits", {
    credential: MOCK_CREDENTIAL,
    registry: MOCK_REGISTRY,
    timestamp: MOCK_TIMESTAMP,
    issuer: MOCK_ISSUER,
    sequenceNumber: 4294967296,
    prior: MOCK_ISSUANCE,
  }),
  distinct_timestamp: recordIssuance("a credential stamped at a different instant, which changes the transaction event alone", {
    credential: MOCK_CREDENTIAL,
    registry: MOCK_REGISTRY,
    timestamp: "2021-06-27T21:26:21.233257+00:00",
    issuer: MOCK_ISSUER,
    sequenceNumber: 1,
    prior: MOCK_CREDENTIAL,
  }),
};

const revocations = {
  pinned_mock_credential: recordRevocation(
    "revoking the pinned mock credential, whose prior transaction event is the issuance above",
    {
      credential: MOCK_CREDENTIAL,
      registry: MOCK_REGISTRY,
      prior: MOCK_ISSUANCE,
      timestamp: MOCK_TIMESTAMP,
      issuer: MOCK_ISSUER,
      sequenceNumber: 2,
    },
  ),
  later_in_the_log: recordRevocation("a revocation anchored well into the issuer's key event log", {
    credential: LE_CREDENTIAL,
    registry: QVI_REGISTRY,
    prior: MOCK_ISSUANCE,
    timestamp: MOCK_TIMESTAMP,
    issuer: MOCK_ISSUER,
    sequenceNumber: 43,
  }),
  distinct_timestamp: recordRevocation("a revocation at a different instant", {
    credential: ECR_CREDENTIAL,
    registry: QVI_REGISTRY,
    prior: MOCK_ISSUANCE,
    timestamp: "2021-06-27T21:26:21.233257+00:00",
    issuer: MOCK_ISSUER,
    sequenceNumber: 7,
  }),
};

// ---------------------------------------------------------------------------
// 3. The artifacts the reference's own test suite publishes.
// ---------------------------------------------------------------------------

const credentialingTest = parse("test/app/credentialing.test.ts");
const utilsTest = parse("test/core/utils.test.ts");

/** Reads one string literal assertion out of a pinned test by its surrounding text. */
function pinnedStrings(source, minimumLength) {
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

/** The concatenated `end` string the pinned IPEX grant assertion publishes. */
function pinnedGrantAttachment(source) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isBinaryExpression(node) && node.getText().includes("-LAg4AACA-e-acdc-IAB")) {
      // A `+`-concatenated chain of string literals; evaluating it is exactly what the test does.
      const parts = [];
      const collect = (child) => {
        if (ts.isStringLiteral(child)) {
          parts.push(child.text);
        } else {
          ts.forEachChild(child, collect);
        }
      };
      collect(node);
      found = parts.join("");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const grantAttachment = pinnedGrantAttachment(credentialingTest.source);
if (grantAttachment === null) {
  throw new Error("the pinned IPEX grant attachment assertion is no longer where this generator expects it");
}

// The pinned IPEX test builds its own `iss` and anchor, then asserts the grant that embeds them.
// Rebuilding both here and finding their bytes inside that assertion is what makes the published
// values evidence for this module rather than for Roadmap 6.3's.
const pinnedIss = issuanceEvent({
  credential: MOCK_CREDENTIAL,
  registry: MOCK_REGISTRY,
  timestamp: MOCK_TIMESTAMP,
});
const pinnedIsserder = new Serder(pinnedIss);
// The pinned test's anchor seals `[{}]` rather than the transaction event, because it is testing
// the grant rather than the issuance; it is reproduced exactly as written.
const pinnedAnc = interact({
  pre: MOCK_ISSUER,
  sn: 1,
  data: [{}],
  dig: MOCK_CREDENTIAL,
  version: undefined,
  kind: undefined,
});

const pinnedArtifacts = {
  iss_raw: pinnedIsserder.raw,
  iss_said: pinnedIss.d,
  iss_said_matches_published: pinnedIss.d === MOCK_ISSUANCE,
  anchor_raw: pinnedAnc.raw,
  anchor_said: pinnedAnc.sad.d,
  anchor_seals_empty_object: JSON.stringify(pinnedAnc.sad.a) === "[{}]",
  credential_attachment: d(serializeACDCAttachment(pinnedIsserder)),
  issuance_attachment: d(serializeIssExnAttachment(pinnedAnc)),
  grant_attachment: grantAttachment,
  attachments_appear_in_grant:
    grantAttachment.includes(d(serializeACDCAttachment(pinnedIsserder))) &&
    grantAttachment.includes(d(serializeIssExnAttachment(pinnedAnc))),
  note: "the pinned `credentialing.test.ts` builds an `iss` and an `ixn` by hand and asserts the IPEX grant embedding them; rebuilding both from the reference's own expressions reproduces the published `iss` SAID, and both attachment strings appear verbatim inside the published grant attachment",
};
if (!pinnedArtifacts.iss_said_matches_published || !pinnedArtifacts.attachments_appear_in_grant) {
  throw new Error("the pinned issuance artifacts no longer reproduce");
}

/** The two serializer vectors `test/core/utils.test.ts` publishes directly. */
const pinnedSerializers = (() => {
  const [, issData] = Saider.saidify({ d: "", v: VS });
  const [, acdcData] = Saider.saidify({
    i: "EP-hA0w9X5FDonCDxQv32OTCAvcxkZxgDLOnDb3Jcn3a",
    d: "",
    v: versify(Protocols.ACDC, undefined, Serials.JSON, 0),
    a: { LEI: "123" },
  });
  const published = pinnedStrings(utilsTest.source, 40);
  return {
    iss_attachment_input: JSON.stringify(issData),
    iss_attachment: d(serializeIssExnAttachment(new Serder(issData))),
    acdc_attachment_input: JSON.stringify(acdcData),
    acdc_attachment: d(serializeACDCAttachment(new Serder(acdcData))),
    published_in_test: published.filter((value) => value.startsWith("-VAS") || value.startsWith("-IAB")),
    note: "`test/core/utils.test.ts` asserts both serializers directly; its `iss` case carries no `s` field at all, so `Serder.sn` reads it as zero",
  };
})();

// ---------------------------------------------------------------------------
// 4. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function quirk(note, rustDecision, produce) {
  return { ...produce(), note, rust_decision: rustDecision };
}

const quirks = {
  revocation_sequence_number_is_always_one: quirk(
    "`_rev.s` is the literal string '1', so the reference can only revoke a credential whose transaction log holds exactly one prior event. A credential in a backed registry, whose log carries backer rotations, or one somehow revoked twice, gets an event claiming a position it does not occupy.",
    "the sequence number is a required input, defaulting to one; the reference's only reachable value is reproduced and anything else is expressible.",
    () => ({ literal_sequence_number: revocationEvent({ credential: MOCK_CREDENTIAL, registry: MOCK_REGISTRY, prior: MOCK_ISSUANCE, timestamp: MOCK_TIMESTAMP }).s }),
  ),
  revocation_reads_the_registry_from_ri_or_rd: quirk(
    "revocation accepts the KERI 2 spelling `rd` as well as `ri`, and throws when neither is present — but Roadmap 6.1's builder always writes `ri`, so the `rd` branch is unreachable from a credential this port built.",
    "the registry is a typed required input; `rd` is unrepresentable here, as `PORTING.md` §5.12 already records CESR 2 to be out of scope.",
    () => ({ fallback_expression: declarations.revocation_registry_fallback }),
  ),
  revocation_timestamp_defaults_to_the_clock: {
    expression: firstText(revokeMethod, (node) => ts.isCallExpression(node) && node.getText().includes("toISOString")),
    note: "the revocation timestamp defaults to a clock reading with three zero digits standing in for microseconds it never had, exactly as Roadmap 6.1's attribute timestamp does.",
    rust_decision: "required: a protocol crate reads no clock, so the timestamp is a validated `Timestamp` the caller supplies.",
  },
  issuance_reuses_the_credential_timestamp: quirk(
    "the `iss` event takes `dt: subject.dt` — the credential's own attribute timestamp — rather than reading the clock a second time, so a credential and its transaction event always agree.",
    "reproduced, and made structural: the issuance builder reads the timestamp off the credential rather than taking one.",
    () => {
      const iss = issuanceEvent({ credential: MOCK_CREDENTIAL, registry: MOCK_REGISTRY, timestamp: MOCK_TIMESTAMP });
      return { credential_timestamp: MOCK_TIMESTAMP, issuance_timestamp: iss.dt, identical: iss.dt === MOCK_TIMESTAMP };
    },
  ),
  acdc_attachment_is_passed_the_issuance_event: quirk(
    "`serializeACDCAttachment(anc)` names its parameter `anc` but every call site passes the *issuance* event, so the triple it builds is (credential SAID, 0, iss SAID) — the credential's own transaction inception, not the key event anchoring it.",
    "the attachment is a method on the issuance event, so there is no parameter to pass the wrong value to.",
    () => ({ triple: d(serializeACDCAttachment(pinnedIsserder)) }),
  ),
  missing_sequence_number_reads_as_zero: quirk(
    "`Serder.sn` builds a `CesrNumber` from `sad['s']`; the pinned `utils.test.ts` vector has no `s` field at all, and the resulting couple carries sequence number zero rather than failing.",
    "unrepresentable: a sequence number is a `u128` on the typed event, never read back out of an untyped map.",
    () => {
      const [, issData] = Saider.saidify({ d: "", v: VS });
      return { input: JSON.stringify(issData), attachment: d(serializeIssExnAttachment(new Serder(issData))) };
    },
  ),
  establishment_only_is_unimplemented: {
    scan: scan("Establishment only not implemented"),
    note: "both `issue` and `revoke` throw outright when the issuer's configuration carries the `EO` trait, because anchoring in an establishment-only log needs a rotation event neither builds.",
    rust_decision: "the anchor is an interaction event and nothing else; an establishment-only issuer is refused with a typed error naming the trait, rather than throwing a string.",
  },
  backed_transaction_events_have_no_builder: {
    scan_bis: scan("Ilks.bis"),
    scan_brv: scan("Ilks.brv"),
    note: "the ilk table declares `bis` and `brv` — the backed spellings of issuance and revocation, used when a registry has backers — but nothing in the pinned tree constructs either.",
    rust_decision: "`N/A`, on the same evidence as Roadmap 3.6's receipt and query messages; the ilks exist in `signify-keri::event::kind` and no builder is invented here.",
  },
  revocation_prior_comes_from_the_server: {
    expression: firstText(revokeMethod, (node) => ts.isPropertyAssignment(node) && node.getText().startsWith("p:")),
    note: "`p` is read from `cred.status.d`, the credential state KERIA returns, so the reference cannot revoke without first fetching the credential.",
    rust_decision: "the prior digest is a required typed input, so revocation artifacts are constructible offline from a status a caller already holds.",
  },
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: [
    "src/keri/app/credentialing.ts",
    "src/keri/core/utils.ts",
    "test/app/credentialing.test.ts",
    "test/core/utils.test.ts",
  ],
  provenance: {
    credential: MOCK_CREDENTIAL,
    issuer: MOCK_ISSUER,
    registry: MOCK_REGISTRY,
    timestamp: MOCK_TIMESTAMP,
    note: "every value is deterministic: none of these builders derives a key, and the credential, issuer, registry, and timestamp are the pinned `test-utils.ts` mock credential's own, which Roadmap 6.1 reproduces byte for byte",
  },
  declarations,
  issuances,
  revocations,
  pinned_artifacts: pinnedArtifacts,
  pinned_serializers: pinnedSerializers,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/acdc-issuance/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("acdc-issuance fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
