// Records the pinned signify-ts checkout's ACDC credential construction.
//
// Roadmap 6.1 ports the two `Saider.saidify(...)` expressions inside `Credentials.issue` — the
// attribute block and the credential itself. Everything around them (the TEL issuance event, the
// anchoring interaction, the keeper signatures, the POST) is Roadmap 6.2 and 6.11 and is
// deliberately not driven here.
//
// The evidence is therefore in two independent halves:
//
//   1. The **expressions themselves**, read from the reference's own syntax tree by its own pinned
//      TypeScript, so the generator is provably re-expressing production code rather than a
//      paraphrase of it. This is the technique Roadmap 5.4 used for the retry formula.
//   2. The **outputs**, produced by the reference's own compiled `Saider` and `versify`, and
//      independently anchored: the credential the reference's own `test/app/test-utils.ts` checks
//      in as `mockCredential.sad` is rebuilt here from its inputs and reproduces both of its
//      published SAIDs, so at least one vector is confirmed against a value the reference asserts
//      against rather than against this generator.
//
// Everything here is deterministic: `saidify` reads no clock and derives no keys. The one clock
// reading in the ported code is the `dt` default, which is recorded by expression and shape only.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { Saider } from "../../reference/signify-ts/dist/keri/core/saider.js";
import { versify, Protocols, Serials } from "../../reference/signify-ts/dist/keri/core/core.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// ---------------------------------------------------------------------------
// 1. The ported expressions, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

/** Parses one pinned TypeScript file with the reference's own compiler. */
function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const credentialing = parse("src/keri/app/credentialing.ts");

/** Returns the body of one named method of one named class. */
function methodBody(source, className, methodName) {
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

/** Collects the source text of every `Saider.saidify(...)` call inside a node, normalised. */
function saidifyCalls(node) {
  const calls = [];
  const visit = (child) => {
    if (
      ts.isCallExpression(child) &&
      ts.isPropertyAccessExpression(child.expression) &&
      child.expression.expression.getText() === "Saider" &&
      child.expression.name.getText() === "saidify"
    ) {
      calls.push(child.getText().replace(/\s+/g, " "));
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return calls;
}

/** Collects the property names of one exported interface, in declaration order. */
function interfaceMembers(source, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isInterfaceDeclaration(node) && node.name.getText() === name) {
      found = node.members.map((member) => ({
        name: member.name?.getText() ?? "[index]",
        optional: member.questionToken !== undefined,
        type: member.type?.getText().replace(/\s+/g, " ") ?? null,
      }));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Collects the static property initialisers of one exported class. */
function staticMembers(source, name) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === name) {
      found = node.members
        .filter((member) => ts.isPropertyDeclaration(member))
        .map((member) => ({
          name: member.name?.getText() ?? "",
          value: member.initializer?.getText().replace(/^'|'$/g, "") ?? null,
        }));
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const issueMethod = methodBody(credentialing.source, "Credentials", "issue");
if (issueMethod === null) {
  throw new Error("Credentials.issue is no longer where this generator expects it");
}
const issueSaidifyCalls = saidifyCalls(issueMethod);
if (issueSaidifyCalls.length !== 3) {
  throw new Error(`expected three saidify calls in Credentials.issue, found ${issueSaidifyCalls.length}`);
}

/** Every `.ts` file in the pinned source and test trees, so an absence can be scanned rather than asserted. */
function pinnedTypeScriptFiles() {
  const roots = ["src", "test", "test-integration", "examples"];
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
  for (const root of roots) {
    walk(root);
  }
  return files.sort();
}

/** Counts one needle across the pinned tree, recording every file that holds it. */
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

const PINNED_FILES = pinnedTypeScriptFiles();

const declarations = {
  credential_subject: interfaceMembers(credentialing.source, "CredentialSubject"),
  credential_data: interfaceMembers(credentialing.source, "CredentialData"),
  credential_filter: interfaceMembers(credentialing.source, "CredentialFilter"),
  credential_types: staticMembers(credentialing.source, "CredentialTypes"),
  attribute_saidify_expression: issueSaidifyCalls[0],
  credential_saidify_expression: issueSaidifyCalls[1],
  issuance_saidify_expression: issueSaidifyCalls[2],
  attribute_saidify_note:
    "the first saidify in `Credentials.issue` builds the attribute block: an empty `d` first, the caller's attributes spread over it, then `dt` — whose value is the caller's own when present, so an attribute block naming `dt` keeps that field where the caller put it",
  credential_saidify_note:
    "the second builds the credential itself in the fixed field order v, d, u, i, ri, s, a, e, r; `JSON.stringify` drops every `undefined`, so an absent optional field is simply absent",
  issuance_saidify_note:
    "the third builds the TEL issuance event and is Roadmap 6.2's, recorded here only to prove this generator read the whole method and left it alone",
  acdc_version_string: versify(Protocols.ACDC, undefined, Serials.JSON, 0),
  digest_code: MtrDex.Blake3_256,
};

// ---------------------------------------------------------------------------
// 2. The two ported expressions, re-expressed exactly as the reference writes them.
// ---------------------------------------------------------------------------

/** The instant every recorded vector stamps, standing in for the reference's `new Date()`. */
const DT = "2023-08-23T15:16:07.553000+00:00";

/** The issuing identifier the pinned `test-utils.ts` mock credential names. */
const ISSUER = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";

/**
 * Runs the two ported expressions over one `CredentialData`.
 *
 * This is `Credentials.issue` with the hab lookup, the TEL event, the anchor, the signatures, and
 * the request removed — none of which is Roadmap 6.1's — and with the `dt` default supplied rather
 * than read from the clock.
 */
function build(args, prefix = ISSUER, fallbackTimestamp = DT) {
  const [, subject] = Saider.saidify({
    d: "",
    ...args.a,
    dt: args.a?.dt ?? fallbackTimestamp,
  });

  const [, acdc] = Saider.saidify({
    v: versify(Protocols.ACDC, undefined, Serials.JSON, 0),
    d: "",
    u: args.u,
    i: args.i ?? prefix,
    ri: args.ri,
    s: args.s,
    a: subject,
    e: args.e,
    r: args.r,
  });

  return { subject, acdc };
}

/** Records one credential's complete output, plus the reference's own verdict on it. */
function record(note, args, options = {}) {
  const { subject, acdc } = build(args, options.prefix ?? ISSUER);
  const raw = JSON.stringify(acdc);
  const attributesRaw = JSON.stringify(subject);
  const saider = new Saider({ qb64: acdc.d });
  const attributeSaider = new Saider({ qb64: subject.d });
  return {
    note,
    raw,
    said: acdc.d,
    size: new TextEncoder().encode(raw).length,
    version: acdc.v,
    attributes_raw: attributesRaw,
    attributes_said: subject.d,
    // Read back from the serialization rather than from `Object.keys`, which still lists the
    // slots holding `undefined` that `JSON.stringify` drops — so a credential with no `u` reports
    // a `u` key that no byte of the digested document carries.
    attribute_labels: Object.keys(JSON.parse(attributesRaw)),
    credential_labels: Object.keys(JSON.parse(raw)),
    // The reference accepting its own output is what a recipient would do with it.
    reference_verifies: saider.verify(acdc, true, true) && attributeSaider.verify(subject, true),
  };
}

// The registry, schema, and issuee the pinned `credentialing.test.ts` uses in its `issue` call.
const PINNED_REGISTRY = "EP10ooRj0DJF0HWZePEYMLPl-arMV-MAoTKK-o3DXbgX";
const PINNED_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const PINNED_ISSUEE = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";

// The vLEI identifiers, schema SAIDs, attribute data, and rule blocks the pinned integration
// suites issue against. They are the only realistic credential shapes in the pinned tree.
const QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao";
const LE_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY";
const ECR_SCHEMA_SAID = "EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw";
const QVI_REGISTRY = "EGK216v1yguLfex4YRFnG7k1sXRjh3OKY7QqzdKsx7df";
const QVI_ISSUER = "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1";
const LE_HOLDER = "EKvn1M6shPLnXTb47bugVJblKMuWC0TcLIePP8p98Bby";
const ECR_HOLDER = "EG2XjQN-3jPN5rcR4spLjaJyM4zA6Lgg-Hd5vSMymu5p";
const PRIVACY_SALT = "0AD6E0lCLBQ0-JOFBoTd9k8I";
const SUBJECT_SALT = "0AB2eqZ4Ce4VPaWCTYlG5r9J";

const USAGE_DISCLAIMER =
  "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws or that an implied or expressly intended purpose will be fulfilled.";
const ISSUANCE_DISCLAIMER =
  "All information in a valid, unexpired, and non-revoked vLEI Credential, as defined in the associated Ecosystem Governance Framework, is accurate as of the date the validation process was complete. The vLEI Credential has been issued to the legal entity or person named in the vLEI Credential as the subject; and the qualified vLEI Issuer exercised reasonable care to perform the validation process set forth in the vLEI Ecosystem Governance Framework.";
const PRIVACY_DISCLAIMER =
  "It is the sole responsibility of Holders as Issuees of an ECR vLEI Credential to present that Credential in a privacy-preserving manner using the mechanisms provided in the Issuance and Presentation Exchange (IPEX) protocol specification and the Authentic Chained Data Container (ACDC) specification. https://github.com/WebOfTrust/IETF-IPEX and https://github.com/trustoverip/tswg-acdc-specification.";

/** The rule and edge blocks the pinned integration suites saidify before issuing. */
const LE_RULES = Saider.saidify({
  d: "",
  usageDisclaimer: { l: USAGE_DISCLAIMER },
  issuanceDisclaimer: { l: ISSUANCE_DISCLAIMER },
})[1];
const ECR_RULES = Saider.saidify({
  d: "",
  usageDisclaimer: { l: USAGE_DISCLAIMER },
  issuanceDisclaimer: { l: ISSUANCE_DISCLAIMER },
  privacyDisclaimer: { l: PRIVACY_DISCLAIMER },
})[1];
const LE_EDGES = Saider.saidify({
  d: "",
  qvi: { n: "EMwcsEMUEruPXVwPCW7zmqmN8m0I3CihxolBm-RDrsJo", s: QVI_SCHEMA_SAID },
})[1];

const supporting = {
  le_rules: { raw: JSON.stringify(LE_RULES), said: LE_RULES.d },
  ecr_rules: { raw: JSON.stringify(ECR_RULES), said: ECR_RULES.d },
  le_edges: { raw: JSON.stringify(LE_EDGES), said: LE_EDGES.d },
  note: "the rule and edge blocks the pinned vLEI integration suites build with `Saider.saidify` before issuing; they reach `issue` already complete and are committed verbatim",
};

const credentials = {
  pinned_mock_credential: record(
    "the credential the pinned `test/app/test-utils.ts` checks in as `mockCredential.sad`, rebuilt from its inputs; both of its published SAIDs must reproduce",
    {
      ri: QVI_REGISTRY,
      s: QVI_SCHEMA_SAID,
      a: { i: LE_HOLDER, dt: DT, LEI: "5493001KJTIIGC8Y1R17" },
    },
    { prefix: QVI_ISSUER },
  ),
  pinned_unit_test_arguments: record(
    "the exact arguments the pinned `credentialing.test.ts` passes to `issue`, whose own `dt` is a clock reading and is supplied here instead",
    { ri: PINNED_REGISTRY, s: PINNED_SCHEMA, a: { i: PINNED_ISSUEE, LEI: "1234" } },
  ),
  qvi_singlesig: record("the QVI credential of the pinned single-signature vLEI suite", {
    i: QVI_ISSUER,
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT, LEI: "254900OPPU84GM83MG36" },
  }),
  le_with_edges_and_rules: record("the LE credential: an attribute block, an edge block, and two rules", {
    i: QVI_ISSUER,
    ri: QVI_REGISTRY,
    s: LE_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT, LEI: "875500ELOZEL05BVXV37" },
    e: LE_EDGES,
    r: LE_RULES,
  }),
  ecr_with_both_salts: record("the ECR credential: a privacy salt at both levels and three rules", {
    u: PRIVACY_SALT,
    i: QVI_ISSUER,
    ri: QVI_REGISTRY,
    s: ECR_SCHEMA_SAID,
    a: {
      i: ECR_HOLDER,
      dt: DT,
      u: SUBJECT_SALT,
      LEI: "875500ELOZEL05BVXV37",
      personLegalName: "John Doe",
      engagementContextRole: "EBA Data Submitter",
    },
    e: LE_EDGES,
    r: ECR_RULES,
  }),
  untargeted: record("a credential naming no issuee, so its attribute block is `d` and `dt` alone", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: {},
  }),
  timestamp_last: record("no `dt` among the attributes, so the default is appended after them", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, LEI: "254900OPPU84GM83MG36" },
  }),
  timestamp_first: record("`dt` written before the issuee, which keeps it in the caller's position", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { dt: DT, i: LE_HOLDER, LEI: "254900OPPU84GM83MG36" },
  }),
  edges_only: record("an edge block with no rules", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT },
    e: LE_EDGES,
  }),
  rules_only: record("rules with no edges", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT },
    r: LE_RULES,
  }),
  nested_attribute_values: record("every JSON shape a SAID can commit to: null, booleans, integers, arrays, maps", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: {
      i: LE_HOLDER,
      dt: DT,
      absent: null,
      flag: true,
      cleared: false,
      count: 42,
      negative: -7,
      zero: 0,
      largest: 9007199254740991,
      list: [1, "two", { three: 3 }, [4], null],
      nested: { inner: { deeper: "value" } },
      empty_map: {},
      empty_list: [],
      empty_text: "",
    },
  }),
  unicode_attribute_values: record("non-ASCII attribute text, which the size in the version string counts as bytes", {
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT, personLegalName: "Geçmiş Özge", note: "éèê 中文 🔐" },
  }),
  privacy_salt_only: record("a privacy salt on the credential but not on its attributes", {
    u: PRIVACY_SALT,
    ri: QVI_REGISTRY,
    s: QVI_SCHEMA_SAID,
    a: { i: LE_HOLDER, dt: DT, LEI: "254900OPPU84GM83MG36" },
  }),
};

// ---------------------------------------------------------------------------
// 3. The mock credential the reference's own test suite checks in.
// ---------------------------------------------------------------------------

const testUtils = parse("test/app/test-utils.ts");

/** Reads the `mockCredential.sad` object literal from the reference's test helper. */
function mockCredentialSad(source) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      node.name.getText() === "mockCredential" &&
      node.initializer !== undefined &&
      ts.isObjectLiteralExpression(node.initializer)
    ) {
      for (const property of node.initializer.properties) {
        if (ts.isPropertyAssignment(property) && property.name.getText() === "sad") {
          // The literal is plain JSON apart from its single quotes and trailing commas.
          found = JSON.parse(
            property.initializer
              .getText()
              .replace(/'/g, '"')
              .replace(/,(\s*[}\]])/g, "$1")
              .replace(/([{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:/g, '$1"$2":'),
          );
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const mockSad = mockCredentialSad(testUtils.source);
if (mockSad === null) {
  throw new Error("mockCredential.sad is no longer where this generator expects it");
}

const pinnedArtifact = {
  raw: JSON.stringify(mockSad),
  said: mockSad.d,
  attributes_said: mockSad.a.d,
  reference_verifies: new Saider({ qb64: mockSad.d }).verify(mockSad, true, true),
  rebuilt_matches: JSON.stringify(mockSad) === credentials.pinned_mock_credential.raw,
  note: "read from `test/app/test-utils.ts` by the reference's own compiler, verified by the reference's own `Saider`, and byte-identical to the credential this generator rebuilds from its inputs",
};
if (!pinnedArtifact.reference_verifies || !pinnedArtifact.rebuilt_matches) {
  throw new Error("the pinned mock credential no longer reproduces from its inputs");
}

// ---------------------------------------------------------------------------
// 4. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

/** Records what the reference emits for an input this port refuses. */
function quirk(note, rustDecision, produce) {
  return { ...produce(), note, rust_decision: rustDecision };
}

const quirks = {
  numeric_attribute_labels_are_hoisted: quirk(
    "JavaScript orders array-index-like keys ahead of every other key, so an attribute named `0` is serialised before the `d` written first — and the SAID commits to that order. `01` has a leading zero, is not an array index, and stays in insertion order.",
    "refused: `Sad` is insertion-ordered by ADR `0008`, so reproducing the hoist is impossible and deriving a different SAID from the same inputs would be an interoperability defect. An array-index-like attribute, edge, or rule label is rejected.",
    () => {
      const { subject, acdc } = build({
        ri: QVI_REGISTRY,
        s: QVI_SCHEMA_SAID,
        a: { b: "x", 0: "y", 10: "z", "01": "w" },
      });
      return { raw: JSON.stringify(acdc), attribute_labels: Object.keys(subject) };
    },
  ),
  attribute_version_string_is_sized: quirk(
    "an attribute named `v` makes the attribute block look like a message to `Saider._derive`, which sizes it: the caller's `ACDC10JSON000000_` comes back rewritten to the block's own length.",
    "refused: `v` is the version label and is reserved in an attribute, edge, or rule block.",
    () => {
      const { subject } = build({
        ri: QVI_REGISTRY,
        s: QVI_SCHEMA_SAID,
        a: { v: versify(Protocols.ACDC, undefined, Serials.JSON, 0) },
      });
      return { attributes_raw: JSON.stringify(subject), rewritten_version: subject.v };
    },
  ),
  attribute_identifier_is_overwritten: quirk(
    "an attribute named `d` is replaced by the placeholder before derivation, so whatever the caller wrote there is silently discarded.",
    "refused: `d` is the identifier label and is reserved; the builder writes it.",
    () => {
      const { subject } = build({
        ri: QVI_REGISTRY,
        s: QVI_SCHEMA_SAID,
        a: { d: "EGARBAGEGARBAGEGARBAGEGARBAGEGARBAGEGARBAGE", LEI: "1" },
      });
      return { attributes_raw: JSON.stringify(subject) };
    },
  ),
  credential_version_and_identifier_are_ignored: quirk(
    "`CredentialData` declares `v` and `d`, but `issue` reads neither: it writes its own version string and an empty identifier, so supplying either changes nothing.",
    "unrepresentable: neither is a builder input.",
    () => {
      const withFields = build({
        v: "NOT-A-VERSION",
        d: "ENOTASAID",
        ri: QVI_REGISTRY,
        s: QVI_SCHEMA_SAID,
        a: { LEI: "1" },
      });
      const without = build({ ri: QVI_REGISTRY, s: QVI_SCHEMA_SAID, a: { LEI: "1" } });
      return { identical: JSON.stringify(withFields.acdc) === JSON.stringify(without.acdc) };
    },
  ),
  absent_attributes_still_produce_a_block: quirk(
    "`CredentialData.a` is declared required, but `{...undefined}` is legal, so a credential built without it still carries an attribute block of `d` and `dt` — and TypeScript's requirement is erased at run time.",
    "the attribute block is a required, always-present value; the empty block is spelled explicitly and produces the same bytes.",
    () => {
      const { acdc } = build({ ri: QVI_REGISTRY, s: QVI_SCHEMA_SAID });
      return {
        raw: JSON.stringify(acdc),
        identical_to_empty_block: JSON.stringify(acdc) === credentials.untargeted.raw,
      };
    },
  ),
  non_object_attributes_are_spread_by_index: quirk(
    "spreading a string yields one numbered key per character, so an attribute block that is not an object becomes a block of array-index labels — which are then hoisted.",
    "unrepresentable: the attribute block is a typed ordered map.",
    () => {
      const { subject } = build({ ri: QVI_REGISTRY, s: QVI_SCHEMA_SAID, a: "hello" });
      return { attributes_raw: JSON.stringify(subject) };
    },
  ),
  fractional_attribute_values_are_committed: quirk(
    "a non-integer attribute is serialised as a JavaScript double, whose shortest round-trip spelling is what the SAID commits to.",
    "refused: ADR `0008` narrowed the accepted number space to exact safe integers, because no other value is provably byte-stable across the two languages.",
    () => {
      const { subject } = build({ ri: QVI_REGISTRY, s: QVI_SCHEMA_SAID, a: { rate: 1.5 } });
      return { attributes_raw: JSON.stringify(subject) };
    },
  ),
  oversized_integers_lose_precision: quirk(
    "an attribute above 2^53 is rounded before it is ever serialised, so the credential commits to a number the caller did not supply.",
    "refused: `SadValue::integer` rejects anything outside the safe range.",
    () => {
      const { subject } = build({ ri: QVI_REGISTRY, s: QVI_SCHEMA_SAID, a: { total: 9007199254740995 } });
      return { attributes_raw: JSON.stringify(subject), committed: JSON.parse(JSON.stringify(subject)).total };
    },
  ),
  identifiers_are_unvalidated_text: quirk(
    "the issuer, registry, schema, and issuee are all interpolated without a single check, so a typo becomes part of the credential's identity.",
    "typed: the issuer, registry, and issuee are `IdentifierPrefix` values and the schema is a `Said`.",
    () => {
      const { acdc } = build(
        { i: "not an identifier", ri: "not a registry", s: "not a schema", a: { i: "not an issuee" } },
      );
      return { accepted: true, raw: JSON.stringify(acdc) };
    },
  ),
  empty_registry_and_schema_are_accepted: quirk(
    "`ri` and `s` are declared optional and an empty string is not `undefined`, so a credential can claim membership of a registry named by the empty string.",
    "refused: both are required and typed, so neither an absent nor an empty value is expressible.",
    () => {
      const { acdc } = build({ ri: "", s: "", a: {} });
      const absent = build({ a: {} });
      return { raw: JSON.stringify(acdc), raw_absent: JSON.stringify(absent.acdc) };
    },
  ),
  timestamp_default_reads_the_clock: {
    expression: "args.a.dt ?? new Date().toISOString().replace('Z', '000+00:00')",
    shape: DT.replace(/\d/g, "9"),
    length: DT.length,
    note: "the attribute timestamp defaults to the system clock, rendered with three zero digits standing in for microseconds the reading never had — the same fake precision Roadmap 5.5 recorded on `Signify-Timestamp`.",
    rust_decision:
      "required: a protocol crate reads no clock, so the timestamp is a validated `Timestamp` the caller supplies, exactly as Roadmap 3.6's reply and Roadmap 4.7's nonce are.",
  },
  credential_types_have_no_consumer: {
    members: declarations.credential_types,
    scan: scan("CredentialTypes"),
    note: "`CredentialTypes.issued` and `.received` are exported, declared once, and referenced nowhere else. The scan records raw counts with their file list rather than asserting the absence: the only hit in the pinned tree is the declaration itself.",
    rust_decision: "`N/A`, on the same evidence as `core/httping.ts`'s `Unqualified`; reintroduce with a real consumer.",
  },
  credential_filter_belongs_to_the_endpoint: {
    members: declarations.credential_filter,
    scan: scan("CredentialFilter"),
    note: "`CredentialFilter` is consumed by `Credentials.list` alone, where it becomes the JSON body of `POST /credentials/query`; it is request shaping, not credential data.",
    rust_decision:
      "deferred to Roadmap 6.11 with the endpoint that sends it, because `ARCHITECTURE.md` §4.5 keeps KERIA request bodies out of `signify-acdc`.",
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
    "test/app/credentialing.test.ts",
    "test/app/test-utils.ts",
    "test-integration/singlesig-vlei-issuance.test.ts",
    "test-integration/multisig-vlei-issuance.test.ts",
  ],
  provenance: {
    issuer: ISSUER,
    timestamp: DT,
    note: "every value is deterministic: `Saider.saidify` reads no clock and derives no keys. The identifiers, schema SAIDs, and attribute data are the pinned unit test's and the pinned vLEI integration suites' own; the timestamp is the mock credential's, standing in for the reference's `new Date()`.",
  },
  declarations,
  supporting,
  credentials,
  pinned_artifact: pinnedArtifact,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/acdc-credential/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("acdc-credential fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
