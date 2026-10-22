// Records the pinned signify-ts checkout's exchange route table, resource variants, and guards.
//
// This fixture ports the half of `src/keri/app/exchanging.ts` that `client-exchanges` left:
// thirteen route constants, thirteen `*Exchange` resource variants, eight `*Group` variants,
// thirteen `is*` type guards, and thirteen `assert*` assertions — forty-seven exported symbols,
// plus the private `assertRoute` they all funnel through.
//
// Unlike every other fixture in this port, the unit under test is a **type system**. The thirteen
// guards and thirteen assertions have one line of run-time behaviour between them — compare
// `msg.exn.r` with a constant — and everything else they do is a compile-time claim. So the
// evidence has two halves, and the second is the interesting one.
//
// The **run-time** half is executed: each guard and each assertion is called on a message of its
// own route, on a message of another route, and on shapes that are not messages at all, with the
// exact verdict or error text recorded.
//
// The **compile-time** half is read from the syntax tree, because there is nothing to execute: what
// each variant declares its `e` and `a` blocks contain. Three things fall out of comparing that
// with what the generated schema declares and with what the integration tests actually send.
//
//   1. `MultisigRevExchange` declares `e: { rev, d? }` where the schema's `MultisigRevokeEmbeds`
//      declares `{ rev, anc }`. The hand-written variant **hides the anchor**.
//   2. `IpexGrantExchange.e` and `MultisigIssExchange.e` are structurally identical, so one embed
//      shape serves two routes.
//   3. The schema names no `gid`, `smids`, or `rmids` anywhere. The `a` block shapes exist only in
//      this file's hand-written types, so they are checked against what the integration tests send.
//
// And one thing falls out of scanning for consumers: **none of the thirteen guards has one**, and
// six of the thirteen assertions have none either — nineteen dead exports of twenty-six. The
// remaining seven account for nineteen call sites, all in the integration tree.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import * as exchangingModule from "./node_modules/signify-ts/dist/keri/app/exchanging.js";
import ts from "./node_modules/typescript/lib/typescript.js";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

// ---------------------------------------------------------------------------
// 1. The declarations, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const exchanging = parse("src/keri/app/exchanging.ts");
const schema = parse("src/types/keria-api-schema.ts");

/** Every exported `const` whose initializer is a string literal, in declaration order. */
function exportedStringConstants(source) {
  const found = [];
  const visit = (node) => {
    if (ts.isVariableStatement(node)) {
      const exported = (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
      if (exported) {
        for (const declaration of node.declarationList.declarations) {
          if (declaration.initializer !== undefined && ts.isStringLiteral(declaration.initializer)) {
            found.push({ name: declaration.name.getText(), value: declaration.initializer.text });
          }
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** The whole text of one exported type alias. */
function typeAlias(source, aliasName) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isTypeAliasDeclaration(node) && node.name.getText() === aliasName) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Every exported function declaration with a body, by name. */
function functionBodies(source) {
  const found = {};
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name !== undefined && node.body !== undefined) {
      found[node.name.getText()] = node.getText().replace(/\s+/g, " ");
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

/** Counts uses of a symbol **outside** its own declaring file. */
function consumers(name, declaringFile) {
  const hit = scan(`${name}(`);
  const outside = hit.files.filter((entry) => entry.file !== declaringFile);
  return {
    needle: hit.needle,
    total: hit.total,
    declared_in: hit.files.find((entry) => entry.file === declaringFile)?.count ?? 0,
    consumer_files: outside,
    consumer_total: outside.reduce((sum, entry) => sum + entry.count, 0),
    scanned_files: hit.scanned_files,
  };
}

const EXCHANGING_FILE = "src/keri/app/exchanging.ts";

const routeConstants = exportedStringConstants(exchanging.source);
if (routeConstants.length !== 13) {
  throw new Error(`exchanging.ts no longer exports exactly thirteen route constants: ${routeConstants.length}`);
}

/** The thirteen routes, each with the variant, guard, and assertion that name it. */
const ROUTES = [
  { constant: "MULTISIG_ICP_ROUTE", variant: "MultisigIcpExchange", group: "MultisigIcpGroup", guard: "isMultisigIcp", assertion: "assertMultisigIcp", slot: "icp" },
  { constant: "MULTISIG_ROT_ROUTE", variant: "MultisigRotExchange", group: "MultisigRotGroup", guard: "isMultisigRot", assertion: "assertMultisigRot", slot: "rot" },
  { constant: "MULTISIG_IXN_ROUTE", variant: "MultisigIxnExchange", group: "MultisigIxnGroup", guard: "isMultisigIxn", assertion: "assertMultisigIxn", slot: "ixn" },
  { constant: "MULTISIG_RPY_ROUTE", variant: "MultisigRpyExchange", group: "MultisigRpyGroup", guard: "isMultisigRpy", assertion: "assertMultisigRpy", slot: "rpy" },
  { constant: "MULTISIG_VCP_ROUTE", variant: "MultisigVcpExchange", group: "MultisigVcpGroup", guard: "isMultisigVcp", assertion: "assertMultisigVcp", slot: "vcp" },
  { constant: "MULTISIG_ISS_ROUTE", variant: "MultisigIssExchange", group: "MultisigIssGroup", guard: "isMultisigIss", assertion: "assertMultisigIss", slot: "iss" },
  { constant: "MULTISIG_EXN_ROUTE", variant: "MultisigExnExchange", group: "MultisigExnGroup", guard: "isMultisigExn", assertion: "assertMultisigExn", slot: "exn" },
  { constant: "MULTISIG_REV_ROUTE", variant: "MultisigRevExchange", group: "MultisigRevGroup", guard: "isMultisigRev", assertion: "assertMultisigRev", slot: "rev" },
  { constant: "IPEX_GRANT_ROUTE", variant: "IpexGrantExchange", group: null, guard: "isIpexGrant", assertion: "assertIpexGrant", slot: "acdc" },
  { constant: "IPEX_OFFER_ROUTE", variant: "IpexOfferExchange", group: null, guard: "isIpexOffer", assertion: "assertIpexOffer", slot: "acdc" },
  { constant: "IPEX_APPLY_ROUTE", variant: "IpexApplyExchange", group: null, guard: "isIpexApply", assertion: "assertIpexApply", slot: null },
  { constant: "IPEX_AGREE_ROUTE", variant: "IpexAgreeExchange", group: null, guard: "isIpexAgree", assertion: "assertIpexAgree", slot: null },
  { constant: "IPEX_ADMIT_ROUTE", variant: "IpexAdmitExchange", group: null, guard: "isIpexAdmit", assertion: "assertIpexAdmit", slot: null },
];

const bodies = functionBodies(exchanging.source);

const table = ROUTES.map((entry) => {
  const value = routeConstants.find((constant) => constant.name === entry.constant)?.value ?? null;
  if (value === null) {
    throw new Error(`the constant ${entry.constant} is no longer exported`);
  }
  return {
    ...entry,
    value,
    variant_declaration: typeAlias(exchanging.source, entry.variant),
    group_declaration: entry.group === null ? null : typeAlias(exchanging.source, entry.group),
    guard_body: bodies[entry.guard] ?? null,
    assertion_body: bodies[entry.assertion] ?? null,
    guard_consumers: consumers(entry.guard, EXCHANGING_FILE),
    assertion_consumers: consumers(entry.assertion, EXCHANGING_FILE),
  };
});

for (const entry of table) {
  for (const field of ["variant_declaration", "guard_body", "assertion_body"]) {
    if (entry[field] === null) {
      throw new Error(`${entry.constant}'s ${field} is no longer where this generator expects it`);
    }
  }
  if (entry.group !== null && entry.group_declaration === null) {
    throw new Error(`${entry.group} is no longer declared`);
  }
}

// The guards are dead: if that ever stops being true, the note below is stale.
const guardsWithConsumers = table.filter((entry) => entry.guard_consumers.consumer_total > 0);
if (guardsWithConsumers.length > 0) {
  throw new Error(`a type guard gained a consumer: ${guardsWithConsumers.map((entry) => entry.guard)}`);
}
// Six of the thirteen assertions have no consumer either, so the dead-export finding is about
// nineteen symbols rather than thirteen. If the *used* set ever changes, the recorded counts are
// stale and the fixture must be regenerated.
const usedAssertions = table
  .filter((entry) => entry.assertion_consumers.consumer_total > 0)
  .map((entry) => entry.assertion)
  .sort();
const EXPECTED_USED_ASSERTIONS = [
  "assertIpexGrant",
  "assertIpexOffer",
  "assertMultisigIcp",
  "assertMultisigIss",
  "assertMultisigIxn",
  "assertMultisigRot",
  "assertMultisigRpy",
];
if (usedAssertions.join(",") !== EXPECTED_USED_ASSERTIONS.join(",")) {
  throw new Error(`the set of used assertions changed: ${usedAssertions}`);
}

const declarations = {
  route_constants: routeConstants,
  assert_route: (() => {
    let found = null;
    const visit = (node) => {
      if (found === null && ts.isFunctionDeclaration(node) && node.name?.getText() === "assertRoute") {
        found = node.getText().replace(/\s+/g, " ");
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(exchanging.source, visit);
    return found;
  })(),
  exn_message_alias: typeAlias(exchanging.source, "ExnMessage"),
  exchange_resource_v1_alias: typeAlias(exchanging.source, "ExchangeResourceV1"),
  anchor_event_alias: typeAlias(exchanging.source, "AnchorEvent"),
  with_group_metadata_alias: typeAlias(exchanging.source, "WithGroupMetadata"),
  schema_exn_embeds: schemaType("ExnEmbeds"),
  schema_multisig_revoke_embeds: schemaType("MultisigRevokeEmbeds"),
  schema_multisig_issue_embeds: schemaType("MultisigIssueEmbeds"),
  schema_exn_multisig: schemaType("ExnMultisig"),
  schema_exchange_resource: schemaType("ExchangeResource"),
  attribute_labels_in_schema: {
    gid: scan('"gid"').total + scan("gid:").total,
    smids: scan("smids:").total,
    rmids: scan("rmids:").total,
    note: "counted across the whole pinned tree; the numbers below record how many of those hits are in the generated schema, which is zero",
    in_generated_schema: (() => {
      const text = schema.text;
      return {
        gid: text.split("gid").length - 1,
        smids: text.split("smids").length - 1,
        rmids: text.split("rmids").length - 1,
      };
    })(),
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

if (
  declarations.attribute_labels_in_schema.in_generated_schema.gid !== 0 ||
  declarations.attribute_labels_in_schema.in_generated_schema.smids !== 0 ||
  declarations.attribute_labels_in_schema.in_generated_schema.rmids !== 0
) {
  throw new Error("the generated schema now names a group attribute; the recorded note is stale");
}

// ---------------------------------------------------------------------------
// 2. What each variant declares, compared with the schema and with real traffic.
// ---------------------------------------------------------------------------

/** The `e:` block one variant declaration writes, normalised. */
function embedBlock(declaration) {
  const match = /e: \{(.*?)\}; a:|e: \{(.*?)\}; \}; \};|e: (object);/.exec(declaration);
  if (match === null) {
    return null;
  }
  return (match[1] ?? match[2] ?? match[3]).trim();
}

/** The `a:` block one variant declaration writes, normalised. */
function attributeBlock(declaration) {
  const match = /a: \{(.*?)\[key: string\]: unknown; \};/.exec(declaration);
  return match === null ? null : match[1].trim();
}

const variantShapes = table.map((entry) => ({
  route: entry.value,
  variant: entry.variant,
  embed_block: embedBlock(entry.variant_declaration),
  attribute_block: attributeBlock(entry.variant_declaration),
  has_group_variant: entry.group !== null,
}));

const shapeFindings = {
  revocation_hides_its_anchor: {
    hand_written: variantShapes.find((shape) => shape.variant === "MultisigRevExchange")?.embed_block ?? null,
    generated_schema: declarations.schema_multisig_revoke_embeds,
    note: "`MultisigRevExchange` declares `e: { rev, d? }` where the generated schema's `MultisigRevokeEmbeds` declares `{ rev, anc }`. The hand-written variant hides the anchoring key event, so a caller who narrows through `assertMultisigRev` cannot reach it — while `assertMultisigVcp` and `assertMultisigIss`, whose schema counterparts carry the same field, both expose it.",
    rust_decision:
      "`ExchangeEmbed` models the schema, so `ExchangeEmbed::Revocation` carries the anchor and this port keeps it. The schema is generated from a live KERIA and the hand-written variant is the outlier; nothing is hidden.",
  },
  a_grant_and_an_issuance_share_one_embed: {
    grant: variantShapes.find((shape) => shape.variant === "IpexGrantExchange")?.embed_block ?? null,
    issuance: variantShapes.find((shape) => shape.variant === "MultisigIssExchange")?.embed_block ?? null,
    note: "`IpexGrantExchange.e` and `MultisigIssExchange.e` declare the same three fields, so one embed shape serves two routes on opposite sides of the table",
    rust_decision:
      "reused rather than duplicated: `MultisigIssuanceEmbed` decodes both, which is why eight schema embed shapes cover nine of the thirteen routes.",
  },
  the_schema_models_no_ipex_embed: {
    schema_union: declarations.schema_exn_embeds,
    note: "the schema's `ExnEmbeds` union has exactly eight members, all multisig; an IPEX offer's `e: { acdc }` is not among them, and apply, agree, and admit declare `e: object`",
    rust_decision:
      "the IPEX payloads are modelled here rather than added to `ExchangeEmbed`, because they were never part of the schema's union and widening a verified untagged enum would change how existing documents decode.",
  },
  the_schema_names_no_group_attribute: {
    counts: declarations.attribute_labels_in_schema.in_generated_schema,
    note: "`gid`, `smids`, and `rmids` appear zero times in the generated schema. The `a` block shapes exist only in this file's hand-written types, which is why they are checked against what the integration tests actually send rather than against a schema.",
    rust_decision: "one `GroupAttributes` value, with the route deciding which of its optional fields are required.",
  },
};

// ---------------------------------------------------------------------------
// 3. The attribute blocks the integration tests actually send.
// ---------------------------------------------------------------------------

/** Every `exchanges().send(...)` call site, with the route and payload literal it passes. */
function sendCallSites() {
  const found = [];
  for (const file of PINNED_FILES) {
    const text = readFileSync(upstreamUrl(file), "utf8");
    if (!text.includes(".send(")) {
      continue;
    }
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
    const visit = (node) => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.getText() === "send" &&
        node.arguments.length === 7
      ) {
        const route = node.arguments[3];
        const payload = node.arguments[4];
        if (ts.isStringLiteral(route)) {
          found.push({
            file,
            route: route.text,
            payload: payload.getText().replace(/\s+/g, " "),
            payload_labels: ts.isObjectLiteralExpression(payload)
              ? payload.properties.map((property) => property.name?.getText() ?? "<spread>")
              : null,
          });
        }
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(source, visit);
  }
  return found;
}

const sendSites = sendCallSites();

/** For each route, the set of attribute labels every real call site sends. */
const observedAttributes = {};
for (const site of sendSites) {
  if (site.payload_labels === null) {
    continue;
  }
  const seen = observedAttributes[site.route] ?? { call_sites: 0, label_sets: [] };
  seen.call_sites += 1;
  const labels = site.payload_labels.join(",");
  if (!seen.label_sets.includes(labels)) {
    seen.label_sets.push(labels);
  }
  observedAttributes[site.route] = seen;
}
for (const value of Object.values(observedAttributes)) {
  value.label_sets.sort();
}

// ---------------------------------------------------------------------------
// 4. Execute every guard and every assertion.
// ---------------------------------------------------------------------------

/** One message on `route`, with whatever embed and attributes are given. */
function message(route, embeds, attributes) {
  return {
    exn: {
      v: "KERI10JSON000100_",
      t: "exn",
      d: "EEXN",
      i: "EMEM",
      rp: "EPEER",
      p: "",
      dt: "2023-11-14T22:13:20.123000+00:00",
      r: route,
      q: {},
      a: attributes,
      e: embeds,
    },
    pathed: {},
  };
}

/** Calls one function, recording its verdict or the exact failure it produced. */
function run(name, argument) {
  const callable = exchangingModule[name];
  if (typeof callable !== "function") {
    throw new Error(`${name} is no longer exported`);
  }
  try {
    const result = callable(argument);
    return { outcome: "returned", verdict: typeof result === "boolean" ? result : "the message itself" };
  } catch (thrown) {
    return { outcome: "threw", error: String(thrown?.message ?? thrown), kind: thrown?.constructor?.name ?? null };
  }
}

const OTHER_ROUTE = "/multisig/icp";
const CHALLENGE_ROUTE = "/challenge/response";

const executed = table.map((entry) => {
  const own = message(entry.value, entry.slot === null ? {} : { [entry.slot]: { t: entry.slot } }, { gid: "EGRP" });
  const other = message(entry.value === OTHER_ROUTE ? "/multisig/rot" : OTHER_ROUTE, {}, { gid: "EGRP" });
  // The right route, and nothing at all in the block the variant declares.
  const empty = message(entry.value, {}, {});
  return {
    route: entry.value,
    guard: entry.guard,
    assertion: entry.assertion,
    guard_on_own_route: run(entry.guard, own),
    guard_on_other_route: run(entry.guard, other),
    assertion_on_own_route: run(entry.assertion, own),
    assertion_on_other_route: run(entry.assertion, other),
    // The finding: both accept a message whose declared payload is simply absent.
    guard_on_empty_payload: run(entry.guard, empty),
    assertion_on_empty_payload: run(entry.assertion, empty),
    declared_slot_present_when_empty: entry.slot === null ? null : Object.keys(empty.exn.e).includes(entry.slot),
  };
});

/** Shapes that are not messages at all, run through one guard and one assertion. */
const hostile = [
  { name: "no_exn_at_all", value: {} },
  { name: "exn_is_null", value: { exn: null } },
  { name: "exn_has_no_route", value: { exn: {} } },
  { name: "route_is_a_number", value: { exn: { r: 7 } } },
  { name: "route_carries_the_label_text", value: { exn: { r: "Multisig ICP message" } } },
  { name: "an_unknown_route", value: message(CHALLENGE_ROUTE, {}, {}) },
].map((entry) => ({
  ...entry,
  guard: run("isMultisigIcp", entry.value),
  assertion: run("assertMultisigIcp", entry.value),
}));

// The guard reads `msg.exn.r` and the assertion reads `msg.exn?.r`, so they disagree on a message
// with no `exn`. If that ever stops being true the recorded divergence is stale.
const noExn = hostile.find((entry) => entry.name === "no_exn_at_all");
if (noExn?.guard.outcome !== "threw" || noExn?.assertion.outcome !== "threw") {
  throw new Error("the no-`exn` case no longer fails on both sides");
}
if (noExn.guard.kind === noExn.assertion.kind) {
  throw new Error("the guard and the assertion now fail the same way; the recorded divergence is stale");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  a_guard_narrows_without_checking: {
    guard: table[0].guard_body,
    variant: table[0].variant_declaration,
    empty_payload: executed[0].guard_on_empty_payload,
    note: "every guard and every assertion is one route comparison. The variant it narrows to declares an `e` block and an `a` block, and neither is looked at — so `assertMultisigIcp` accepts a message on `/multisig/icp` carrying no `icp` at all, hands back a value typed as though it did, and the caller's `exn.e.icp` is `undefined` while the compiler says it is an inception.",
    rust_decision:
      "the classifier decodes the payload the route promises, so a route and a payload that disagree are a typed refusal rather than a wrong type. That is the whole difference between the two: upstream the narrowing is a claim, here it is a check.",
  },
  the_guards_have_no_consumers: {
    guards: table.map((entry) => ({ name: entry.guard, consumers: entry.guard_consumers.consumer_total })),
    assertions: table.map((entry) => ({ name: entry.assertion, consumers: entry.assertion_consumers.consumer_total })),
    used_assertions: usedAssertions,
    unused_symbol_count: table.length + table.filter((entry) => entry.assertion_consumers.consumer_total === 0).length,
    note: "thirteen exported type guards, zero call sites anywhere in the pinned tree outside their own declaration — and six of the thirteen assertions beside them have none either. Nineteen of the twenty-six are dead exports; the seven that are used account for nineteen call sites, all in `test-integration/multisig*.test.ts`.",
    rust_decision:
      "not ported as functions. A guard is `matches!` on the classified enum, which costs nothing and cannot drift from the assertion beside it — the same reasoning that recorded `Unqualified` and `CredentialTypes` as having no Rust equivalent, applied to a capability the enum simply subsumes.",
  },
  a_guard_and_its_assertion_disagree_on_a_malformed_message: {
    guard: hostile.find((entry) => entry.name === "no_exn_at_all")?.guard ?? null,
    assertion: hostile.find((entry) => entry.name === "no_exn_at_all")?.assertion ?? null,
    declaration: declarations.assert_route,
    note: "`assertRoute` reads `msg.exn?.r` and every guard reads `msg.exn.r`, so a value with no `exn` gives the assertion a clean `Error` and the guard a `TypeError`. Two functions that differ by one question mark and by which exception a caller has to catch.",
    rust_decision: "unrepresentable: a classified message is decoded from a typed `ExchangeResource`, which has no shape without an `exn`.",
  },
  the_failure_message_repeats_the_route: {
    declaration: declarations.assert_route,
    example: executed[0].assertion_on_other_route,
    note: "`Expected ${label} but got route: ${msg.exn?.r}` interpolates a value that came from the agent into the error a caller logs",
    rust_decision:
      "the refusal names the route it expected and the route it found, both bounded — the found one is the message's own field, already length-bounded by the transport's response limit, and neither is formatted into a message a caller is invited to trust.",
  },
  the_route_table_is_not_closed: {
    unknown_route: hostile.find((entry) => entry.name === "an_unknown_route") ?? null,
    note: "thirteen constants, and the reference's own `Challenges.respond` sends a fourteenth — `/challenge/response` — which no variant, guard, or assertion names. Every guard simply returns false for it and every assertion throws.",
    rust_decision:
      "the classifier has an `Other` case rather than refusing: a route this table does not name is a message, not an error, because this crate itself sends one. Only a *named* route whose payload disagrees is refused.",
  },
  only_multisig_routes_have_a_group_variant: {
    with_group: variantShapes.filter((shape) => shape.has_group_variant).map((shape) => shape.route),
    without_group: variantShapes.filter((shape) => !shape.has_group_variant).map((shape) => shape.route),
    declaration: declarations.with_group_metadata_alias,
    note: "the eight multisig routes each have a `*Group` variant for the form a group request returns; the five IPEX routes have none, so `assertIpexGrant(msg: ExnMultisig)` returns the unnarrowed `ExnMultisig`",
    rust_decision:
      "one classifier over both containers. The group form differs only in its wrapper — `paths` beside `pathed`, plus three optional labels — so the message inside it classifies identically and the asymmetry disappears.",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-26",
  sources: ["src/keri/app/exchanging.ts", "src/types/keria-api-schema.ts", "test-integration/multisig.test.ts"],
  provenance: {
    note: "The unit here is a type system, so the evidence has two halves. The run-time half is **executed**: every guard and every assertion is called on its own route, on another, on a message whose declared payload is absent, and on six shapes that are not messages, with the exact verdict or error recorded. The compile-time half is **read from the syntax tree**, because there is nothing to execute. No key is derived and no client is built; nothing here is secret.",
  },
  declarations,
  route_table: table,
  variant_shapes: variantShapes,
  observed_attributes: observedAttributes,
  send_call_sites: sendSites.length,
  executed,
  hostile,
  shape_findings: shapeFindings,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-client/fixtures/client-exchange-routes/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-exchange-routes fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
