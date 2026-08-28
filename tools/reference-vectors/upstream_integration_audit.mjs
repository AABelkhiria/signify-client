// Inventories the pinned signify-ts checkout's KERIA integration suite.
//
// Roadmap 9.2 must answer every upstream integration scenario with Rust evidence or a documented
// reason. Roadmap 9.1 did the same for the unit suite, and its unit was the `it`/`test` case — one
// row per case, 139 of them, each mapping cleanly onto a Rust test.
//
// **That unit is useless here.** `multisig.test.ts` is 1,342 lines and *one* case;
// `multisig-vlei-issuance.test.ts` is 1,335 lines and one case. Counting cases would report
// "35 of 35 answered" while hundreds of behaviours went unexamined — an audit that passes while
// certifying nothing. So this inventory records a finer unit: **every `client.<family>().<method>()`
// call site**, which decomposes a monolith into a behaviour list and maps onto the endpoint
// families `PORTING.md` §5 already tracks.
//
// It also records the suite's defects mechanically rather than in prose, so that every "this port
// does better" claim in the ledger cites a generated file and line instead of a memory.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const ROOT = "test-integration";

function read(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  return readFileSync(url, "utf8");
}

function parse(relativePath) {
  const text = read(relativePath);
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

/** Every file under `test-integration`, split into scenarios and support. */
function tree() {
  const scenarios = [];
  const support = [];
  const walk = (relative) => {
    const url = new URL(`../../reference/signify-ts/${relative}`, import.meta.url);
    for (const entry of readdirSync(url, { withFileTypes: true })) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(child);
      } else if (entry.name.endsWith(".test.ts")) {
        scenarios.push(child);
      } else if (entry.name.endsWith(".ts")) {
        support.push(child);
      }
    }
  };
  walk(ROOT);
  return { scenarios: scenarios.sort(), support: support.sort() };
}

/** The line a node starts on, one-based. */
function lineOf(source, node) {
  return source.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

/// The endpoint families a client exposes, so `Date.now().toString()` is not read as one.
///
/// An allowlist rather than a shape test, because `x().y()` is a common JavaScript idiom and the
/// families are a closed set the reference itself declares on `SignifyClient`.
const FAMILIES = new Set([
  "challenges", "config", "contacts", "credentials", "delegations", "escrows", "exchanges",
  "groups", "identifiers", "ipex", "keyEvents", "keyStates", "notifications", "oobis",
  "operations", "registries", "schemas",
]);

const CASE_NAMES = new Set(["it", "test"]);
const GROUP_NAMES = new Set(["describe", "suite"]);

function calleeName(node) {
  let expression = node.expression;
  while (ts.isPropertyAccessExpression(expression) || ts.isCallExpression(expression)) {
    expression = ts.isCallExpression(expression) ? expression.expression : expression.expression;
  }
  return ts.isIdentifier(expression) ? expression.getText() : null;
}

function titleOf(node) {
  const argument = node.arguments[0];
  if (argument === undefined) return "<no title>";
  if (ts.isStringLiteralLike(argument)) return argument.text;
  return "<computed>";
}

/**
 * Every `client.<family>().<method>(…)` inside a node, counted.
 *
 * This is the unit the whole audit turns on: it is mechanically derivable, it survives a 1,342-line
 * function with no internal structure, and it names the endpoint families a scenario exercises.
 */
function apiCalls(node) {
  const counts = new Map();
  const visit = (child) => {
    if (
      ts.isCallExpression(child) &&
      ts.isPropertyAccessExpression(child.expression) &&
      ts.isCallExpression(child.expression.expression) &&
      ts.isPropertyAccessExpression(child.expression.expression.expression)
    ) {
      const family = child.expression.expression.expression.name.getText();
      const method = child.expression.name.getText();
      // `client.identifiers().create(...)` — the family call takes no arguments.
      if (child.expression.expression.arguments.length === 0 && FAMILIES.has(family)) {
        const key = `${family}.${method}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return [...counts.entries()]
    .sort()
    .map(([key, count]) => {
      const [family, method] = key.split(".");
      return { family, method, count };
    });
}

/**
 * Which `utils/` helpers a scenario calls.
 *
 * Several scenarios make few direct API calls because they delegate to the shared helpers — so a
 * count of a file's own calls under-reports what it actually drives. Recording the delegation makes
 * that visible without building a call graph.
 */
function sharedHelpersUsed(source, shared) {
  const used = new Set();
  const visit = (node) => {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && shared.has(node.expression.getText())) {
      used.add(node.expression.getText());
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return [...used].sort();
}

/** Every assertion helper a node calls, counted. */
function assertionsIn(node) {
  const counts = new Map();
  const visit = (child) => {
    if (ts.isCallExpression(child)) {
      const text = child.expression.getText();
      if (/^assert(\.[A-Za-z]+)?$/.test(text) || text === "expect") {
        counts.set(text, (counts.get(text) ?? 0) + 1);
      }
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  let total = 0;
  for (const count of counts.values()) total += count;
  return { total, helpers: [...counts.keys()].sort() };
}

/** The `step('…')` labels inside a node, in order. */
function stepsIn(node) {
  const labels = [];
  const visit = (child) => {
    if (ts.isCallExpression(child) && calleeName(child) === "step" && ts.isStringLiteralLike(child.arguments[0])) {
      labels.push(child.arguments[0].text);
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return labels;
}

/**
 * What live infrastructure a scenario needs, read from what it references.
 *
 * Witnesses are needed two ways, and both are recorded. A scenario may name them — `witnessIds`, a
 * `wits:` argument, an inlined witness AID — or it may inherit them: `getOrCreateIdentifier`
 * defaults `kargs` to every witness the environment declares (`utils/test-util.ts`:355-358) when
 * the caller passes none. Counting only the first would have said eleven scenarios need witnesses
 * when the true figure is higher, so `witnesses` is the union and the two reasons are kept apart.
 */
function infrastructure(text) {
  const clients = [...text.matchAll(/getOrCreateClients\(\s*(\d+)/g)].map((match) => Number(match[1]));
  const singles = (text.match(/getOrCreateClient\(/g) ?? []).length;
  const named = /witnessIds|witnessUrls|WITNESS_AID|wits:/.test(text);
  // A helper call with no `kargs` inherits the environment's whole witness set.
  const inherited = /getOrCreateIdentifier\(\s*[^,]+,\s*[^,)]+\s*\)/.test(text) || /createAid\(|createAID\(/.test(text);
  return {
    clients: clients.length > 0 ? Math.max(...clients) : Math.max(singles, 1),
    witnesses: named || inherited,
    witnesses_named: named,
    witnesses_inherited: inherited,
    vlei: /vleiServerUrl|SCHEMA_OOBI|schemaOobi/.test(text),
    oobis: /resolveOobi|\.oobis\(\)/.test(text),
  };
}

/** Everything `utils/` exports, so a local redefinition of one is detectable. */
function sharedHelpers(support) {
  const names = new Set();
  for (const file of support) {
    for (const match of read(file).matchAll(/^export (?:async )?function ([A-Za-z0-9_]+)/gm)) {
      names.add(match[1]);
    }
  }
  return names;
}

/**
 * The suite's defects, as data.
 *
 * Every kind here is something the ported scenarios must not reproduce, and recording it with a
 * line number means the ledger's claims can be checked against the reference rather than believed.
 */
function defectsIn(file, text, source, shared) {
  const found = [];
  const lines = text.split("\n");
  const at = (index) => index + 1;

  lines.forEach((line, index) => {
    if (/setTimeout\(\s*resolve/.test(line) || /new Promise\(\(resolve\) => setTimeout/.test(line)) {
      found.push({ kind: "bare_sleep", file, line: at(index), text: line.trim().slice(0, 120) });
    }
    if (/^\s*\/\/\s*assert/.test(line)) {
      found.push({ kind: "commented_assertion", file, line: at(index), text: line.trim().slice(0, 120) });
    }
    if (/^const [A-Z_]+ = createTimestamp\(\)/.test(line)) {
      found.push({ kind: "module_scope_timestamp", file, line: at(index), text: line.trim().slice(0, 120) });
    }
    if (/Date\.now\(\)\.toString\(/.test(line)) {
      found.push({ kind: "wall_clock_identifier", file, line: at(index), text: line.trim().slice(0, 120) });
    }
    if (/^\s*\} catch \{\s*$/.test(line) || /catch \(?_?\)? *\{\s*\}/.test(line)) {
      found.push({ kind: "swallowing_catch", file, line: at(index), text: line.trim().slice(0, 120) });
    }
  });

  // A helper redefined locally while `utils/` already exports it.
  const visit = (node) => {
    if (ts.isFunctionDeclaration(node) && node.name !== undefined && shared.has(node.name.getText())) {
      found.push({
        kind: "local_reimplementation",
        file,
        line: lineOf(source, node),
        text: `${node.name.getText()} is exported by utils/ and redefined here`,
      });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);

  if (!text.includes("assertOperations")) {
    found.push({ kind: "no_operation_teardown", file, line: 1, text: "the file never calls assertOperations" });
  }
  return found;
}

/** Module- or describe-scope `let` bindings, which is how state leaks between cases. */
function mutableScope(source) {
  const names = [];
  const visit = (node, depth) => {
    if (
      ts.isVariableStatement(node) &&
      (node.declarationList.flags & ts.NodeFlags.Let) !== 0 &&
      depth <= 1
    ) {
      for (const declaration of node.declarationList.declarations) {
        names.push(declaration.name.getText());
      }
    }
    ts.forEachChild(node, (child) => visit(child, ts.isBlock(node) || ts.isSourceFile(node) ? depth : depth + 1));
  };
  ts.forEachChild(source, (node) => visit(node, 0));
  return names;
}

const { scenarios, support } = tree();
const shared = sharedHelpers(support);

const cases = [];
const files = [];
const defects = [];

for (const file of scenarios) {
  const { text, source } = parse(file);
  const fileCases = [];

  const visit = (node, chain) => {
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      if (name !== null && GROUP_NAMES.has(name)) {
        const inner = [...chain, titleOf(node)];
        for (const argument of node.arguments.slice(1)) {
          ts.forEachChild(argument, (child) => visit(child, inner));
        }
        return;
      }
      if (name !== null && CASE_NAMES.has(name)) {
        const { total, helpers } = assertionsIn(node);
        fileCases.push({
          file,
          group: chain.join(" › "),
          title: titleOf(node),
          line: lineOf(source, node),
          lines: node.getText().split("\n").length,
          assertions: total,
          helpers,
          steps: stepsIn(node),
          api_calls: apiCalls(node),
        });
        return;
      }
    }
    ts.forEachChild(node, (child) => visit(child, chain));
  };
  ts.forEachChild(source, (node) => visit(node, []));

  const fileCalls = apiCalls(source);
  const fileDefects = defectsIn(file, text, source, shared);
  defects.push(...fileDefects);
  cases.push(...fileCases);
  files.push({
    file,
    cases: fileCases.length,
    lines: text.split("\n").length,
    assertions: fileCases.reduce((sum, entry) => sum + entry.assertions, 0),
    api_calls: fileCalls,
    shared_helpers_used: sharedHelpersUsed(source, shared),
    infrastructure: infrastructure(text),
    shared_state: mutableScope(source),
    defects: fileDefects.length,
  });
}

cases.sort((left, right) =>
  `${left.file}${left.group}${left.title}`.localeCompare(`${right.file}${right.group}${right.title}`),
);

/** Every endpoint family the suite reaches, with how many calls land on it. */
const families = (() => {
  const counts = new Map();
  for (const entry of files) {
    for (const call of entry.api_calls) {
      counts.set(call.family, (counts.get(call.family) ?? 0) + call.count);
    }
  }
  return [...counts.entries()].sort().map(([family, calls]) => ({ family, calls }));
})();

const keys = cases.map((entry) => `${entry.file}::${entry.group}::${entry.title}`);
const duplicates = keys.filter((key, index) => keys.indexOf(key) !== index);
if (duplicates.length > 0) {
  throw new Error(`duplicate case keys, which a ledger cannot key on: ${[...new Set(duplicates)].join(", ")}`);
}

const byKind = {};
for (const defect of defects) {
  byKind[defect.kind] = (byKind[defect.kind] ?? 0) + 1;
}

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-28",
  note: "Every scenario the pinned checkout's integration suite declares, decomposed by API call because four of its files are a single case each. `ledger.json` beside this file answers each scenario; `crates/signify-client/tests/keria_integration_audit.rs` requires the two to agree.",
  totals: {
    files: scenarios.length,
    support_files: support.length,
    cases: cases.length,
    lines: files.reduce((sum, entry) => sum + entry.lines, 0),
    assertions: cases.reduce((sum, entry) => sum + entry.assertions, 0),
    api_calls: files.reduce((sum, entry) => sum + entry.api_calls.reduce((inner, call) => inner + call.count, 0), 0),
    defects: defects.length,
  },
  runner: {
    file: "vitest.integration.ts",
    file_parallelism: read("vitest.integration.ts").includes("fileParallelism: false") ? false : true,
    bail: /bail:\s*(\d+)/.exec(read("vitest.integration.ts"))?.[1] ?? null,
    test_timeout_ms: /testTimeout:\s*(\d+)/.exec(read("vitest.integration.ts"))?.[1] ?? null,
    note: "`fileParallelism: false` with `bail: 1` — the first failure aborts the suite, and nothing is designed to run in parallel against one agent.",
  },
  files,
  families,
  defect_counts: byKind,
  defects,
  cases,
};

const outputUrl = new URL("../../fixtures/keria-integration/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keria-integration inventory is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
