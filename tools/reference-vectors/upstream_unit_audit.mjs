// Inventories every unit test the pinned signify-ts checkout declares.
//
// The unit audit checks the whole upstream unit suite against this port: every case must be answered
// by Rust evidence or by a documented `N/A`. This generator produces the left-hand side of that
// comparison — a machine-read inventory of what upstream actually tests — so the audit is a
// checkable artifact rather than a claim, and so it goes stale loudly when the reference moves.
//
// A case is one `it(...)` or `test(...)`, named by the `describe` chain enclosing it. For each one
// the inventory records where it is, how many assertions it makes, which assertion helpers it uses,
// and which upstream symbols it imports — which is what makes a case mappable to the port of those
// symbols.
//
// The right-hand side is `ledger.json` beside the output: authored rather than generated, because
// "this Rust test covers that upstream case" is a judgement. The Rust test in
// `crates/signify-client/tests/upstream_unit_audit.rs` requires the two to agree exactly.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import ts from "./node_modules/typescript/lib/typescript.js";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

/** Every `*.test.ts` under `test/`, sorted. */
function testFiles() {
  const files = [];
  const walk = (relative) => {
    const url = upstreamUrl(relative);
    for (const entry of readdirSync(url, { withFileTypes: true })) {
      const child = `${relative}/${entry.name}`;
      if (entry.isDirectory()) {
        walk(child);
      } else if (entry.name.endsWith(".test.ts")) {
        files.push(child);
      }
    }
  };
  walk("test");
  return files.sort();
}

/** Names that introduce a case, and names that introduce a group. */
const CASE_NAMES = new Set(["it", "test"]);
const GROUP_NAMES = new Set(["describe", "suite"]);

/** The callee's plain name, seeing through `it.each`, `describe.only`, and friends. */
function calleeName(node) {
  let expression = node.expression;
  while (ts.isPropertyAccessExpression(expression) || ts.isCallExpression(expression)) {
    expression = ts.isCallExpression(expression) ? expression.expression : expression.expression;
  }
  return ts.isIdentifier(expression) ? expression.getText() : null;
}

/** The first argument as a literal title, or a marker when it is computed. */
function titleOf(node) {
  const argument = node.arguments[0];
  if (argument === undefined) {
    return "<no title>";
  }
  if (ts.isStringLiteralLike(argument)) {
    return argument.text;
  }
  if (ts.isTemplateExpression(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) {
    return argument.getText().replace(/\s+/g, " ");
  }
  return "<computed>";
}

/** Every assertion helper one node's subtree calls, counted. */
function assertionsIn(node) {
  const counts = new Map();
  const visit = (child) => {
    if (ts.isCallExpression(child)) {
      const text = child.expression.getText();
      // `assert(...)`, `assert.equal(...)`, `expect(...).toBe(...)`, `strictEqual(...)`.
      const match =
        /^assert(\.[A-Za-z]+)?$/.exec(text) ??
        /^expect$/.exec(text) ??
        /^(strictEqual|deepEqual|deepStrictEqual|equal|notEqual|ok|fail|throws|rejects)$/.exec(text);
      if (match !== null) {
        counts.set(text, (counts.get(text) ?? 0) + 1);
      }
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return counts;
}

/** Every import of upstream source, mapped to the module path it comes from. */
function upstreamImports(source) {
  const found = [];
  const visit = (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
      const specifier = node.moduleSpecifier.text;
      if (!specifier.includes("/src/")) {
        return;
      }
      // `../../src/keri/core/tholder.ts` becomes `src/keri/core/tholder.ts`.
      const module = `src/${specifier.split("/src/")[1]}`.replace(/\.ts$/, ".ts");
      const names = [];
      const clause = node.importClause;
      if (clause?.name !== undefined) {
        names.push(clause.name.getText());
      }
      if (clause?.namedBindings !== undefined && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          names.push(element.name.getText());
        }
      }
      if (clause?.namedBindings !== undefined && ts.isNamespaceImport(clause.namedBindings)) {
        names.push(`* as ${clause.namedBindings.name.getText()}`);
      }
      found.push({ module, names });
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Walks one file, collecting a record per case with the group chain enclosing it. */
function casesIn(file, source) {
  const cases = [];
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
        const assertions = assertionsIn(node);
        let total = 0;
        for (const count of assertions.values()) {
          total += count;
        }
        cases.push({
          file,
          group: chain.join(" › "),
          title: titleOf(node),
          assertions: total,
          helpers: [...assertions.keys()].sort(),
          skipped: /\.(skip|todo)\b/.test(node.expression.getText()),
          lines: node.getText().split("\n").length,
        });
        return;
      }
    }
    ts.forEachChild(node, (child) => visit(child, chain));
  };
  ts.forEachChild(source, (node) => visit(node, []));
  return cases;
}

const files = testFiles();
const inventory = [];
const perFile = [];

for (const file of files) {
  const text = readFileSync(upstreamUrl(file), "utf8");
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.ES2022, true);
  const cases = casesIn(file, source);
  inventory.push(...cases);
  perFile.push({
    file,
    cases: cases.length,
    assertions: cases.reduce((sum, entry) => sum + entry.assertions, 0),
    imports: upstreamImports(source),
  });
}

inventory.sort((left, right) => `${left.file}${left.group}${left.title}`.localeCompare(`${right.file}${right.group}${right.title}`));

/** Every upstream source module any test imports, with how many files reach it. */
const modules = (() => {
  const counts = new Map();
  for (const entry of perFile) {
    for (const imported of entry.imports) {
      counts.set(imported.module, (counts.get(imported.module) ?? 0) + 1);
    }
  }
  return [...counts.entries()].sort().map(([module, files]) => ({ module, files }));
})();

/** Cases whose title the tree computes rather than writes, which a ledger cannot key on. */
const uncomputable = inventory.filter((entry) => entry.title === "<computed>" || entry.title === "<no title>");
if (uncomputable.length > 0) {
  throw new Error(`${uncomputable.length} cases have no literal title; the ledger cannot key on them`);
}

const keys = inventory.map((entry) => `${entry.file}::${entry.group}::${entry.title}`);
const duplicates = keys.filter((key, index) => keys.indexOf(key) !== index);
if (duplicates.length > 0) {
  throw new Error(`duplicate case keys, which a ledger cannot key on: ${[...new Set(duplicates)].join(", ")}`);
}

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-27",
  note: "Every unit case the pinned checkout declares. `ledger.json` beside this file answers each one with Rust evidence or a documented `N/A`; `crates/signify-client/tests/upstream_unit_audit.rs` requires the two to agree exactly.",
  totals: {
    files: files.length,
    cases: inventory.length,
    assertions: inventory.reduce((sum, entry) => sum + entry.assertions, 0),
    skipped: inventory.filter((entry) => entry.skipped).length,
  },
  files: perFile,
  modules,
  cases: inventory,
};

const outputUrl = new URL("../../fixtures/upstream-unit-audit/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("upstream-unit-audit fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
