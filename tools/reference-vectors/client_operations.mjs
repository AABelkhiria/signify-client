// Records the pinned signify-ts checkout's operations endpoint.
//
// This port covers `Operations.get`, `.list`, and `.delete` from `src/keri/app/coring.ts`,
// together with the failure surfacing `throwIfFailed` performs on a completed-but-failed
// operation. `wait` — the polling loop — is `client-operation-wait`'s; the `http-retry` fixture
// already pinned its delay schedule by executing it.
//
// As with the IPEX artifact and `client-lifecycle` fixtures, this one **drives the reference**
// rather than re-expressing it. `Operations` takes an `OperationsDeps` — one `fetch` method — so
// the generator hands it a recorder, exactly as the pinned `coring.test.ts` does, and every request
// it makes is captured with its path, method, and body.
//
// Everything is deterministic: nothing here derives a key or reads a clock.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { Operations } from "./node_modules/signify-ts/dist/keri/app/coring.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

// ---------------------------------------------------------------------------
// 1. The ported declarations, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const coring = parse("src/keri/app/coring.ts");

function method(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name?.getText() === methodName) {
          // `wait` is overloaded; the implementation is the one with a body.
          if (member.body !== undefined) {
            found = member;
          }
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

/** The union of operation families the schema declares, in declaration order. */
function operationUnion(source) {
  let found = null;
  const visit = (node) => {
    if (found === null && ts.isTypeAliasDeclaration(node) && node.name.getText() === "Operation") {
      found = node.type
        .getText()
        .split("|")
        .map((member) => member.trim())
        .filter((member) => member.length > 0);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const declarations = {
  get_path: firstText(
    method(coring.source, "Operations", "get"),
    (node) => ts.isTemplateExpression(node) && node.getText().includes("/operations/"),
  ),
  list_path: firstText(
    method(coring.source, "Operations", "list"),
    (node) => ts.isTemplateExpression(node) && node.getText().includes("/operations?"),
  ),
  list_parameters: firstText(
    method(coring.source, "Operations", "list"),
    (node) => ts.isVariableDeclaration(node) && node.name.getText() === "params",
  ),
  list_append: firstText(
    method(coring.source, "Operations", "list"),
    (node) => ts.isCallExpression(node) && node.getText().startsWith("params.append("),
  ),
  delete_path: firstText(
    method(coring.source, "Operations", "delete"),
    (node) => ts.isTemplateExpression(node) && node.getText().includes("/operations/"),
  ),
  throw_if_failed: (() => {
    let found = null;
    const visit = (node) => {
      if (found === null && ts.isMethodDeclaration(node) && node.name?.getText() === "throwIfFailed") {
        found = node.getText().replace(/\s+/g, " ");
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(coring.source, visit);
    return found;
  })(),
  has_depends: (() => {
    let found = null;
    const visit = (node) => {
      if (found === null && ts.isMethodDeclaration(node) && node.name?.getText() === "hasDepends") {
        found = node.getText().replace(/\s+/g, " ");
      }
      ts.forEachChild(node, visit);
    };
    ts.forEachChild(coring.source, visit);
    return found;
  })(),
  operation_union: operationUnion(coring.source),
  notes: {
    paths: "get and delete address the same path and differ only by method; list builds its query with `URLSearchParams` and always appends `?`, even when there is nothing after it",
    failure:
      "`throwIfFailed` turns a completed-but-failed operation into a thrown string carrying the name, the code, the message, and — when present — the details as JSON",
    depends:
      "`hasDepends` is a run-time `'depends' in op.metadata`, which the fourteen-way union cannot express statically; the dependency chain it feeds is operation waiting's",
  },
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}

// ---------------------------------------------------------------------------
// 2. Drive the reference's own `Operations` against a recorder.
// ---------------------------------------------------------------------------

const recorded = [];
let nextBody = "{}";

/** The `OperationsDeps` the reference asks for: one `fetch` method. */
const deps = {
  async fetch(path, method, body) {
    recorded.push({ path, method, body: body === undefined ? null : body });
    return new Response(nextBody, { status: 200, headers: { "Content-Type": "application/json" } });
  },
};

const operations = new Operations(deps);

/** Runs one call and records the request it produced, with whatever it returned. */
async function drive(name, note, body, run) {
  nextBody = body;
  const before = recorded.length;
  let result;
  let error = null;
  try {
    result = await run();
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  return {
    name,
    note,
    request: recorded[before] ?? null,
    result: result === undefined ? null : result,
    error,
  };
}

/** One pending witness operation, the commonest shape a caller polls. */
const PENDING = {
  name: "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0",
  metadata: { pre: "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1", sn: 0 },
  done: false,
  error: null,
};

/** The same operation completed, carrying the key event it was waiting for. */
const COMPLETED = {
  name: "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0",
  metadata: { pre: "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1", sn: 0 },
  done: true,
  error: null,
  response: {
    v: "KERI10JSON00012b_",
    t: "icp",
    d: "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
    i: "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
    s: "0",
    kt: "1",
    k: ["DAbWjobbaLqRB94KiAutAHb_qzPpOHm3LURA_ksxetVc"],
    nt: "1",
    n: ["EIFG_uqfr1yN560LoHYHfvPAhxQ5sN6xZZT_E3h7d2tL"],
    bt: "0",
    b: [],
    c: [],
    a: [],
  },
};

/** A failed operation, with and without structured details. */
const FAILED = {
  name: "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0",
  metadata: { pre: "EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1", sn: 0 },
  done: true,
  error: { code: 408, message: "Timed out waiting for witness receipts", details: { received: 2, expected: 3 } },
};
const FAILED_WITHOUT_DETAILS = {
  ...FAILED,
  error: { code: 500, message: "Internal error" },
};

const calls = [];

calls.push(
  await drive("get_pending", "the pinned unit test's own get, answered with a pending operation", JSON.stringify(PENDING), () =>
    operations.get("operationName"),
  ),
);
calls.push(
  await drive("get_completed", "the same call answered with a completed operation carrying its key event", JSON.stringify(COMPLETED), () =>
    operations.get(COMPLETED.name),
  ),
);
calls.push(
  await drive("list_all", "the pinned unit test's list with no type, whose path ends in a bare question mark", "[]", () =>
    operations.list(),
  ),
);
calls.push(
  await drive("list_by_type", "the pinned unit test's list filtered by type", "[]", () => operations.list("witness")),
);
calls.push(
  await drive("list_by_type_needing_encoding", "a type whose characters the query must encode", "[]", () =>
    operations.list("a b&c=d"),
  ),
);
calls.push(
  await drive("delete", "the pinned unit test's delete, which returns nothing", "{}", () =>
    operations.delete("operationName"),
  ),
);
calls.push(
  await drive("get_name_needing_encoding", "a name whose characters the path must encode", JSON.stringify(PENDING), () =>
    operations.get("a/b?c=d"),
  ),
);

// ---------------------------------------------------------------------------
// 3. The failure surfacing, recorded through the reference's own `wait`.
// ---------------------------------------------------------------------------

/** `throwIfFailed` is private; `wait` on an already-done operation is the way to reach it. */
async function failureMessage(operation) {
  nextBody = JSON.stringify(operation);
  try {
    await operations.wait(operation);
    return null;
  } catch (thrown) {
    return String(thrown?.message ?? thrown);
  }
}

const failures = {
  with_details: {
    operation: FAILED,
    message: await failureMessage(FAILED),
  },
  without_details: {
    operation: FAILED_WITHOUT_DETAILS,
    message: await failureMessage(FAILED_WITHOUT_DETAILS),
  },
  completed_returns_itself: await (async () => {
    nextBody = JSON.stringify(COMPLETED);
    const returned = await operations.wait(COMPLETED);
    return { identical: JSON.stringify(returned) === JSON.stringify(COMPLETED) };
  })(),
  note: "`throwIfFailed` is private, so the failure messages are reached through `wait` on an already-completed operation, which returns immediately without polling",
};
if (failures.with_details.message === null || failures.without_details.message === null) {
  throw new Error("the reference no longer throws on a failed operation");
}

// ---------------------------------------------------------------------------
// 4. The values the pinned unit test publishes.
// ---------------------------------------------------------------------------

const coringTest = parse("test/app/coring.test.ts");

function publishedPaths(source) {
  const found = [];
  const visit = (node) => {
    if (ts.isStringLiteral(node) && node.text.startsWith("/operations")) {
      found.push(node.text);
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const published = publishedPaths(coringTest.source);
const pinnedConfirmations = {
  published_paths: [...new Set(published)].sort(),
  driven_paths: calls.filter((call) => call.request !== null).map((call) => call.request.path),
  every_pinned_path_is_driven: ["/operations/operationName", "/operations?", "/operations?type=witness"].every(
    (path) => published.includes(path) && calls.some((call) => call.request?.path === path),
  ),
  note: "the three paths the pinned `coring.test.ts` asserts are all produced here by the reference's own methods",
};
if (!pinnedConfirmations.every_pinned_path_is_driven) {
  throw new Error("the pinned operations paths no longer reproduce");
}

// ---------------------------------------------------------------------------
// 5. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const quirks = {
  list_always_appends_a_question_mark: {
    path: calls.find((call) => call.name === "list_all")?.request?.path ?? null,
    expression: declarations.list_path,
    note: "`list()` builds its query with `URLSearchParams` and interpolates `?${params.toString()}` unconditionally, so a list with no filter addresses `/operations?` — a bare question mark with nothing after it. The pinned unit test asserts exactly that string.",
    rust_decision:
      "not reproduced: the request builder emits a query only when there is one, so an unfiltered list addresses `/operations`. An empty query is not a distinguishable resource, the signed path is `/operations` either way — request authentication strips the query before signing — and a KERIA agent parses the two identically.",
  },
  path_components_are_not_encoded: {
    path: calls.find((call) => call.name === "get_name_needing_encoding")?.request?.path ?? null,
    note: "an operation name is interpolated into the path with no encoding, so a name carrying `/` or `?` addresses a different resource entirely — the same defect the `http-request-response` fixture recorded across the endpoint families and pinned four executions of",
    rust_decision: "refused by construction: the request builder's `ResourcePath` encodes every dynamic component exactly once and offers no way to skip it.",
  },
  query_values_are_not_encoded_by_the_path: {
    path: calls.find((call) => call.name === "list_by_type_needing_encoding")?.request?.path ?? null,
    note: "the type filter *is* encoded, because `URLSearchParams` does it — one of only two encoded dynamic values in the whole reference, which the `http-request-response` fixture counted",
    rust_decision: "reproduced: the path builder encodes it too, so the two agree on this one.",
  },
  failure_is_a_thrown_string: {
    with_details: failures.with_details.message,
    without_details: failures.without_details.message,
    note: "a completed-but-failed operation becomes one interpolated message carrying the name, the code, the message, and the details as JSON; nothing structured survives",
    rust_decision:
      "typed: `ClientError::OperationFailed` keeps the name, the code, the message, and the details apart, and the message is bounded because it is remote text.",
  },
  delete_discards_its_response: {
    request: calls.find((call) => call.name === "delete")?.request ?? null,
    note: "`delete` awaits the fetch and returns `void`, so a caller learns nothing about what happened beyond the absence of a throw",
    rust_decision: "reproduced: the Rust method returns `Result<(), ClientError>`, since the status check is what carries the outcome.",
  },
  get_returns_the_untyped_union: {
    union: declarations.operation_union,
    scan: scan("hasDepends"),
    note: "`get` returns the fourteen-way `Operation` union, which a caller must narrow by inspecting `metadata` at run time — `hasDepends` is the reference's own example of that",
    rust_decision:
      "The KERIA API types already replaced the union with `Operation<M, R>` plus an `UntypedOperation`; `get` returns the untyped form and `get_typed` narrows it, so the narrowing is a decode rather than a property test.",
  },
};

// ---------------------------------------------------------------------------
// 6. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: ["src/keri/app/coring.ts", "test/app/coring.test.ts"],
  provenance: {
    note: "`Operations` takes an `OperationsDeps` — one `fetch` method — so the reference's own class is driven against a recorder, exactly as the pinned `coring.test.ts` drives it. Nothing here derives a key or reads a clock.",
  },
  declarations,
  calls,
  failures,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-operations/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-operations fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
