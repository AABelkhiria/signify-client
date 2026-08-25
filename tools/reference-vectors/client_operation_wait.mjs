// Records the pinned signify-ts checkout's operation polling loop.
//
// Roadmap 7.2 ports `Operations.wait` from `src/keri/app/coring.ts`, together with the private
// `hasDepends` it consults and the `throwIfFailed` it applies at every exit.
//
// Roadmap 5.4 already recorded this function's **delay schedule** by executing it with the global
// timer replaced, and reproduces all five recorded schedules exactly (`fixtures/http-retry/`). So
// what this fixture adds is everything else the loop does: how many requests each shape costs, in
// what order, when the dependency chain is walked and when it is skipped, which exits throw, and
// what the thrown message says.
//
// `Operations` takes an `OperationsDeps` — one `fetch` method — so the reference's own class is
// driven against a recorder, exactly as the pinned `coring.test.ts` drives it, and the global
// timer is replaced so nothing waits in wall-clock time. Both techniques are Roadmap 5.4's and
// 6.5's; neither is new here.
//
// The five pinned `wait` cases in `coring.test.ts` each assert an exact request count, and
// `pinned_confirmations.unit_test_cases` reproduces every one of those counts from the reference's
// own driven output.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";

import { Operations } from "../../reference/signify-ts/dist/keri/app/coring.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// ---------------------------------------------------------------------------
// 1. The ported declarations, read from the reference's own syntax tree.
// ---------------------------------------------------------------------------

function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const coring = parse("src/keri/app/coring.ts");
const schema = parse("src/types/keria-api-schema.ts");
const coringTest = parse("test/app/coring.test.ts");
const testUtil = parse("test-integration/utils/test-util.ts");

/** The one declaration of a method that has a body; `wait` is overloaded fifteen times. */
function method(source, className, methodName) {
  let found = null;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        const named =
          (ts.isMethodDeclaration(member) || ts.isPropertyDeclaration(member)) && member.name?.getText() === methodName;
        if (named && member.body !== undefined) {
          found = member;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** How many times a method is declared, which for `wait` is the size of its overload set. */
function overloadCount(source, className, methodName) {
  let count = 0;
  const visit = (node) => {
    if (ts.isClassDeclaration(node) && node.name?.getText() === className) {
      for (const member of node.members) {
        if (ts.isMethodDeclaration(member) && member.name?.getText() === methodName) {
          count += 1;
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return count;
}

function text(node) {
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

function localDeclaration(node, name) {
  return firstText(node, (child) => ts.isVariableDeclaration(child) && child.name.getText() === name);
}

/** Every function declared in one file, by name, so a helper can be read whole. */
function functionText(source, name) {
  let found = null;
  const visit = (node) => {
    const named =
      (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) &&
      node.name?.getText() === name &&
      node.body !== undefined;
    if (named) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/**
 * Every schema property signature named `depends`, with the interface that declares it.
 *
 * This is what decides how long a dependency chain can be: the reference *writes* recursion, but if
 * nothing a dependency can be also declares `depends`, the chain is one link and no deeper.
 */
function dependsDeclarations() {
  const found = [];
  const visit = (node) => {
    if (ts.isPropertySignature(node) && node.name?.getText() === "depends") {
      // Walk up to the nearest named property signature, which is the schema entry it belongs to.
      let owner = node.parent;
      while (owner !== undefined && !(ts.isPropertySignature(owner) && owner.name !== undefined)) {
        owner = owner.parent;
      }
      found.push({
        owner: owner?.name?.getText() ?? "<unnamed>",
        declaration: node.getText().replace(/\s+/g, " "),
      });
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

function scan(needle, { normalizeWhitespace = false } = {}) {
  const hits = [];
  let total = 0;
  for (const file of PINNED_FILES) {
    let body = readFileSync(new URL(`../../reference/signify-ts/${file}`, import.meta.url), "utf8");
    if (normalizeWhitespace) {
      // A call written across several lines is still one call site.
      body = body.replace(/\s+/g, "");
    }
    const count = body.split(needle).length - 1;
    if (count > 0) {
      hits.push({ file, count });
      total += count;
    }
  }
  return { needle, total, files: hits, scanned_files: PINNED_FILES.length, normalized: normalizeWhitespace };
}

/**
 * The whole text of one schema entry, so a claim about what it declares can be machine-checked.
 */
function schemaEntry(typeName) {
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

const waitMethod = method(coring.source, "Operations", "wait");
const hasDependsMethod = method(coring.source, "Operations", "hasDepends");
const throwIfFailedMethod = method(coring.source, "Operations", "throwIfFailed");

const declarations = {
  wait_body: text(waitMethod?.body ?? null),
  wait_overloads: overloadCount(coring.source, "Operations", "wait"),
  wait_defaults: {
    min_sleep: localDeclaration(waitMethod, "minSleep"),
    max_sleep: localDeclaration(waitMethod, "maxSleep"),
    increase_factor: localDeclaration(waitMethod, "increaseFactor"),
  },
  wait_delay: localDeclaration(waitMethod, "delay"),
  wait_dependency_guard: firstText(
    waitMethod,
    (node) => ts.isIfStatement(node) && node.getText().includes("hasDepends"),
  ),
  wait_loop: firstText(waitMethod, (node) => ts.isWhileStatement(node)),
  wait_abort: firstText(waitMethod, (node) => ts.isExpressionStatement(node) && node.getText().includes("throwIfAborted")),
  has_depends_body: text(hasDependsMethod?.body ?? null),
  throw_if_failed_body: text(throwIfFailedMethod?.body ?? null),
  depends_declarations: dependsDeclarations(),
  kel_operation_schema: schemaEntry("KelOperation"),
  kel_metadata_schemas: ["KelOperationMetadata", "DoneOperationMetadata"]
    .map((name) => ({ name, declaration: schemaEntry(name) }))
    .filter((entry) => entry.declaration !== null),
  integration_wait_operation: functionText(testUtil.source, "waitOperation"),
  integration_delete_operations: functionText(testUtil.source, "deleteOperations"),
};

for (const [name, value] of Object.entries(declarations)) {
  if (value === null || value === undefined) {
    throw new Error(`the declaration for ${name} is no longer where this generator expects it`);
  }
}
if (declarations.depends_declarations.length === 0) {
  throw new Error("no schema shape declares `depends` any more");
}
// The claim that the chain is one link long is machine-checked here rather than inferred: every
// declaration types its dependency as a `KelOperation`, and that shape declares no `depends`.
for (const entry of declarations.depends_declarations) {
  if (!entry.declaration.includes("['KelOperation']")) {
    throw new Error(`${entry.owner} no longer declares its dependency as a KelOperation`);
  }
}
// The `depends_declarations` list is exhaustive over the whole schema file, so naming its owners
// exactly is what proves no *other* family — the four a `KelOperation` can be, among them — has one.
const DEPENDS_OWNERS = ["RegistryOperationMetadata", "CredentialOperationMetadata", "DelegatorOperationMetadata"];
const owners = declarations.depends_declarations.map((entry) => entry.owner).sort();
if (JSON.stringify(owners) !== JSON.stringify([...DEPENDS_OWNERS].sort())) {
  throw new Error(`the set of schemas declaring a dependency changed: ${owners.join(", ")}`);
}
if (declarations.kel_operation_schema?.includes("depends") === true) {
  throw new Error("a KelOperation now declares a dependency of its own; the chain is deeper than one link");
}
for (const entry of declarations.kel_metadata_schemas) {
  if (entry.declaration.includes("depends")) {
    throw new Error(`${entry.name} now declares a dependency; the chain is deeper than one link`);
  }
}

// ---------------------------------------------------------------------------
// 2. Drive the reference's own `Operations.wait` against a recorder.
// ---------------------------------------------------------------------------

const recorded = [];
/** Answers queued for successive `fetch` calls; the last one repeats. */
let answers = [];

const deps = {
  async fetch(path, httpMethod, body) {
    recorded.push({ path, method: httpMethod, body: body === undefined ? null : body });
    const next = answers.length > 1 ? answers.shift() : answers[0];
    return new Response(JSON.stringify(next ?? {}), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  },
};

const operations = new Operations(deps);

/**
 * Runs one `wait` with the global timer replaced, capturing every request and every delay.
 *
 * `coring.ts` sleeps with `new Promise((resolve) => setTimeout(resolve, delay))` against the
 * **global** timer, so replacing it records the real schedule with no wall-clock waiting — the
 * technique Roadmap 5.4's fixture established.
 */
async function drive(name, note, operation, queued, options = {}) {
  recorded.length = 0;
  answers = queued.length > 0 ? [...queued] : [{}];
  const delays = [];
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay) => {
    delays.push(delay);
    // Hand control back through a microtask rather than calling straight through, so the
    // reference's own `await` ordering is preserved.
    queueMicrotask(callback);
    return 0;
  };
  let result = null;
  let error = null;
  let sameObject = null;
  try {
    result = await operations.wait(operation, options);
    sameObject = result === operation;
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
  return {
    name,
    note,
    options,
    requests: recorded.map((entry) => ({ path: entry.path, method: entry.method })),
    request_count: recorded.length,
    delays_ms: delays,
    result,
    returned_the_same_object: sameObject,
    error,
  };
}

const NAME = "witness.EMQQpnSkgfUOgWdzQTWfrgiVHKIDAhvAZIPQ6z3EAfz1.0";
const DEPENDENCY = "witness.EABC.0";
const REGISTRY = "registry.EREG";

/** A completed operation of the shape a real agent answers with. */
function completed(name, response = {}) {
  return { name, done: true, response };
}

/** A failed operation, with or without the structured detail block. */
function failed(name, code, message, details) {
  const error = details === undefined ? { code, message } : { code, message, details };
  return { name, done: false, error, ...{ done: true } };
}

/** A registry operation whose metadata names the key-event operation it waits on. */
function registryOperation(dependsState, done = false) {
  const operation = {
    name: REGISTRY,
    done,
    metadata: {
      pre: "EPRE",
      anchor: { pre: "EPRE", sn: 0, d: "EANCHOR" },
      depends: dependsState,
    },
  };
  if (done) {
    operation.response = { anchor: { pre: "EPRE", sn: 0, d: "EANCHOR" } };
  }
  return operation;
}

const calls = [];

calls.push(
  await drive(
    "already_done",
    "the pinned `does not wait for operation that is already \"done\"` case: nothing is fetched at all, and the *same object* comes back",
    { name: NAME, done: true, response: {} },
    [],
  ),
);

calls.push(
  await drive(
    "done_after_first_poll",
    "the pinned `returns when operation is done after first call` case: one request, no sleep",
    { name: NAME, done: false },
    [{ name: NAME, done: true }],
  ),
);

calls.push(
  await drive(
    "done_after_second_poll",
    "the pinned `returns when operation is done after second call` case, with its own `maxSleep: 10`",
    { name: NAME, done: false },
    [
      { name: NAME, done: false },
      { name: NAME, done: true },
    ],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "dependency_polled_first",
    "the pinned `returns when child operation is also done` case: four requests, the dependency's two before the parent's two",
    registryOperation({ name: DEPENDENCY, done: false }),
    [
      { name: DEPENDENCY, done: false },
      { name: DEPENDENCY, done: true },
      registryOperation({ name: DEPENDENCY, done: true }),
      registryOperation({ name: DEPENDENCY, done: true }, true),
    ],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "dependency_already_done",
    "a dependency the snapshot already reports finished is never polled: only the parent is",
    registryOperation({ name: DEPENDENCY, done: true, response: {} }),
    [registryOperation({ name: DEPENDENCY, done: true, response: {} }, true)],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "dependency_done_but_failed",
    "a dependency the snapshot reports finished **and failed** is skipped in silence — the guard tests `done`, not success, so the parent is polled as though nothing were wrong",
    registryOperation({ name: DEPENDENCY, done: true, error: { code: 500, message: "witness receipts timed out" } }),
    [registryOperation({ name: DEPENDENCY, done: true }, true)],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "dependency_fails_while_polled",
    "a dependency that fails while being polled throws under the **dependency's** name, not the parent's",
    registryOperation({ name: DEPENDENCY, done: false }),
    [{ name: DEPENDENCY, done: true, error: { code: 500, message: "witness receipts timed out" } }],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "dependency_null",
    "`hasDepends` is `'depends' in op.metadata`, so a metadata block carrying an explicit `null` passes the guard and is then skipped by the truthiness test beside it",
    { name: REGISTRY, done: false, metadata: { pre: "EPRE", anchor: { pre: "EPRE", sn: 0, d: "EA" }, depends: null } },
    [{ name: REGISTRY, done: true, response: {} }],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "metadata_without_depends",
    "a family whose metadata has no `depends` at all — an OOBI resolution — skips the guard entirely",
    { name: "oobi.EABC", done: false, metadata: { oobi: "http://oobiurl.com" } },
    [{ name: "oobi.EABC", done: true, response: {} }],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "already_failed",
    "a snapshot that already reports failure throws before any request is made",
    { name: NAME, done: true, error: { code: 400, message: "bad witness threshold" } },
    [],
  ),
);

calls.push(
  await drive(
    "fails_while_polling",
    "a failure discovered by polling throws with the reference's own interpolated message",
    { name: NAME, done: false },
    [{ name: NAME, done: true, error: { code: 500, message: "witness receipts timed out" } }],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "fails_with_details",
    "the same, with the structured detail block the message appends whole",
    { name: NAME, done: false },
    [
      {
        name: NAME,
        done: true,
        error: { code: 500, message: "witness receipts timed out", details: { witnesses: ["BABC"], received: 1 } },
      },
    ],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "error_null_is_not_a_failure",
    "`throwIfFailed` tests `op.error !== null`, so a completed operation carrying an explicit `null` error is returned rather than thrown",
    { name: NAME, done: false },
    [{ name: NAME, done: true, response: {}, error: null }],
    { maxSleep: 10 },
  ),
);

calls.push(
  await drive(
    "long_run_reaches_the_ceiling",
    "twelve sleeps, far enough for the 10 s ceiling to bind — the schedule Roadmap 5.4 already reproduces, recorded here beside its request count",
    { name: NAME, done: false },
    [
      ...Array.from({ length: 12 }, () => ({ name: NAME, done: false })),
      { name: NAME, done: true, response: {} },
    ],
  ),
);

// The abort case is driven separately: it needs a signal aborted from outside the loop.
const abortCase = await (async () => {
  recorded.length = 0;
  answers = [{ name: NAME, done: false }];
  const delays = [];
  const realSetTimeout = globalThis.setTimeout;
  let abortedDuringSleep = null;
  globalThis.setTimeout = (callback, delay) => {
    delays.push(delay);
    // Abort *while the sleep is outstanding*, which is the case the reference cannot notice: it
    // reads the signal only after waking.
    if (delays.length === 1) {
      abortedDuringSleep = recorded.length;
      controller.abort(new Error("Aborted"));
    }
    queueMicrotask(callback);
    return 0;
  };
  const controller = new AbortController();
  let error = null;
  try {
    await operations.wait({ name: NAME, done: false }, { signal: controller.signal, maxSleep: 10 });
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
  return {
    name: "aborted_during_sleep",
    note: "the pinned `throw if aborted` case, with the abort raised while the sleep is outstanding: the loop still completes the full delay and only then reads the signal",
    options: { maxSleep: 10 },
    requests: recorded.map((entry) => ({ path: entry.path, method: entry.method })),
    request_count: recorded.length,
    delays_ms: delays,
    requests_before_abort: abortedDuringSleep,
    result: null,
    returned_the_same_object: null,
    error,
  };
})();
calls.push(abortCase);

// ---------------------------------------------------------------------------
// 3. What the pinned tree does and does not contain.
// ---------------------------------------------------------------------------

const UNIT_TEST_CASES = [
  { title: 'does not wait for operation that is already "done"', expects: 0, driven: "already_done" },
  { title: "returns when operation is done after first call", expects: 1, driven: "done_after_first_poll" },
  { title: "returns when operation is done after second call", expects: 2, driven: "done_after_second_poll" },
  { title: "throw if aborted", expects: null, driven: "aborted_during_sleep" },
  { title: "returns when child operation is also done", expects: 4, driven: "dependency_polled_first" },
];

for (const entry of UNIT_TEST_CASES) {
  if (!coringTest.text.includes(entry.title)) {
    throw new Error(`the pinned unit test no longer declares the case ${entry.title}`);
  }
  if (entry.expects === null) {
    continue;
  }
  const driven = calls.find((call) => call.name === entry.driven);
  if (driven === undefined || driven.request_count !== entry.expects) {
    throw new Error(
      `the case ${entry.title} asserts ${entry.expects} requests; driving the reference produced ${driven?.request_count}`,
    );
  }
}

const ASSERTED_COUNTS = [
  "assert.equal(client.fetch.mock.calls.length, 0)",
  "assert.equal(client.fetch.mock.calls.length, 1)",
  "assert.equal(client.fetch.mock.calls.length, 2)",
  "assert.equal(client.fetch.mock.calls.length, 4)",
];
const assertedCounts = ASSERTED_COUNTS.filter((line) => coringTest.text.replace(/\s+/g, " ").includes(line));
if (assertedCounts.length !== ASSERTED_COUNTS.length) {
  throw new Error("a request-count assertion this fixture reproduces has moved");
}

const pinnedConfirmations = {
  unit_test_cases: UNIT_TEST_CASES.map((entry) => ({
    ...entry,
    reproduced: entry.expects === null ? null : calls.find((call) => call.name === entry.driven)?.request_count,
  })),
  asserted_request_counts: assertedCounts,
  returns_the_same_object: coringTest.text.includes("assert.equal<unknown>(op, result)"),
  wait_call_sites: scan("operations().wait(", { normalizeWhitespace: true }),
  integration_wait_call_sites: scan("waitOperation(", { normalizeWhitespace: true }),
  integration_timeout: firstText(
    testUtil.source,
    (node) => ts.isCallExpression(node) && node.getText().includes("AbortSignal.timeout"),
  ),
  note: "unlike most families this one has real pinned unit coverage of the *behaviour* rather than the address: five cases, four of which assert an exact request count, and one of which asserts the returned object is the very one passed in. Every count is reproduced here by driving the reference itself. The pinned tree calls `wait` directly only from those five cases; every other caller goes through `waitOperation`, which supplies a 30-second abort timeout and then deletes the operation.",
};

// ---------------------------------------------------------------------------
// 4. Reference behaviour recorded as deliberate divergences.
// ---------------------------------------------------------------------------

function call(name) {
  return calls.find((entry) => entry.name === name) ?? null;
}

const quirks = {
  the_loop_has_no_bound_at_all: {
    loop: declarations.wait_loop?.slice(0, 160) ?? null,
    long_run: call("long_run_reaches_the_ceiling")?.request_count ?? null,
    note: "`while (true)` with no deadline, no attempt cap, and no total budget: an operation the agent never finishes is polled forever, ten seconds apart, for as long as the process lives",
    rust_decision:
      "bounded by construction. `PollPolicy` carries Roadmap 5.4's `RetryPolicy` — the same schedule, so every recorded delay still reproduces — plus a maximum attempt count and a total deadline, defaulting to the 30 seconds the reference's *own* integration helper supplies through `AbortSignal.timeout(30000)`. Giving up is a typed `ClientError::PollingStopped` naming which bound was reached.",
  },
  the_abort_is_read_only_after_sleeping: {
    statement: declarations.wait_abort,
    requests_before_abort: call("aborted_during_sleep")?.requests_before_abort ?? null,
    delays: call("aborted_during_sleep")?.delays_ms ?? null,
    error: call("aborted_during_sleep")?.error ?? null,
    note: "`options.signal?.throwIfAborted()` sits *after* the `await` on the sleep, so a caller who aborts during a wait still waits out the full delay — up to the ten-second ceiling — before anything notices. The signal is also never read before the first request, so an already-aborted signal still costs one poll.",
    rust_decision:
      "**unrepresentable**: there is no signal. Cancellation is dropping the future, which is ADR `0019`'s decision for the whole crate, and dropping it cancels the outstanding sleep or request immediately. A test polls the future once, drops it mid-sleep, and asserts no further request is made.",
  },
  a_failed_dependency_is_skipped_in_silence: {
    guard: declarations.wait_dependency_guard,
    requests: call("dependency_done_but_failed")?.request_count ?? null,
    error: call("dependency_done_but_failed")?.error ?? null,
    note: "the guard is `!op.metadata.depends.done` — it tests whether the dependency *finished*, not whether it succeeded. A snapshot whose dependency is already done-and-failed therefore skips it entirely and polls the parent as though nothing were wrong, which is how a caller ends up waiting on an operation that can no longer complete.",
    rust_decision:
      "reproduced exactly, and documented on the method. Diverging would mean failing a wait the reference completes — and the parent's own outcome is the thing being waited on, so the agent still gets to decide. What is *not* reproduced is the silence: the condition is named in the rustdoc and a test pins it.",
  },
  the_chain_is_one_link_long: {
    declarations: declarations.depends_declarations,
    kel_operation_schema: declarations.kel_operation_schema,
    recursion: declarations.wait_dependency_guard,
    note: "`wait` calls itself on `op.metadata.depends`, which reads as arbitrary depth — but the schema declares `depends` on exactly three shapes, and all three declare it as a `KelOperation`, whose own metadata declares none. The reference's own type declarations therefore bound its recursion at one link.",
    rust_decision:
      "reproduced as a **loop over one optional dependency** rather than as recursion, because the schema makes deeper chains unrepresentable and an unbounded recursion over remote data is a stack the agent controls. `PollableMetadata` is implemented for every metadata type; a unit test asserts exactly the three the schema declares return a dependency.",
  },
  the_guard_tests_the_key_not_the_value: {
    has_depends: declarations.has_depends_body,
    requests: call("dependency_null")?.request_count ?? null,
    note: "`hasDepends` is `op.metadata !== undefined && 'depends' in op.metadata`, which is true for a metadata block carrying `depends: null`; the truthiness test beside it is what actually skips it",
    rust_decision:
      "an absent dependency and a null one are the same value here — `Option<Dependency>` — so the two-step guard collapses to one and the recorded request count is unchanged",
  },
  an_already_finished_operation_costs_nothing: {
    requests: call("already_done")?.request_count ?? null,
    same_object: call("already_done")?.returned_the_same_object ?? null,
    note: "a snapshot that already reports `done` is returned without a single request, and it is returned *by identity* — the pinned test asserts `op === result`",
    rust_decision:
      "reproduced: the operation is taken by value and moved through, so the returned `Completed` owns exactly what was handed in. Zero requests, asserted.",
  },
  an_already_failed_operation_throws_before_asking: {
    requests: call("already_failed")?.request_count ?? null,
    error: call("already_failed")?.error ?? null,
    note: "`throwIfFailed` runs on the snapshot too, so waiting on an operation that already failed raises without contacting the agent",
    rust_decision: "reproduced, through Roadmap 6.5's `completed`, which keeps the failure's four parts apart",
  },
  a_null_error_is_not_a_failure: {
    throw_if_failed: declarations.throw_if_failed_body,
    result: call("error_null_is_not_a_failure")?.result ?? null,
    error: call("error_null_is_not_a_failure")?.error ?? null,
    note: "`'error' in op && op.error !== null` — a completed operation carrying an explicit `null` error is *not* a failure, which is the shape a KERIA agent sends for a successful long-running operation",
    rust_decision:
      "reproduced by Roadmap 4.1's decoder, which reads `done`, `response`, and `error` into one three-state outcome and refuses the combinations the schema does not admit",
  },
  the_failure_message_is_one_interpolated_string: {
    plain: call("fails_while_polling")?.error ?? null,
    with_details: call("fails_with_details")?.error ?? null,
    note: "`Operation '<name>' failed [Code <code>]: <message>` with ` Details: <JSON>` appended when the structured block is present — four values a caller can only recover by parsing a sentence",
    rust_decision:
      "Roadmap 6.5 already keeps the four apart in `ClientError::OperationFailed`, with the remote message bounded at 512 bytes; `wait` reuses it unchanged and adds no variant of its own for failure",
  },
  the_integration_helper_deletes_what_it_waited_for: {
    helper: declarations.integration_wait_operation,
    deleter: declarations.integration_delete_operations,
    note: "`waitOperation` supplies a 30-second `AbortSignal.timeout` and then deletes the operation *and its whole dependency chain* — the only place the pinned tree recursively walks `depends` for anything other than waiting",
    rust_decision:
      "the timeout becomes `PollPolicy`'s default deadline, because it is the reference's own statement of how long polling should take. The deletion is **not** ported: it is a test helper's cleanup, `Operations::delete` is Roadmap 6.5's and already available, and a wait that silently deleted its subject would be a surprising side effect. Recorded here so the omission is a decision rather than an oversight.",
  },
};

// ---------------------------------------------------------------------------
// 5. Emit.
// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-25",
  sources: [
    "src/keri/app/coring.ts",
    "src/types/keria-api-schema.ts",
    "test/app/coring.test.ts",
    "test-integration/utils/test-util.ts",
  ],
  provenance: {
    operation_name: NAME,
    dependency_name: DEPENDENCY,
    registry_name: REGISTRY,
    note: "`Operations` takes an `OperationsDeps` — one `fetch` method — so the reference's own class is driven against a recorder, exactly as the pinned `coring.test.ts` drives it, with the **global timer replaced** so every delay is captured and nothing waits. Both techniques are Roadmap 6.5's and 5.4's. Nothing here derives a key, reads a clock, or is secret.",
  },
  declarations,
  calls,
  pinned_confirmations: pinnedConfirmations,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/client-operation-wait/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("client-operation-wait fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
