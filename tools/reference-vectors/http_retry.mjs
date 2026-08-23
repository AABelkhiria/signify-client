// Records the pinned signify-ts checkout's retry behaviour: the exact delays it waits, and the
// server guidance it ignores.
//
// There is no retry module upstream to port. The delay formula appears exactly twice — in the
// production `Operations.wait` of `src/keri/app/coring.ts`, and in `test-integration/utils/retry.ts`
// — and nothing else in the pinned tree retries anything. So this generator produces two kinds of
// evidence.
//
// The production one is *executed*: `Operations.wait` builds its sleep as
// `new Promise((resolve) => setTimeout(resolve, delay))` against the **global** timer, so replacing
// that global with a recorder captures the real schedule with no wall-clock waiting at all. The
// operation responses are canned, exactly as Roadmap 5.1's generator cans `fetch`.
//
// The test helper is *read from the syntax tree* rather than executed, using the reference's own
// pinned TypeScript — the technique ADR `0012` established for Roadmap 4.1. Executing it would mean
// rewriting its `timers/promises` import to intercept the sleep, which changes the code under
// test; pinning its default values and its delay expression proves the same thing without touching
// it, and additionally proves the two formulas are textually identical.
//
// Finally, the absence of `Retry-After` handling is recorded as a *scan* rather than a claim: the
// whole pinned source and test tree is searched for the header, and the count is the evidence.
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { Operations } from "../../reference/signify-ts/dist/keri/app/coring.js";
import ts from "../../reference/signify-ts/node_modules/typescript/lib/typescript.js";

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

// ---------------------------------------------------------------------------
// 1. The production schedule, executed.
// ---------------------------------------------------------------------------

/** A client stub whose operation answers are canned; `Operations` only ever calls `fetch`. */
function operationClient(doneAfter) {
  let calls = 0;
  return {
    fetch: async (path, method) => {
      if (path !== `/operations/${OPERATION_NAME}` || method !== "GET") {
        throw new Error(`unexpected request ${method} ${path}`);
      }
      const done = calls >= doneAfter;
      calls += 1;
      return new Response(JSON.stringify({ name: OPERATION_NAME, done }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    },
    get calls() {
      return calls;
    },
  };
}

const OPERATION_NAME = "witness.EPRE";

/** Drives `Operations.wait` with the global timer replaced by a recorder.
 *
 * `coring.ts` sleeps with `new Promise((resolve) => setTimeout(resolve, delay))`, so the recorder
 * captures each delay and resolves immediately. Nothing waits, and the schedule is exact.
 */
async function recordWaitSchedule(doneAfter, options) {
  const delays = [];
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay) => {
    delays.push(delay);
    // Hand control back through a microtask rather than calling straight through, so the
    // reference's own `await` ordering is preserved.
    queueMicrotask(callback);
    return 0;
  };
  try {
    const client = operationClient(doneAfter);
    const operations = new Operations(client);
    const settled = await operations.wait({ name: OPERATION_NAME, done: false }, options);
    return { delays, polls: client.calls, done: settled.done };
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
}

/** The option sets the pinned integration suites actually pass, plus the defaults. */
const WAIT_CASES = [
  {
    name: "defaults",
    options: {},
    done_after: 8,
    note: "no options at all: minSleep 10 ms, maxSleep 10000 ms, increaseFactor 50 ms",
  },
  {
    name: "vlei_issuance",
    options: { minSleep: 1000, maxSleep: 10000 },
    done_after: 8,
    note: "singlesig-vlei-issuance and delegation-multisig: a 1000 ms floor that really does bind",
  },
  {
    name: "multisig_join",
    options: { minSleep: 500, maxSleep: 500 },
    done_after: 5,
    note: "multisig-join: an equal floor and ceiling, which flattens the curve to a constant",
  },
  {
    name: "immediate",
    options: {},
    done_after: 0,
    note: "an operation already finished on the first poll, which never sleeps",
  },
  {
    name: "long_run",
    options: {},
    done_after: 12,
    note: "far enough for the ceiling to bind and the delay to stop growing",
  },
];

const waitSchedules = [];
for (const entry of WAIT_CASES) {
  const recorded = await recordWaitSchedule(entry.done_after, entry.options);
  waitSchedules.push({
    name: entry.name,
    options: entry.options,
    polls: recorded.polls,
    done: recorded.done,
    delays_ms: recorded.delays,
    note: entry.note,
  });
}

// ---------------------------------------------------------------------------
// 2. The integration helper, read from the syntax tree.
// ---------------------------------------------------------------------------

/** Parses one pinned TypeScript file with the reference's own compiler. */
function parse(relativePath) {
  const url = new URL(`../../reference/signify-ts/${relativePath}`, import.meta.url);
  const text = readFileSync(url, "utf8");
  return {
    text,
    source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true),
  };
}

/** Collects `name = literal` defaults out of a destructuring pattern. */
function destructuredDefaults(node) {
  const defaults = {};
  const visit = (child) => {
    if (ts.isBindingElement(child) && child.initializer && ts.isIdentifier(child.name)) {
      defaults[child.name.text] = Number(child.initializer.getText());
    }
    ts.forEachChild(child, visit);
  };
  ts.forEachChild(node, visit);
  return defaults;
}

/** Finds the `Math.max(...)` delay expression in a file, normalised to one line. */
function delayExpression(source) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isCallExpression(node) &&
      node.expression.getText() === "Math.max" &&
      node.getText().includes("Math.min")
    ) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

/** Finds a `const name = literal;` declaration by name. */
function constantValue(source, name) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === name &&
      node.initializer
    ) {
      found = Number(node.initializer.getText());
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const helper = parse("test-integration/utils/retry.ts");
const production = parse("src/keri/app/coring.ts");

let helperDefaults = {};
{
  const visit = (node) => {
    if (
      ts.isVariableStatement(node) &&
      node.declarationList.declarations.some(
        (declaration) => declaration.initializer && declaration.initializer.getText() === "options"
      )
    ) {
      helperDefaults = { ...helperDefaults, ...destructuredDefaults(node) };
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(helper.source, visit);
}

const helperDelay = delayExpression(helper.source);
const productionDelay = delayExpression(production.source);

const integrationHelper = {
  path: "test-integration/utils/retry.ts",
  defaults: {
    ...helperDefaults,
    increaseFactor: constantValue(helper.source, "increaseFactor"),
  },
  delay_expression: helperDelay,
  production_delay_expression: productionDelay,
  formulas_are_identical: helperDelay === productionDelay,
  retries_on_any_error: helper.text.includes("catch (err)"),
  note: "read from the reference's own syntax tree by its own TypeScript, not executed: driving it would mean rewriting its `timers/promises` import to intercept the sleep, which would change the code under test",
};

// ---------------------------------------------------------------------------
// 3. Server guidance: a scan, so the absence is evidence rather than a claim.
// ---------------------------------------------------------------------------

/** Every `.ts` file in the pinned source and test trees. */
function typescriptFiles(relativeRoot) {
  const root = new URL(`../../reference/signify-ts/${relativeRoot}/`, import.meta.url);
  const found = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory)) {
      const child = new URL(`${entry}`, directory);
      if (statSync(fileURLToPath(child)).isDirectory()) {
        walk(new URL(`${entry}/`, directory));
      } else if (entry.endsWith(".ts")) {
        found.push(child);
      }
    }
  };
  walk(root);
  return found;
}

const scanned = ["src", "test", "test-integration"].flatMap(typescriptFiles);
const guidanceScan = {
  roots: ["src", "test", "test-integration"],
  files_scanned: scanned.length,
  matches: {},
  note: "the pinned tree is searched for every spelling of the header and of a rate-limit status; a zero count is what makes the absence evidence rather than an assertion",
};
for (const needle of ["Retry-After", "retry-after", "retryAfter", "429", "503", "Retry-after"]) {
  guidanceScan.matches[needle] = scanned.filter((file) => readFileSync(file, "utf8").includes(needle)).length;
}

// ---------------------------------------------------------------------------
// 4. Reference behaviours recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const defaults = waitSchedules.find((entry) => entry.name === "defaults");
const flat = waitSchedules.find((entry) => entry.name === "multisig_join");
const long = waitSchedules.find((entry) => entry.name === "long_run");

const quirks = {
  production_polling_is_unbounded: {
    loop: "while (true)",
    has_deadline: false,
    has_attempt_cap: false,
    note: "`Operations.wait` polls in a `while (true)` with no deadline and no attempt cap, so an operation the agent never finishes hangs the caller forever; only an AbortSignal can end it, and only the caller can supply one",
    rust_decision: "a policy is bounded by construction: a maximum attempt count is required and a total deadline is optional but checked, so a schedule always terminates",
  },
  production_abort_is_checked_after_sleeping: {
    order: ["await sleep(delay)", "options.signal?.throwIfAborted()"],
    note: "`Operations.wait` passes no signal to its `setTimeout`, then checks the signal only after waking, so aborting during a sleep still waits out the full delay — up to the 10000 ms default ceiling — before anything notices",
    rust_decision: "cancellation is dropping the future, so a dropped retry stops inside the sleep; the sleep itself is the cancellation point",
  },
  helper_abort_differs_from_production: {
    helper_passes_signal: true,
    production_passes_signal: false,
    note: "the integration helper passes its signal into `setTimeout(delay, undefined, { signal })`, so its sleep really is interruptible; the production loop does not — the two disagree about what aborting means",
    rust_decision: "one behaviour, at the one place a wait happens",
  },
  no_jitter_anywhere: {
    expression: productionDelay,
    note: "the delay is a pure function of the attempt number, so every client that starts a long-running operation at the same moment retries at the same moments forever",
    rust_decision: "jitter is applied by default (`Jitter::Equal`, a delay in [d/2, d]); `Jitter::None` exists to reproduce this schedule exactly and for deterministic tests",
  },
  server_guidance_is_ignored: {
    matches: guidanceScan.matches,
    note: "no file in the pinned tree mentions `Retry-After` in any spelling, so a server asking to be left alone for thirty seconds is retried on the client's own schedule regardless",
    rust_decision: "a valid `Retry-After` in delta-seconds overrides the computed delay, bounded by a configured ceiling so a hostile or mistaken server cannot park a client indefinitely",
  },
  min_sleep_cannot_bind_at_the_defaults: {
    default_min_sleep: 10,
    default_increase_factor: 50,
    first_delay_ms: defaults?.delays_ms?.[0] ?? null,
    note: "the floor is compared against `2**0 * increaseFactor`, which is already 50 ms at the defaults, so the documented 10 ms minimum can never take effect unless a caller raises it — as the vLEI suites do, to 1000 ms",
    rust_decision: "the floor is kept as a real parameter and the reference's own schedule is reproduced exactly, floor included",
  },
  an_equal_floor_and_ceiling_flattens_the_curve: {
    delays_ms: flat?.delays_ms ?? null,
    note: "`multisig-join` passes minSleep === maxSleep === 500, which makes the exponential term irrelevant and the schedule constant; it is the only pinned caller that does",
    rust_decision: "reproduced: the same floor and ceiling produce the same constant schedule",
  },
  the_ceiling_binds_and_the_delay_stops_growing: {
    delays_ms: long?.delays_ms ?? null,
    note: "at the defaults the delay doubles from 50 ms until it reaches the 10000 ms ceiling and then stays there",
    rust_decision: "same, with the doubling computed on checked integers so a long-lived poll cannot overflow the shift",
  },
  every_failure_is_retried_by_the_helper: {
    catches: "catch (err)",
    note: "`retry.ts` retries whatever the callback threw — a network fault, a 400, a programming error — and the integration suites wrap whole credential lookups in it, so a permanently wrong request is repeated until the 10000 ms timeout elapses",
    rust_decision: "an outcome is classified before it is retried, and a method HTTP does not define as idempotent is not retried at all unless the caller widens the scope explicitly",
  },
};

// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: ["src/keri/app/coring.ts", "test-integration/utils/retry.ts"],
  provenance: {
    operation_name: OPERATION_NAME,
    typescript_version: ts.version,
    note: "the production schedules are executed with `globalThis.setTimeout` replaced by a recorder, so no wall-clock time passes and the delays are exact; the integration helper is read from the reference's own syntax tree instead, because intercepting its sleep would mean rewriting its import",
  },
  wait_schedules: waitSchedules,
  integration_helper: integrationHelper,
  server_guidance_scan: guidanceScan,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/http-retry/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("http-retry fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
