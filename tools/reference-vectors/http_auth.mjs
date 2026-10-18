// Records the pinned signify-ts checkout's complete authenticated-request pipeline.
//
// The `authing` port verified `siginput` and `Authenticater` in isolation, with `created` supplied
// as a parameter. What is left is the *composition* `SignifyClient.fetch` performs around them:
// stamp `Signify-Resource` and `Signify-Timestamp`, declare a content type, sign, send, then check
// the response's resource header and verify its signature.
//
// Every earlier generator had to mask `Signature`, `Signature-Input`, and `Signify-Timestamp`,
// because each is a clock reading or covers one. This one **pins the clock**: `globalThis.Date` is
// replaced by a subclass whose no-argument constructor returns a fixed instant, so the whole
// pipeline becomes deterministic and those three headers are recorded with their exact bytes. That
// makes this the first byte-exact evidence for the composed request rather than for its parts.
//
// The reference performs no freshness check anywhere — `verify` reads `created` only to rebuild the
// signature base — so that absence is recorded as a scan, as the `http-retry` fixture recorded the
// absence of `Retry-After`.
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Authenticater } from "./node_modules/signify-ts/dist/keri/core/authing.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import ts from "./node_modules/typescript/lib/typescript.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";
import { upstreamUrl } from "./upstream.mjs";

await libsodium.ready;

/** The passcode the pinned client tests use, and the URLs a deployment is configured with. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://localhost:3901";
const BOOT_URL = "http://localhost:3903";

/** The instant every clock reading returns: 2023-11-14T22:13:20.123Z. */
const FIXED_MS = 1_700_000_000_123;

// ---------------------------------------------------------------------------
// 0. Pin the clock, so the signature and the timestamp it covers are deterministic.
// ---------------------------------------------------------------------------

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
// 1. The reference's own constants and the timestamp expression.
// ---------------------------------------------------------------------------

/** Parses one pinned TypeScript file with the reference's own compiler. */
function parse(relativePath) {
  const url = upstreamUrl(relativePath);
  const text = readFileSync(url, "utf8");
  return { text, source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.ES2022, true) };
}

const clienting = parse("src/keri/app/clienting.ts");

/** Finds the expression `Signify-Timestamp` is set from, normalised to one line. */
function timestampExpression(source) {
  let found = null;
  const visit = (node) => {
    if (
      found === null &&
      ts.isCallExpression(node) &&
      node.getText().includes("toISOString") &&
      node.getText().includes("replace")
    ) {
      found = node.getText().replace(/\s+/g, " ");
    }
    ts.forEachChild(node, visit);
  };
  ts.forEachChild(source, visit);
  return found;
}

const producedTimestamp = new Date().toISOString().replace("Z", "000+00:00");

const constants = {
  default_fields: [...Authenticater.DefaultFields],
  timestamp_expression: timestampExpression(clienting.source),
  timestamp_at_fixed_clock: producedTimestamp,
  fixed_clock_ms: FIXED_MS,
  fixed_clock_iso: new Date().toISOString(),
  note: "`DefaultFields` is read from the built module and the timestamp expression from the reference's own syntax tree; the value beside it is that expression evaluated at the pinned clock",
};

// ---------------------------------------------------------------------------
// 2. Build a connected client whose agent identity is deterministic.
// ---------------------------------------------------------------------------

const recorded = [];

/** Records one fetch call and answers it with a canned response. */
function recordingFetch(nextResponse) {
  return async (url, init = {}) => {
    const headers = [];
    const raw = init.headers;
    if (raw instanceof Headers) {
      raw.forEach((value, key) => headers.push([key, value]));
    } else if (raw && typeof raw === "object") {
      for (const [key, value] of Object.entries(raw)) {
        headers.push([key, value]);
      }
    }
    recorded.push({
      url: String(url),
      method: init.method ?? "GET",
      headers: headers.map(([name, value]) => ({ name, value })),
      body: init.body === undefined || init.body === null ? null : String(init.body),
    });
    return nextResponse();
  };
}

function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
const controllerPrefix = client.controller.pre;

/** The agent's own key, fixed so its verification key and signatures are reproducible. */
const agentSigner = new Signer({
  raw: new Uint8Array([
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122,
    87, 143, 109, 39, 98, 153, 192, 148,
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
const controllerState = {
  state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
  ee: { ...client.controller.serder.sad },
};

globalThis.fetch = recordingFetch(() =>
  jsonResponse({ agent: agentState, controller: controllerState, ridx: 0, pidx: 0 })
);
await client.state();
try {
  await client.connect();
} catch (error) {
  const message = String(error?.message ?? error);
  if (message !== "message from a different remote agent" && message !== "response verification failed") {
    throw error;
  }
}

// ---------------------------------------------------------------------------
// 3. Drive the signed pipeline and record every header, unmasked.
// ---------------------------------------------------------------------------

const requests = [];

async function drive(name, note, run) {
  const before = recorded.length;
  try {
    await run();
  } catch (error) {
    const message = String(error?.message ?? error);
    const expected =
      message === "message from a different remote agent" || message === "response verification failed";
    if (!expected || recorded.length === before) {
      throw error;
    }
  }
  requests.push({ name, note, request: recorded[recorded.length - 1] ?? null });
}

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("get_identifiers", "the plainest authenticated call: a GET with no body", () =>
  client.fetch("/identifiers", "GET", null)
);
await drive("get_with_query", "a GET whose query is stripped before the path is signed", () =>
  client.fetch("/contacts?group=g&filter_field=f", "GET", null)
);
await drive("put_with_body", "a PUT whose body is signed only indirectly, through no covered field", () =>
  client.fetch("/identifiers/aid1", "PUT", { name: "renamed" })
);
await drive("post_with_body", "a POST carrying a JSON document", () =>
  client.fetch("/identifiers", "POST", { name: "aid1" })
);
await drive("delete_no_body", "a DELETE, whose absent data sends no body at all", () =>
  client.fetch("/contacts/EPRE", "DELETE", undefined)
);

// ---------------------------------------------------------------------------
// 4. Response authentication: what the reference accepts, and what it refuses.
// ---------------------------------------------------------------------------

/** Signs a response the way a KERIA agent would, using the agent's own key. */
function signedResponseHeaders(method, path, resource = agentPrefix) {
  const authenticator = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Content-Type", "application/json"],
    ["Signify-Resource", resource],
    ["Signify-Timestamp", producedTimestamp],
  ]);
  return authenticator.sign(headers, method, path);
}

const responseCases = [];

/** Runs the reference's own verification over one set of response headers. */
function verifyResponse(name, note, headers, method, path) {
  let accepted = false;
  let error = null;
  try {
    accepted = client.authn.verify(headers, method, path) === true;
  } catch (thrown) {
    error = String(thrown?.message ?? thrown);
  }
  const recordedHeaders = [];
  headers.forEach((value, key) => recordedHeaders.push({ name: key, value }));
  responseCases.push({ name, note, method, path, headers: recordedHeaders, accepted, error });
}

{
  const headers = signedResponseHeaders("GET", "/identifiers");
  verifyResponse("valid", "a response the agent signed over the same method and path", headers, "GET", "/identifiers");
}
{
  const headers = signedResponseHeaders("GET", "/identifiers");
  verifyResponse(
    "wrong_path",
    "the same signature checked against a different path, which changes the base",
    headers,
    "GET",
    "/contacts"
  );
}
{
  const headers = signedResponseHeaders("GET", "/identifiers");
  verifyResponse(
    "wrong_method",
    "the same signature checked against a different method",
    headers,
    "POST",
    "/identifiers"
  );
}
{
  const headers = signedResponseHeaders("GET", "/identifiers");
  headers.set("Signify-Timestamp", "2020-01-01T00:00:00.000000+00:00");
  verifyResponse(
    "tampered_covered_header",
    "a covered header changed after signing",
    headers,
    "GET",
    "/identifiers"
  );
}
{
  const headers = signedResponseHeaders("GET", "/identifiers");
  headers.delete("Signature");
  verifyResponse("no_signature", "no Signature header at all", headers, "GET", "/identifiers");
}
{
  const headers = signedResponseHeaders("GET", "/identifiers");
  headers.delete("Signature-Input");
  verifyResponse("no_signature_input", "no Signature-Input header at all", headers, "GET", "/identifiers");
}
{
  // A signature made years ago, still accepted: nothing anywhere compares `created` to a clock.
  const stale = new Authenticater(agentSigner, agentSigner.verfer);
  const headers = new Headers([
    ["Signify-Resource", agentPrefix],
    ["Signify-Timestamp", producedTimestamp],
  ]);
  const signed = stale.sign(headers, "GET", "/identifiers");
  verifyResponse(
    "replayed_after_the_fact",
    "the same valid signature, verified again at any later moment: the reference has no freshness check, so a captured response authenticates forever",
    signed,
    "GET",
    "/identifiers"
  );
}

// ---------------------------------------------------------------------------
// 5. The resource check, and the absence of a freshness check, as scans.
// ---------------------------------------------------------------------------

function typescriptFiles(relativeRoot) {
  const root = upstreamUrl(`${relativeRoot}/`);
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
const freshnessScan = {
  roots: ["src", "test", "test-integration"],
  files_scanned: scanned.length,
  matches: {},
  note: "a raw count is not the evidence, because two needles do match: `expires` is a signature parameter the grammar carries, and `replay` names KEL replay messages. What matters is the three booleans below — the parameter is never set, never compared, and no clock is read during verification.",
};
for (const needle of ["expires", "maxAge", "max_age", "skew", "freshness", "staleness", "replay"]) {
  const hits = scanned.filter((file) => readFileSync(file, "utf8").includes(needle));
  freshnessScan.matches[needle] = {
    count: hits.length,
    files: hits.map((file) => fileURLToPath(file).split("upstream/signify-ts/")[1] ?? "").sort(),
  };
}

const authingSource = readFileSync(
  upstreamUrl("src/keri/core/authing.ts"),
  "utf8"
);
const httpingSource = readFileSync(
  upstreamUrl("src/keri/core/httping.ts"),
  "utf8"
);
// `Authenticater.sign` passes exactly `name`, `method`, `path`, `headers`, `fields`, `alg`, and
// `keyid`; it never supplies an `expires`, so no signature it makes can ever carry one.
freshnessScan.checks = {};
freshnessScan.checks.authenticater_ever_sets_expires = /expires\s*[:,]/.test(
  authingSource.slice(authingSource.indexOf("sign("))
);
// Nowhere is `created` or `expires` compared to anything: they are read only to rebuild the base.
freshnessScan.checks.a_parameter_is_ever_compared = /(created|expires)\s*[<>]|[<>]=?\s*(created|expires)/.test(
  authingSource + httpingSource
);
// And verification reads no clock at all.
freshnessScan.checks.verification_reads_a_clock = /Date|nowUTC/.test(
  authingSource.slice(authingSource.indexOf("verify("), authingSource.indexOf("sign("))
);

// ---------------------------------------------------------------------------
// 6. Reference behaviours recorded as deliberate divergences.
// ---------------------------------------------------------------------------

const signed = requests.find((entry) => entry.name === "get_identifiers");
const withQuery = requests.find((entry) => entry.name === "get_with_query");
const headerNames = (entry) => (entry?.request?.headers ?? []).map((header) => header.name);

const quirks = {
  there_is_no_freshness_check: (() => {
    const replayed = responseCases.find((entry) => entry.name === "replayed_after_the_fact");
    return {
      accepted: replayed?.accepted ?? null,
      checks: {
        authenticater_ever_sets_expires: freshnessScan.checks.authenticater_ever_sets_expires,
        a_parameter_is_ever_compared: freshnessScan.checks.a_parameter_is_ever_compared,
        verification_reads_a_clock: freshnessScan.checks.verification_reads_a_clock,
      },
      note: "`Authenticater.verify` reads `created` only to rebuild the signature base and never compares it to a clock, and `sign` never supplies the `expires` the grammar would carry — so a captured response authenticates forever and a replayed one is indistinguishable from a fresh one",
      rust_decision: "a `Freshness` policy rejects a `created` outside a configured window by default; `Freshness::Ignore` reproduces the reference",
    };
  })(),
  the_timestamp_claims_precision_it_does_not_have: {
    expression: constants.timestamp_expression,
    produced: producedTimestamp,
    iso: constants.fixed_clock_iso,
    note: "`toISOString()` yields millisecond precision and `.replace('Z','000+00:00')` appends three zeros, so the value always ends in `000` and claims microseconds it never had",
    rust_decision: "reproduced exactly, because the value is a covered header and any other spelling would change the bytes a signature commits to",
  },
  two_clock_readings_per_request: {
    note: "`SignifyClient.fetch` reads the clock for `Signify-Timestamp` and `siginput` reads it again for `created`, so the header and the parameter can disagree by however long the two calls are apart",
    rust_decision: "one reading is taken and used for both, so a signed request is internally consistent; the reference's own two readings are identical here only because the clock is pinned",
  },
  the_query_is_stripped_before_signing: (() => ({
    url: withQuery?.request?.url ?? null,
    note: "`this.authn.sign(headers, method, path.split('?')[0])` signs the path without its query, so two requests differing only in their query have the same signature base",
    rust_decision: "reproduced: `@path` is the path alone, which is also what the transport's `RequestUrl::path` returns",
  }))(),
  covered_fields_are_fixed: {
    fields: constants.default_fields,
    note: "`Authenticater.DefaultFields` is the same four components for every request, and the body is not among them — nothing signed covers what was sent",
    rust_decision: "the same four by default and configurable, but a body digest is not invented: adding one would produce a signature KERIA cannot verify",
  },
  headers_are_appended_not_set: {
    note: "`sign` uses `headers.append` for both signature headers, so signing the same collection twice yields two comma-joined values rather than an error",
    rust_decision: "`keri-http-auth`'s `Headers` refuses a duplicate name, so a request signed twice does not build",
  },
  a_failed_verification_and_a_missing_header_are_the_same: {
    missing_signature: responseCases.find((entry) => entry.name === "no_signature")?.accepted ?? null,
    missing_input: responseCases.find((entry) => entry.name === "no_signature_input")?.accepted ?? null,
    note: "`verify` returns `false` for an absent header and throws for a bad signature, and `SignifyClient.fetch` turns both into the single message `response verification failed`",
    rust_decision: "each is a distinct typed error, as request authentication already decided",
  },
  the_resource_check_is_an_equality_on_an_untyped_header: {
    note: "`this.agent?.pre === res.headers.get('signify-resource')` compares a prefix to a raw header, so an absent header compares against `null` and a client with no agent compares `undefined` — neither is distinguished from a genuine mismatch",
    rust_decision: "the expected resource is a validated value and an absent header is its own error",
  },
};

// ---------------------------------------------------------------------------

globalThis.Date = RealDate;

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: ["src/keri/app/clienting.ts", "src/keri/core/authing.ts", "src/keri/core/httping.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    controller_prefix: controllerPrefix,
    agent_prefix: agentPrefix,
    agent_verification_key: agentSigner.verfer.qb64,
    agent_signing_seed: agentSigner.qb64,
    controller_signing_seed: client.controller.signer.qb64,
    controller_verification_key: client.controller.signer.verfer.qb64,
    seed_warning: "PUBLIC TEST MATERIAL. Both seeds are recorded so a Rust test can reproduce the exact signature bytes above. The controller's is derived by the reference itself from the passcode `0123456789abcdefghijk`, which the pinned `test/app/clienting.test.ts` publishes, and the agent's is the fixed array in this generator. Neither has ever protected anything and neither may be used for anything.",
    fixed_clock_ms: FIXED_MS,
    typescript_version: ts.version,
    note: "`globalThis.Date` is replaced by a subclass returning a fixed instant, so the whole pipeline is deterministic and `Signature`, `Signature-Input`, and `Signify-Timestamp` are recorded with their exact bytes — the first generator able to do so",
  },
  constants,
  requests,
  response_verification: responseCases,
  freshness_scan: freshnessScan,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/http-auth/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("http-auth fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
