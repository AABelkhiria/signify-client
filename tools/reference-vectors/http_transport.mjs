// Records the shape of every request the pinned signify-ts checkout puts on the wire.
//
// There is no transport module upstream to port: `app/clienting.ts` calls the global `fetch`
// directly. So this generator replaces that global with a recorder, drives the reference's own
// client and endpoint code, and captures the exact method, URL, header order, and body of each
// call. The Rust transport boundary's cross-language evidence is that its `Request` type can
// express every one of these without loss.
//
// Two header values are non-deterministic by construction — `Signify-Timestamp` is a clock read
// and `Signature` covers it — so those are masked, exactly as earlier fixtures masked the
// reference's timestamps. Their byte-exact content is request authentication's evidence, already
// verified.
import { readFileSync, writeFileSync } from "node:fs";

import { SignifyClient } from "./node_modules/signify-ts/dist/keri/app/clienting.js";
import { Tier } from "./node_modules/signify-ts/dist/keri/core/salter.js";
import { Diger } from "./node_modules/signify-ts/dist/keri/core/diger.js";
import { Signer } from "./node_modules/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "./node_modules/signify-ts/dist/keri/core/matter.js";
import { b } from "./node_modules/signify-ts/dist/keri/core/core.js";
import libsodium from "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

import { referenceSha } from "./reference.mjs";

await libsodium.ready;

/** The passcode the pinned client tests use, and the URLs a deployment is configured with. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://localhost:3901";
const BOOT_URL = "http://localhost:3903";

/** Headers whose values are a clock read or cover one; recorded by name only. */
const MASKED_HEADERS = new Set(["signify-timestamp", "signature", "signature-input"]);

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
      headers: headers.map(([name, value]) => ({
        name,
        value: MASKED_HEADERS.has(name.toLowerCase()) ? null : value,
        masked: MASKED_HEADERS.has(name.toLowerCase()),
      })),
      body: sanitizeBody(init.body),
    });
    return nextResponse();
  };
}

/** Masks the one body field that is not deterministic.
 *
 * A salty keeper's `sxlt` is a sealed salt, and a sealed box draws a fresh ephemeral key on every
 * call, so the same request built twice differs in those bytes. What it opens to is the
 * `keri-keeping` fixture's evidence; here only the request's shape matters, so the value is
 * replaced by a marker.
 */
function sanitizeBody(body) {
  if (body === undefined || body === null) {
    return null;
  }
  const text = String(body);
  try {
    const parsed = JSON.parse(text);
    if (parsed?.salty?.sxlt) {
      parsed.salty.sxlt = "(sealed; a fresh ephemeral key each call)";
      return JSON.stringify(parsed);
    }
  } catch {
    // Not JSON: recorded as sent.
  }
  return text;
}

/** A canned response, so the reference's own code path completes. */
function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

// ---------------------------------------------------------------------------
// The agent state a connected client sees, anchored to this passcode's controller.
// ---------------------------------------------------------------------------

const client = new SignifyClient(ADMIN_URL, BRAN, Tier.low, BOOT_URL);
const controllerPrefix = client.controller.pre;

/** A delegated agent inception anchored to the controller, as `Agent` requires. */
const agentSigner = new Signer({
  raw: new Uint8Array([
    187, 140, 234, 145, 219, 254, 20, 194, 16, 18, 97, 194, 140, 192, 61, 145, 222, 110, 59, 160, 152, 2, 72, 122,
    87, 143, 109, 39, 98, 153, 192, 148,
  ]),
  code: MtrDex.Ed25519_Seed,
  transferable: false,
});
const agentState = {
  vn: [1, 0],
  i: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
  s: "0",
  p: "",
  d: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY",
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
  ee: { s: "0", d: "EJoqUumpXCf9HXV6JAGCsQ5aGCxCfSqhSGZGoVmVuDdY", br: [], ba: [] },
  di: controllerPrefix,
};

/** The controller half of the state response, whose `ee` drives the restore branch. */
const controllerState = {
  state: {
    ...agentState,
    i: controllerPrefix,
    d: controllerPrefix,
    et: "icp",
    di: "",
  },
  ee: { ...client.controller.serder.sad },
};

// ---------------------------------------------------------------------------
// Drive the reference: boot, state, connect, and one authenticated call of each method.
// ---------------------------------------------------------------------------

const cases = [];
function label(name, note) {
  cases.push({ name, note, request: recorded[recorded.length - 1] });
}

/** Drives one reference call, keeping the request it sent even if it rejects the canned answer.
 *
 * After `connect`, `SignifyClient.fetch` requires the response to carry the agent's
 * `Signify-Resource` header and an agent signature over it. Producing those is the `http-auth`
 * fixture's subject, not this fixture's: the request has already been recorded by the time the
 * reference inspects the answer, and the request is what the transport boundary must be able to
 * express.
 */
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
  label(name, note);
}

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await client.boot();
label("boot", "the unauthenticated POST that creates an agent; its headers are a plain object");

globalThis.fetch = recordingFetch(() =>
  jsonResponse({ agent: agentState, controller: controllerState, ridx: 0, pidx: 0 })
);
await client.state();
label("state", "the unauthenticated GET that reads agent and controller state");

// `connect` reads state, builds the controller and agent, and — because the stored establishment
// event is at sequence zero — approves the delegation, which is itself a recorded request.
await drive("approve_delegation", "the authenticated PUT that anchors the agent, sent during connect", () =>
  client.connect()
);

globalThis.fetch = recordingFetch(() =>
  jsonResponse([], 200, { "Content-Range": "aids 0-1/2", "Content-Type": "application/json" })
);
await drive("identifiers_list", "an authenticated GET carrying a Range header and no body", () =>
  client.identifiers().list()
);

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("identifier_update", "an authenticated PUT whose path holds percent-encoded UTF-8", () =>
  client.identifiers().update("a name with ñ!", { name: "renamed" })
);

globalThis.fetch = recordingFetch(() => jsonResponse([]));
await drive("contacts_list_with_query", "an authenticated GET with a query string", () =>
  client.contacts().list("group", "field", "value")
);

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("contact_delete", "an authenticated DELETE with no body", () => client.contacts().delete("EPRE"));

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("identifier_create", "an authenticated POST whose body carries an inception event and its signatures", () =>
  client.identifiers().create("aid1", { bran: BRAN })
);

// ---------------------------------------------------------------------------
// The response shapes a transport must be able to carry back.
// ---------------------------------------------------------------------------

const responses = [
  {
    name: "json_ok",
    status: 200,
    headers: [{ name: "content-type", value: "application/json" }],
    body: '{"name":"aid1"}',
    note: "the ordinary success a typed endpoint decodes",
  },
  {
    name: "ranged_list",
    status: 200,
    headers: [
      { name: "content-type", value: "application/json" },
      { name: "content-range", value: "aids 0-1/2" },
    ],
    body: "[]",
    note: "a list response whose Content-Range drives the response decoder's paging",
  },
  {
    name: "accepted_operation",
    status: 202,
    headers: [{ name: "content-type", value: "application/json" }],
    body: '{"name":"operation","done":false}',
    note: "a long-running operation, which KERIA answers with 202",
  },
  {
    name: "not_found",
    status: 404,
    headers: [{ name: "content-type", value: "text/plain" }],
    body: "not found",
    note: "a non-success status is still a response the transport must return",
  },
  {
    name: "empty_body",
    status: 204,
    headers: [],
    body: "",
    note: "no content at all",
  },
];

const quirks = {
  get_sends_a_null_body: (() => {
    const list = cases.find((entry) => entry.name === "identifiers_list");
    return {
      body: list?.request.body ?? null,
      note: "`SignifyClient.fetch` sends `method == 'GET' ? null : JSON.stringify(data)`, so a GET carries no body at all rather than an empty one",
      rust_decision: "an absent body and an empty body are different values on Request; a transport may not turn one into the other",
    };
  })(),
  headers_are_joined_on_duplicates: {
    note: "the reference builds headers with the WHATWG `Headers` class, whose `append` joins a repeated name into one comma-separated value, silently changing what a signature covers",
    rust_decision: "`keri-http-auth`'s `Headers` refuses a duplicate name; a request carrying one does not build",
  },
  boot_uses_a_second_base_url: (() => {
    const boot = cases.find((entry) => entry.name === "boot");
    const state = cases.find((entry) => entry.name === "state");
    return {
      boot_url: boot?.request.url ?? null,
      admin_url: state?.request.url ?? null,
      note: "boot goes to a separate boot interface, so a client holds two base URLs and the transport must carry whichever it is given",
      rust_decision: "the transport takes a whole absolute URL; choosing between the two is the client lifecycle's",
    };
  })(),
  delegation_approval_is_unauthenticated: (() => {
    const approval = cases.find((entry) => entry.name === "approve_delegation");
    const names = (approval?.request.headers ?? []).map((header) => header.name.toLowerCase());
    return {
      headers: names,
      carries_signature: names.includes("signature"),
      note: "`approveDelegation` calls the global fetch directly instead of `SignifyClient.fetch`, so the PUT that anchors the agent's delegation carries no Signature, Signature-Input, Signify-Resource, or Signify-Timestamp header at all — the payload's own KERI signatures are the only thing authenticating it",
      rust_decision: "recorded, not reproduced or corrected here: the transport sends whatever request it is handed, and whether this call is signed is the client lifecycle's composition decision",
    };
  })(),
  no_timeout_anywhere: {
    note: "no fetch call in the pinned source sets a signal or a timeout, so a request can hang until the platform's own default gives up",
    rust_decision: "a timeout is a transport outcome (`TransportError::Timeout`) and the policy that sets one is the retry policy",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-22",
  sources: ["src/keri/app/clienting.ts", "src/keri/app/aiding.ts", "src/keri/app/contacting.ts"],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    controller_prefix: controllerPrefix,
    masked_headers: [...MASKED_HEADERS],
    note: "the global fetch is replaced by a recorder and the reference's own client and endpoint code is driven through it; `Signify-Timestamp` is a clock read and `Signature` covers it, so both are recorded by name with the value masked — their exact bytes are request authentication's evidence",
  },
  requests: cases,
  responses,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../crates/signify-http/fixtures/http-transport/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("http-transport fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
