// Records how the pinned signify-ts checkout builds a request URL and reads a response.
//
// Roadmap 5.3 has two halves and this generator has two kinds of evidence for them.
//
// The *request* half has no single upstream function: `app/clienting.ts` concatenates a base URL
// with a path its endpoint modules assembled, so the evidence is the reference's own output —
// `encodeURIComponent` for a path segment, `URLSearchParams` for a query, and the exact URL,
// `Accept`, `Content-Type`, and `Range` header of real endpoint calls captured by replacing the
// global `fetch`, exactly as Roadmap 5.1's generator does.
//
// The *response* half does have one: `parseRangeHeaders` in `core/httping.ts`, the last capability
// of that file left unported. It is called directly across a matrix of well-formed and malformed
// `Content-Range` values, and its `NaN` results are recorded as the string "NaN" because JSON
// cannot spell one. The status-to-error mapping is captured from `SignifyClient.fetch` itself, and
// the body decoding from the platform `Response` the reference calls `.json()` and `.text()` on.
import { readFileSync, readdirSync, writeFileSync } from "node:fs";

import { SignifyClient } from "../../reference/signify-ts/dist/keri/app/clienting.js";
import { Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { parseRangeHeaders } from "../../reference/signify-ts/dist/keri/core/httping.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";

/** The passcode the pinned client tests use, and the URLs a deployment is configured with. */
const BRAN = "0123456789abcdefghijk";
const ADMIN_URL = "http://localhost:3901";
const BOOT_URL = "http://localhost:3903";

/** Headers whose values are a clock read or cover one; recorded by name only, as Roadmap 5.1 did. */
const MASKED_HEADERS = new Set(["signify-timestamp", "signature", "signature-input"]);

// ---------------------------------------------------------------------------
// 1. Path segments: what `encodeURIComponent` does to a dynamic component.
// ---------------------------------------------------------------------------

const SEGMENT_INPUTS = [
  ["aid1", "an ordinary alias, unchanged"],
  ["EPRE_yBSc0Pg9DhRfqOZWQXFOAAcJlLGCwNGVAQ_z_A0", "a qualified prefix, unchanged"],
  ["a name with ñ!", "the pinned unit test's alias: spaces and Latin-1 escape, `!` does not"],
  ["-_.!~*'()", "the complete unreserved-plus-mark set the function leaves alone"],
  ["a/b", "a path separator inside a name, which must not open a new segment"],
  ["a?b", "a query delimiter inside a name"],
  ["a#b", "a fragment delimiter inside a name"],
  ["a&b=c", "query syntax inside a name"],
  ["..", "a dot segment, which `encodeURIComponent` does NOT escape"],
  [".", "a single dot, likewise unescaped"],
  ["%", "a bare percent"],
  ["%41", "an already-escaped value, escaped a second time"],
  ["a%2Fb", "a caller who pre-encoded, double-encoded by the reference"],
  ["日本", "multi-byte UTF-8"],
  ["\u{1f600}", "an astral scalar, encoded as its four UTF-8 bytes"],
  ["", "an empty name, which collapses the segment"],
  ["aid:1", "a colon"],
  ["a@b", "an at sign"],
  ["a$b,c", "a sub-delimiter pair"],
  ["a;b", "a semicolon"],
  ["a[b]", "brackets"],
  ["a+b", "a plus, which is escaped here but means a space in a query"],
  ["a b", "a space, escaped as %20 rather than +"],
];

const pathSegments = SEGMENT_INPUTS.map(([input, note]) => ({
  input,
  encoded: encodeURIComponent(input),
  note,
}));

// ---------------------------------------------------------------------------
// 2. Query strings: what `URLSearchParams` does to a name and a value.
// ---------------------------------------------------------------------------

const QUERY_INPUTS = [
  [[["group", "g1"]], "the simplest contacts filter"],
  [
    [
      ["group", "a b"],
      ["filter_field", "a+b"],
      ["filter_value", "ñ"],
    ],
    "the reference's three contact parameters: a space becomes `+` and a real `+` becomes %2B",
  ],
  [[["type", "witness"]], "the operations type filter"],
  [[["route", "/multisig/icp"]], "an escrow route, whose slashes are escaped"],
  [
    [
      ["a", ""],
      ["b", "~*'()!-_."],
    ],
    "an empty value, and the marks a query escapes where a path segment does not",
  ],
  [[["k", "a&b=c"]], "query syntax inside a value"],
  [[["k", "日本"]], "multi-byte UTF-8"],
  [[["k", "\u{1f600}"]], "an astral scalar"],
  [[], "no parameters at all, which still yields a trailing `?` at the call site"],
  [[["k", "a/b"]], "a slash inside a value"],
  [[["k", "%"]], "a bare percent"],
  [[["a b", "c"]], "a space in the parameter *name*"],
  [
    [
      ["pre", "EPRE"],
      ["pre", "EOTHER"],
    ],
    "a repeated name, which `states` builds by hand rather than with URLSearchParams",
  ],
];

const queryStrings = QUERY_INPUTS.map(([pairs, note]) => {
  const params = new URLSearchParams();
  for (const [name, value] of pairs) {
    params.append(name, value);
  }
  return { pairs: pairs.map(([name, value]) => ({ name, value })), serialized: params.toString(), note };
});

// ---------------------------------------------------------------------------
// 3. Content-Range: `parseRangeHeaders`, the last unported capability of httping.ts.
// ---------------------------------------------------------------------------

/** JSON cannot spell a `NaN`, and the reference produces them freely; record them by name. */
function numeric(value) {
  return Number.isNaN(value) ? "NaN" : value;
}

const RANGE_INPUTS = [
  ["aids 0-1/2", "aids", "the value the reference's own list mock returns"],
  ["notes 20-40/100", "notes", "the notification unit"],
  [null, "aids", "an absent header, which yields zeros indistinguishable from a real empty range"],
  ["", "aids", "an empty header, which yields three NaNs"],
  ["aids 0-24/24", "aids", "the default page the reference requests"],
  ["aids 5-5/6", "aids", "a single item"],
  ["bytes 0-1/2", "aids", "the wrong unit: only `start` is lost, `end` and `total` still parse"],
  ["AIDS 0-1/2", "aids", "unit matching is case-sensitive"],
  ["xaids 0-1/2", "aids", "a unit with a prefix, which still strips and yields a NaN start"],
  ["aids 0-1", "aids", "no total"],
  ["aids /2", "aids", "no start or end"],
  ["aids 0-1/", "aids", "an empty total"],
  ["aids -1/2", "aids", "a missing start before the dash"],
  ["aids 1-0/2", "aids", "end before start, accepted without complaint"],
  ["aids 0-1/*", "aids", "the RFC's unknown-length form, which becomes NaN"],
  ["*/2", "aids", "the RFC's unsatisfied form"],
  ["aids 00-01/02", "aids", "leading zeros"],
  ["aids 0-1/2 aids ", "aids", "trailing junk after the total, silently ignored"],
  ["aids  0-1/2", "aids", "a doubled space, tolerated by parseInt"],
  ["  aids 0-1/2  ", "aids", "surrounding whitespace, tolerated"],
  ["aids 0-1/2/3", "aids", "a second slash, silently ignored"],
  ["aids 1e3-2e3/3e3", "aids", "exponent notation, truncated at the `e`"],
  ["aids 0x10-0x20/0x30", "aids", "parseInt reads a 0x prefix as hexadecimal"],
  ["aids 1.5-2.5/3.5", "aids", "a decimal point, truncated"],
  ["aids +1--2/+3", "aids", "signs, which parseInt accepts for a leading `+`"],
  ["aids -0-1/2", "aids", "a leading dash, which splits into an empty first field"],
  [
    "aids 9007199254740993-9007199254740994/9007199254740995",
    "aids",
    "beyond 2^53: the values come back changed, because they are doubles",
  ],
  ["aids 99999999999999999999-1/2", "aids", "far beyond 2^53"],
  ["aids 0-1/2", "", "an empty unit, which strips the first space instead"],
  ["aids 0-1/2", "aids ", "a unit with its own trailing space, which never matches"],
  ["aids 0-1/2", "s", "a unit that matches nothing, leaving the whole value in place"],
];

const contentRanges = RANGE_INPUTS.map(([header, unit, note]) => {
  const parsed = parseRangeHeaders(header, unit);
  return {
    header,
    unit,
    start: numeric(parsed.start),
    end: numeric(parsed.end),
    total: numeric(parsed.total),
    note,
  };
});

// ---------------------------------------------------------------------------
// 4. Response decoding: what the platform `Response` the reference uses actually does.
// ---------------------------------------------------------------------------

const DECODE_INPUTS = [
  ["json_ok", '{"name":"aid1"}', 200, { "Content-Type": "application/json" }, "the ordinary success"],
  [
    "json_body_declared_text",
    '{"name":"aid1"}',
    200,
    { "Content-Type": "text/plain" },
    "a JSON body declared as text, which `res.json()` parses anyway: the reference never looks at the type",
  ],
  [
    "no_content_type",
    '{"name":"aid1"}',
    200,
    {},
    "no declared type at all; the platform invents `text/plain;charset=UTF-8` and json() still parses",
  ],
  ["empty_json", "", 200, { "Content-Type": "application/json" }, "an empty body declared as JSON"],
  ["no_content", null, 204, {}, "a 204 with no body"],
  ["not_found_text", "not found", 404, { "Content-Type": "text/plain" }, "a text error body"],
  [
    "cesr_stream",
    '{"v":"ACDC10JSON000197_"}-FABEPRE0AAAAAAAAAAAAAAAAAAAAAAA',
    200,
    { "Content-Type": "application/json+cesr" },
    "the CESR stream `credentials().get(said, true)` asks for, which is not valid JSON",
  ],
  [
    "json_with_charset",
    '{"name":"aid1"}',
    200,
    { "Content-Type": "application/json; charset=utf-8" },
    "a charset parameter on the media type",
  ],
  [
    "uppercase_media_type",
    "{}",
    200,
    { "Content-Type": "APPLICATION/JSON" },
    "an upper-case media type, which HTTP compares case-insensitively",
  ],
  ["boundary_299", "{}", 299, { "Content-Type": "application/json" }, "the last status `res.ok` accepts"],
  ["boundary_300", "{}", 300, { "Content-Type": "application/json" }, "the first status `res.ok` refuses"],
  ["server_error", "boom", 500, { "Content-Type": "text/plain" }, "a server failure"],
];

const payloadDecoding = [];
for (const [name, body, status, headers, note] of DECODE_INPUTS) {
  const response = new Response(body, { status, headers });
  const copy = response.clone();
  const entry = {
    name,
    status,
    ok: response.ok,
    status_text: response.statusText,
    declared_content_type: headers["Content-Type"] ?? null,
    observed_content_type: response.headers.get("content-type"),
    body: body ?? "",
    note,
  };
  try {
    entry.json = JSON.stringify(await response.json());
    entry.json_error = null;
  } catch (error) {
    entry.json = null;
    entry.json_error = String(error?.message ?? error);
  }
  entry.text = await copy.text();
  payloadDecoding.push(entry);
}

// ---------------------------------------------------------------------------
// 5. Drive the reference's own endpoint code and record the requests it builds.
// ---------------------------------------------------------------------------

const recorded = [];

/** Records one fetch call and answers it with a canned response, as Roadmap 5.1's generator does. */
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
      body: init.body === undefined || init.body === null ? null : String(init.body),
    });
    return nextResponse();
  };
}

/** A canned response, so the reference's own code path completes. */
function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

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
const controllerState = {
  state: { ...agentState, i: controllerPrefix, d: controllerPrefix, et: "icp", di: "" },
  ee: { ...client.controller.serder.sad },
};

globalThis.fetch = recordingFetch(() =>
  jsonResponse({ agent: agentState, controller: controllerState, ridx: 0, pidx: 0 })
);
await client.state();
await drive(null, null, () => client.connect());

const requests = [];

/** Drives one reference call and keeps the request it sent, even when it rejects the canned answer.
 *
 * After `connect`, `SignifyClient.fetch` requires an agent signature over the response, which is
 * Roadmap 5.5's subject. The request is already recorded by the time the reference inspects the
 * answer, and the request is what this half of the fixture is about.
 */
async function drive(name, note, run) {
  const before = recorded.length;
  let thrown = null;
  try {
    await run();
  } catch (error) {
    const message = String(error?.message ?? error);
    const expected =
      message === "message from a different remote agent" || message === "response verification failed";
    if (!expected || recorded.length === before) {
      thrown = message;
      if (name === null) {
        throw error;
      }
    }
  }
  if (name !== null) {
    requests.push({ name, note, request: recorded[recorded.length - 1] ?? null, error: thrown });
  }
}

globalThis.fetch = recordingFetch(() =>
  jsonResponse([], 200, { "Content-Range": "aids 0-1/2", "Content-Type": "application/json" })
);
await drive("identifiers_list_default", "the default page, whose Range header names the `aids` unit", () =>
  client.identifiers().list()
);
await drive("identifiers_list_explicit", "an explicit page", () => client.identifiers().list(20, 40));

globalThis.fetch = recordingFetch(() =>
  jsonResponse([], 200, { "Content-Range": "notes 20-40/100", "Content-Type": "application/json" })
);
await drive("notifications_list", "the other range unit the reference uses", () =>
  client.notifications().list(20, 40)
);

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("identifier_get_encoded", "the one path the reference percent-encodes", () =>
  client.identifiers().get("a name with ñ!")
);
await drive("identifier_get_dot_segments", "an alias of dot segments, which encodeURIComponent leaves alone", () =>
  client.identifiers().get("..")
);

globalThis.fetch = recordingFetch(() => jsonResponse([]));
await drive("contacts_list_query", "a query built with URLSearchParams", () =>
  client.contacts().list("group", "field", "value")
);
await drive("contacts_list_no_filter", "the same call with nothing to filter on, which still emits `?`", () =>
  client.contacts().list()
);

globalThis.fetch = recordingFetch(() => jsonResponse([]));
await drive("operations_list_typed", "the operations type filter", () => client.operations().list("witness"));

globalThis.fetch = recordingFetch(() => jsonResponse([]));
await drive("escrows_list_reply", "a route whose slashes the query escapes", () =>
  client.escrows().listReply("/multisig/icp")
);

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("credential_get_json", "the JSON form, which sets an explicit Accept header", () =>
  client.credentials().get("ECRED", false)
);
await drive("credential_get_cesr", "the CESR form, whose Accept header selects a stream response", () =>
  client.credentials().get("ECRED", true)
);

globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("credential_state", "two dynamic components in one path", () =>
  client.credentials().state("EREGISTRY", "ECRED")
);

// The un-encoded interpolations: every dynamic component outside `aiding.get`/`aiding.update`.
globalThis.fetch = recordingFetch(() => jsonResponse({}));
await drive("operation_get_traversal", "an operation name of dot segments, interpolated raw", () =>
  client.operations().get("../identifiers")
);
await drive("contact_delete_raw_slash", "a contact prefix holding a slash, interpolated raw", () =>
  client.contacts().delete("a/b")
);
await drive("notification_mark_raw_query", "a notification SAID holding a query delimiter, interpolated raw", () =>
  client.notifications().mark("a?b=c")
);
await drive("key_states_raw_query_value", "a prefix interpolated raw into a query value", () =>
  client.keyStates().get("a&b=c")
);

// ---------------------------------------------------------------------------
// 6. The status-to-error mapping `SignifyClient.fetch` applies.
// ---------------------------------------------------------------------------

const STATUS_INPUTS = [
  [200, "{}", "a success"],
  [202, '{"done":false}', "the long-running operation status KERIA answers with"],
  [299, "{}", "the last status accepted"],
  [300, "{}", "the first status refused"],
  [400, "bad request", "a client error carrying a text body"],
  [404, '{"title":"not found"}', "a missing resource whose body is JSON"],
  [409, "", "a conflict with an empty body"],
  [500, "internal error", "a server failure"],
];

const statusOutcomes = [];
for (const [status, body, note] of STATUS_INPUTS) {
  globalThis.fetch = recordingFetch(
    () => new Response(body, { status, headers: { "Content-Type": "application/json" } })
  );
  let message = null;
  try {
    await client.fetch("/identifiers/aid1", "GET", null);
  } catch (error) {
    message = String(error?.message ?? error);
  }
  statusOutcomes.push({
    status,
    body,
    ok: status >= 200 && status <= 299,
    // A response the reference accepts still fails afterwards on the missing agent signature,
    // which is Roadmap 5.5's; only the status branch is this fixture's evidence.
    message,
    note,
  });
}

// ---------------------------------------------------------------------------
// 7. Reference behaviours recorded as deliberate divergences.
// ---------------------------------------------------------------------------

/** Counts the dynamic values the reference interpolates into a path, and how many it encodes.
 *
 * Read from the pinned source rather than hand-counted, so the number is evidence: every line
 * assigning a `path` (or building one inline in `clienting.ts`) is scanned for substitutions and
 * `+ identifier` concatenations, and each is classified by whether `encodeURIComponent` appears.
 */
function countPathInterpolations() {
  const directory = new URL("../../reference/signify-ts/src/keri/app/", import.meta.url);
  const files = readdirSync(directory).filter((name) => name.endsWith(".ts"));
  let encoded = 0;
  let raw = 0;
  for (const name of files) {
    const source = readFileSync(new URL(name, directory), "utf8");
    for (const line of source.split("\n")) {
      if (!/const path\s*=|this\.url \+|bootUrl \+/.test(line)) {
        continue;
      }
      for (const value of line.match(/\$\{[^}]*\}/g) ?? []) {
        if (value.includes("encodeURIComponent")) {
          encoded += 1;
        } else if (!value.includes("params.toString()")) {
          // A `URLSearchParams` serialization is already encoded; it is not a raw interpolation.
          raw += 1;
        }
      }
      // `+ path` and `+ params.toString()` are not dynamic components; only a further identifier
      // concatenated into the path itself counts.
      for (const value of line.match(/\+\s*[A-Za-z_][A-Za-z0-9_.]*(\(\))?/g) ?? []) {
        const identifier = value.replace(/^\+\s*/, "");
        if (identifier !== "path" && identifier !== "params.toString()") {
          raw += 1;
        }
      }
    }
  }
  return {
    encoded,
    raw,
    total: encoded + raw,
    files: files.length,
    method:
      "every line in src/keri/app assigning a `path` or concatenating onto a base URL, scanned for `${...}` substitutions and `+ identifier` concatenations; `+ path` and any `params.toString()` are excluded because they are the assembled path itself and an already-encoded query",
  };
}

const interpolations = countPathInterpolations();

const quirks = {
  dynamic_components_are_usually_not_encoded: (() => {
    const traversal = requests.find((entry) => entry.name === "operation_get_traversal");
    const slash = requests.find((entry) => entry.name === "contact_delete_raw_slash");
    const query = requests.find((entry) => entry.name === "notification_mark_raw_query");
    const value = requests.find((entry) => entry.name === "key_states_raw_query_value");
    return {
      encoded_paths: ["/identifiers/${encodeURIComponent(name)}"],
      encoded_interpolations: interpolations.encoded,
      raw_interpolations: interpolations.raw,
      total_interpolations: interpolations.total,
      scanned_files: interpolations.files,
      counting_method: interpolations.method,
      operation_get_url: traversal?.request?.url ?? null,
      contact_delete_url: slash?.request?.url ?? null,
      notification_mark_url: query?.request?.url ?? null,
      key_states_url: value?.request?.url ?? null,
      note: "only `aiding.get` and `aiding.update` call encodeURIComponent; every other dynamic path component and every query value built outside URLSearchParams is interpolated raw, so a value holding `/`, `?`, `#`, or `..` changes which resource is addressed — and Roadmap 3.10 signs `@path`, so it changes what the signature covers too",
      rust_decision: "every dynamic component is encoded exactly once by the URL builder, so a name can never open a segment, a query, or a fragment; the reference's raw paths are recorded here rather than reproduced",
    };
  })(),
  a_missing_content_range_is_zero: (() => {
    const absent = contentRanges.find((entry) => entry.header === null);
    const real = contentRanges.find((entry) => entry.header === "aids 0-1/2" && entry.unit === "aids");
    return {
      absent_header_result: absent ? { start: absent.start, end: absent.end, total: absent.total } : null,
      note: "`parseRangeHeaders(null, typ)` returns {0,0,0}, which a caller cannot tell apart from a server that really answered `aids 0-0/0`",
      rust_decision: "an absent header is `None` and a present one is parsed; the two are different values",
      real_zero_range_is_indistinguishable: real !== undefined,
    };
  })(),
  malformed_content_range_yields_nan: {
    note: "every field is `parseInt` of whatever the split produced, so a missing, hexadecimal, exponential, fractional, or signed field becomes a silently wrong number or a NaN that flows on into arithmetic",
    rust_decision: "a typed strict parser: the unit must match exactly, both positions and the total must be ASCII digits, and anything else is a typed error rather than a NaN",
  },
  content_range_loses_precision: (() => {
    const large = contentRanges.find((entry) => entry.header?.startsWith("aids 9007199254740993"));
    return {
      header: large?.header ?? null,
      parsed: large ? { start: large.start, end: large.end, total: large.total } : null,
      note: "the results are doubles, so a total past 2^53 comes back as a different number than the server sent",
      rust_decision: "the fields are `u64`, parsed exactly, and a value that does not fit is a typed error",
    };
  })(),
  response_json_ignores_the_content_type: (() => {
    const mislabelled = payloadDecoding.find((entry) => entry.name === "json_body_declared_text");
    return {
      declared: mislabelled?.observed_content_type ?? null,
      parsed: mislabelled?.json ?? null,
      note: "`res.json()` parses whatever the body holds regardless of what the server declared, so a text/plain or text/html error page is decoded as a domain record whenever it happens to be valid JSON",
      rust_decision: "`json()` refuses a declared media type that is not application/json, and accepts an absent one because nothing contradicts it",
    };
  })(),
  status_error_message_carries_the_body: (() => {
    const failure = statusOutcomes.find((entry) => entry.status === 400);
    return {
      status: failure?.status ?? null,
      message: failure?.message ?? null,
      note: "the thrown message is `HTTP ${method} ${path} - ${status} ${statusText} - ${body}`, interpolating the whole response body and the request path including its query",
      rust_decision: "a typed `Status` error carrying the method, the path without its query, the status, and a bounded excerpt of the body",
    };
  })(),
  status_text_is_empty: (() => {
    const failure = statusOutcomes.find((entry) => entry.status === 500);
    return {
      message: failure?.message ?? null,
      note: "the platform Response leaves `statusText` empty unless a server sends a reason phrase, so the message reads `- 500  - internal error` with two spaces",
      rust_decision: "the reason phrase is not modelled at all: HTTP/2 removed it and nothing in the reference reads it",
    };
  })(),
  content_type_is_declared_even_without_a_body: (() => {
    const list = requests.find((entry) => entry.name === "identifiers_list_default");
    const names = (list?.request?.headers ?? []).map((header) => header.name.toLowerCase());
    return {
      method: list?.request?.method ?? null,
      body: list?.request?.body ?? null,
      headers: names,
      note: "`SignifyClient.fetch` sets Content-Type: application/json on every request, including a GET that carries no body at all",
      rust_decision: "the content type and the body are set independently, so declaring one without the other stays expressible and is never implied",
    };
  })(),
  a_bodyless_put_sends_the_word_null: (() => {
    const mark = requests.find((entry) => entry.name === "notification_mark_raw_query");
    const remove = requests.find((entry) => entry.name === "contact_delete_raw_slash");
    return {
      put_body: mark?.request?.body ?? null,
      delete_body: remove?.request?.body ?? null,
      note: "`_body = method == 'GET' ? null : JSON.stringify(data)`, so a PUT whose caller passed `null` sends the four bytes `null` while a DELETE whose caller passed `undefined` sends nothing at all — the two endpoint modules differ only in which absent value they wrote",
      rust_decision: "a body is present or it is not; `null` is a JSON document a caller must ask for explicitly, never something an absent argument turns into",
    };
  })(),
  recorded_header_order_is_the_platform_sort: (() => {
    const list = requests.find((entry) => entry.name === "identifiers_list_default");
    return {
      names: (list?.request?.headers ?? []).map((header) => header.name),
      note: "the reference hands `fetch` a WHATWG `Headers`, whose iteration order is sorted by lowercased name rather than insertion — so the order recorded here is the platform's, not a choice the reference made",
      rust_decision: "this crate's `Headers` preserves insertion order, and the request builder emits its own headers before a caller's; the wire order of the authentication headers is Roadmap 5.5's composition and does not affect a signature, whose base order comes from the covered-fields list",
    };
  })(),
  empty_query_still_emits_a_delimiter: (() => {
    const empty = requests.find((entry) => entry.name === "contacts_list_no_filter");
    return {
      url: empty?.request?.url ?? null,
      note: "`/contacts` + '?' + params.toString() emits a bare trailing `?` when no filter is given; the signed `@path` is `path.split('?')[0]`, so the signature covers `/contacts` either way",
      rust_decision: "a query with no parameters is omitted, including its `?`; the reference's trailing delimiter is recorded and not reproduced",
    };
  })(),
};

// ---------------------------------------------------------------------------

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-23",
  sources: [
    "src/keri/core/httping.ts",
    "src/keri/app/clienting.ts",
    "src/keri/app/aiding.ts",
    "src/keri/app/contacting.ts",
    "src/keri/app/coring.ts",
    "src/keri/app/credentialing.ts",
    "src/keri/app/escrowing.ts",
    "src/keri/app/notifying.ts",
  ],
  provenance: {
    bran: BRAN,
    admin_url: ADMIN_URL,
    boot_url: BOOT_URL,
    controller_prefix: controllerPrefix,
    masked_headers: [...MASKED_HEADERS],
    note: "path and query encodings come from the platform functions the reference calls; `content_ranges` come from `parseRangeHeaders` directly, with NaN recorded as the string \"NaN\"; requests and status outcomes are captured by replacing the global fetch and driving the reference's own endpoint code, as Roadmap 5.1's generator does",
  },
  media_types: {
    request_content_type: "application/json",
    accept_json: "application/json",
    accept_json_cesr: "application/json+cesr",
    range_units: ["aids", "notes"],
    note: "the complete set of media types and range units the pinned source names",
  },
  path_segments: pathSegments,
  query_strings: queryStrings,
  requests,
  content_ranges: contentRanges,
  payload_decoding: payloadDecoding,
  status_outcomes: statusOutcomes,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/http-request-response/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("http-request-response fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
