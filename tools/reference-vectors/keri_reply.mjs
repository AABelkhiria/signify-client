// Generates and checks reply-message vectors from the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { b, Ilks, Serials } from "../../reference/signify-ts/dist/keri/core/core.js";
import * as eventing from "../../reference/signify-ts/dist/keri/core/eventing.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const { reply } = eventing;

// The stamp the pinned `test/app/aiding.test.ts` asserts.
const STAMP = "2021-06-27T21:26:21.233257+00:00";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function replyCase(name, route, data, stamp = STAMP) {
  const serder = reply(route, data, stamp, undefined, Serials.JSON);
  const raw = serder.raw;
  return {
    name,
    route,
    timestamp: stamp,
    attributes_json: JSON.stringify(data ?? {}),
    said: serder.sad.d,
    version_string: serder.sad.v,
    raw,
    raw_hex: hex(b(raw)),
    raw_byte_size: b(raw).length,
  };
}

// 1. The two routes the pinned aiding tests exercise, plus the reference's own defaults.
const cases = [
  replyCase("end_role_add", "/end/role/add", {
    cid: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
    role: "agent",
  }),
  replyCase("loc_scheme", "/loc/scheme", {
    eid: "EHgwVwQT15OJvilVvW57HE4w0-GPs_Stj2OFoAHZSysY",
    url: "https://test.com",
    scheme: "https",
  }),
  replyCase("empty_route_and_attributes", "", {}),
  replyCase("nested_attributes", "/x", { a: { b: [1, "z"] } }),
  replyCase("non_ascii_route", "/ünïcode", {}),
  replyCase("one_microsecond_later", "/x", {}, "2021-06-27T21:26:21.233258+00:00"),
];

// 2. Which event builders the pinned reference actually exports. This is the evidence behind the
//    `N/A` decisions for receipt, query, and key-state messages: there is nothing to port.
const exportedBuilders = Object.keys(eventing)
  .filter((name) => typeof eventing[name] === "function")
  .sort();
const ilks = Object.keys(Ilks).sort();

// 3. Reference behavior that Rust deliberately does not reproduce.
const quirks = {
  the_timestamp_defaults_to_the_system_clock: (() => {
    const first = reply("/x", {}, undefined, undefined, Serials.JSON);
    return {
      shape: first.sad.dt.replace(/\d/g, "9"),
      length: first.sad.dt.length,
      note: "with no stamp the reference calls new Date().toISOString() and rewrites the trailing Z as 000+00:00, so the message -- and therefore its SAID -- depends on when it was built",
      rust_decision:
        "the timestamp is a required, validated parameter; a protocol crate never reads the clock",
    };
  })(),
  any_string_is_accepted_as_a_timestamp: {
    garbage: reply("/x", {}, "not-a-timestamp", undefined, Serials.JSON).raw,
    empty: reply("/x", {}, "", undefined, Serials.JSON).raw,
    note: "the stamp is interpolated without validation, so a typo becomes part of the message the SAID commits to and every recipient must accept",
    rust_error_category: "TimestampError",
  },
  attributes_need_not_be_a_map: {
    string: reply("/x", "hello", STAMP, undefined, Serials.JSON).raw,
    array: reply("/x", [1, 2], STAMP, undefined, Serials.JSON).raw,
    number: reply("/x", 42, STAMP, undefined, Serials.JSON).raw,
    note: "the data argument is typed `any` and is written through unchanged, so a reply can assert a bare string, array, or number where the protocol expects an attribute block",
    rust_decision: "attributes are a field map, which is the only shape the protocol defines",
  },
  null_attributes_become_an_empty_map: {
    raw: reply("/x", null, STAMP, undefined, Serials.JSON).raw,
    note: "the guard is `data == undefined`, whose loose equality also matches null, so null silently becomes {} rather than being written as null",
    rust_decision: "attributes default to an empty map and cannot be null",
  },
  the_post_derivation_check_is_unreachable: {
    note: "reply() re-verifies the SAID it just derived with prefixed and versioned both true; saidify has already written that exact identifier and version string, so the throw is dead code",
    rust_decision: "Rust derives once; the property tests assert the same invariant the check intends",
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/core/eventing.ts", "test/app/aiding.test.ts"],
  exported_builders: exportedBuilders,
  ilks,
  cases,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-reply/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-reply fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
