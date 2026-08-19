// Generates and checks exchange-message vectors from the compiled pinned signify-ts checkout.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

import { b, d, Ilks } from "../../reference/signify-ts/dist/keri/core/core.js";
import { exchange } from "../../reference/signify-ts/dist/keri/app/exchanging.js";
import { Serder } from "../../reference/signify-ts/dist/keri/core/serder.js";
import { Diger } from "../../reference/signify-ts/dist/keri/core/diger.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// Identifiers already pinned by earlier fixtures: a self-addressing sender, a self-addressing
// recipient, and a basic (Ed25519) sender. The reference validates none of them, so using real
// prefixes is what makes the vectors reproducible by a Rust builder that does.
const SENDER = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const RECIPIENT = "EAKUR-LmLHWMwXTLWQ1QjxHrihBmwwrV2tYaSG7hOrWj";
const BASIC_SENDER = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
// The reference's own default shape: millisecond `toISOString` output with the trailing `Z`
// rewritten as `000+00:00`.
const STAMP = "2023-08-30T17:22:54.183000+00:00";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

// The inception event and signature the pinned `test/app/exchanging.test.ts` embeds, rebuilt from
// the salt that test uses so no secret is stored here.
const salter = new Salter({
  raw: new Uint8Array([5, 170, 143, 45, 83, 154, 233, 250, 85, 156, 2, 156, 155, 8, 72, 117]),
});
const current = salter.signer(MtrDex.Ed25519_Seed, true, "A", Tier.low, true);
const next = salter.signer(MtrDex.Ed25519_Seed, true, "N", Tier.low, true);
const icp = new Serder({
  v: "KERI10JSON000000_",
  t: Ilks.icp,
  d: "",
  i: "",
  s: "0",
  kt: "1",
  k: [current.verfer.qb64],
  nt: "1",
  n: [new Diger({}, next.verfer.qb64b).qb64],
  bt: "0",
  b: [],
  c: [],
  a: [],
});
const vcp = new Serder({ v: "KERI10JSON000000_", t: Ilks.vcp, d: "", i: "", s: "0", bt: "0", b: [] });
const SIGNATURE = current.sign(b(icp.raw), 0).qb64;
// A complete controller signature group, which is what `SignedMessage::attachments` yields.
const GROUP = `-AAB${SIGNATURE}`;

function embedCase(label, serder, attachment) {
  return { label, event_raw: serder.raw, attachment: attachment ?? null };
}

function exchangeCase(name, options) {
  const {
    route,
    payload = {},
    sender = SENDER,
    recipient = RECIPIENT,
    stamp = STAMP,
    prior,
    modifiers,
    embeds = [],
  } = options;
  const referenceEmbeds = {};
  for (const embed of embeds) {
    referenceEmbeds[embed.label] = [
      new Serder(JSON.parse(embed.event_raw)),
      embed.attachment === null ? undefined : embed.attachment,
    ];
  }
  const [exn, end] = exchange(route, payload, sender, recipient, stamp, prior, modifiers, referenceEmbeds);
  const attachments = d(end);

  // Reverse direction: the reference re-reads the exact bytes and agrees on size and identifier.
  const reparsed = new Serder(JSON.parse(exn.raw));

  return {
    name,
    route,
    sender,
    recipient,
    timestamp: stamp,
    prior: prior ?? null,
    payload_json: JSON.stringify(payload),
    modifiers_json: JSON.stringify(modifiers ?? {}),
    embeds,
    said: exn.sad.d,
    embeds_said: exn.sad.e.d ?? null,
    version_string: exn.sad.v,
    raw: exn.raw,
    raw_hex: hex(b(exn.raw)),
    raw_byte_size: b(exn.raw).length,
    attachments,
    attachments_length: attachments.length,
    reparse: {
      raw_identical: reparsed.raw === exn.raw,
      size: b(reparsed.raw).length,
      said: reparsed.sad.d,
    },
  };
}

// 1. Messages a Rust builder reproduces byte for byte.
const noEmbeds = exchangeCase("no_embeds", { route: "/multisig/vcp" });
const cases = [
  noEmbeds,
  exchangeCase("ipex_apply_payload", {
    route: "/ipex/apply",
    payload: { m: "", s: "EMwcy7QflVQyLzZlaXWQY-mllTaqxL_G5rZAAmn6vNBd", a: {} },
  }),
  exchangeCase("prior_and_modifiers", {
    route: "/ipex/offer",
    payload: { m: "please review" },
    prior: noEmbeds.said,
    modifiers: { usage: "test", count: 3 },
  }),
  exchangeCase("basic_prefix_sender", { route: "/multisig/rpy", sender: BASIC_SENDER }),
  exchangeCase("embed_without_attachment", {
    route: "/multisig/vcp",
    embeds: [embedCase("vcp", vcp, null)],
  }),
  exchangeCase("embed_with_signature_group", {
    route: "/multisig/icp",
    embeds: [embedCase("icp", icp, GROUP), embedCase("vcp", vcp, null)],
  }),
  // The shape the pinned unit test transposes: a bare indexed signature with no counter.
  exchangeCase("embed_with_bare_signature", {
    route: "/multisig/icp",
    embeds: [embedCase("icp", icp, SIGNATURE)],
  }),
  exchangeCase("two_attachments", {
    route: "/ipex/grant",
    embeds: [embedCase("acdc", vcp, GROUP), embedCase("iss", icp, GROUP)],
  }),
  exchangeCase("empty_attachment", {
    route: "/multisig/vcp",
    embeds: [embedCase("vcp", vcp, "")],
  }),
  exchangeCase("non_ascii_payload", {
    route: "/multisig/rpy",
    payload: { m: "héllo — ünïcode" },
  }),
  // A count wide enough to need both Base64 digits.
  exchangeCase("wide_quadlet_count", {
    route: "/multisig/exn",
    embeds: [embedCase("exn", vcp, "A".repeat(400))],
  }),
];

// 2. The pinned unit test's own vectors, recorded verbatim. Its sender is the text `test`, its
//    recipient the empty string, and its stamp a millisecond `Z` form; all three are values the
//    reference never validates and a Rust builder cannot express.
const unitTestStamp = "2023-08-30T17:22:54.183Z";
const [unitExn, unitEnd] = exchange("/multisig/vcp", {}, "test", "", unitTestStamp);
const [unitEmbedExn, unitEmbedEnd] = exchange(
  "/multisig/vcp",
  {},
  "test",
  "",
  unitTestStamp,
  undefined,
  undefined,
  { icp: [icp, SIGNATURE], vcp: [vcp, undefined] },
);
const upstreamUnitTest = {
  source: "test/app/exchanging.test.ts",
  sender: "test",
  recipient: "",
  timestamp: unitTestStamp,
  no_embeds: { said: unitExn.sad.d, raw: unitExn.raw, attachments: d(unitEnd) },
  with_embeds: {
    said: unitEmbedExn.sad.d,
    embeds_said: unitEmbedExn.sad.e.d,
    raw: unitEmbedExn.raw,
    attachments: d(unitEmbedEnd),
  },
  note: "the asserted identifiers are only reachable from an unvalidated sender, recipient, and timestamp",
  rust_decision:
    "sender and recipient are identifier prefixes and the timestamp is validated, so each of these three inputs is refused; the same message shape is proven byte for byte in `cases` using real prefixes and the reference's own stamp format",
};

// 3. Reference behavior that Rust deliberately does not reproduce.
function raw(...args) {
  return exchange(...args)[0].raw;
}
function attachmentsOf(...args) {
  return d(exchange(...args)[1]);
}
function rejected(operation) {
  try {
    operation();
    return { threw: false, error_category: null, error_message: null };
  } catch (error) {
    return {
      threw: true,
      error_category: error?.constructor?.name ?? "Unknown",
      error_message: String(error?.message ?? error),
    };
  }
}

const quirks = {
  the_timestamp_defaults_to_the_system_clock: (() => {
    const stamp = exchange("/x", {}, SENDER, RECIPIENT)[0].sad.dt;
    return {
      shape: stamp.replace(/\d/g, "9"),
      length: stamp.length,
      note: "with no stamp the reference calls new Date().toISOString() and rewrites the trailing Z as 000+00:00, so the message -- and therefore its SAID -- depends on when it was built",
      rust_decision: "the timestamp is a required, validated parameter; a protocol crate never reads the clock",
    };
  })(),
  sender_and_recipient_are_unvalidated_text: {
    raw: raw("/x", {}, "test", "not-a-prefix", STAMP),
    note: "neither field is parsed, so an exchange can name a sender and a recipient that are not identifiers at all, and every recipient must then accept the SAID that commits to them",
    rust_decision: "both are IdentifierPrefix values, so an unparsable identifier cannot reach a message",
  },
  the_payload_overrides_the_recipient: {
    raw: raw("/x", { i: "EOTHERTHANTHERECIPIENT_00000000000000000000", m: "hi" }, SENDER, RECIPIENT, STAMP),
    note: "the attribute block is built as {...{i: recipient}, ...payload}, so a payload field named i silently readdresses the attributes while rp still names the original recipient",
    rust_error_category: "PayloadOverridesRecipient",
  },
  an_embed_labelled_d_destroys_itself: {
    raw: raw("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, { d: [vcp, undefined] }),
    note: "the embeds block's own identifier field is written after the embeds, so an embed labelled d is overwritten by the block SAID and the embedded message disappears entirely",
    rust_error_category: "ReservedEmbedLabel",
  },
  an_embed_labelled_v_throws: {
    ...rejected(() => exchange("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, { v: [vcp, undefined] })),
    note: "a v at the top of the embeds block makes the SAID machinery treat the block as a versioned message and try to parse an object as a version string",
    rust_error_category: "ReservedEmbedLabel",
  },
  a_separator_in_a_label_changes_the_path: {
    attachments: attachmentsOf("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, {
      "a-b": [vcp, "AAAA"],
    }),
    note: "the label is written into the attachment path unescaped, so a-b yields -e-a-b, which parses back as three components naming a different field; the reference's own separator check never runs on it",
    rust_error_category: "InvalidEmbedLabel",
  },
  an_empty_label_is_accepted: {
    attachments: attachmentsOf("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, { "": [vcp, "AAAA"] }),
    note: "an empty label produces the path -e-, an identity step that names no field",
    rust_error_category: "InvalidEmbedLabel",
  },
  numeric_labels_are_hoisted: {
    raw: raw("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, {
      2: [vcp, undefined],
      1: [vcp, undefined],
      a: [vcp, undefined],
    }),
    note: "JavaScript enumerates array-index-like keys first, so the embeds block is written 1, 2, a regardless of insertion order, and a numeric label is an ordinal rather than a field in an attachment path",
    rust_error_category: "InvalidEmbedLabel",
  },
  a_misaligned_attachment_truncates_its_count: {
    attachments: attachmentsOf("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, { icp: [vcp, "ABC"] }),
    note: "the count is Math.floor(length / 4), so the trailing bytes fall outside the group a parser reads and corrupt whatever follows",
    rust_error_category: "NonIntegralAttachment",
  },
  a_non_cesr_attachment_is_embedded_verbatim: {
    attachments: attachmentsOf("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, { icp: [vcp, '{"a"'] }),
    note: "the attachment is concatenated without inspection, so arbitrary bytes are injected into the CESR stream a recipient parses",
    rust_error_category: "InvalidAttachmentText",
  },
  the_payload_and_modifiers_need_not_be_maps: {
    string_payload: raw("/x", "hello", SENDER, RECIPIENT, STAMP),
    array_payload: raw("/x", [1, 2], SENDER, RECIPIENT, STAMP),
    null_modifiers: raw("/x", {}, SENDER, RECIPIENT, STAMP, undefined, null, undefined),
    string_modifiers: raw("/x", {}, SENDER, RECIPIENT, STAMP, undefined, "mods", undefined),
    note: "both arguments are typed Dict<any> and written through unchanged; spreading a string into the attribute block even produces one field per character",
    rust_decision: "both are field maps, the only shape the protocol defines",
  },
};

// 4. The pathed-material counter's own bound, which both implementations enforce.
const widestAttachment = "A".repeat((4095 - 3) * 4);
const widest = attachmentsOf("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, {
  icp: [vcp, widestAttachment],
});
const countBoundary = {
  path_quadlets: 3,
  max_accepted: {
    quadlets: 4095,
    attachment_length: widestAttachment.length,
    attachments_prefix: widest.slice(0, 16),
    attachments_length: widest.length,
    attachments_sha256: createHash("sha256").update(widest).digest("hex"),
  },
  rejected: {
    quadlets: 4096,
    ...rejected(() =>
      exchange("/x", {}, SENDER, RECIPIENT, STAMP, undefined, undefined, {
        icp: [vcp, "A".repeat((4096 - 3) * 4)],
      }),
    ),
  },
};

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-19",
  sources: ["src/keri/app/exchanging.ts", "test/app/exchanging.test.ts"],
  embedded_events: { icp: icp.raw, vcp: vcp.raw },
  signature: SIGNATURE,
  cases,
  upstream_unit_test: upstreamUnitTest,
  count_boundary: countBoundary,
  reference_quirks: quirks,
};

const outputUrl = new URL("../../fixtures/keri-exchange/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("keri-exchange fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
