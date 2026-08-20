// Generates and checks KERIA API type vectors from the pinned signify-ts checkout.
//
// Unlike every other generator here, there is no function to call: `src/types/keria-api-schema.ts`
// declares types, which vanish at run time. The reference for this module is therefore the
// TypeScript *compiler*, and this script uses it two ways.
//
//  1. It reads the declaration itself, so `schemas` below is the exact structure of every schema in
//     the pinned file — each field, whether it is optional, and the type it is written as, taken
//     from the syntax tree rather than transcribed by hand.
//  2. It type-checks documents against named schemas, so `documents` below records the reference's
//     own verdict on each one. Every document is checked twice: once written as a literal, where
//     TypeScript also applies its excess-property check, and once assigned through a variable,
//     where it does not. The second is the closer model of run time, where a KERIA response is cast
//     with no check at all.
//
// The upstream generator, `scripts/generate-types.js`, fetches an OpenAPI document from
// `http://localhost:3902/spec.yaml` — a live agent. That document is checked in nowhere, so
// regeneration is not reproducible from the pinned checkout and the generated TypeScript is the
// pinned artifact. See `docs/adr/0012-keria-api-record-types.md`.
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

const referenceRoot = new URL("../../reference/signify-ts/", import.meta.url);
const require = createRequire(new URL("package.json", referenceRoot));
const ts = require("typescript");

const referenceSha = "91a04a5edd804425f42be75ffbf034f8d14e5cb2";
const schemaPath = new URL("src/types/keria-api-schema.ts", referenceRoot).pathname;
const keyStatePath = new URL("src/keri/core/keyState.ts", referenceRoot).pathname;
// A virtual file, served from memory by the compiler host below. The pinned submodule working
// tree is never written to: `AGENTS.md` §12 forbids a Rust module port from touching it.
const documentsPath = new URL("src/types/__vector-documents.ts", referenceRoot).pathname;

// ---------------------------------------------------------------------------
// Documents whose acceptance the reference compiler decides.
// ---------------------------------------------------------------------------

// The `agent` block of the pinned `test/app/test-utils.ts` `mockConnect`.
const AGENT_KEY_STATE = {
  vn: [1, 0],
  i: "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
  s: "0",
  p: "",
  d: "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei",
  f: "0",
  dt: "2023-08-19T21:04:57.948863+00:00",
  et: "dip",
  kt: "1",
  k: ["DMZh_y-H5C3cSbZZST-fqnsmdNTReZxIh0t2xSTOJQ8a"],
  nt: "1",
  n: ["EM9M2EQNCBK0MyAhVYBvR98Q0tefpvHgE-lHLs82XgqC"],
  bt: "0",
  b: [],
  c: [],
  ee: { s: "0", d: "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei", br: [], ba: [] },
  di: "ELI7pg979AdhmvrjDeam2eAO2SR5niCgnjAJXJHtJose",
};

// The `KeyState` literal the pinned `test/app/registry.test.ts` declares; every numeric-looking
// field is the empty string.
const EMPTY_KEY_STATE = {
  s: "0",
  d: "a digest",
  i: "",
  p: "",
  f: "",
  dt: "",
  et: "",
  kt: "",
  k: [],
  nt: "",
  n: [],
  bt: "",
  b: [],
  c: [],
  ee: { s: "", d: "", br: [], ba: [] },
  di: "",
};

const CONTROLLER_INCEPTION = {
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
};

const INTERACTION = {
  v: "KERI10JSON0000cb_",
  t: "ixn",
  d: "EANC",
  i: "EISS",
  s: "1",
  p: "EPP",
  a: [],
};

const ROTATION = {
  v: "KERI10JSON000_",
  t: "rot",
  d: "EAB",
  i: "ECD",
  s: "1",
  p: "EPP",
  kt: "1",
  k: ["DAA"],
  nt: "1",
  n: ["EAA"],
  bt: "0",
  br: [],
  ba: [],
  a: [],
};

const DELEGATED_INCEPTION = { ...CONTROLLER_INCEPTION, t: "dip", di: "EDEL" };

const REPLY = {
  v: "KERI10JSON000_",
  t: "rpy",
  d: "ERPY",
  dt: "2023-08-19T21:04:57.948863+00:00",
  r: "/end/role/add",
  a: {},
};

const EXCHANGE = {
  v: "KERI10JSON000_",
  t: "exn",
  d: "EEXN",
  i: "EMEM",
  rp: "EPEER",
  p: "",
  dt: "2023-08-19T21:04:57.948863+00:00",
  r: "/multisig/icp",
  q: {},
  a: {},
  e: {},
};

const ACDC = {
  v: "ACDC10JSON000_",
  d: "ECRED",
  i: "EISS",
  ri: "EREG",
  s: "ESCH",
  a: { d: "EATT", i: "EHOLD", LEI: "254900OPPU84GM83MG36" },
};

const ISSUANCE_EVENT = {
  v: "KERI10JSON0000ed_",
  t: "iss",
  d: "EISSEV",
  i: "ECRED",
  s: "0",
  ri: "EREG",
  dt: "2023-08-19T21:04:57.948863+00:00",
};

const REVOCATION = {
  v: "KERI10JSON000_",
  t: "rev",
  d: "EREV",
  i: "ECRED",
  s: "1",
  ri: "EREG",
  p: "EISSEV",
  dt: "2023-08-19T21:04:57.948863+00:00",
};

const REGISTRY_INCEPTION = {
  v: "KERI10JSON000_",
  t: "vcp",
  d: "EVCP",
  i: "EREG",
  ii: "EISS",
  s: "0",
  c: ["NB"],
  bt: "0",
  b: [],
  n: "AKl",
};

const SCHEMA = {
  $id: "ESCH",
  $schema: "http://json-schema.org/draft-07/schema#",
  title: "Legal Entity",
  description: "vLEI",
  type: "object",
  credentialType: "LegalEntityvLEICredential",
  version: "1.0.0",
  properties: {},
  additionalProperties: false,
  required: ["i"],
};

const UNBACKED_STATUS = {
  vn: [1, 0],
  i: "ECRED",
  s: "0",
  d: "EAB",
  ri: "EREG",
  a: { s: "1", d: "EANC" },
  dt: "2023-08-19T21:04:57.948863+00:00",
  et: "iss",
  ra: {},
};

const BACKED_STATUS = {
  ...UNBACKED_STATUS,
  s: "1",
  et: "brv",
  ra: { i: "EREG", s: "1", d: "EREGEV" },
};

const SALTY_STATE = {
  tier: "low",
  sxlt: "1AAHnNQTkD0yxOC9tSz_ukbB2e-qhDTStH18uCsi5PCwOyXLONDR3MeKwWv_AVJKGKGi6xiBQH25_R1RXLS2OuK3TN3ovoUKH7-A",
  pidx: 0,
  kidx: 0,
  stem: "signify:aid",
  dcode: "E",
  icodes: ["A"],
  ncodes: ["A"],
  transferable: true,
};

// The `HabState` literal the pinned `test/app/registry.test.ts` declares.
const PENDING_HAB = {
  name: "test-hab",
  prefix: "hab prefix",
  icp_dt: "2023-12-01T10:05:25.062609+00:00",
  transferable: false,
  windexes: [],
  randy: { prxs: [], nxts: [] },
};

const ACCEPTED_HAB = { ...PENDING_HAB, state: EMPTY_KEY_STATE };

const EMPTY_ENDS = {
  agent: null,
  controller: null,
  witness: null,
  registrar: null,
  watcher: null,
  judge: null,
  juror: null,
  peer: null,
  mailbox: null,
};

const documents = [
  {
    name: "key_state_agent",
    schema: "KeyStateRecord",
    provenance: "the `agent` block of `mockConnect` in test/app/test-utils.ts",
    note: "a delegated agent's key state, with every field the schema requires",
    json: AGENT_KEY_STATE,
  },
  {
    name: "key_state_empty_numeric_fields",
    schema: "KeyStateRecord",
    provenance: "the `keystate` literal declared as `KeyState` in test/app/registry.test.ts",
    note: "every numeric-looking field is the empty string, which is why Rust keeps them as text",
    json: EMPTY_KEY_STATE,
  },
  {
    name: "key_state_missing_signing_keys",
    schema: "KeyStateRecord",
    note: "a required field removed",
    json: (() => {
      const { k, ...rest } = AGENT_KEY_STATE;
      return rest;
    })(),
  },
  {
    name: "key_state_numeric_sequence_number",
    schema: "KeyStateRecord",
    note: "the sequence number sent as a JSON number rather than KERI's hexadecimal text",
    json: { ...AGENT_KEY_STATE, s: 0 },
  },
  {
    name: "key_state_unknown_field",
    schema: "KeyStateRecord",
    note: "a field a newer agent might add; the compiler's excess-property check refuses it while its run time keeps it",
    json: { ...AGENT_KEY_STATE, zz: 1 },
  },
  {
    name: "establishment_state",
    schema: "StateEERecord",
    json: { s: "0", d: "EEXekkGu9IAzav6pZVJhkLnjtjM5v3AcyA-pdKUcaGei", br: [], ba: [] },
  },
  {
    name: "establishment_state_without_witness_lists",
    schema: "StateEERecord",
    note: "`br` and `ba` are optional",
    json: { s: "0", d: "EAB" },
  },
  {
    name: "controller",
    schema: "Controller",
    provenance: "the `controller` block of `mockConnect` in test/app/test-utils.ts",
    json: { state: AGENT_KEY_STATE, ee: CONTROLLER_INCEPTION },
  },
  {
    name: "agent_resource_result",
    schema: "AgentResourceResult",
    note: "the connected-agent response with every required field present",
    json: {
      agent: AGENT_KEY_STATE,
      controller: { state: AGENT_KEY_STATE, ee: CONTROLLER_INCEPTION },
      pidx: 0,
      ridx: 0,
      sxlt: null,
    },
  },
  {
    name: "agent_resource_result_upstream_mock",
    schema: "AgentResourceResult",
    provenance: "`mockConnect` in test/app/test-utils.ts, verbatim",
    note: "the upstream mock omits `sxlt`, which the schema requires with a null default; Rust treats a nullable field as optional, so it accepts what the reference compiler refuses",
    json: {
      agent: AGENT_KEY_STATE,
      controller: { state: AGENT_KEY_STATE, ee: CONTROLLER_INCEPTION },
      ridx: 0,
      pidx: 0,
    },
  },
  { name: "key_event_inception", schema: "KeyEvent", json: CONTROLLER_INCEPTION },
  { name: "key_event_rotation", schema: "KeyEvent", json: ROTATION },
  { name: "key_event_interaction", schema: "KeyEvent", json: INTERACTION },
  { name: "key_event_delegated_inception", schema: "KeyEvent", json: DELEGATED_INCEPTION },
  {
    name: "key_event_receipt_ilk",
    schema: "KeyEvent",
    note: "an ilk outside the union; the schema types `t` as a bare string, so the reference accepts it and Rust does not",
    json: { ...INTERACTION, t: "rct" },
  },
  {
    name: "key_event_record",
    schema: "KeyEventRecord",
    json: { ked: INTERACTION, atc: "-AABAAA" },
  },
  { name: "reply", schema: "RPY_V_1", json: REPLY },
  { name: "exchange", schema: "EXN_V_1", json: EXCHANGE },
  { name: "acdc", schema: "ACDC_V_1", json: ACDC },
  {
    name: "acdc_attributes_open_block",
    schema: "ACDCAttributes",
    note: "the attribute block declares an index signature, so an unnamed attribute is accepted by both checks",
    json: { d: "EATT", i: "EHOLD", LEI: "254900OPPU84GM83MG36" },
  },
  { name: "issuance_event", schema: "IssEvent", json: ISSUANCE_EVENT },
  {
    name: "issuance_event_revocation_ilk",
    schema: "IssEvent",
    note: "`IssEvent` types `t` as a two-value enum, unlike every other message record",
    json: { ...ISSUANCE_EVENT, t: "rev" },
  },
  { name: "revocation_event", schema: "REV_V_1", json: REVOCATION },
  { name: "registry_inception_event", schema: "VCP_V_1", json: REGISTRY_INCEPTION },
  { name: "schema_document", schema: "Schema", json: SCHEMA },
  { name: "credential_status_unbacked", schema: "CredentialState", json: UNBACKED_STATUS },
  { name: "credential_status_backed", schema: "CredentialState", json: BACKED_STATUS },
  {
    name: "credential_status_unbacked_with_registry_anchor",
    schema: "CredentialState",
    note: "`ra` is `Record<string, never>` on the unbacked arm",
    json: { ...UNBACKED_STATUS, ra: { i: "EREG", s: "1", d: "EREGEV" } },
  },
  {
    name: "credential_status_unknown_kind",
    schema: "CredentialState",
    note: "an `et` outside the four the schema declares",
    json: { ...UNBACKED_STATUS, et: "vcp" },
  },
  {
    name: "credential",
    schema: "Credential",
    json: {
      sad: ACDC,
      atc: "-AAB",
      iss: ISSUANCE_EVENT,
      issatc: "-AAC",
      pre: "EISS",
      schema: SCHEMA,
      chains: [],
      status: UNBACKED_STATUS,
      anchor: { pre: "EISS", sn: 1, d: "EANC" },
      anc: INTERACTION,
      ancatc: ["-AAD"],
    },
  },
  {
    name: "registry",
    schema: "Registry",
    json: {
      name: "vLEI",
      regk: "EREG",
      pre: "EISS",
      state: {
        vn: [1, 0],
        i: "EREG",
        s: "0",
        d: "EAB",
        ii: "EISS",
        dt: "2023-08-19T21:04:57.948863+00:00",
        et: "vcp",
        bt: "0",
        b: [],
        c: ["NB"],
      },
    },
  },
  {
    name: "registry_state_unknown_kind",
    schema: "RegistryState",
    note: "an `et` outside `vcp` and `vrt`",
    json: {
      vn: [1, 0],
      i: "EREG",
      s: "0",
      d: "EAB",
      ii: "EISS",
      dt: "2023-08-19T21:04:57.948863+00:00",
      et: "iss",
      bt: "0",
      b: [],
      c: [],
    },
  },
  {
    name: "hab_pending",
    schema: "PendingHabState",
    provenance: "the `hab` literal declared as `HabState` in test/app/registry.test.ts",
    note: "a randy identifier with no key state",
    json: PENDING_HAB,
  },
  { name: "hab_accepted", schema: "HabState", json: ACCEPTED_HAB },
  {
    name: "hab_accepted_as_pending",
    schema: "PendingHabState",
    note: "key state present where the pending alias forbids it",
    json: ACCEPTED_HAB,
  },
  {
    name: "hab_pending_as_accepted",
    schema: "HabState",
    note: "no key state where the accepted alias requires it",
    json: PENDING_HAB,
  },
  {
    name: "hab_salty",
    schema: "HabState",
    provenance: "`mockGetAID` in test/app/test-utils.ts, with the `icp_dt` the schema requires added",
    json: {
      name: "aid1",
      prefix: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
      icp_dt: "2023-08-21T22:30:46.473545+00:00",
      salty: SALTY_STATE,
      transferable: true,
      state: AGENT_KEY_STATE,
      windexes: [],
    },
  },
  {
    name: "hab_upstream_mock_without_inception_stamp",
    schema: "HabState",
    provenance: "`mockGetAID` in test/app/test-utils.ts, verbatim",
    note: "the upstream mock omits `icp_dt`, which the schema requires",
    json: {
      name: "aid1",
      prefix: "ELUvZ8aJEHAQE-0nsevyYTP98rBbGJUrTj5an-pCmwrK",
      salty: SALTY_STATE,
      transferable: true,
      state: AGENT_KEY_STATE,
      windexes: [],
    },
  },
  {
    name: "hab_no_key_manager",
    schema: "HabState",
    note: "the union requires one of salty, randy, group, or extern",
    json: { name: "a", prefix: "E", icp_dt: "2023-12-01T10:05:25.062609+00:00", state: EMPTY_KEY_STATE },
  },
  {
    name: "hab_two_key_managers",
    schema: "HabState",
    note: "two arms of the union at once; the excess-property check refuses it and the structural check does not",
    json: {
      ...ACCEPTED_HAB,
      extern: { extern_type: "module", pidx: 0 },
    },
  },
  {
    name: "hab_group",
    schema: "HabState",
    note: "`mhab` is narrowed by hand in keyState.ts to the accepted form",
    json: {
      name: "multisig",
      prefix: "EGRP",
      icp_dt: "2023-12-01T10:05:25.062609+00:00",
      state: EMPTY_KEY_STATE,
      group: { mhab: ACCEPTED_HAB, keys: ["DAA"], ndigs: ["EAA"] },
    },
  },
  {
    name: "hab_extern_open_block",
    schema: "HabState",
    note: "an external key manager declares an index signature, so a module-specific field is kept",
    json: {
      name: "hsm",
      prefix: "EHSM",
      icp_dt: "2023-08-21T22:30:46.473545+00:00",
      state: EMPTY_KEY_STATE,
      extern: { extern_type: "module", pidx: 1, slot: "7" },
    },
  },
  {
    name: "salty_state_unknown_tier",
    schema: "SaltyState",
    note: "a tier outside low, med, and high",
    json: { ...SALTY_STATE, tier: "ultra" },
  },
  {
    name: "operation_pending",
    schema: "PendingWitnessOperation",
    json: { name: "witness.EABC", metadata: { pre: "EABC", sn: 0 }, done: false },
  },
  {
    name: "operation_completed",
    schema: "CompletedWitnessOperation",
    json: { name: "witness.EABC", metadata: { pre: "EABC", sn: 0 }, response: INTERACTION, done: true },
  },
  {
    name: "operation_failed",
    schema: "FailedWitnessOperation",
    json: {
      name: "witness.EABC",
      error: { code: 408, message: "timed out", details: null },
      done: true,
    },
  },
  {
    name: "operation_done_without_result",
    schema: "Operation",
    note: "the shape upstream's own `coring.test.ts` mock returns; it matches no arm of the union",
    json: { name: "witness.EABC", done: true },
  },
  {
    name: "operation_pending_claiming_done",
    schema: "PendingWitnessOperation",
    note: "`done` is a constant on each arm",
    json: { name: "witness.EABC", done: true },
  },
  {
    name: "operation_registry_with_dependency",
    schema: "PendingRegistryOperation",
    note: "one operation nesting another",
    json: {
      name: "registry.EREG",
      metadata: {
        pre: "EABC",
        depends: { name: "witness.EABC", metadata: { pre: "EABC", sn: 0 }, done: false },
        anchor: { pre: "EABC", sn: 1, d: "EAB" },
      },
      done: false,
    },
  },
  {
    name: "operation_done_metadata_carries_an_exchange",
    schema: "PendingDoneOperation",
    json: { name: "done.EABC", metadata: { response: EXCHANGE, pre: null }, done: false },
  },
  {
    name: "operation_status_without_details",
    schema: "OperationStatus",
    json: { code: 500, message: "internal error" },
  },
  {
    name: "operation_status_string_code",
    schema: "OperationStatus",
    note: "a status code sent as text",
    json: { code: "500", message: "internal error" },
  },
  { name: "member_ends", schema: "MemberEnds", json: EMPTY_ENDS },
  {
    name: "member_ends_with_agent",
    schema: "MemberEnds",
    json: { ...EMPTY_ENDS, agent: { EAGT: { http: "http://agent:3902/" } } },
  },
  {
    name: "member_ends_missing_a_role",
    schema: "MemberEnds",
    note: "every one of the nine roles is required",
    json: (() => {
      const { juror, ...rest } = EMPTY_ENDS;
      return rest;
    })(),
  },
  {
    name: "contact_open_block",
    schema: "Contact",
    note: "a contact declares an index signature, so an unnamed field is kept",
    json: {
      id: "ECON",
      alias: "alice",
      oobi: "http://witness:5642/oobi/ECON",
      challenges: [
        { words: ["a", "b"], dt: "2023-08-19T21:04:57.948863+00:00", said: "EANS", authenticated: true },
      ],
      wellKnowns: [{ url: "https://example.test", dt: "2023-08-19T21:04:57.948863+00:00" }],
      company: "Example",
    },
  },
  { name: "contact_minimal", schema: "Contact", json: { id: "ECON" } },
  { name: "challenge", schema: "Challenge", json: { words: ["a"] } },
  { name: "aid_record", schema: "AidRecord", json: { aid: "EMEM", ends: EMPTY_ENDS } },
  {
    name: "group_member",
    schema: "GroupMember",
    json: { signing: [{ aid: "EMEM", ends: EMPTY_ENDS }], rotation: [] },
  },
  {
    name: "notification",
    schema: "Notification",
    json: {
      i: "0AB",
      dt: "2023-08-19T21:04:57.948863+00:00",
      r: false,
      a: { r: "/multisig/icp", d: "EEXN", m: "", extra: 1 },
    },
  },
  {
    name: "oobi",
    schema: "OOBI",
    json: { role: "agent", oobis: ["http://agent:3902/oobi/EAGT/agent/EAG2"] },
  },
  {
    name: "oobi_unknown_role",
    schema: "OOBI",
    note: "an OOBI role is a nine-value enum while an end role is a bare string",
    json: { role: "notary", oobis: [] },
  },
  { name: "end_role", schema: "EndRole", json: { cid: "ECID", role: "agent", eid: "EEID" } },
  {
    name: "end_role_unknown_role",
    schema: "EndRole",
    note: "the same role text the OOBI record refuses",
    json: { cid: "ECID", role: "notary", eid: "EEID" },
  },
  { name: "agent_config", schema: "AgentConfig", json: { iurls: ["http://witness:5642/oobi"] } },
  { name: "well_known", schema: "WellKnown", json: { url: "https://example.test", dt: "2023-08-19T21:04:57.948863+00:00" } },
  { name: "seal", schema: "Seal", json: { s: "0", d: "EAB" } },
  { name: "anchor", schema: "Anchor", json: { pre: "ECD", sn: 3, d: "EAB" } },
  {
    name: "anchor_fractional_sequence_number",
    schema: "Anchor",
    note: "the schema types `sn` as a number, which in JavaScript admits a fraction",
    json: { pre: "ECD", sn: 1.5, d: "EAB" },
  },
  {
    name: "exchange_resource",
    schema: "ExchangeResource",
    json: { exn: EXCHANGE, pathed: { acdc: "-IAB" } },
  },
  {
    name: "exchange_embeds_inception",
    schema: "ExnEmbeds",
    json: { d: "EEMB", icp: CONTROLLER_INCEPTION },
  },
  {
    name: "exchange_embeds_delegated_inception",
    schema: "ExnEmbeds",
    note: "the `icp` slot admits an inception or a delegated inception",
    json: { d: "EEMB", icp: DELEGATED_INCEPTION },
  },
  {
    name: "exchange_embeds_interaction_in_inception_slot",
    schema: "MultisigInceptEmbeds",
    note: "an interaction where the slot admits only an inception; both refuse it, the reference on shape and Rust on ilk",
    json: { icp: INTERACTION },
  },
  {
    name: "exchange_embeds_issuance",
    schema: "ExnEmbeds",
    json: { d: "EEMB", acdc: ACDC, iss: ISSUANCE_EVENT, anc: INTERACTION },
  },
  {
    name: "exchange_embeds_revocation",
    schema: "ExnEmbeds",
    json: { d: "EEMB", rev: REVOCATION, anc: INTERACTION },
  },
  {
    name: "exchange_embeds_registry_inception",
    schema: "ExnEmbeds",
    json: { d: "EEMB", vcp: REGISTRY_INCEPTION, anc: INTERACTION },
  },
  { name: "exchange_embeds_reply", schema: "MultisigRpyEmbeds", json: { rpy: REPLY } },
  {
    name: "exchange_embeds_unknown_slot",
    schema: "ExnEmbeds",
    note: "a slot name the union does not declare",
    json: { d: "EEMB", rct: {} },
  },
  {
    name: "multisig_exchange_resource",
    schema: "ExnMultisig",
    json: { exn: EXCHANGE, paths: {}, groupName: "multisig", memberName: "member1", sender: "EMEM" },
  },
  { name: "empty_dict", schema: "EmptyDict", json: {} },
  { name: "empty_dict_with_a_field", schema: "EmptyDict", note: "`Record<string, never>`", json: { a: 1 } },
];

// ---------------------------------------------------------------------------
// What the Rust records do with the same documents.
// ---------------------------------------------------------------------------

// The Rust type each document is decoded as, and whether decoding is expected to succeed. This is
// the port's own decision, recorded next to the reference's verdict so that every disagreement is
// visible in one table rather than argued in prose. `PORTING.md` §9 explains each one.
const rustExpectations = {
  key_state_agent: ["KeyState", "accept"],
  key_state_empty_numeric_fields: ["KeyState", "accept"],
  key_state_missing_signing_keys: ["KeyState", "reject"],
  key_state_numeric_sequence_number: ["KeyState", "reject"],
  key_state_unknown_field: ["KeyState", "accept"],
  establishment_state: ["EstablishmentState", "accept"],
  establishment_state_without_witness_lists: ["EstablishmentState", "accept"],
  controller: ["Controller", "accept"],
  agent_resource_result: ["AgentResourceResult", "accept"],
  agent_resource_result_upstream_mock: ["AgentResourceResult", "accept"],
  key_event_inception: ["KeyEvent", "accept"],
  key_event_rotation: ["KeyEvent", "accept"],
  key_event_interaction: ["KeyEvent", "accept"],
  key_event_delegated_inception: ["KeyEvent", "accept"],
  key_event_receipt_ilk: ["KeyEvent", "reject"],
  key_event_record: ["KeyEventRecord", "accept"],
  reply: ["ReplyRecord", "accept"],
  exchange: ["ExchangeRecord", "accept"],
  acdc: ["AcdcRecord", "accept"],
  acdc_attributes_open_block: ["AcdcAttributes", "accept"],
  issuance_event: ["IssuanceEvent", "accept"],
  issuance_event_revocation_ilk: ["IssuanceEvent", "reject"],
  revocation_event: ["RevocationRecord", "accept"],
  registry_inception_event: ["RegistryInceptionRecord", "accept"],
  schema_document: ["Schema", "accept"],
  credential_status_unbacked: ["CredentialState", "accept"],
  credential_status_backed: ["CredentialState", "accept"],
  credential_status_unbacked_with_registry_anchor: ["CredentialState", "reject"],
  credential_status_unknown_kind: ["CredentialState", "reject"],
  credential: ["Credential", "accept"],
  registry: ["Registry", "accept"],
  registry_state_unknown_kind: ["RegistryState", "reject"],
  hab_pending: ["Hab", "accept"],
  hab_accepted: ["Hab", "accept"],
  hab_accepted_as_pending: ["PendingHab", "reject"],
  hab_pending_as_accepted: ["AcceptedHab", "reject"],
  hab_salty: ["Hab", "accept"],
  hab_upstream_mock_without_inception_stamp: ["Hab", "reject"],
  hab_no_key_manager: ["Hab", "reject"],
  hab_two_key_managers: ["Hab", "reject"],
  hab_group: ["Hab", "accept"],
  hab_extern_open_block: ["Hab", "accept"],
  salty_state_unknown_tier: ["SaltyState", "reject"],
  operation_pending: ["WitnessOperation", "accept"],
  operation_completed: ["WitnessOperation", "accept"],
  operation_failed: ["WitnessOperation", "accept"],
  operation_done_without_result: ["UntypedOperation", "reject"],
  operation_pending_claiming_done: ["WitnessOperation", "reject"],
  operation_registry_with_dependency: ["RegistryOperation", "accept"],
  operation_done_metadata_carries_an_exchange: ["DoneOperation", "accept"],
  operation_status_without_details: ["OperationStatus", "accept"],
  operation_status_string_code: ["OperationStatus", "reject"],
  member_ends: ["MemberEnds", "accept"],
  member_ends_with_agent: ["MemberEnds", "accept"],
  member_ends_missing_a_role: ["MemberEnds", "accept"],
  contact_open_block: ["Contact", "accept"],
  contact_minimal: ["Contact", "accept"],
  challenge: ["Challenge", "accept"],
  aid_record: ["AidRecord", "accept"],
  group_member: ["GroupMember", "accept"],
  notification: ["Notification", "accept"],
  oobi: ["Oobi", "accept"],
  oobi_unknown_role: ["Oobi", "accept"],
  end_role: ["EndRole", "accept"],
  end_role_unknown_role: ["EndRole", "accept"],
  agent_config: ["AgentConfig", "accept"],
  well_known: ["WellKnown", "accept"],
  seal: ["Seal", "accept"],
  anchor: ["Anchor", "accept"],
  anchor_fractional_sequence_number: ["Anchor", "reject"],
  exchange_resource: ["ExchangeResource", "accept"],
  exchange_embeds_inception: ["ExchangeEmbeds", "accept"],
  exchange_embeds_delegated_inception: ["ExchangeEmbeds", "accept"],
  exchange_embeds_interaction_in_inception_slot: ["MultisigInceptionEmbed", "reject"],
  exchange_embeds_issuance: ["ExchangeEmbeds", "accept"],
  exchange_embeds_revocation: ["ExchangeEmbeds", "accept"],
  exchange_embeds_registry_inception: ["ExchangeEmbeds", "accept"],
  exchange_embeds_reply: ["MultisigReplyEmbed", "accept"],
  exchange_embeds_unknown_slot: ["ExchangeEmbeds", "reject"],
  multisig_exchange_resource: ["MultisigExchangeResource", "accept"],
  empty_dict: ["EmptyObject", "accept"],
  empty_dict_with_a_field: ["EmptyObject", "reject"],
};

// ---------------------------------------------------------------------------
// Reading the declaration.
// ---------------------------------------------------------------------------

/** Collapses the whitespace TypeScript's printer leaves in a type's source text. */
function typeText(node, source) {
  return node.getText(source).replace(/\s+/g, " ").trim();
}

/** Describes one type node structurally, keeping schema references as references. */
function describeType(node, source) {
  if (ts.isTypeLiteralNode(node)) {
    const fields = [];
    let index = null;
    for (const member of node.members) {
      if (ts.isIndexSignatureDeclaration(member)) {
        index = typeText(member.type, source);
      } else if (ts.isPropertySignature(member)) {
        fields.push({
          name: member.name.getText(source).replace(/^['"]|['"]$/g, ""),
          optional: member.questionToken !== undefined,
          type: describeType(member.type, source),
        });
      }
    }
    return index === null ? { kind: "object", fields } : { kind: "object", fields, index };
  }

  if (ts.isUnionTypeNode(node)) {
    return { kind: "union", members: node.types.map((member) => describeType(member, source)) };
  }

  if (ts.isIntersectionTypeNode(node)) {
    return { kind: "intersection", members: node.types.map((member) => describeType(member, source)) };
  }

  if (ts.isArrayTypeNode(node)) {
    return { kind: "array", element: describeType(node.elementType, source) };
  }

  if (ts.isParenthesizedTypeNode(node)) {
    return describeType(node.type, source);
  }

  if (ts.isIndexedAccessTypeNode(node)) {
    const text = typeText(node, source);
    const match = /^components\['schemas'\]\['([A-Za-z0-9_]+)'\]$/.exec(text);
    if (match) {
      return { kind: "ref", name: match[1] };
    }
    return { kind: "other", text };
  }

  if (ts.isTypeReferenceNode(node)) {
    return { kind: "named", name: typeText(node, source) };
  }

  return { kind: "other", text: typeText(node, source) };
}

const compilerOptions = {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  strict: true,
  allowImportingTsExtensions: true,
  noEmit: true,
};

/** Builds a program in which `documentsPath` is served from memory rather than from disk. */
function createProgram(documentsText) {
  const host = ts.createCompilerHost(compilerOptions, true);
  const readFile = host.readFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const getSourceFile = host.getSourceFile.bind(host);
  host.readFile = (name) => (name === documentsPath ? documentsText : readFile(name));
  host.fileExists = (name) => name === documentsPath || fileExists(name);
  host.getSourceFile = (name, languageVersion, onError, shouldCreate) =>
    name === documentsPath
      ? ts.createSourceFile(name, documentsText, languageVersion, true)
      : getSourceFile(name, languageVersion, onError, shouldCreate);
  return ts.createProgram([schemaPath, keyStatePath, documentsPath], compilerOptions, host);
}

const program = createProgram("");
const schemaSource = program.getSourceFile(schemaPath);
if (!schemaSource) {
  throw new Error("the pinned keria-api-schema.ts could not be read");
}

let schemasNode = null;
const enums = {};
for (const statement of schemaSource.statements) {
  if (ts.isInterfaceDeclaration(statement) && statement.name.text === "components") {
    for (const member of statement.members) {
      if (ts.isPropertySignature(member) && member.name.getText(schemaSource) === "schemas") {
        schemasNode = member.type;
      }
    }
  }
  if (ts.isEnumDeclaration(statement)) {
    enums[statement.name.text] = statement.members.map((member) => ({
      name: member.name.getText(schemaSource),
      value: member.initializer ? member.initializer.getText(schemaSource).replace(/^['"]|['"]$/g, "") : null,
    }));
  }
}
if (!schemasNode || !ts.isTypeLiteralNode(schemasNode)) {
  throw new Error("the `components.schemas` member was not found");
}

const schemas = {};
for (const member of schemasNode.members) {
  if (ts.isPropertySignature(member)) {
    schemas[member.name.getText(schemaSource)] = describeType(member.type, schemaSource);
  }
}

const keyStateSource = program.getSourceFile(keyStatePath);
if (!keyStateSource) {
  throw new Error("the pinned keyState.ts could not be read");
}
const keyStateExports = {};
const keyStateFunctions = [];
for (const statement of keyStateSource.statements) {
  const exported = ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
  if (!exported) {
    continue;
  }
  if (ts.isTypeAliasDeclaration(statement)) {
    keyStateExports[statement.name.text] = typeText(statement.type, keyStateSource);
  } else if (ts.isFunctionDeclaration(statement) && statement.name) {
    keyStateFunctions.push(statement.name.text);
  } else if (ts.isInterfaceDeclaration(statement)) {
    keyStateExports[statement.name.text] = "interface";
  }
}

// ---------------------------------------------------------------------------
// Type-checking the documents.
// ---------------------------------------------------------------------------

// Each document is written twice: once as a literal, where TypeScript's excess-property check also
// applies, and once assigned through an inferred variable, where it does not. The second models
// what actually happens at run time, where a response body is cast without any check.
const lines = [
  "// AUTO-GENERATED by tools/reference-vectors/types_keria_api.mjs; safe to delete.",
  "import type { components } from './keria-api-schema.ts';",
  "import type { HabState, PendingHabState } from '../keri/core/keyState.ts';",
  "type Schema<Name extends keyof components['schemas']> = components['schemas'][Name];",
  "type Named = { HabState: HabState; PendingHabState: PendingHabState };",
];
const positions = new Map();
for (const [index, document] of documents.entries()) {
  const literal = JSON.stringify(document.json);
  const target =
    document.schema === "HabState" || document.schema === "PendingHabState"
      ? `Named['${document.schema}']`
      : `Schema<'${document.schema}'>`;
  positions.set(index, { literal: lines.length, structural: lines.length + 3 });
  lines.push(`const strict${index}: ${target} = ${literal};`);
  lines.push(`void strict${index};`);
  lines.push(`const raw${index} = ${literal};`);
  lines.push(`const structural${index}: ${target} = raw${index};`);
  lines.push(`void structural${index};`);
}
const checkedProgram = createProgram(`${lines.join("\n")}\n`);
const documentsSource = checkedProgram.getSourceFile(documentsPath);
const diagnostics = checkedProgram.getSemanticDiagnostics(documentsSource);

const byLine = new Map();
for (const diagnostic of diagnostics) {
  if (diagnostic.start === undefined) {
    continue;
  }
  const { line } = documentsSource.getLineAndCharacterOfPosition(diagnostic.start);
  const message = ts.flattenDiagnosticMessageText(diagnostic.messageText, " ");
  byLine.set(line, [...(byLine.get(line) ?? []), message]);
}

const checked = documents.map((document, index) => {
  const at = positions.get(index);
  const strict = byLine.get(at.literal) ?? [];
  const structural = byLine.get(at.structural) ?? [];
  const expectation = rustExpectations[document.name];
  if (!expectation) {
    throw new Error(`document ${document.name} has no recorded Rust expectation`);
  }
  const [rustType, rustExpected] = expectation;
  const record = {
    name: document.name,
    schema: document.schema,
    json: document.json,
    literal_accepted: strict.length === 0,
    structural_accepted: structural.length === 0,
    rust_type: rustType,
    rust_expected: rustExpected,
  };
  if (document.provenance) {
    record.provenance = document.provenance;
  }
  if (document.note) {
    record.note = document.note;
  }
  if (strict.length > 0) {
    record.literal_diagnostics = strict;
  }
  if (structural.length > 0) {
    record.structural_diagnostics = structural;
  }
  return record;
});

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-20",
  sources: [
    "src/types/keria-api-schema.ts",
    "src/keri/core/keyState.ts",
    "scripts/generate-types.js",
    "test/app/test-utils.ts",
    "test/app/registry.test.ts",
  ],
  typescript_version: ts.version,
  generation: {
    upstream_command: "node scripts/generate-types.js",
    upstream_spec_url: "http://localhost:3902/spec.yaml",
    upstream_spec_checked_in: false,
    note: "the OpenAPI document is fetched from a live KERIA agent and is checked in nowhere, so the generated TypeScript is the pinned artifact and these vectors are taken from it",
  },
  schema_count: Object.keys(schemas).length,
  schema_names: Object.keys(schemas),
  schemas,
  enums,
  key_state_exports: keyStateExports,
  key_state_functions: keyStateFunctions,
  documents: checked,
  // Documents the two implementations decide differently, computed rather than transcribed.
  divergences: checked
    .filter((document) => document.literal_accepted !== (document.rust_expected === "accept"))
    .map((document) => ({
      name: document.name,
      reference_accepts: document.literal_accepted,
      rust_accepts: document.rust_expected === "accept",
    })),
};

const outputUrl = new URL("../../fixtures/types-keria-api/v1.json", import.meta.url);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("types-keria-api fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
