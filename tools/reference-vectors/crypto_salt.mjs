// Generates salt/KDF vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Cigar } from "../../reference/signify-ts/dist/keri/core/cigar.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter, Tier } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const saltRaw = new TextEncoder().encode("0123456789abcdef");
const serialization = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456789",
);

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function derivationCase(name, path, tier, temporary, transferable) {
  const salter = new Salter({ raw: saltRaw, tier });
  const reparsedSalt = new Salter({ qb64: salter.qb64, tier });
  const signer = salter.signer(
    MtrDex.Ed25519_Seed,
    transferable,
    path,
    tier,
    temporary,
  );
  const reparsedSigner = new Signer({
    qb64: signer.qb64,
    transferable,
  });
  const signature = signer.sign(serialization);
  const reparsedSignature = new Cigar({ qb64: signature.qb64 });
  return {
    name,
    path,
    path_utf8_hex: hex(new TextEncoder().encode(path)),
    tier,
    temporary,
    transferable,
    salt_code: salter.code,
    salt_raw_hex: hex(salter.raw),
    salt_qb64: salter.qb64,
    salt_qb64_bytes_hex: hex(salter.qb64b),
    salt_qb2_hex: hex(decodeBase64Url(salter.qb64)),
    salt_qb64_round_trip: reparsedSalt.qb64,
    seed_code: signer.code,
    seed_raw_hex: hex(signer.raw),
    seed_qb64: signer.qb64,
    seed_qb64_round_trip: reparsedSigner.qb64,
    verifier_code: signer.verfer.code,
    verifier_qb64: signer.verfer.qb64,
    serialization_hex: hex(serialization),
    signature_code: signature.code,
    signature_raw_hex: hex(signature.raw),
    signature_qb64: signature.qb64,
    signature_qb64_round_trip: reparsedSignature.qb64,
    verifies_serialization: signer.verfer.verify(
      signature.raw,
      serialization,
    ),
  };
}

function rejectedCase(name, operation, rustErrorCategory) {
  try {
    operation();
  } catch (error) {
    return {
      name,
      reference_error_category: error?.constructor?.name ?? "Unknown",
      reference_error_message: String(error?.message ?? error),
      rust_error_category: rustErrorCategory,
    };
  }
  throw new Error(`reference unexpectedly accepted rejected case ${name}`);
}

const excessRaw = Uint8Array.from([...saltRaw, 0xff]);
const excessSalter = new Salter({ raw: excessRaw });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-13",
  sources: [
    "src/keri/core/salter.ts",
    "src/keri/core/signer.ts",
    "src/keri/core/matter.ts",
    "test/core/salter.test.ts",
  ],
  algorithm_dependencies:
    "libsodium-wrappers-sumo 0.8.4 crypto_pwhash Argon2id v1.3 with one lane",
  binary_derivation:
    "salt_qb2_hex is decodeBase64Url(reference-produced qb64) because the pinned Matter qb2 constructor is unimplemented; qb64 salt, signer, and signature round trips are accepted by pinned constructors",
  secret_fixture_policy:
    "salt and derived seeds are deterministic public test material only and must never be used as production secrets",
  profile_parameters: {
    temporary: { iterations: 1, memory_bytes: 8192 },
    low: { iterations: 2, memory_bytes: 67108864 },
    med: { iterations: 3, memory_bytes: 268435456 },
    high: { iterations: 4, memory_bytes: 1073741824 },
    parallelism: 1,
    algorithm: "Argon2id v1.3",
  },
  cases: [
    derivationCase("temporary_empty_path", "", Tier.low, true, true),
    derivationCase(
      "temporary_controller_path",
      "signify:controller00",
      Tier.low,
      true,
      true,
    ),
    derivationCase(
      "temporary_utf8_nontransferable",
      "signify:clé/α",
      Tier.med,
      true,
      false,
    ),
    derivationCase("low_empty_path", "", Tier.low, false, true),
    derivationCase(
      "low_controller_path",
      "signify:controller00",
      Tier.low,
      false,
      true,
    ),
  ],
  rejected_cases: [
    rejectedCase(
      "short_salt",
      () => new Salter({ raw: saltRaw.slice(0, 15) }),
      "Truncated",
    ),
    rejectedCase(
      "invalid_digest_code",
      () => new Salter({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 }),
      "InvalidSaltCode",
    ),
    rejectedCase(
      "unsupported_tier",
      () =>
        new Salter({ raw: saltRaw }).signer(
          MtrDex.Ed25519_Seed,
          true,
          "",
          "unknown",
          false,
        ),
      "UnrepresentableSecurityTier",
    ),
    rejectedCase(
      "qb2_constructor",
      () =>
        new Salter({
          qb2: decodeBase64Url(new Salter({ raw: saltRaw }).qb64),
        }),
      "ReferenceUnsupported",
    ),
  ],
  reference_quirks: {
    excess_raw_truncation: {
      input_raw_hex: hex(excessRaw),
      retained_raw_hex: hex(excessSalter.raw),
      salt_qb64: excessSalter.qb64,
      rust_error_category: "TrailingMaterial",
    },
    null_tier_defaults_low: {
      resulting_tier: new Salter({ raw: saltRaw, tier: null }).tier,
      rust_decision: "SecurityTier is non-null and defaults through its Default implementation",
    },
    secret_exposure: {
      reference_raw_and_qb64_are_public: true,
      rust_decision:
        "Salt exposes no raw bytes and returns only explicit zeroizing qb64/qb2 export buffers",
    },
    path_bound: {
      reference_has_no_explicit_bound: true,
      rust_maximum_utf8_bytes: 4096,
      rust_error_category: "DerivationPathTooLong",
    },
  },
};

const outputUrl = new URL("../../fixtures/crypto-salt/v1.json", import.meta.url);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
