// Generates private-signer vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Cigar } from "../../reference/signify-ts/dist/keri/core/cigar.js";
import { IdrDex } from "../../reference/signify-ts/dist/keri/core/indexer.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Siger } from "../../reference/signify-ts/dist/keri/core/siger.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const serialization = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456789",
);

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function signerCase(
  name,
  transferable,
  index = null,
  only = false,
  ondex = undefined,
) {
  const signer = new Signer({ raw: seed, transferable });
  const reparsedSigner = new Signer({ qb64: signer.qb64, transferable });
  const signature = signer.sign(serialization, index, only, ondex);
  const reparsedSignature =
    index == null
      ? new Cigar({ qb64: signature.qb64 })
      : new Siger({ qb64: signature.qb64 });
  return {
    name,
    transferable,
    seed_code: signer.code,
    seed_raw_hex: hex(signer.raw),
    seed_qb64: signer.qb64,
    seed_qb64_bytes_hex: hex(signer.qb64b),
    seed_qb2_hex: hex(decodeBase64Url(signer.qb64)),
    seed_qb64_round_trip: reparsedSigner.qb64,
    verifier_code: signer.verfer.code,
    verifier_raw_hex: hex(signer.verfer.raw),
    verifier_qb64: signer.verfer.qb64,
    serialization_hex: hex(serialization),
    signature_kind: index == null ? "unindexed" : "indexed",
    signature_code: signature.code,
    signature_index: index == null ? null : signature.index,
    signature_ondex: index == null ? null : (signature.ondex ?? null),
    signature_raw_hex: hex(signature.raw),
    signature_qb64: signature.qb64,
    signature_qb64_bytes_hex: hex(signature.qb64b),
    signature_qb2_hex: hex(decodeBase64Url(signature.qb64)),
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

const excessSeed = new Uint8Array(33);
excessSeed.set(seed);
excessSeed[32] = 0xff;
const excessSigner = new Signer({ raw: excessSeed });

const cases = [
  signerCase("unindexed_transferable", true),
  signerCase("unindexed_nontransferable", false),
  signerCase("both_small_default", true, 3),
  signerCase("both_big_distinct", true, 3, false, 4),
  signerCase("both_big_index", true, 64),
  signerCase("current_small", true, 63, true),
  signerCase("current_big", true, 64, true),
];

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-12",
  sources: [
    "src/keri/core/signer.ts",
    "src/keri/core/matter.ts",
    "src/keri/core/verfer.ts",
    "src/keri/core/cigar.ts",
    "src/keri/core/siger.ts",
    "src/keri/core/indexer.ts",
    "test/core/signer.test.ts",
  ],
  algorithm_dependencies:
    "libsodium-wrappers-sumo 0.8.4 Ed25519 seed-keypair derivation and detached signing",
  binary_derivation:
    "seed_qb2_hex and signature_qb2_hex are decodeBase64Url(reference-produced qb64) because the pinned Matter/Indexer qb2 constructors are unimplemented; qb64 round trips are accepted by the pinned constructors",
  secret_fixture_policy:
    "seed 000102...1f is deterministic public test material only and must never be used as a production secret",
  cases,
  rejected_cases: [
    rejectedCase(
      "short_ed25519_seed",
      () =>
        new Signer({
          raw: seed.slice(0, 31),
          code: MtrDex.Ed25519_Seed,
        }),
      "Truncated",
    ),
    rejectedCase(
      "unsupported_secp256k1_seed",
      () => new Signer({ raw: seed, code: MtrDex.ECDSA_256k1_Seed }),
      "UnsupportedSigningAlgorithm",
    ),
    rejectedCase(
      "invalid_digest_code",
      () => new Signer({ raw: seed, code: MtrDex.Blake3_256 }),
      "InvalidSigningCode",
    ),
    rejectedCase(
      "empty_unsupported_seed",
      () => new Signer({ code: MtrDex.ECDSA_256r1_Seed }),
      "UnsupportedSigningAlgorithm",
    ),
    rejectedCase(
      "qb2_constructor",
      () =>
        new Signer({
          qb2: decodeBase64Url(new Signer({ raw: seed }).qb64),
        }),
      "ReferenceUnsupported",
    ),
  ],
  reference_quirks: {
    excess_raw_truncation: {
      input_raw_hex: hex(excessSeed),
      retained_raw_hex: hex(excessSigner.raw),
      verifier_qb64: excessSigner.verfer.qb64,
      rust_error_category: "TrailingMaterial",
    },
    current_only_discards_ondex: {
      requested_index: 3,
      requested_ondex: 4,
      result: signerCase("current_discards_ondex", true, 3, true, 4),
      rust_decision:
        "SignaturePlacement::current_list makes a prior-list index unrepresentable",
    },
    secret_exposure: {
      reference_raw_and_qb64_are_public: true,
      rust_decision:
        "Signer exposes no seed bytes or encoded seed and does not implement Clone, Display, equality, or serialization",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-signer/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
