// Generates and checks X25519 encrypter vectors against the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Encrypter } from "../../reference/signify-ts/dist/keri/core/encrypter.js";
import { Matter, MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import { Verfer } from "../../reference/signify-ts/dist/keri/core/verfer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const referenceSeedQb64 =
  "ABg7MMQPKnZG-uOiRWVlH5ZvzilHheNYhtoE8NzeBsAr";
const referenceSaltQb64 = "0AA2CGQNobs5jXCNoMATSody";
const rustSeedCipherQb64 =
  "PBO-T-rq8gTH_TNY_JwAchiB0XQngSgifsZ0839_6XttzG8cehOC0KYRK_IJh20mnNHMu9QmTEFdMSV-VY13PwMUlyZnoE3_0x-sip0x_7K5J9JfzbLXFBvu7eqQ";
const rustSaltCipherQb64 =
  "1AAHMdSras7slhE3kXA3k25gcW-sVzr-lNnahKgCBEjfwRKrWrKDCDCEa3V8DhzqI1blWMiIGpY432PbGS__nGpEj-rZ5HMqrVls";
const cryptSeed = new Uint8Array([
  104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24,
  25, 240, 102, 50, 44, 121, 196, 194, 49, 64, 245, 64, 21, 46, 162,
  26, 207,
]);

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
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

const keypair = libsodium.crypto_sign_seed_keypair(cryptSeed);
const x25519Public = libsodium.crypto_sign_ed25519_pk_to_curve25519(
  keypair.publicKey,
);
const x25519Private = libsodium.crypto_sign_ed25519_sk_to_curve25519(
  keypair.privateKey,
);
const signer = new Signer({ raw: cryptSeed, transferable: true });
const verifier = new Verfer({ raw: keypair.publicKey, code: MtrDex.Ed25519 });
const fromRaw = new Encrypter({ raw: x25519Public });
const fromVerifier = new Encrypter({}, verifier.qb64b);
const seedCipher = new Cipher({ qb64: rustSeedCipherQb64 });
const saltCipher = new Cipher({ qb64: rustSaltCipherQb64 });
const openedSeed = libsodium.crypto_box_seal_open(
  seedCipher.raw,
  x25519Public,
  x25519Private,
);
const openedSalt = libsodium.crypto_box_seal_open(
  saltCipher.raw,
  x25519Public,
  x25519Private,
);
if (new TextDecoder().decode(openedSeed) !== referenceSeedQb64) {
  throw new Error("pinned libsodium did not open the Rust seed ciphertext");
}
if (new TextDecoder().decode(openedSalt) !== referenceSaltQb64) {
  throw new Error("pinned libsodium did not open the Rust salt ciphertext");
}

const p256Verifier = new Verfer({
  qb64: "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ",
});
const digest = new Matter({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 });
const digestCipher = fromRaw.encrypt(digest.qb64b);

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-14",
  sources: [
    "src/keri/core/encrypter.ts",
    "src/keri/core/cipher.ts",
    "src/keri/core/signer.ts",
    "src/keri/core/verfer.ts",
    "test/core/encrypter.test.ts",
    "test/core/decrypter.test.ts",
  ],
  algorithm_dependencies:
    "libsodium-wrappers-sumo 0.8.4 Ed25519-to-X25519 conversion and crypto_box_seal_open",
  secret_fixture_policy:
    "all fixed seeds and ephemeral secrets are deterministic public test material and must never be used as production secrets",
  encrypter: {
    code: fromRaw.code,
    raw_hex: hex(fromRaw.raw),
    qb64: fromRaw.qb64,
    verifier_qb64: verifier.qb64,
    from_verifier_qb64: fromVerifier.qb64,
    crypt_seed_qb64: signer.qb64,
    verifies_crypt_seed: fromRaw.verifySeed(signer.qb64b),
    rejects_other_valid_seed: !fromRaw.verifySeed(
      new TextEncoder().encode(referenceSeedQb64),
    ),
  },
  rust_ciphertexts_accepted_by_reference: [
    {
      name: "fixed_ephemeral_07_seed",
      ephemeral_secret_hex: "07".repeat(32),
      plaintext_kind: "qualified_seed",
      plaintext_qb64: referenceSeedQb64,
      code: seedCipher.code,
      raw_hex: hex(seedCipher.raw),
      qb64: seedCipher.qb64,
      opened_plaintext_hex: hex(openedSeed),
    },
    {
      name: "fixed_ephemeral_08_salt",
      ephemeral_secret_hex: "08".repeat(32),
      plaintext_kind: "qualified_salt",
      plaintext_qb64: referenceSaltQb64,
      code: saltCipher.code,
      raw_hex: hex(saltCipher.raw),
      qb64: saltCipher.qb64,
      opened_plaintext_hex: hex(openedSalt),
    },
  ],
  rejected_cases: [
    rejectedCase("empty_encrypter", () => new Encrypter({}), "EmptyInput"),
    rejectedCase(
      "p256_verifier",
      () => new Encrypter({}, p256Verifier.qb64b),
      "UnsupportedEncryptionKey",
    ),
    rejectedCase(
      "missing_plaintext",
      () => fromRaw.encrypt(),
      "TypedPlaintextRequired",
    ),
  ],
  reference_quirks: {
    arbitrary_matter_is_labeled_as_seed: {
      input_code: digest.code,
      reference_cipher_code: digestCipher.code,
      rust_decision:
        "encrypt_seed_qb64 strictly accepts only canonical Ed25519 seed material; salt encryption requires a typed Salt",
      rust_error_category: "InvalidSigningCode",
    },
    public_key_validation: {
      reference_accepts_non_contributory_raw_key: true,
      rust_decision:
        "reject non-contributory X25519 public keys before sealed-box encryption",
      rust_error_category: "InvalidEncryptionKey",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-encrypter/v1.json",
  import.meta.url,
);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("crypto-encrypter fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
