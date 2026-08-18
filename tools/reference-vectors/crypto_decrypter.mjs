// Generates and checks X25519 decrypter vectors against the compiled pinned signify-ts checkout.
import { readFileSync, writeFileSync } from "node:fs";

import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { b } from "../../reference/signify-ts/dist/keri/core/core.js";
import { Decrypter } from "../../reference/signify-ts/dist/keri/core/decrypter.js";
import { Encrypter } from "../../reference/signify-ts/dist/keri/core/encrypter.js";
import { Matter, MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Salter } from "../../reference/signify-ts/dist/keri/core/salter.js";
import { Signer } from "../../reference/signify-ts/dist/keri/core/signer.js";
import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";

// Deterministic public test material from the pinned test/core/decrypter.test.ts.
const seed = new Uint8Array([
  24, 59, 48, 196, 15, 42, 118, 70, 250, 227, 162, 69, 101, 101, 31, 150, 111,
  206, 41, 71, 133, 227, 88, 134, 218, 4, 240, 220, 222, 6, 192, 43,
]);
const saltRaw = new Uint8Array([
  54, 8, 100, 13, 161, 187, 57, 141, 112, 141, 160, 192, 19, 74, 135, 114,
]);
const cryptSeed = new Uint8Array([
  104, 44, 35, 124, 138, 112, 34, 18, 196, 51, 116, 50, 166, 225, 24, 25, 240,
  102, 50, 44, 121, 196, 194, 49, 64, 245, 64, 21, 46, 162, 26, 207,
]);
// Stored fully qualified ciphertexts from the pinned test (stable across nonces).
const storedSeedCipherQb64 =
  "PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw";
const storedSaltCipherQb64 =
  "1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWyIwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu";
// Deterministic Rust ciphertexts pinned by fixtures/crypto-encrypter/v1.json.
const rustSeedCipherQb64 =
  "PBO-T-rq8gTH_TNY_JwAchiB0XQngSgifsZ0839_6XttzG8cehOC0KYRK_IJh20mnNHMu9QmTEFdMSV-VY13PwMUlyZnoE3_0x-sip0x_7K5J9JfzbLXFBvu7eqQ";
const rustSaltCipherQb64 =
  "1AAHMdSras7slhE3kXA3k25gcW-sVzr-lNnahKgCBEjfwRKrWrKDCDCEa3V8DhzqI1blWMiIGpY432PbGS__nGpEj-rZ5HMqrVls";

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

const signer = new Signer({ raw: seed, code: MtrDex.Ed25519_Seed });
const salter = new Salter({ raw: saltRaw, code: MtrDex.Salt_128 });
const cryptSigner = new Signer({
  raw: cryptSeed,
  code: MtrDex.Ed25519_Seed,
  transferable: true,
});
const keypair = libsodium.crypto_sign_seed_keypair(cryptSeed);
const x25519Private = libsodium.crypto_sign_ed25519_sk_to_curve25519(
  keypair.privateKey,
);

const fromRaw = new Decrypter({ raw: x25519Private });
const fromSeedParam = new Decrypter({}, cryptSigner.qb64b);

const storedSeedCipher = new Cipher({ qb64: storedSeedCipherQb64 });
const storedSaltCipher = new Cipher({ qb64: storedSaltCipherQb64 });
const transferableSigner = fromRaw.decrypt(null, storedSeedCipher, true);
const nonTransferableSigner = fromRaw.decrypt(null, storedSeedCipher, false);
const viaSer = fromRaw.decrypt(b(storedSeedCipherQb64), null, true);
const recoveredSalter = fromSeedParam.decrypt(b(storedSaltCipherQb64));

const rustSeedRecovered = fromRaw.decrypt(b(rustSeedCipherQb64), null, true);
const rustSaltRecovered = fromRaw.decrypt(b(rustSaltCipherQb64));

// Quirk material: excess raw is silently truncated by the Matter base class.
const excessRaw = new Uint8Array(33);
excessRaw.set(x25519Private);
excessRaw.set([0xaa], 32);
const truncated = new Decrypter({ raw: excessRaw });

// Quirk material: an authenticated sealed box wrapping non-seed qualified material is labeled a
// seed cipher by the reference encrypter; decrypting it throws a Signer construction error that is
// distinguishable from an authentication failure.
const encrypter = new Encrypter({
  raw: libsodium.crypto_sign_ed25519_pk_to_curve25519(keypair.publicKey),
});
const digest = new Matter({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 });
const wrongShapeCipher = encrypter.encrypt(digest.qb64b);
// Quirk material: a tampered stored ciphertext fails inside libsodium with a different error.
const tamperedRaw = Uint8Array.from(storedSeedCipher.raw);
tamperedRaw[0] ^= 0x01;
const tamperedCipher = new Cipher({ raw: tamperedRaw, code: MtrDex.X25519_Cipher_Seed });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-18",
  sources: [
    "src/keri/core/decrypter.ts",
    "src/keri/core/cipher.ts",
    "src/keri/core/signer.ts",
    "src/keri/core/salter.ts",
    "test/core/decrypter.test.ts",
  ],
  algorithm_dependencies:
    "libsodium-wrappers-sumo 0.8.4 crypto_sign_ed25519_sk_to_curve25519 and crypto_box_seal_open",
  secret_fixture_policy:
    "all fixed seeds, salts, and private keys are deterministic public test material and must never be used as production secrets",
  conversion: {
    crypt_seed_hex: hex(cryptSeed),
    crypt_signer_qb64: cryptSigner.qb64,
    x25519_private_raw_hex: hex(x25519Private),
    decrypter_code: fromRaw.code,
    decrypter_qb64: fromRaw.qb64,
    from_seed_param_qb64: fromSeedParam.qb64,
    from_seed_param_matches_raw: fromSeedParam.qb64 === fromRaw.qb64,
  },
  stored_reference_ciphertexts: [
    {
      name: "stored_seed_cipher",
      qb64: storedSeedCipherQb64,
      code: storedSeedCipher.code,
      raw_hex: hex(storedSeedCipher.raw),
      decrypted_qb64: transferableSigner.qb64,
      decrypted_code: transferableSigner.code,
      transferable_verfer_code: transferableSigner.verfer.code,
      non_transferable_verfer_code: nonTransferableSigner.verfer.code,
      ser_and_cipher_paths_agree: viaSer.qb64 === transferableSigner.qb64,
      expected_seed_qb64: signer.qb64,
    },
    {
      name: "stored_salt_cipher",
      qb64: storedSaltCipherQb64,
      code: storedSaltCipher.code,
      raw_hex: hex(storedSaltCipher.raw),
      decrypted_qb64: recoveredSalter.qb64,
      decrypted_code: recoveredSalter.code,
      expected_salt_qb64: salter.qb64,
    },
  ],
  rust_ciphertexts_opened_by_reference_decrypter: [
    {
      name: "fixed_ephemeral_07_seed",
      qb64: rustSeedCipherQb64,
      decrypted_qb64: rustSeedRecovered.qb64,
      decrypted_code: rustSeedRecovered.code,
    },
    {
      name: "fixed_ephemeral_08_salt",
      qb64: rustSaltCipherQb64,
      decrypted_qb64: rustSaltRecovered.qb64,
      decrypted_code: rustSaltRecovered.code,
    },
  ],
  rejected_cases: [
    rejectedCase("empty_decrypter", () => new Decrypter({}), "Cesr"),
    rejectedCase(
      "unsupported_decrypter_code",
      () => new Decrypter({ raw: x25519Private, code: MtrDex.Ed25519_Seed }),
      "InvalidDecrypterCode",
    ),
    rejectedCase(
      "salt_material_as_seed_parameter",
      () => new Decrypter({}, salter.qb64b),
      "InvalidSigningCode",
    ),
    rejectedCase(
      "decrypt_without_input",
      () => fromRaw.decrypt(),
      "UnrepresentableInRust",
    ),
    rejectedCase(
      "tampered_seed_ciphertext",
      () => fromRaw.decrypt(null, tamperedCipher, true),
      "DecryptionFailed",
    ),
  ],
  reference_quirks: {
    excess_raw_truncation: {
      input_raw_hex: hex(excessRaw),
      reference_qb64: truncated.qb64,
      truncated_to_reference_key: truncated.qb64 === fromRaw.qb64,
      rust_decision: "reject excess raw bytes with a typed trailing-material error",
      rust_error_category: "Cesr",
    },
    data_driven_kind_dispatch: {
      note: "the reference decrypt returns a Salter or Signer selected by the ciphertext code, so a caller cannot state which secret kind it expects",
      salt_cipher_decrypts_to_code: recoveredSalter.code,
      rust_decision:
        "typed decrypt_seed/decrypt_salt operations reject a mismatched ciphertext kind before opening",
      rust_error_category: "CiphertextKindMismatch",
    },
    distinguishable_failure_stages: {
      note: "the reference throws different error classes for tampered ciphertexts and for authenticated boxes wrapping unexpected plaintext",
      wrong_shape_cipher_code: wrongShapeCipher.code,
      wrong_shape_error: rejectedCase(
        "authenticated_wrong_shape_plaintext",
        () => fromRaw.decrypt(null, wrongShapeCipher, true),
        "DecryptionFailed",
      ),
      rust_decision:
        "authentication failure and recovered-plaintext failure return one detail-free DecryptionFailed error",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-decrypter/v1.json",
  import.meta.url,
);
const rendered = `${JSON.stringify(fixture, null, 2)}\n`;
if (process.argv.includes("--check")) {
  if (readFileSync(outputUrl, "utf8") !== rendered) {
    throw new Error("crypto-decrypter fixture is stale; run with --write");
  }
} else if (process.argv.includes("--write")) {
  writeFileSync(outputUrl, rendered);
} else {
  process.stdout.write(rendered);
}
