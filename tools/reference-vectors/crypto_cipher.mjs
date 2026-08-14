// Generates typed ciphertext-material vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Cipher } from "../../reference/signify-ts/dist/keri/core/cipher.js";
import { Matter, MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const seedQb64 =
  "PM9jOGWNYfjM_oLXJNaQ8UlFSAV5ACjsUY7J16xfzrlpc9Ve3A5WYrZ4o_NHtP5lhp78Usspl9fyFdnCdItNd5JyqZ6dt8SXOt6TOqOCs-gy0obrwFkPPqBvVkEw";
const saltQb64 =
  "1AAHjlR2QR9J5Et67Wy-ZaVdTryN6T6ohg44r73GLRPnHw-5S3ABFkhWyIwLOI6TXUB_5CT13S8JvknxLxBaF8ANPK9FSOPD8tYu";

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function cipherCase(name, qb64, plaintextKind) {
  const ciphertext = new Cipher({ qb64 });
  const reparsedFromText = new Cipher({ qb64: ciphertext.qb64 });
  const reparsedFromRaw = new Cipher({
    raw: ciphertext.raw,
    code: ciphertext.code,
  });
  return {
    name,
    plaintext_kind: plaintextKind,
    code: ciphertext.code,
    raw_hex: hex(ciphertext.raw),
    raw_size: ciphertext.raw.length,
    qb64: ciphertext.qb64,
    qb64_bytes_hex: hex(ciphertext.qb64b),
    qb2_hex: hex(decodeBase64Url(ciphertext.qb64)),
    qb64_round_trip: reparsedFromText.qb64,
    raw_round_trip: reparsedFromRaw.qb64,
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

const seedCiphertext = new Cipher({ qb64: seedQb64 });
const saltCiphertext = new Cipher({ qb64: saltQb64 });
const shortSeed = seedCiphertext.raw.slice(0, seedCiphertext.raw.length - 1);
const shortSalt = saltCiphertext.raw.slice(0, saltCiphertext.raw.length - 1);
const digest = new Matter({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 });

const excessSeedRaw = new Uint8Array(seedCiphertext.raw.length + 1);
excessSeedRaw.set(seedCiphertext.raw);
excessSeedRaw[seedCiphertext.raw.length] = 0xff;
const truncatedExcessSeed = new Cipher({
  raw: excessSeedRaw,
  code: MtrDex.X25519_Cipher_Seed,
});

const excessSaltRaw = new Uint8Array(saltCiphertext.raw.length + 1);
excessSaltRaw.set(saltCiphertext.raw);
excessSaltRaw[saltCiphertext.raw.length] = 0xff;
const truncatedExcessSalt = new Cipher({
  raw: excessSaltRaw,
  code: MtrDex.X25519_Cipher_Salt,
});

const inferredSeed = new Cipher({ raw: seedCiphertext.raw });
const inferredSalt = new Cipher({ raw: saltCiphertext.raw });

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-14",
  sources: [
    "src/keri/core/cipher.ts",
    "src/keri/core/matter.ts",
    "test/core/encrypter.test.ts",
    "test/core/decrypter.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; qb64_round_trip and raw_round_trip are accepted by the pinned Cipher constructor",
  cases: [
    cipherCase("stored_seed_ciphertext", seedQb64, "qualified_seed"),
    cipherCase("stored_salt_ciphertext", saltQb64, "qualified_salt"),
  ],
  rejected_cases: [
    rejectedCase("empty_material", () => new Cipher({}), "EmptyInput"),
    rejectedCase(
      "short_seed_ciphertext",
      () =>
        new Cipher({ raw: shortSeed, code: MtrDex.X25519_Cipher_Seed }),
      "Truncated",
    ),
    rejectedCase(
      "short_salt_ciphertext",
      () =>
        new Cipher({ raw: shortSalt, code: MtrDex.X25519_Cipher_Salt }),
      "Truncated",
    ),
    rejectedCase(
      "non_cipher_code",
      () => new Cipher({ qb64: digest.qb64 }),
      "InvalidCiphertextCode",
    ),
    rejectedCase(
      "qb2_constructor",
      () => new Cipher({ qb2: decodeBase64Url(seedQb64) }),
      "ReferenceUnsupported",
    ),
  ],
  reference_quirks: {
    excess_seed_raw_truncation: {
      input_raw_hex: hex(excessSeedRaw),
      retained_raw_hex: hex(truncatedExcessSeed.raw),
      qb64: truncatedExcessSeed.qb64,
      rust_error_category: "TrailingMaterial",
    },
    excess_salt_raw_truncation: {
      input_raw_hex: hex(excessSaltRaw),
      retained_raw_hex: hex(truncatedExcessSalt.raw),
      qb64: truncatedExcessSalt.qb64,
      rust_error_category: "TrailingMaterial",
    },
    raw_seed_inference_misclassifies_and_truncates: {
      input_raw_hex: hex(seedCiphertext.raw),
      reference_code: inferredSeed.code,
      retained_raw_hex: hex(inferredSeed.raw),
      qb64: inferredSeed.qb64,
      rust_code: MtrDex.X25519_Cipher_Seed,
      rust_decision: "infer the unique correct code from the exact 92-byte width without truncation",
    },
    raw_salt_inference: {
      input_raw_hex: hex(saltCiphertext.raw),
      reference_code: inferredSalt.code,
      retained_raw_hex: hex(inferredSalt.raw),
      qb64: inferredSalt.qb64,
      rust_code: MtrDex.X25519_Cipher_Salt,
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-cipher/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
