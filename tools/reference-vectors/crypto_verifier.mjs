// Generates public-verification-key vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import libsodium from "../../reference/signify-ts/node_modules/libsodium-wrappers-sumo/dist/modules-sumo-esm/libsodium-wrappers.mjs";
import { p256 } from "../../reference/signify-ts/node_modules/@noble/curves/esm/p256.js";
import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Verfer } from "../../reference/signify-ts/dist/keri/core/verfer.js";

await libsodium.ready;

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const serialization = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456789",
);
const changedSerialization = new TextEncoder().encode(
  "abcdefghijklmnopqrstuvwxyz0123456788",
);

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function verifierCase(name, code, publicKey, signature) {
  const verifier = new Verfer({ raw: publicKey, code });
  const reparsed = new Verfer({ qb64: verifier.qb64 });
  return {
    name,
    code: verifier.code,
    raw_hex: hex(verifier.raw),
    qb64: verifier.qb64,
    qb64_bytes_hex: hex(verifier.qb64b),
    qb2_hex: hex(decodeBase64Url(verifier.qb64)),
    qb64_round_trip: reparsed.qb64,
    serialization_hex: hex(serialization),
    signature_hex: hex(signature),
    verifies_serialization: verifier.verify(signature, serialization),
    verifies_changed_serialization: verifier.verify(
      signature,
      changedSerialization,
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

function verificationResult(operation) {
  try {
    return { result: operation(), error_category: null };
  } catch (error) {
    return {
      result: null,
      error_category: error?.constructor?.name ?? "Unknown",
    };
  }
}

const ed25519Seed = Uint8Array.from({ length: 32 }, (_, index) => index);
const ed25519Keypair = libsodium.crypto_sign_seed_keypair(ed25519Seed);
const ed25519Signature = libsodium.crypto_sign_detached(
  serialization,
  ed25519Keypair.privateKey,
);

const p256PrivateKey = new Uint8Array([
  138, 17, 14, 173, 86, 68, 80, 39, 61, 52, 208, 154, 211, 190, 21, 99, 156,
  134, 184, 90, 166, 171, 226, 251, 239, 132, 127, 221, 144, 51, 245, 71,
]);
const p256PublicKey = p256.getPublicKey(p256PrivateKey);
const p256Signature = p256.sign(serialization, p256PrivateKey);
const p256SignatureBytes = p256Signature.toCompactRawBytes();
const p256NormalizedSignatureBytes = p256Signature
  .normalizeS()
  .toCompactRawBytes();
const p256FullMessageSignature = p256.sign(serialization, p256PrivateKey, {
  prehash: true,
});
const p256FullMessageSignatureBytes =
  p256FullMessageSignature.toCompactRawBytes();
const p256FullMessageHighSignature = p256FullMessageSignature.hasHighS()
  ? p256FullMessageSignature
  : new p256.Signature(
      p256FullMessageSignature.r,
      p256.CURVE.n - p256FullMessageSignature.s,
    );
const p256FullMessageHighSignatureBytes =
  p256FullMessageHighSignature.toCompactRawBytes();

const invalidSecp256k1Key = new Uint8Array([
  2, 79, 93, 30, 107, 249, 254, 237, 205, 87, 8, 149, 203, 214, 36, 187, 162,
  251, 58, 206, 241, 203, 27, 76, 236, 37, 189, 148, 240, 178, 204, 133, 31,
]);
const excessEd25519Key = new Uint8Array(33);
excessEd25519Key.set(ed25519Keypair.publicKey);
excessEd25519Key[32] = 0xff;
const truncatedEd25519Signature = ed25519Signature.slice(0, 63);
const truncatedP256Signature = p256SignatureBytes.slice(0, 63);
const weakEd25519Key = new Uint8Array(32);
const invalidP256Key = new Uint8Array(33);

const weakEd25519Verifier = new Verfer({
  raw: weakEd25519Key,
  code: MtrDex.Ed25519,
});
const invalidP256Verifier = new Verfer({
  raw: invalidP256Key,
  code: MtrDex.ECDSA_256r1,
});
const excessEd25519Verifier = new Verfer({
  raw: excessEd25519Key,
  code: MtrDex.Ed25519,
});
const p256Verifier = new Verfer({
  raw: p256PublicKey,
  code: MtrDex.ECDSA_256r1,
});

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-11",
  sources: [
    "src/keri/core/verfer.ts",
    "src/keri/core/matter.ts",
    "test/core/verfer.test.ts",
  ],
  algorithm_dependencies:
    "libsodium-wrappers-sumo 0.8.4 Ed25519; @noble/curves 1.9.7 p256 with SHA-256",
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; qb64_round_trip is accepted by the pinned Verfer constructor",
  cases: [
    verifierCase(
      "ed25519_nontransferable",
      MtrDex.Ed25519N,
      ed25519Keypair.publicKey,
      ed25519Signature,
    ),
    verifierCase(
      "ed25519_transferable",
      MtrDex.Ed25519,
      ed25519Keypair.publicKey,
      ed25519Signature,
    ),
    verifierCase(
      "p256_nontransferable",
      MtrDex.ECDSA_256r1N,
      p256PublicKey,
      p256SignatureBytes,
    ),
    verifierCase(
      "p256_transferable",
      MtrDex.ECDSA_256r1,
      p256PublicKey,
      p256SignatureBytes,
    ),
  ],
  rejected_cases: [
    rejectedCase(
      "unsupported_secp256k1",
      () =>
        new Verfer({
          raw: invalidSecp256k1Key,
          code: MtrDex.ECDSA_256k1,
        }),
      "UnsupportedVerificationAlgorithm",
    ),
    rejectedCase(
      "short_ed25519_key",
      () => new Verfer({ raw: new Uint8Array(31), code: MtrDex.Ed25519 }),
      "Truncated",
    ),
    rejectedCase(
      "digest_code",
      () => new Verfer({ raw: new Uint8Array(32), code: MtrDex.Blake3_256 }),
      "InvalidVerificationCode",
    ),
    rejectedCase(
      "qb2_constructor",
      () =>
        new Verfer({
          qb2: decodeBase64Url(
            new Verfer({
              raw: ed25519Keypair.publicKey,
              code: MtrDex.Ed25519,
            }).qb64,
          ),
        }),
      "ReferenceUnsupported",
    ),
  ],
  verification_edges: {
    p256_signature_is_high_s: p256Signature.hasHighS(),
    p256_high_s_signature_hex: hex(p256SignatureBytes),
    p256_low_s_signature_hex: hex(p256NormalizedSignatureBytes),
    p256_accepts_high_s: p256Verifier.verify(p256SignatureBytes, serialization),
    p256_accepts_low_s: p256Verifier.verify(
      p256NormalizedSignatureBytes,
      serialization,
    ),
    ed25519_truncated_signature: verificationResult(() =>
      new Verfer({
        raw: ed25519Keypair.publicKey,
        code: MtrDex.Ed25519,
      }).verify(truncatedEd25519Signature, serialization),
    ),
    p256_truncated_signature: verificationResult(() =>
      p256Verifier.verify(truncatedP256Signature, serialization),
    ),
  },
  safe_p256_divergence: {
    decision: "SHA-256 over the complete serialization",
    signature_hex: hex(p256FullMessageSignatureBytes),
    signature_is_high_s: p256FullMessageSignature.hasHighS(),
    high_s_signature_hex: hex(p256FullMessageHighSignatureBytes),
    noble_full_message_verifies: p256.verify(
      p256FullMessageSignatureBytes,
      serialization,
      p256PublicKey,
      { prehash: true },
    ),
    noble_full_message_verifies_changed: p256.verify(
      p256FullMessageSignatureBytes,
      changedSerialization,
      p256PublicKey,
      { prehash: true },
    ),
    noble_full_message_verifies_high_s: p256.verify(
      p256FullMessageHighSignatureBytes,
      serialization,
      p256PublicKey,
      { prehash: true },
    ),
    pinned_verfer_verifies_safe_signature: p256Verifier.verify(
      p256FullMessageSignatureBytes,
      serialization,
    ),
    safe_mode_verifies_pinned_signature: p256.verify(
      p256SignatureBytes,
      serialization,
      p256PublicKey,
      { prehash: true },
    ),
  },
  reference_quirks: {
    excess_raw_truncation: {
      input_raw_hex: hex(excessEd25519Key),
      retained_raw_hex: hex(excessEd25519Verifier.raw),
      qb64: excessEd25519Verifier.qb64,
      rust_error_category: "TrailingMaterial",
    },
    weak_ed25519_key_accepted_at_construction: {
      raw_hex: hex(weakEd25519Key),
      qb64: weakEd25519Verifier.qb64,
      verification_result: weakEd25519Verifier.verify(
        ed25519Signature,
        serialization,
      ),
      rust_error_category: "InvalidVerificationKey",
      rust_decision: "reject weak Ed25519 public keys during construction",
    },
    invalid_p256_key_accepted_at_construction: {
      raw_hex: hex(invalidP256Key),
      qb64: invalidP256Verifier.qb64,
      verification_result: invalidP256Verifier.verify(
        p256SignatureBytes,
        serialization,
      ),
      rust_error_category: "InvalidVerificationKey",
      rust_decision: "reject invalid SEC1 P-256 points during construction",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-verifier/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
