// Generates unindexed-signature vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { Cigar } from "../../reference/signify-ts/dist/keri/core/cigar.js";
import { MtrDex } from "../../reference/signify-ts/dist/keri/core/matter.js";
import { Verfer } from "../../reference/signify-ts/dist/keri/core/verfer.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const ed25519Signature = fromHex(
  "78ddfcf41a4223e88342beaef7d9dec5059c6ddc6c34f12d666a4f53791812b6caf18943c429c3003fd4a526bb7ab20e61da912f4ec86b633e7aaccf0823370e",
);
const p256Signature = fromHex(
  "e672499089617f1e8d28537ba5127801b53a5dd7555e0514400811b61ed94dfb56e5b4c80da5605a933de581bdc3b9f1101f3c3ab1fe6181d95511787a4d17cd",
);
const secp256k1Signature = Uint8Array.from(
  { length: 64 },
  (_, index) => index,
);
const ed25519Verifier = new Verfer({
  qb64: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
});
const p256Verifier = new Verfer({
  qb64: "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ",
});

function fromHex(value) {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function signatureCase(name, code, raw, verifier) {
  const signature = new Cigar({ raw, code }, verifier);
  const reparsed = new Cigar({ qb64: signature.qb64 });
  return {
    name,
    code: signature.code,
    raw_hex: hex(signature.raw),
    qb64: signature.qb64,
    qb64_bytes_hex: hex(signature.qb64b),
    qb2_hex: hex(decodeBase64Url(signature.qb64)),
    qb64_round_trip: reparsed.qb64,
    verifier_qb64: signature.verfer?.qb64 ?? null,
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

const excessRaw = new Uint8Array(65);
excessRaw.set(ed25519Signature);
excessRaw[64] = 0xff;
const excessSignature = new Cigar({
  raw: excessRaw,
  code: MtrDex.Ed25519_Sig,
});
const nonSignatureMaterial = new Cigar({
  raw: ed25519Signature,
  code: MtrDex.Blake3_256,
});
const mismatchedAssociation = new Cigar(
  { raw: ed25519Signature, code: MtrDex.Ed25519_Sig },
  p256Verifier,
);
const reassignedAssociation = new Cigar(
  { raw: ed25519Signature, code: MtrDex.Ed25519_Sig },
  ed25519Verifier,
);
reassignedAssociation.verfer = undefined;
const clearedVerifierIsUndefined = reassignedAssociation.verfer === undefined;
reassignedAssociation.verfer = ed25519Verifier;

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-12",
  sources: [
    "src/keri/core/cigar.ts",
    "src/keri/core/matter.ts",
    "test/core/signer.test.ts",
    "test/end/ending.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Matter._bexfil is unimplemented; qb64_round_trip is accepted by the pinned Cigar constructor",
  cases: [
    signatureCase(
      "ed25519_with_verifier",
      MtrDex.Ed25519_Sig,
      ed25519Signature,
      ed25519Verifier,
    ),
    signatureCase(
      "p256_with_verifier",
      MtrDex.ECDSA_256r1_Sig,
      p256Signature,
      p256Verifier,
    ),
    signatureCase(
      "secp256k1_without_verifier",
      MtrDex.ECDSA_256k1_Sig,
      secp256k1Signature,
      undefined,
    ),
  ],
  rejected_cases: [
    rejectedCase(
      "short_ed25519_signature",
      () =>
        new Cigar({
          raw: ed25519Signature.slice(0, 63),
          code: MtrDex.Ed25519_Sig,
        }),
      "Truncated",
    ),
    rejectedCase(
      "empty_material",
      () => new Cigar({}),
      "EmptyInput",
    ),
    rejectedCase(
      "qb2_constructor",
      () =>
        new Cigar({
          qb2: decodeBase64Url(
            new Cigar({
              raw: ed25519Signature,
              code: MtrDex.Ed25519_Sig,
            }).qb64,
          ),
        }),
      "ReferenceUnsupported",
    ),
  ],
  reference_quirks: {
    excess_raw_truncation: {
      input_raw_hex: hex(excessRaw),
      retained_raw_hex: hex(excessSignature.raw),
      qb64: excessSignature.qb64,
      rust_error_category: "TrailingMaterial",
    },
    non_signature_code_accepted: {
      input_code: MtrDex.Blake3_256,
      retained_raw_hex: hex(nonSignatureMaterial.raw),
      qb64: nonSignatureMaterial.qb64,
      rust_error_category: "InvalidSignatureCode",
      rust_decision: "reject non-signature derivation codes",
    },
    mismatched_verifier_accepted: {
      signature_code: mismatchedAssociation.code,
      verifier_code: mismatchedAssociation.verfer?.code ?? null,
      rust_error_category: "SignatureVerifierMismatch",
      rust_decision: "reject verifier/signature algorithm mismatches",
    },
    mutable_verifier_reassignment: {
      cleared_verifier_is_undefined: clearedVerifierIsUndefined,
      reassigned_verifier_qb64: reassignedAssociation.verfer?.qb64 ?? null,
      rust_decision: "use immutable fallible association",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-signature/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
