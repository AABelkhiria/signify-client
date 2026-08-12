// Generates indexed-signature vectors from the compiled pinned signify-ts checkout.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { decodeBase64Url } from "../../reference/signify-ts/dist/keri/core/base64.js";
import { IdrDex } from "../../reference/signify-ts/dist/keri/core/indexer.js";
import { Siger } from "../../reference/signify-ts/dist/keri/core/siger.js";
import { Verfer } from "../../reference/signify-ts/dist/keri/core/verfer.js";

const referenceSha = "ae92eceb8e776ad57669707bff7f84db9390b711";
const raw64 = Uint8Array.from({ length: 64 }, (_, index) => index);
const raw114 = Uint8Array.from({ length: 114 }, (_, index) => index);
const ed25519Verifier = new Verfer({
  qb64: "DAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4",
});
const p256Verifier = new Verfer({
  qb64: "1AAJA-blKBTkTkEEOX_Yq3i3KxZJvcHarPfu_crKVwcfEwvQ",
});

function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

function signatureCase(name, code, index, ondex, raw, verifier) {
  const signature = new Siger({ raw, code, index, ondex }, verifier);
  const reparsed = new Siger({ qb64: signature.qb64 });
  return {
    name,
    code: signature.code,
    index: signature.index,
    ondex: signature.ondex ?? null,
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

const caseInputs = [
  ["ed25519_both_small", IdrDex.Ed25519_Sig, 3, 3, raw64, ed25519Verifier],
  ["ed25519_current_small", IdrDex.Ed25519_Crt_Sig, 4, undefined, raw64],
  ["secp256k1_both_small", IdrDex.ECDSA_256k1_Sig, 5, 5, raw64],
  ["secp256k1_current_small", IdrDex.ECDSA_256k1_Crt_Sig, 6, undefined, raw64],
  ["p256_both_small", IdrDex.ECDSA_256r1_Sig, 7, 7, raw64, p256Verifier],
  ["p256_current_small", IdrDex.ECDSA_256r1_Crt_Sig, 8, undefined, raw64],
  ["ed448_both_small", IdrDex.Ed448_Sig, 9, 10, raw114],
  ["ed448_current_small", IdrDex.Ed448_Crt_Sig, 11, undefined, raw114],
  ["ed25519_both_big", IdrDex.Ed25519_Big_Sig, 64, 65, raw64],
  ["ed25519_current_big", IdrDex.Ed25519_Big_Crt_Sig, 66, undefined, raw64],
  ["secp256k1_both_big", IdrDex.ECDSA_256k1_Big_Sig, 67, 68, raw64],
  ["secp256k1_current_big", IdrDex.ECDSA_256k1_Big_Crt_Sig, 69, undefined, raw64],
  ["p256_both_big", IdrDex.ECDSA_256r1_Big_Sig, 70, 71, raw64],
  ["p256_current_big", IdrDex.ECDSA_256r1_Big_Crt_Sig, 72, undefined, raw64],
  ["ed448_both_big", IdrDex.Ed448_Big_Sig, 4096, 4097, raw114],
  ["ed448_current_big", IdrDex.Ed448_Big_Crt_Sig, 4098, undefined, raw114],
];

const excessRaw = new Uint8Array(65);
excessRaw.set(raw64);
excessRaw[64] = 0xff;
const excessSignature = new Siger({
  raw: excessRaw,
  code: IdrDex.Ed25519_Sig,
  index: 0,
});
const mismatchedAssociation = new Siger(
  { raw: raw64, code: IdrDex.Ed25519_Sig, index: 0 },
  p256Verifier,
);
const reassignedAssociation = new Siger(
  { raw: raw64, code: IdrDex.Ed25519_Sig, index: 0 },
  ed25519Verifier,
);
reassignedAssociation.verfer = undefined;
const clearedVerifierIsUndefined = reassignedAssociation.verfer === undefined;
reassignedAssociation.verfer = ed25519Verifier;
const omittedP256OtherIndex = new Siger({
  raw: raw64,
  code: IdrDex.ECDSA_256r1_Big_Sig,
  index: 70,
});

const fixture = {
  schema_version: 1,
  upstream: "https://github.com/WebOfTrust/signify-ts.git",
  reference_sha: referenceSha,
  generated_on: "2026-08-12",
  sources: [
    "src/keri/core/siger.ts",
    "src/keri/core/indexer.ts",
    "src/keri/core/signer.ts",
    "test/core/signer.test.ts",
    "test/core/eventing.test.ts",
    "test/end/ending.test.ts",
  ],
  binary_derivation:
    "qb2_hex is decodeBase64Url(reference-produced qb64) because Indexer._bexfil is unimplemented; qb64_round_trip is accepted by the pinned Siger constructor",
  cases: caseInputs.map((input) => signatureCase(...input)),
  rejected_cases: [
    rejectedCase(
      "short_ed25519_signature",
      () =>
        new Siger({
          raw: raw64.slice(0, 63),
          code: IdrDex.Ed25519_Sig,
          index: 0,
        }),
      "Truncated",
    ),
    rejectedCase("empty_material", () => new Siger({}), "EmptyInput"),
    rejectedCase(
      "current_only_with_ondex",
      () =>
        new Siger({
          raw: raw64,
          code: IdrDex.Ed25519_Crt_Sig,
          index: 0,
          ondex: 0,
        }),
      "InvalidIndexRelation",
    ),
    rejectedCase(
      "qb2_constructor",
      () =>
        new Siger({
          qb2: decodeBase64Url(
            new Siger({
              raw: raw64,
              code: IdrDex.Ed25519_Sig,
              index: 0,
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
    p256_omitted_ondex: {
      code: omittedP256OtherIndex.code,
      index: omittedP256OtherIndex.index,
      reference_ondex: omittedP256OtherIndex.ondex ?? null,
      reference_qb64: omittedP256OtherIndex.qb64,
      rust_decision: "default both-list prior index to the current index",
    },
  },
};

const outputUrl = new URL(
  "../../fixtures/crypto-indexed-signature/v1.json",
  import.meta.url,
);
mkdirSync(fileURLToPath(new URL(".", outputUrl)), { recursive: true });
writeFileSync(outputUrl, `${JSON.stringify(fixture, null, 2)}\n`);
