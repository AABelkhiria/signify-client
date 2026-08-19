"""Generates and checks witness/receipt attachment vectors from the pinned keripy checkout.

signify-ts cannot emit witness indexed-signature groups or non-transferable receipt couples --
its guards are unreachable and its counters are wrong (see fixtures/keri-attachment/README.md) --
so these two group kinds are verified against keripy instead, per ADR 0009. Run with a Python
3.12+ environment that has the pinned ``reference/keripy`` checkout installed:

    uv venv --python 3.12 .venv-keripy
    uv pip install --python .venv-keripy/bin/python ./reference/keripy
    DYLD_LIBRARY_PATH=/opt/homebrew/lib .venv-keripy/bin/python \\
        tools/reference-vectors/keri_attachment_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH`` is only needed where pysodium cannot find libsodium on its own.
"""

import json
import pathlib
import sys

from keri.core import eventing, serdering
from keri.core.coring import MtrDex, NonTransDex
from keri.core.eventing import SealEvent
from keri.core.indexing import Siger
from keri.core.signing import Signer

REFERENCE_SHA = "4ce4cc79e06653f77342be1bf604086b89b1f090"
REFERENCE_VERSION = "1.3.6"
GENERATED_ON = "2026-08-19"

# The exact inception event the pinned signify-ts unit test builds, reused verbatim from
# fixtures/keri-attachment/v1.json so both fixtures describe the same message.
EVENT = (
    '{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL",'
    '"i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,'
    '"k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,'
    '"n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}'
)

# The controller signature over that event from the same pinned test, reused verbatim.
CONTROLLER_SIGNATURE = (
    "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I"
)

# Deterministic witness seeds: the byte sequences 0..31 and 32..63.
WITNESS_SEEDS = [bytes(range(0, 32)), bytes(range(32, 64))]


def build_case(name, serder, *, sigers=None, seal=None, wigers=None, cigars=None, pipelined=False):
    message = bytes(
        eventing.messagize(
            serder, sigers=sigers, seal=seal, wigers=wigers, cigars=cigars, pipelined=pipelined
        )
    )
    event = serder.raw
    if not message.startswith(event):
        raise AssertionError(f"case {name} does not start with its event")
    return {
        "name": name,
        "event": event.decode(),
        "attachments": message[len(event):].decode(),
        "controller_signature_count": len(sigers) if sigers else 0,
        "witness_signature_count": len(wigers) if wigers else 0,
        "receipt_couple_count": len(cigars) if cigars else 0,
        "seal_kind": type(seal).__name__ if seal is not None else None,
        "pipelined": pipelined,
        "raw": message.decode(),
        "raw_hex": message.hex(),
        "raw_byte_size": len(message),
    }


def rejected_case(name, operation, rust_error_category):
    try:
        operation()
    except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
        return {
            "name": name,
            "reference_error_category": type(error).__name__,
            "reference_error_message": str(error),
            "rust_error_category": rust_error_category,
        }
    raise AssertionError(f"reference unexpectedly accepted rejected case {name}")


def main():
    serder = serdering.SerderKERI(raw=EVENT.encode())
    controller = Siger(qb64=CONTROLLER_SIGNATURE)

    witness_signers = [
        Signer(raw=seed, code=MtrDex.Ed25519_Seed, transferable=False) for seed in WITNESS_SEEDS
    ]
    wigers = [signer.sign(ser=serder.raw, index=index) for index, signer in enumerate(witness_signers)]
    cigars = [signer.sign(ser=serder.raw) for signer in witness_signers]
    for wiger in wigers:
        if wiger.verfer.code not in NonTransDex:
            raise AssertionError("witness verfer is unexpectedly transferable")

    seal = SealEvent(i=serder.pre, s="0", d=serder.said)

    cases = [
        build_case("witness_only", serder, wigers=wigers[:1]),
        build_case("two_witnesses", serder, wigers=wigers),
        build_case("controller_and_witness", serder, sigers=[controller], wigers=wigers[:1]),
        build_case("witness_pipelined", serder, wigers=wigers[:1], pipelined=True),
        build_case("receipt_couple", serder, cigars=cigars[:1]),
        build_case("two_receipt_couples", serder, cigars=cigars),
        build_case("receipt_pipelined", serder, cigars=cigars[:1], pipelined=True),
        build_case(
            "controller_witness_receipt",
            serder,
            sigers=[controller],
            wigers=wigers[:1],
            cigars=cigars[:1],
        ),
        build_case(
            "seal_event_controller_and_witness",
            serder,
            sigers=[controller],
            seal=seal,
            wigers=wigers[:1],
        ),
    ]

    transferable = Signer(raw=WITNESS_SEEDS[0], code=MtrDex.Ed25519_Seed, transferable=True)
    rejected = [
        rejected_case(
            "transferable_receipt_key",
            lambda: eventing.messagize(serder, cigars=[transferable.sign(ser=serder.raw)]),
            "TransferableReceiptKey",
        ),
        rejected_case(
            "transferable_witness_key",
            lambda: eventing.messagize(serder, wigers=[transferable.sign(ser=serder.raw, index=0)]),
            "TransferableWitnessKey",
        ),
        rejected_case(
            "no_signatures",
            lambda: eventing.messagize(serder),
            "MissingSignatures",
        ),
    ]

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": ["src/keri/core/eventing.py", "src/keri/core/coring.py"],
        "signatures": {
            "controller": CONTROLLER_SIGNATURE,
            "witness_seeds_hex": [seed.hex() for seed in WITNESS_SEEDS],
            "witness_verfers": [signer.verfer.qb64 for signer in witness_signers],
            "witness_indexed": [wiger.qb64 for wiger in wigers],
            "receipt_unindexed": [cigar.qb64 for cigar in cigars],
        },
        "cases": cases,
        "rejected_cases": rejected,
        "reference_facts": {
            "code_b_is_in_non_trans_dex": "B" in NonTransDex,
            "non_transferable_codex_values": list(NonTransDex),
            "witness_counter_code": "-B",
            "receipt_couple_counter_code": "-C",
            "note": (
                "Python's `in` iterates the codex dataclass values, so `'B' in NonTransDex` is"
                " true and the guards are reachable; signify-ts translated the same guard to a"
                " JavaScript `in`, which tests property keys, so its equivalents can never emit"
                " and also write the controller counter. keripy is therefore the reference for"
                " these two group kinds; see ADR 0009."
            ),
        },
    }

    output = pathlib.Path(__file__).resolve().parents[2] / "fixtures" / "keri-attachment-keripy" / "v1.json"
    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if output.read_text(encoding="utf-8") != rendered:
            raise SystemExit("keri-attachment-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
