"""Judges passcode rotations with the pinned keripy checkout's own key event validation.

The reference's passcode rotation always claims sequence number one. A connected client's log
already holds the delegation-approval interaction at sequence one, so keripy's ``Kever.rotate``
reads that rotation as a recovery and refuses it -- which a live KERIA, built on keripy, answers
with 500. This generator replays the log ``client_passcode_rotation.mjs`` recorded -- inception,
interaction -- into a fresh keripy database and asks keripy's ``Kevery`` to process each candidate
rotation from ``fixtures/client-passcode-rotation/v1.json``: the reference's own, the corrected one
this port builds, and a third at the right sequence number with the wrong prior. It records what
keripy did with each.

Every event and signature is read from the signify-ts fixture; nothing is signed here, so the
verdicts are keripy's judgement of the reference's bytes. Run with a Python 3.12+ environment that
has the pinned ``reference/keripy`` checkout installed:

    uv venv --python 3.12 .venv-keripy
    uv pip install --python .venv-keripy/bin/python ./reference/keripy
    .venv-keripy/bin/python tools/reference-vectors/client_passcode_rotation_keripy.py --write   # or --check

``DYLD_LIBRARY_PATH=/opt/homebrew/lib`` is only needed where pysodium cannot find libsodium.
"""

import json
import pathlib
import sys

from keri.core import eventing, serdering
from keri.core.indexing import Siger
from keri.db import basing

REFERENCE_SHA = "4ce4cc79e06653f77342be1bf604086b89b1f090"
REFERENCE_VERSION = "1.3.6"
GENERATED_ON = "2026-09-16"

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "fixtures" / "client-passcode-rotation" / "v1.json"
OUTPUT = ROOT / "fixtures" / "client-passcode-rotation-keripy" / "v1.json"

CANDIDATES = [
    (
        "reference_rotation",
        "the reference's request: `s = 1` over the interaction at sequence one",
        "refused",
    ),
    (
        "corrected_rotation",
        "this port's rotation: the next sequence number over the current event",
        "accepted",
    ),
    (
        "inception_prior_rotation",
        "the next sequence number, naming the inception rather than the current event",
        "refused",
    ),
]


def process(kevery, entry):
    serder = serdering.SerderKERI(raw=entry["raw"].encode("utf-8"))
    sigers = [Siger(qb64=signature) for signature in entry["sigs"]]
    kevery.processEvent(serder=serder, sigers=sigers)
    return serder


def judge(kel, name):
    """Replays the recorded log into an empty database and processes one candidate rotation."""
    with basing.openDB(name=f"signify-rs-{name}", temp=True) as db:
        kevery = eventing.Kevery(db=db)
        inception = process(kevery, kel["inception"])
        process(kevery, kel["interaction"])
        kever = kevery.kevers[inception.pre]
        before = {"sn": kever.sn, "ilk": kever.ilk, "said": kever.serder.said}

        candidate = serdering.SerderKERI(raw=kel[name]["raw"].encode("utf-8"))
        try:
            process(kevery, kel[name])
        except Exception as error:  # noqa: BLE001 - the error class is the datum being recorded
            outcome = {
                "verdict": "refused",
                "error_class": type(error).__name__,
                "error_message": str(error),
            }
        else:
            kever = kevery.kevers[inception.pre]
            if kever.serder.said != candidate.said:
                outcome = {"verdict": "escrowed", "error_class": None, "error_message": None}
            else:
                outcome = {"verdict": "accepted", "error_class": None, "error_message": None}
        kever = kevery.kevers[inception.pre]
        return {
            "name": name,
            "rotation_sequence": candidate.ked["s"],
            "rotation_prior": candidate.ked["p"],
            "rotation_said": candidate.said,
            "log_before": before,
            **outcome,
            "log_after": {
                "sn": kever.sn,
                "ilk": kever.ilk,
                "said": kever.serder.said,
                "keys": [verfer.qb64 for verfer in kever.verfers],
                "next_digests": [diger.qb64 for diger in kever.ndigers],
            },
        }


def main():
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    kel = source["kel"]

    verdicts = []
    for name, description, expected in CANDIDATES:
        judged = judge(kel, name)
        if judged["verdict"] != expected:
            raise AssertionError(f"keripy {judged['verdict']} {name}, expected {expected}: {judged}")
        verdicts.append({"description": description, **judged})

    fixture = {
        "schema_version": 1,
        "upstream": "https://github.com/WebOfTrust/keripy.git",
        "reference_sha": REFERENCE_SHA,
        "reference_version": REFERENCE_VERSION,
        "generated_on": GENERATED_ON,
        "sources": [
            "src/keri/core/eventing.py (Kevery.processEvent, Kever.update, Kever.rotate)",
            "fixtures/client-passcode-rotation/v1.json (kel)",
        ],
        "generator": "tools/reference-vectors/client_passcode_rotation_keripy.py",
        "input": {
            "fixture": "fixtures/client-passcode-rotation/v1.json",
            "signify_ts_sha": source["reference_sha"],
            "controller_prefix": source["provenance"]["controller_prefix"],
            "inception_said": json.loads(kel["inception"]["raw"])["d"],
            "interaction_said": json.loads(kel["interaction"]["raw"])["d"],
        },
        "verdicts": verdicts,
        "note": (
            "Each candidate is processed by a fresh keripy Kevery that has accepted the recorded"
            " inception and interaction. KERIA calls the same validation through"
            " SignifyHab.processEvent, which re-raises any failure as ConfigurationError"
            " ('Improper Habitat event type=rot'), and its AgentResourceEnd.on_put leaves that"
            " unhandled, so a refused rotation reaches a client as 500."
        ),
    }

    rendered = json.dumps(fixture, indent=2, ensure_ascii=False) + "\n"
    if "--check" in sys.argv:
        if OUTPUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit("client-passcode-rotation-keripy fixture is stale; run with --write")
    elif "--write" in sys.argv:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


if __name__ == "__main__":
    main()
