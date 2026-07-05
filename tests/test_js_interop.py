"""
Cross-language Triple Ratchet interop: the browser client's JS engine
(static/crypto.js) against the Python host engine, over the real JSON
wire format, across epochs and state serialization on both sides.
"""
import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from omail.crypto.triple_ratchet import ResponderKeys, TripleRatchet, make_prekey_bundle

NODE = shutil.which("node")
DRIVER = Path(__file__).parent / "js_interop_driver.js"

pytestmark = pytest.mark.skipif(NODE is None, reason="node not available")


def _node(phase: str, work_dir: Path) -> None:
    subprocess.run(
        [NODE, str(DRIVER), phase, str(work_dir)],
        check=True, capture_output=True, timeout=120,
    )


def test_js_client_speaks_to_python_host(tmp_path):
    import os

    # Python side (the host) publishes a prekey bundle
    seed = os.urandom(32)
    bundle, keys = make_prekey_bundle(seed)
    (tmp_path / "bob_bundle.json").write_text(
        json.dumps({"bundle": bundle.to_dict()})
    )

    # JS Alice initiates and sends two messages
    _node("initiate", tmp_path)
    js_out = json.loads((tmp_path / "js_envelopes.json").read_text())

    # Python Bob establishes the session and reads both
    bob = TripleRatchet.respond(keys, js_out["e1"]["init"])
    assert bob.decrypt(js_out["e1"]) == b"js->py message one"
    assert bob.decrypt(js_out["e2"]) == b"js->py message two"

    # Bob replies twice (forces a Python->JS DH+KEM ratchet epoch),
    # then survives a state serialization round trip
    r1 = bob.encrypt(b"py->js reply one")
    bob = TripleRatchet.from_dict(json.loads(json.dumps(bob.to_dict())))
    r2 = bob.encrypt(b"py->js reply two")
    (tmp_path / "py_replies.json").write_text(json.dumps({"r1": r1, "r2": r2}))

    # JS Alice (deserialized from her own state dump) decrypts both and
    # answers in a fresh epoch
    _node("finish", tmp_path)
    js_final = json.loads((tmp_path / "js_final.json").read_text())
    assert js_final["decrypted"] == ["py->js reply one", "py->js reply two"]
    assert bob.decrypt(js_final["e3"]) == b"js epoch-two"

    # The whole conversation ran on the post-quantum KEM
    assert js_out["e1"]["init"]["kem_alg"] == "ML-KEM-768"
    assert len(base64.b64decode(js_out["e1"]["header"]["kem_ct"])) == 1088
