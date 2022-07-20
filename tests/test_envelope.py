import hashlib

import pytest

from dissect.hypervisor.util.envelope import Envelope, KeyStore, HAS_PYCRYPTODOME, HAS_PYSTANDALONE


def test_keystore(keystore):
    store = KeyStore.from_text(keystore.read())

    assert store.store[".encoding"] == "UTF-8"
    assert store.store["includeKeyCache"] == "FALSE"
    assert store.store["mode"] == "NONE"
    assert store.store["ConfigEncData"] == (
        "keyId=fmLOxWrvTX6Di8rjLu/SUQ%3d%3d:"
        "data1=Uz8MFZfqTbWN2jIHbFPhag%3d%3d:"
        "data2=IDcZE41aR+uxDv7Iz8zJSA%3d%3d:"
        "version=1"
    )

    assert store.mode == "NONE"
    assert store._id == "7e62cec5-6aef-4d7e-838b-cae32eefd251"
    assert store._key == bytes.fromhex("ae29634dca8627013f7c7cf2d05b4d5cc444d42cd4e8acbaa4fb815dda3b3066")


def test_envelope(envelope):
    ev = Envelope(envelope)

    assert ev.key_info == "7e62cec5-6aef-4d7e-838b-cae32eefd251"
    assert ev.cipher_name == "AES-256-GCM"
    assert ev.key_hash == bytes.fromhex("7eaad9a3be03cbf5e092adc8ce04724f9b2a49785fba2533c56b7e26977b8c86")
    assert ev.iv == bytes.fromhex("574d565f0000000000000000")
    assert ev.digest == bytes.fromhex("ee54bdd51ac29a73a3bcaac47b3b6d93")
    assert ev.size == 102400


@pytest.mark.skipif((not HAS_PYCRYPTODOME and not HAS_PYSTANDALONE), reason="No crypto module available")
def test_decrypt(envelope, keystore):
    ev = Envelope(envelope)
    store = KeyStore.from_text(keystore.read())

    decrypted = ev.decrypt(store.key, aad=b"ESXConfiguration")
    assert len(decrypted) == 94293
    assert hashlib.sha256(decrypted).hexdigest() == "fe131620351b9fd5fc4aef219bf3211340f3742464c038e1695e7b6667f86952"
