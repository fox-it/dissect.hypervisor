from __future__ import annotations

import gzip
import io

import pytest

from dissect.hypervisor.disk.dmg import DMG
from tests._util import absolute_path

ENCRYPTED_VARIANTS = ["aes128_udzo", "aes256_udzo"]
COMPRESSED_VARIANTS = ["udro", "udzo", "udbz", "udco", "ulfo", "ulmo"]
PASSWORD = "dissect"


def _open(name: str) -> io.BytesIO:
    # The DMG parser seeks to the koly trailer at the end of the file, which a GzipFile does not support.
    with gzip.open(absolute_path(f"_data/disk/dmg/{name}.dmg.gz"), "rb") as fh:
        return io.BytesIO(fh.read())


@pytest.fixture
def reference() -> bytes:
    return DMG(_open("udro")).open().read()


def test_dmg_udro(reference: bytes) -> None:
    """The uncompressed UDRO image parses and exposes the raw disk."""
    dmg = DMG(_open("udro"))

    assert dmg.size == dmg.sector_count * 512
    assert dmg.size == len(reference)
    assert reference[:2] == b"\x00\x00"  # APFS container starts with a zeroed block 0
    assert b"README.txt" in reference


@pytest.mark.parametrize("variant", COMPRESSED_VARIANTS)
def test_dmg_variant_matches_reference(variant: str, reference: bytes) -> None:
    """Every compressed variant decompresses byte-identical to the uncompressed reference."""
    dmg = DMG(_open(variant))

    assert dmg.size == len(reference)
    assert dmg.open().read() == reference


@pytest.mark.parametrize("variant", ENCRYPTED_VARIANTS)
def test_dmg_encrypted(variant: str, reference: bytes) -> None:
    """Password-encrypted (encrcdsa AES-128/256) DMGs decrypt and decode to the same raw disk."""
    pytest.importorskip("Crypto")

    dmg = DMG(_open(variant), password=PASSWORD)
    assert dmg.size == len(reference)
    assert dmg.open().read() == reference


def test_dmg_encrypted_wrong_or_no_password() -> None:
    """Decrypting without a password, or with the wrong one, is rejected."""
    pytest.importorskip("Crypto")

    with pytest.raises(ValueError, match="wrong password"):
        DMG(_open("aes256_udzo"), password="notthepassword")

    with pytest.raises(ValueError, match="no password was provided"):
        DMG(_open("aes128_udzo"))
