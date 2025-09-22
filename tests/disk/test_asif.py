from __future__ import annotations

from typing import BinaryIO

from dissect.hypervisor.disk.asif import ASIF


def test_asif(basic_asif: BinaryIO) -> None:
    """Test ASIF parsing."""
    asif = ASIF(basic_asif)

    assert asif.internal_metadata == {"stable uuid": "13db9632-b79f-4e95-aada-835d5ef97bba"}
    assert asif.user_metadata == {}

    with asif.open() as stream:
        for i in range(100):
            assert stream.read(1024 * 1024).strip(bytes([i])) == b"", f"Mismatch at offset {i * 1024 * 1024:#x}"
