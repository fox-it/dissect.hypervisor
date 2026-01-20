from __future__ import annotations

import gzip

from dissect.hypervisor.disk.asif import ASIF
from tests._util import absolute_path


def test_asif() -> None:
    """Test ASIF parsing."""
    with gzip.open(absolute_path("_data/disk/asif/basic.asif.gz"), "rb") as fh:
        asif = ASIF(fh)

        assert asif.internal_metadata == {"stable uuid": "13db9632-b79f-4e95-aada-835d5ef97bba"}
        assert asif.user_metadata == {}

        with asif.open() as stream:
            for i in range(100):
                assert stream.read(1024 * 1024).strip(bytes([i])) == b"", f"Mismatch at offset {i * 1024 * 1024:#x}"
