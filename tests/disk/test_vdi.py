from __future__ import annotations

import gzip
import struct
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import BinaryIO
from unittest.mock import patch

from dissect.hypervisor.disk.c_vdi import c_vdi
from dissect.hypervisor.disk.vdi import VDI, VDIStream
from tests._util import absolute_path


def mock_open_gz(self: Path, *args, **kwargs) -> BinaryIO:
    return gzip.open(self)


def test_vdi() -> None:
    """Test a basic VDI file."""
    with gzip.open(absolute_path("_data/disk/vdi/basic.vdi.gz"), "rb") as fh:
        vdi = VDI(fh)

        assert vdi.type == c_vdi.VDI_IMAGE_TYPE.NORMAL
        assert vdi.flags == c_vdi.VDI_IMAGE_FLAGS(0)
        assert vdi.size == 10 * 1024 * 1024
        assert vdi.block_size == 1048576

        stream = vdi.open()
        assert stream.read(1 * 1024 * 1024) == bytes([0] * (1 * 1024 * 1024))

        for i in range((1 * 1024 * 1024) // 4096, stream.size // 4096):
            expected = bytes([i % 256] * 4096)
            assert stream.read(4096) == expected, f"Mismatch at offset {i * 4096:#x}"

        assert stream.read() == b""


def test_vdi_read_across_non_contiguous_blocks() -> None:
    """Test a single read spanning non-contiguous VDI allocation-map blocks."""
    block_size = 4
    allocation_map = struct.pack("<ii", 1, 0)
    fh = BytesIO(allocation_map + b"AAAABBBBCCCC")

    vdi = SimpleNamespace(
        fh=fh,
        blocks_offset=0,
        number_of_blocks=2,
        block_size=block_size,
        size=2 * block_size,
        data_offset=len(allocation_map),
        parent=None,
    )

    stream = VDIStream(vdi)

    assert stream.read(vdi.size) == b"BBBBAAAA"


def test_vdi_context_manager() -> None:
    """Test VDI context manager."""
    with patch.object(Path, "open", gzip.open), VDI(absolute_path("_data/disk/vdi/basic.vdi.gz")) as vdi:
        assert vdi.path is not None
    assert vdi.fh.closed

    with gzip.open(absolute_path("_data/disk/vdi/basic.vdi.gz"), "rb") as fh:
        with VDI(fh) as vdi:
            assert vdi.path is None
        assert fh.closed is False
