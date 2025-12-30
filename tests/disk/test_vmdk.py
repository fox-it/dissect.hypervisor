from __future__ import annotations

import gzip
from pathlib import Path
from typing import BinaryIO
from unittest.mock import MagicMock, patch

import pytest

from dissect.hypervisor.disk.c_vmdk import c_vmdk
from dissect.hypervisor.disk.vmdk import VMDK, DiskDescriptor, ExtentDescriptor, SESparseExtent, open_parent
from tests._util import absolute_path


def mock_open_gz(self: Path, *args, **kwargs) -> BinaryIO:
    return gzip.open(self if self.suffix.lower() == ".gz" else self.with_suffix(self.suffix + ".gz"))


@pytest.mark.parametrize(
    ("path"),
    [
        pytest.param("_data/disk/vmdk/flat.vmdk.gz", id="flat"),
        pytest.param("_data/disk/vmdk/sparse.vmdk.gz", id="sparse"),
        pytest.param("_data/disk/vmdk/split-flat.vmdk.gz", id="split-flat"),
        pytest.param("_data/disk/vmdk/split-sparse.vmdk.gz", id="split-sparse"),
        pytest.param("_data/disk/vmdk/stream.vmdk.gz", id="stream"),
    ],
)
def test_vmdk(path: str) -> None:
    """Test basic VMDK reading."""
    with patch.object(Path, "open", mock_open_gz):
        vmdk = VMDK(absolute_path(path))

        assert vmdk.size == 10 * 1024 * 1024

        stream = vmdk.open()
        assert stream.read(1 * 1024 * 1024) == bytes([0] * (1 * 1024 * 1024))

        for i in range((1 * 1024 * 1024) // 4096, stream.size // 4096):
            expected = bytes([i % 256] * 4096)
            assert stream.read(4096) == expected, f"Mismatch at offset {i * 4096:#x}"

        assert stream.read() == b""


def test_vmdk_sesparse() -> None:
    # TODO: Recreate test data with new test pattern
    with gzip.open(absolute_path("_data/disk/vmdk/sesparse.vmdk.gz"), "rb") as fh:
        vmdk = VMDK(fh)

        extent = vmdk.extents[0]
        assert isinstance(extent, SESparseExtent)

        assert extent.header.constMagic == c_vmdk.SESPARSE_CONST_HEADER_MAGIC
        assert extent.header.version == 0x200000001

        assert extent._num_gte_per_gt == 0x1000
        assert len(extent._gd) == 0x20000
        assert extent._gd[0] == 0x1000000000000000

        stream = vmdk.open()
        assert stream.read(0x1000000) == b"a" * 0x1000000


@pytest.mark.parametrize(
    ("raw", "expected_extents"),
    [
        pytest.param(
            'RW 123456789 SPARSE "disk.vmdk"',
            [
                ExtentDescriptor(
                    access="RW",
                    size=123456789,
                    type="SPARSE",
                    filename="disk.vmdk",
                ),
            ],
            id="sparse",
        ),
        pytest.param(
            'RW 123456789 FLAT "disk-flat.vmdk" 0',
            [
                ExtentDescriptor(
                    access="RW",
                    size=123456789,
                    type="FLAT",
                    filename="disk-flat.vmdk",
                    offset=0,
                )
            ],
            id="flat",
        ),
        pytest.param(
            "RDONLY 0 ZERO",
            [
                ExtentDescriptor(
                    access="RDONLY",
                    size=0,
                    type="ZERO",
                ),
            ],
            id="zero",
        ),
        pytest.param(
            'NOACCESS 123456789 SPARSE "disk-sparse.vmdk" 123 partition-uuid device-id',
            [
                ExtentDescriptor(
                    access="NOACCESS",
                    size=123456789,
                    type="SPARSE",
                    filename="disk-sparse.vmdk",
                    offset=123,
                ),
            ],
            id="sparse-ids",
        ),
        pytest.param(
            "RW 1234567890",
            [],
            id="bad-1",
        ),
        pytest.param(
            'RDONLY "file.vmdk"',
            [],
            id="bad-2",
        ),
        pytest.param(
            "NOACCESS",
            [],
            id="bad-3",
        ),
        pytest.param(
            'RW 1234567890 SPARSE "disk with spaces.vmdk"',
            [
                ExtentDescriptor(
                    access="RW",
                    size=1234567890,
                    type="SPARSE",
                    filename="disk with spaces.vmdk",
                )
            ],
            id="spaces-four-parts",
        ),
        pytest.param(
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123',
            [
                ExtentDescriptor(
                    access="RW",
                    size=1234567890,
                    type="SPARSE",
                    filename="disk with spaces.vmdk",
                    offset=123,
                )
            ],
            id="spaces-five-parts",
        ),
        pytest.param(
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid',
            [
                ExtentDescriptor(
                    access="RW",
                    size=1234567890,
                    type="SPARSE",
                    filename="disk with spaces.vmdk",
                    offset=123,
                )
            ],
            id="spaces-six-parts",
        ),
        pytest.param(
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid device-id',
            [
                ExtentDescriptor(
                    access="RW",
                    size=1234567890,
                    type="SPARSE",
                    filename="disk with spaces.vmdk",
                    offset=123,
                )
            ],
            id="spaces-seven-parts",
        ),
        pytest.param(
            r'RW 16777216 SPARSE "this is an example "\' diskëäô:)\\\'`\foo.vmdk" 123',
            [
                ExtentDescriptor(
                    access="RW",
                    size=16777216,
                    type="SPARSE",
                    filename=r'this is an example "\' diskëäô:)\\\'`\foo.vmdk',
                    offset=123,
                )
            ],
            id="specials-five-parts",
        ),
        pytest.param(
            r'RW 13371337 SPARSE "🦊 🦊 🦊.vmdk"',
            [
                ExtentDescriptor(
                    access="RW",
                    size=13371337,
                    type="SPARSE",
                    filename="🦊 🦊 🦊.vmdk",
                )
            ],
            id="emoji-four-parts",
        ),
    ],
)
def test_vmdk_extent_description(raw: str, expected_extents: list[ExtentDescriptor]) -> None:
    """test if we correctly parse VMDK sparse and flat extent descriptions.

    Resources:
        - https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#22-extent-descriptions
        - https://web.archive.org/web/20120302211605/http://www.vmware.com/support/developer/vddk/vmdk_50_technote.pdf
    """

    descriptor = DiskDescriptor(raw)
    assert descriptor.extents == expected_extents


def test_open_parent_all_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test open_parent handles absolute and relative filename_hint paths."""

    # Mock Path.exists to simulate file existence
    def mock_exists(path: Path) -> bool:
        return str(path) in {
            "/a/b/c/d.vmdk",  # Case: absolute path
            "base/relative/hint.vmdk",  # Case: full relative path
            "base/hint.vmdk",  # Case: basename in same dir
            "../sibling/hint.vmdk",  # Case: fallback to sibling
        }

    with monkeypatch.context() as m:
        m.setattr("pathlib.Path.exists", mock_exists)

        # Mock VMDK to avoid real file I/O
        mock_vmdk = MagicMock()
        m.setattr("dissect.hypervisor.disk.vmdk.VMDK", lambda path: mock_vmdk)
        mock_vmdk.path = "mocked-path"

        # Case: Absolute path — should use /a/b/c/d.vmdk directly
        vmdk = open_parent(Path("base"), "/a/b/c/d.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Full relative path — try base/relative/hint.vmdk
        vmdk = open_parent(Path("base"), "relative/hint.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Basename only — fall back to base/hint.vmdk
        vmdk = open_parent(Path("base"), "hint.vmdk")
        assert str(vmdk.path) == "mocked-path"

        # Case: Fallback to sibling — try ../sibling/hint.vmdk
        vmdk = open_parent(Path("base"), "sibling/hint.vmdk")
        assert str(vmdk.path) == "mocked-path"
