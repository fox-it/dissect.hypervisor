from __future__ import annotations

import gzip
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from dissect.hypervisor.disk.c_vmdk import c_vmdk
from dissect.hypervisor.disk.vmdk import VMDK, DiskDescriptor, ExtentDescriptor, open_parent
from tests._util import absolute_path


def test_vmdk_sesparse() -> None:
    with gzip.open(absolute_path("_data/disk/vmdk/sesparse.vmdk.gz"), "rb") as fh:
        vmdk = VMDK(fh)

        disk = vmdk.disks[0]

        assert disk.is_sesparse
        assert disk._grain_directory_size == 0x20000
        assert disk._grain_table_size == 0x1000
        assert disk._grain_entry_type == c_vmdk.uint64
        assert disk._grain_directory[0] == 0x1000000000000000

        header = disk.header
        assert header.magic == c_vmdk.SESPARSE_CONST_HEADER_MAGIC
        assert header.version == 0x200000001

        assert vmdk.read(0x1000000) == b"a" * 0x1000000


def test_vmdk_descriptor_declared_encoding(tmp_path: Path) -> None:
    extent_name = "CentOS 64 副本-flat.vmdk"
    descriptor_path = tmp_path / "disk.vmdk"
    (tmp_path / extent_name).write_bytes(b"\x00" * 512)
    descriptor_path.write_bytes(
        (
            "# Disk DescriptorFile\n"
            "version=1\n"
            'encoding="GBK"\n'
            "CID=369b13fd\n"
            "parentCID=ffffffff\n"
            f'RW 1 FLAT "{extent_name}" 0\n'
        ).encode("gbk")
    )

    vmdk = VMDK(descriptor_path)

    assert vmdk.descriptor.extents[0].filename == extent_name
    assert vmdk.size == 512


@pytest.mark.parametrize(
    ("extent_description", "expected_extents"),
    [
        (
            'RW 123456789 SPARSE "disk.vmdk"',
            [
                ExtentDescriptor(
                    raw='RW 123456789 SPARSE "disk.vmdk"',
                    access_mode="RW",
                    sectors=123456789,
                    type="SPARSE",
                    filename='"disk.vmdk"',
                    start_sector=None,
                    partition_uuid=None,
                    device_identifier=None,
                ),
            ],
        ),
        (
            'RW 123456789 FLAT "disk-flat.vmdk" 0',
            [
                ExtentDescriptor(
                    raw='RW 123456789 FLAT "disk-flat.vmdk" 0',
                    access_mode="RW",
                    sectors=123456789,
                    type="FLAT",
                    filename='"disk-flat.vmdk"',
                    start_sector=0,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            "RDONLY 0 ZERO",
            [
                ExtentDescriptor(
                    raw="RDONLY 0 ZERO",
                    access_mode="RDONLY",
                    sectors=0,
                    type="ZERO",
                ),
            ],
        ),
        (
            'NOACCESS 123456789 SPARSE "disk-sparse.vmdk" 123 partition-uuid device-id',
            [
                ExtentDescriptor(
                    raw='NOACCESS 123456789 SPARSE "disk-sparse.vmdk" 123 partition-uuid device-id',
                    access_mode="NOACCESS",
                    sectors=123456789,
                    type="SPARSE",
                    filename='"disk-sparse.vmdk"',
                    start_sector=123,
                    partition_uuid="partition-uuid",
                    device_identifier="device-id",
                ),
            ],
        ),
        ("RW 1234567890", []),
        ('RDONLY "file.vmdk"', []),
        ("NOACCESS", []),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk"',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk"',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=None,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid="part-uuid",
                    device_identifier=None,
                )
            ],
        ),
        (
            'RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid device-id',
            [
                ExtentDescriptor(
                    raw='RW 1234567890 SPARSE "disk with spaces.vmdk" 123 part-uuid device-id',
                    access_mode="RW",
                    sectors=1234567890,
                    type="SPARSE",
                    filename='"disk with spaces.vmdk"',
                    start_sector=123,
                    partition_uuid="part-uuid",
                    device_identifier="device-id",
                )
            ],
        ),
        (
            r'RW 16777216 SPARSE "this is an example "\' diskëäô:)\\\'`\foo.vmdk" 123',
            [
                ExtentDescriptor(
                    raw=r'RW 16777216 SPARSE "this is an example "\' diskëäô:)\\\'`\foo.vmdk" 123',
                    access_mode="RW",
                    sectors=16777216,
                    type="SPARSE",
                    filename=r'"this is an example "\' diskëäô:)\\\'`\foo.vmdk"',
                    start_sector=123,
                    partition_uuid=None,
                    device_identifier=None,
                )
            ],
        ),
        (
            r'RW 13371337 SPARSE "🦊 🦊 🦊.vmdk"',
            [
                ExtentDescriptor(
                    raw=r'RW 13371337 SPARSE "🦊 🦊 🦊.vmdk"',
                    access_mode="RW",
                    sectors=13371337,
                    type="SPARSE",
                    filename='"🦊 🦊 🦊.vmdk"',
                )
            ],
        ),
    ],
    ids=(
        "sparse",
        "flat",
        "zero",
        "sparse-ids",
        "bad-1",
        "bad-2",
        "bad-3",
        "spaces-four-parts",
        "spaces-five-parts",
        "spaces-six-parts",
        "spaces-seven-parts",
        "specials-five-parts",
        "emoji-four-parts",
    ),
)
def test_vmdk_extent_description(extent_description: str, expected_extents: list[ExtentDescriptor]) -> None:
    """Test if we correctly parse VMDK sparse and flat extent descriptions.

    Resources:
        - https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#22-extent-descriptions
    """
    descriptor = DiskDescriptor.parse(extent_description)
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
