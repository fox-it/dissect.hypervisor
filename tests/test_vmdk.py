import pytest

from dissect.hypervisor.disk.c_vmdk import c_vmdk
from dissect.hypervisor.disk.vmdk import VMDK, DiskDescriptor, ExtentDescriptor


def test_vmdk_sesparse(sesparse_vmdk):
    vmdk = VMDK(sesparse_vmdk)

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


@pytest.mark.parametrize(
    "extent_description, expected_extents",
    [
        (
            'RW 123456789 SPARSE "disk.vmdk"',
            [
                ExtentDescriptor(
                    access_mode="RW",
                    sectors=123456789,
                    type="SPARSE",
                    filename="disk.vmdk",
                    partition_uuid=None,
                    device_identifier=None,
                ),
            ],
        ),
        (
            'RW 123456789 FLAT "disk-flat.vmdk" 0',
            [
                ExtentDescriptor(
                    access_mode="RW",
                    sectors=123456789,
                    type="FLAT",
                    filename="disk-flat.vmdk",
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
                    access_mode="NOACCESS",
                    sectors=123456789,
                    type="SPARSE",
                    filename="disk-sparse.vmdk",
                    start_sector=123,
                    partition_uuid="partition-uuid",
                    device_identifier="device-id",
                ),
            ],
        ),
        ("RW 1234567890", []),
        ('RDONLY "file.vmdk"', []),
        ("NOACCESS", []),
    ],
    ids=("sparse", "flat", "zero", "sparse-ids", "bad-1", "bad-2", "bad-3"),
)
def test_vmdk_extent_description(extent_description: str, expected_extents: list) -> None:
    """test if we correctly parse VMDK sparse and flat extent descriptions.

    Resources:
        - https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc#22-extent-descriptions
    """  # noqa: E501

    descriptor = DiskDescriptor.parse(extent_description)
    assert descriptor.extents == expected_extents
