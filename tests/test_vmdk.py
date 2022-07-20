from dissect.hypervisor.disk.vmdk import VMDK
from dissect.hypervisor.disk.c_vmdk import c_vmdk


def test_sesparse(sesparse_vmdk):
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
