import pytest

from dissect.hypervisor.descriptor.vmx import VMX, HAS_PYCRYPTODOME, HAS_PYSTANDALONE


def test_vmx():
    data_scsi = """
scsi0.virtualDev = "lsisas1068"
scsi0.present = "TRUE"
scsi0:0.fileName = "Virtual Disk-cl1.vmdk"
scsi0:0.present = "TRUE"
scsi0:0.redo = ""
scsi0.pciSlotNumber = "160"
scsi0.sasWWID = "50 05 05 68 05 82 7f 70"
    """
    vmx_scsi = VMX.parse(data_scsi)

    assert len(vmx_scsi.attr) == 7
    assert vmx_scsi.disks() == ["Virtual Disk-cl1.vmdk"]

    data_nvme = """
nvme0.pcislotnumber = "160"
nvme0.present = "TRUE"
nvme0:0.filename = "Virtual Disk-000003.vmdk"
nvme0:0.present = "TRUE"
nvme0:0.redo = ""
    """
    vmx_nvme = VMX.parse(data_nvme)

    assert len(vmx_nvme.attr) == 5
    assert vmx_nvme.disks() == ["Virtual Disk-000003.vmdk"]

    data_ide = """
ide1:0.deviceType = "cdrom-image"
ide1:0.fileName = "file.iso"
ide1:0.present = "TRUE"
ide0:0.fileName = "Virtual Disk 2.vmdk"
ide0:0.present = "TRUE"
    """
    vmx_ide = VMX.parse(data_ide)

    assert len(vmx_ide.attr) == 5
    assert vmx_ide.disks() == ["Virtual Disk 2.vmdk"]

    data_sata = """
sata0.present = "TRUE"
sata0:0.fileName = "Virtual Disk 3.vmdk"
sata0:0.present = "TRUE"
    """
    vmx_sata = VMX.parse(data_sata)

    assert len(vmx_sata.attr) == 3
    assert vmx_sata.disks() == ["Virtual Disk 3.vmdk"]

    data_casing = """
sata0:0.FILENAME = "Virtual Disk 3.vmdk"
    """
    vmx_casing = VMX.parse(data_casing)

    assert len(vmx_casing.attr) == 1
    assert vmx_casing.disks() == ["Virtual Disk 3.vmdk"]


@pytest.mark.skipif((not HAS_PYCRYPTODOME and not HAS_PYSTANDALONE), reason="No crypto module available")
def test_vmx_encrypted(encrypted_vmx):
    vmx = VMX.parse(encrypted_vmx.read().decode())

    assert vmx.encrypted

    vmx.unlock_with_phrase("password")

    assert "datafilekey" in vmx.attr
