from __future__ import annotations

from uuid import UUID

from dissect.hypervisor.descriptor.vbox import VBox
from tests._util import absolute_path


def test_vbox_snapshots() -> None:
    """Test parsing VirtualBox XML descriptor with snapshots."""
    with absolute_path("_data/descriptor/vbox/GOAD-DC01.vbox").open() as fh:
        vbox = VBox(fh)

        assert vbox.uuid == UUID("a6277950-3d1b-45d3-b2fd-dc1f385027e1")
        assert vbox.name == "GOAD-DC01"

        # Check that the "current" disk is correct
        assert len(vbox.machine.hardware.disks) == 1
        assert vbox.machine.hardware.disks[0].uuid == UUID("e6800503-8273-4f16-b584-c7ba2c1df698")
        assert vbox.machine.hardware.disks[0].location == "Snapshots/{e6800503-8273-4f16-b584-c7ba2c1df698}.vmdk"

        assert vbox.machine.parent.uuid == UUID("264ccd7e-9ffd-45ba-bd0e-4e1968d3355a")

        # Just to verify that we resolve the snapshot state disks correctly
        assert len(vbox.snapshots) == 2
        snapshot = vbox.snapshots[UUID("95b1572d-c893-48f0-9bc9-6a01a0fd2cb6")]
        assert snapshot.parent is None
        assert snapshot.uuid == UUID("95b1572d-c893-48f0-9bc9-6a01a0fd2cb6")
        assert snapshot.name == "push_1766163705_7292"
        assert snapshot.ts.isoformat() == "2025-12-19T17:01:46+00:00"
        assert len(snapshot.hardware.disks) == 1
        assert snapshot.hardware.disks[0].uuid == UUID("0898f36f-01c3-4b43-8aeb-36ba7adaef95")
        assert snapshot.hardware.disks[0].location == "WindowsServer2019-disk001.vmdk"

        snapshot = vbox.snapshots[UUID("264ccd7e-9ffd-45ba-bd0e-4e1968d3355a")]
        assert snapshot.parent.uuid == UUID("95b1572d-c893-48f0-9bc9-6a01a0fd2cb6")
        assert snapshot.uuid == UUID("264ccd7e-9ffd-45ba-bd0e-4e1968d3355a")
        assert snapshot.name == "push_1766170151_8843"
        assert snapshot.ts.isoformat() == "2025-12-19T18:49:11+00:00"
        assert len(snapshot.hardware.disks) == 1
        assert snapshot.hardware.disks[0].uuid == UUID("3c72ec80-dc73-4448-a63e-97970cdd87e5")
        assert snapshot.hardware.disks[0].location == "Snapshots/{3c72ec80-dc73-4448-a63e-97970cdd87e5}.vmdk"

        # Test the tree of disks snapshots
        disk = vbox.media[UUID("706a96fe-0e11-4985-af32-7561d26612d4")]
        assert disk.parent.uuid == UUID("35bf5129-1caa-4117-b20a-d73868d9d5d2")
        assert disk.parent.parent.uuid == UUID("0898f36f-01c3-4b43-8aeb-36ba7adaef95")
        assert disk.parent.parent.parent is None

        disk = vbox.media[UUID("e6800503-8273-4f16-b584-c7ba2c1df698")]
        assert disk.parent.uuid == UUID("3c72ec80-dc73-4448-a63e-97970cdd87e5")
        assert disk.parent.parent.uuid == UUID("0898f36f-01c3-4b43-8aeb-36ba7adaef95")
        assert disk.parent.parent.parent is None


def test_vbox_encrypted() -> None:
    with absolute_path("_data/descriptor/vbox/encrypted.vbox").open() as fh:
        vbox = VBox(fh)

        disk = vbox.media[UUID("24cdb8e9-35d6-42f2-aa17-c2d78bf1e1de")]
        assert disk.properties["CRYPT/KeyId"] == "encrypted test"
        assert "CRYPT/KeyStore" in disk.properties
        assert disk.is_encrypted

        disk = vbox.media[UUID("742e6d0f-8896-4aa6-97f4-e05d70e73029")]
        assert disk.is_encrypted

        disk = vbox.media[UUID("1db0b9fe-36c2-44e8-9b7c-61fa5b6d1462")]
        assert not disk.is_encrypted
