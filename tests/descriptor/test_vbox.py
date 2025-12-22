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
        assert len(vbox.hardware.disks) == 1
        assert vbox.hardware.disks[0].uuid == UUID("e6800503-8273-4f16-b584-c7ba2c1df698")
        assert vbox.hardware.disks[0].location == "Snapshots/{e6800503-8273-4f16-b584-c7ba2c1df698}.vmdk"

        # Just to verify that we resolve the snapshot state disks correctly
        assert len(vbox.snapshots) == 2
        assert vbox.snapshots[0].uuid == UUID("95b1572d-c893-48f0-9bc9-6a01a0fd2cb6")
        assert vbox.snapshots[0].name == "push_1766163705_7292"
        assert vbox.snapshots[0].ts.isoformat() == "2025-12-19T17:01:46+00:00"
        assert len(vbox.snapshots[0].hardware.disks) == 1
        assert vbox.snapshots[0].hardware.disks[0].uuid == UUID("0898f36f-01c3-4b43-8aeb-36ba7adaef95")
        assert vbox.snapshots[0].hardware.disks[0].location == "WindowsServer2019-disk001.vmdk"

        assert vbox.snapshots[1].uuid == UUID("264ccd7e-9ffd-45ba-bd0e-4e1968d3355a")
        assert vbox.snapshots[1].name == "push_1766170151_8843"
        assert vbox.snapshots[1].ts.isoformat() == "2025-12-19T18:49:11+00:00"
        assert len(vbox.snapshots[1].hardware.disks) == 1
        assert vbox.snapshots[1].hardware.disks[0].uuid == UUID("3c72ec80-dc73-4448-a63e-97970cdd87e5")
        assert vbox.snapshots[1].hardware.disks[0].location == "Snapshots/{3c72ec80-dc73-4448-a63e-97970cdd87e5}.vmdk"
