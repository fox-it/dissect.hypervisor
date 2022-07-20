import hashlib

from dissect.hypervisor.backup.vma import VMA, _iter_clusters


def test_vma(simple_vma):
    vma = VMA(simple_vma)

    assert vma.version == 1
    assert str(vma.uuid) == "04fc12eb-0fed-4322-9aaa-f4e412f68096"

    assert vma.blob_string(1) == "qemu-server.conf"
    assert len(vma.blob_data(20)) == 417
    assert vma.blob_string(439) == "drive-scsi0"

    assert vma.config("qemu-server.conf") == vma.blob_data(20)
    assert len(vma.configs()) == 1

    assert len(vma.devices()) == 1

    device = vma.device(1)
    assert device.id == 1
    assert device.name == "drive-scsi0"
    assert device.size == 10737418240

    extents = list(vma.extents())
    # The test data is just a small piece of a real VMA file
    assert len(extents) == 2

    assert list(_iter_clusters(vma, device.id, 0, 23)) == [
        (0, 65535, 13312),
        (1, 0, 78848),
        (2, 0, 78848),
        (3, 0, 78848),
        (4, 0, 78848),
        (5, 0, 78848),
        (6, 0, 78848),
        (7, 0, 78848),
        (8, 0, 78848),
        (9, 0, 78848),
        (10, 0, 78848),
        (11, 0, 78848),
        (12, 0, 78848),
        (13, 0, 78848),
        (14, 0, 78848),
        (15, 0, 78848),
        (16, 65535, 79360),
        (17, 65535, 144896),
        (18, 65535, 210432),
        (19, 65535, 275968),
        (20, 65535, 341504),
        (21, 65535, 407040),
        (22, 65535, 472576),
    ]

    stream = device.open()
    buf = stream.read(65536)
    assert hashlib.sha256(buf).hexdigest() == "cf4adcf1933a8c9a0a3ff5588e1400e6beea8a32212b3a35ba08c7b08e4e6b1f"

    buf = stream.read(65536 * 15)
    assert buf.strip(b"\x00") == b""

    buf = stream.read(65536 * 7)
    assert hashlib.sha256(buf).hexdigest() == "8c989a3aa590795fa919ccb7d1f28651c85f8a0d9ba00ab22cdd9fb760fa7955"
