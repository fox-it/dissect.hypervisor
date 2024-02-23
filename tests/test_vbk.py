import hashlib
from typing import BinaryIO

from dissect.hypervisor.backup.vbk import VBK, MetaVector, MetaVector2


def test_vbk_version_9(vbk9: BinaryIO) -> None:
    vbk = VBK(vbk9)

    assert vbk.format_version == 9
    assert vbk.is_v7()
    assert isinstance(vbk.block_store, MetaVector)

    assert vbk.root.is_dir()
    assert not vbk.root.is_file()
    assert list(vbk.get("/").listdir().keys()) == [
        "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)"  # noqa: E501
    ]

    entry = vbk.get(
        "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)"  # noqa: E501
    )
    assert entry.is_dir()
    assert not vbk.root.is_file()
    assert list(entry.listdir().keys()) == [
        "DEV__dev_nvme1n1",
        "summary.xml",
    ]

    entry = vbk.get("DEV__dev_nvme1n1", entry)
    assert not entry.is_dir()
    assert entry.is_file()
    assert entry.is_internal_file()
    assert not entry.properties
    assert entry.size == 0x400000

    with entry.open() as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
        assert digest == "337350cac29d2ed34c23ce9fc675950badf85fd2b694791abe6999d36f0dc1b3"


def test_vbk_version_13(vbk13: BinaryIO) -> None:
    vbk = VBK(vbk13)

    assert vbk.format_version == 13
    assert vbk.is_v7()
    assert isinstance(vbk.block_store, MetaVector2)
    assert list(vbk.get("/").listdir().keys()) == [
        "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)"
    ]

    entry = vbk.get("6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)")
    assert entry.is_dir()
    assert not entry.is_file()
    assert list(entry.listdir().keys()) == [
        "digest_47d9f323-442b-433d-bd4f-1ecb3fa97351",
        "8b14f74c-360d-4d7a-98f7-7f4c5e737eb7",
        "GuestMembers.xml",
        "BackupComponents.xml",
        "summary.xml",
    ]

    entry = vbk.get(
        "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/8b14f74c-360d-4d7a-98f7-7f4c5e737eb7"  # noqa: E501
    )
    assert not entry.is_dir()
    assert entry.is_file()
    assert entry.is_internal_file()
    assert "DefinedBlocksMask" in entry.properties
    assert len(entry.properties["DefinedBlocksMask"]) == 35
    assert entry.size == 0x314200

    with entry.open() as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
        assert digest == "e9ed281cf9c2fe1745e4eb9c926c1a64bd47569c48be511c5fdf6fd5793e5a77"
