import gzip
from pathlib import Path
from unittest.mock import patch

from dissect.hypervisor.disk.hdd import HDD

Path_open = Path.open


def mock_open_gz(self, *args, **kwargs):
    if self.suffix.lower() != ".hds":
        return Path_open(self, *args, **kwargs)

    return gzip.open(self.with_suffix(self.suffix + ".gz"))


def test_plain_hdd(plain_hdd):
    hdd = HDD(Path(plain_hdd))
    storages = hdd.descriptor.storage_data.storages

    assert len(storages) == 1
    assert storages[0].start == 0
    assert storages[0].end == 204800
    assert len(storages[0].images) == 1
    assert storages[0].images[0].type == "Plain"

    with patch.object(Path, "open", mock_open_gz):
        stream = hdd.open()

        for i in range(100):
            assert stream.read(1024 * 1024).strip(bytes([i])) == b""


def test_expanding_hdd(expanding_hdd):
    hdd = HDD(Path(expanding_hdd))
    storages = hdd.descriptor.storage_data.storages

    assert len(storages) == 1
    assert storages[0].start == 0
    assert storages[0].end == 204800
    assert len(storages[0].images) == 1
    assert storages[0].images[0].type == "Compressed"

    with patch.object(Path, "open", mock_open_gz):
        stream = hdd.open()

        for i in range(100):
            assert stream.read(1024 * 1024).strip(bytes([i])) == b""


def test_split_hdd(split_hdd):
    hdd = HDD(Path(split_hdd))
    storages = hdd.descriptor.storage_data.storages

    assert len(storages) == 6

    split_sizes = [3989504, 3989504, 3989504, 3989504, 3989504, 1024000]

    start = 0

    for storage, split_size in zip(storages, split_sizes):
        assert storage.start == start
        assert storage.end == start + split_size
        assert len(storage.images) == 1
        assert storage.images[0].type == "Compressed"

        start = storage.end

    with patch.object(Path, "open", mock_open_gz):
        stream = hdd.open()

        assert stream.read(1024 * 1024).strip(b"\x01") == b""

        offset = 0
        for i, split_size in enumerate(split_sizes):
            offset += split_size * 512
            stream.seek(offset - 512)

            buf = stream.read(1024)
            if i < 5:
                assert buf == bytes([i + 1] * 512) + bytes([i + 2] * 512)
            else:
                assert buf == bytes([i + 1] * 512)
