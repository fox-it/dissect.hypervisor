from __future__ import annotations

import gzip
import hashlib
from pathlib import Path
from typing import BinaryIO
from unittest.mock import patch

import pytest

from dissect.hypervisor.disk.qcow2 import QCow2, QCow2Stream
from dissect.hypervisor.exceptions import Error


def mock_open_gz(self: Path, *args, **kwargs) -> BinaryIO:
    return gzip.open(self if self.suffix.lower() == ".gz" else self.with_suffix(self.suffix + ".gz"))


@pytest.mark.parametrize("name", ["basic_qcow2", "basic_zstd_qcow2"])
def test_basic(name: str, request: pytest.FixtureRequest) -> None:
    qcow2 = QCow2(request.getfixturevalue(name))

    assert qcow2.backing_file is None
    assert qcow2.data_file is qcow2.fh
    assert qcow2.size == 536870912

    with qcow2.open() as stream:
        for i in range(255):
            assert stream.read(1024 * 1024).strip(bytes([i])) == b"", f"Mismatch at offset {i * 1024 * 1024:#x}"


def test_data_file(data_file_qcow2: Path) -> None:
    # Test with file handle
    with gzip.open(data_file_qcow2, "rb") as fh:
        with pytest.raises(Error, match=r"data-file required but not provided \(image_data_file = 'data-file.bin'\)"):
            QCow2(fh)

        with gzip.open(data_file_qcow2.with_name("data-file.bin.gz"), "rb") as fh_bin:
            qcow2 = QCow2(fh, data_file=fh_bin)

            assert qcow2.backing_file is None
            assert qcow2.data_file is fh_bin

            with qcow2.open() as stream:
                for i in range(255):
                    assert stream.read(1024 * 1024).strip(bytes([i])) == b"", f"Mismatch at offset {i * 1024 * 1024:#x}"

        # Test with allow_no_data_file
        qcow2 = QCow2(fh, allow_no_data_file=True)
        assert qcow2.data_file is None
        with pytest.raises(Error, match=r"data-file required but not provided \(image_data_file = 'data-file.bin'\)"):
            qcow2.open()

    # Test with Path
    with patch.object(Path, "open", mock_open_gz), patch.object(Path, "exists", return_value=True):
        qcow2 = QCow2(data_file_qcow2)

        assert qcow2.backing_file is None
        assert qcow2.data_file is not qcow2.fh

        with qcow2.open() as stream:
            for i in range(255):
                assert stream.read(1024 * 1024).strip(bytes([i])) == b"", f"Mismatch at offset {i * 1024 * 1024:#x}"


def test_backing_file(backing_chain_qcow2: tuple[Path, Path, Path]) -> None:
    file1, file2, file3 = backing_chain_qcow2

    # Test with file handle
    with gzip.open(file1, "rb") as fh1, gzip.open(file2, "rb") as fh2, gzip.open(file3, "rb") as fh3:
        with pytest.raises(
            Error, match=r"backing-file required but not provided \(auto_backing_file = 'backing-chain-2.qcow2'\)"
        ):
            QCow2(fh1)

        with pytest.raises(
            Error, match=r"backing-file required but not provided \(auto_backing_file = 'backing-chain-3.qcow2'\)"
        ):
            QCow2(fh1, backing_file=fh2)

        backing2 = QCow2(fh2, backing_file=fh3)
        assert isinstance(backing2.backing_file, QCow2Stream)

        qcow2 = QCow2(fh1, backing_file=backing2.open())
        assert isinstance(qcow2.backing_file, QCow2Stream)

        # Test with allow_no_backing_file
        qcow2 = QCow2(fh1, allow_no_backing_file=True)
        assert qcow2.backing_file is None
        with pytest.raises(
            Error, match=r"backing-file required but not provided \(auto_backing_file = 'backing-chain-2.qcow2'\)"
        ):
            qcow2.open()

    # Test with Path
    with patch.object(Path, "open", mock_open_gz), patch.object(Path, "exists", return_value=True):
        qcow2 = QCow2(file1)

        assert isinstance(qcow2.backing_file, QCow2Stream)
        assert qcow2.backing_file.qcow2.fh.name == str(file2)

        assert isinstance(qcow2.backing_file.qcow2.backing_file, QCow2Stream)
        assert qcow2.backing_file.qcow2.backing_file.qcow2.fh.name == str(file3)

        # Test reading through the backing chain
        with QCow2(file3).open() as stream:
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here too"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here three"
            assert stream.read(1024 * 1024).strip(b"\x00") == b""
            assert stream.read(1024 * 1024).strip(b"\x00") == b""

        with QCow2(file2).open() as stream:
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Nothing here"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here too"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here three"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here four"
            assert stream.read(1024 * 1024).strip(b"\x00") == b""

        with QCow2(file1).open() as stream:
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Nothing here"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Nothing here two"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here three"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here four"
            assert stream.read(1024 * 1024).strip(b"\x00") == b"Something here five"


def test_snapshot(snapshot_qcow2: BinaryIO) -> None:
    qcow2 = QCow2(snapshot_qcow2)

    assert qcow2.backing_file is None
    assert qcow2.data_file is qcow2.fh
    assert qcow2.size == 536870912

    with qcow2.open() as stream:
        assert stream.read(4 * 1024 * 1024).strip(b"\x00") == b""

    assert len(qcow2.snapshots) == 2
    assert qcow2.snapshots[0].id == "1"
    assert qcow2.snapshots[0].name == "you can't see me"
    assert qcow2.snapshots[1].id == "2"
    assert qcow2.snapshots[1].name == "confused"

    with qcow2.snapshots[1].open() as stream:
        assert hashlib.sha1(stream.read(813857)).hexdigest() == "c97f53aece77ea49099d15e5f53af3af5f62fb54"

    with qcow2.snapshots[0].open() as stream:
        assert hashlib.sha1(stream.read(2261577)).hexdigest() == "2c7a6b5f6b5c4739f6d24c11e86c764bdf86096f"
