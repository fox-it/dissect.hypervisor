from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

from dissect.hypervisor.tools.vmtar import main as vmtar_main
from dissect.hypervisor.util import vmtar
from tests.conftest import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_vmtar(vgz: BinaryIO) -> None:
    tar = vmtar.open(fileobj=vgz)

    members = {member.name: member for member in tar.getmembers()}

    # The test file has no textPgs/fixUpPgs
    assert all(member.is_visor for member in members.values())
    assert set(members.keys()) == {
        "test/file1",
        "test/file2",
        "test/file3",
        "test/subdir",
        "test/subdir/file4",
    }

    assert tar.extractfile(members["test/file1"]).read() == (b"a" * 512) + b"\n"
    assert tar.extractfile(members["test/file2"]).read() == (b"b" * 1024) + b"\n"
    assert tar.extractfile(members["test/file3"]).read() == (b"c" * 2048) + b"\n"
    assert tar.extractfile(members["test/subdir/file4"]).read() == (b"f" * 2048) + b"\n"


def test_vmtar_tool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    vgz_path = absolute_path("_data/util/vmtar/test.vgz")

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["vmtar", "-l", str(vgz_path)])

        vmtar_main()

    out, _ = capsys.readouterr()
    assert out.splitlines() == [
        "test/ ",
        "test/file3 ",
        "test/file2 ",
        "test/subdir/ ",
        "test/subdir/file4 ",
        "test/file1 ",
    ]

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["vmtar", "-t", str(vgz_path)])

        vmtar_main()

    _, err = capsys.readouterr()
    assert err.startswith("[<VisorTarInfo 'test'")

    with monkeypatch.context() as m:
        m.setattr("sys.argv", ["vmtar", "-e", str(vgz_path), str(tmp_path)])

        vmtar_main()

    for path in (
        "test",
        "test/file1",
        "test/file2",
        "test/file3",
        "test/subdir",
        "test/subdir/file4",
    ):
        assert tmp_path.joinpath(path).exists()

    assert tmp_path.joinpath("test/file1").read_text() == (b"a" * 512).decode() + "\n"
    assert tmp_path.joinpath("test/file2").read_text() == (b"b" * 1024).decode() + "\n"
    assert tmp_path.joinpath("test/file3").read_text() == (b"c" * 2048).decode() + "\n"
    assert tmp_path.joinpath("test/subdir/file4").read_text() == (b"f" * 2048).decode() + "\n"
