from dissect.hypervisor.util import vmtar


def test_vmtar(vgz):
    tar = vmtar.open(fileobj=vgz)

    members = {member.name: member for member in tar.getmembers()}

    # The test file has no textPgs/fixUpPgs
    assert all(member.is_visor for member in members.values())
    assert set(members.keys()) == {
        "test",
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
