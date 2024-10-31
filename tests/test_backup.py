import gzip
import hashlib
from pathlib import Path
from typing import IO
from unittest.mock import patch

import pytest

from dissect.hypervisor.tools.backup import main


@pytest.mark.parametrize(
    "filename, expected",
    [
        (
            "test9.vbk.gz",
            [
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)/DEV__dev_nvme1n1",
                    "337350cac29d2ed34c23ce9fc675950badf85fd2b694791abe6999d36f0dc1b3",
                ),
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (78a5467d-87f5-8540-9a84-7569ae2849ad_2d1bb20f-49c1-485d-a689-696693713a5a)/summary.xml",
                    "d2b8f4d08e57a44b817b57d9c03e670c292e5a21e91fb5895b51e923781175e8",
                ),
            ],
        ),
        (
            "test13.vbk.gz",
            [
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/BackupComponents.xml",
                    "a9615b1cbce437074235ac194681d42e1f018f1c804277293dc24d4dd90eb504",
                ),
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/digest_47d9f323-442b-433d-bd4f-1ecb3fa97351",
                    "d6f9dced7c58628a4648e1a5ed349609f11cefb0ac6721c35c5f943ac18aaf10",
                ),
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/GuestMembers.xml",
                    "18228ae41c1e7ddb23ee6cfe49c9e2c1cdfe99393b45f20d7fbbdb5d247938b4",
                ),
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/summary.xml",
                    "c93e3460a4495a96047fd8c1c80c3169782207e106cc3b5f5d9b5edae68eb3d9",
                ),
                (
                    "6745a759-2205-4cd2-b172-8ec8f7e60ef8 (3c834d56-37ac-8bd3-b946-30113c55c4b5)/8b14f74c-360d-4d7a-98f7-7f4c5e737eb7",
                    "e9ed281cf9c2fe1745e4eb9c926c1a64bd47569c48be511c5fdf6fd5793e5a77",
                ),
            ],
        ),
    ],
)
def test_backup_tool(
    filename: str, expected: list[tuple[str, str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    Path_open = Path.open

    def mock_open(self, mode: str, *args, **kwargs) -> IO:
        if filename.endswith(".gz") and self.name == filename:
            return gzip.open(self, mode)

        return Path_open(self, mode, *args, **kwargs)

    with patch.object(Path, "open", mock_open):
        with monkeypatch.context() as m:
            m.setattr("sys.argv", ["backup-extract", f"tests/data/{filename}", "-o", str(tmp_path)])
            main()

    for name, digest in expected:
        out_path = tmp_path / name
        assert out_path.exists()
        assert hashlib.sha256(out_path.read_bytes()).hexdigest() == digest
