from __future__ import annotations

import gzip
import io
import struct
from uuid import UUID

import pytest

from dissect.hypervisor.disk.vhdx import VHDX, _iter_partial_runs, c_vhdx
from tests._util import absolute_path


def test_vhdx_fixed() -> None:
    with gzip.open(absolute_path("_data/disk/vhdx/fixed.vhdx.gz"), "rb") as fh:
        v = VHDX(fh)

        assert v.size == 0xA00000
        assert v.block_size == 0x200000
        assert v.has_parent == 0
        assert v.sector_size == 0x200
        assert v.bat.chunk_ratio == 0x800
        assert v.id == UUID("4a49d245-db0a-4634-9818-9f93db5ba6c1")

        assert v.read(512) == bytes.fromhex(
            "33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400"
            "bdbe07807e00007c0b0f850e0183c510e2f1cd1888560055c6461105c6461000"
            "b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074"
            "2666680000000066ff760868000068007c680100681000b4428a56008bf4cd13"
            "9f83c4109eeb14b80102bb007c8a56008a76018a4e028a6e03cd136661731cfe"
            "4e11750c807e00800f848a00b280eb845532e48a5600cd135deb9e813efe7d55"
            "aa756eff7600e88d007517fab0d1e664e88300b0dfe660e87c00b0ffe664e875"
            "00fbb800bbcd1a6623c0753b6681fb54435041753281f90201722c666807bb00"
            "006668000200006668080000006653665366556668000000006668007c000066"
            "6168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e4"
            "0500078bf0ac3c007409bb0700b40ecd10ebf2f4ebfd2bc9e464eb002402e0f8"
            "2402c3496e76616c696420706172746974696f6e207461626c65004572726f72"
            "206c6f6164696e67206f7065726174696e672073797374656d004d697373696e"
            "67206f7065726174696e672073797374656d000000637b9a8a3dad8c00000002"
            "030007e525008000000000380000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000055aa"
        )

        v.seek(0x200000)
        assert v.read(512) == b"\xff" * 512

        for block in range(v.bat._pb_count):
            block_entry = v.bat.pb(block)
            assert block_entry.state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT


def test_vhdx_dynamic() -> None:
    with gzip.open(absolute_path("_data/disk/vhdx/dynamic.vhdx.gz"), "rb") as fh:
        v = VHDX(fh)

        assert v.size == 0xA00000
        assert v.block_size == 0x2000000
        assert v.has_parent == 0
        assert v.sector_size == 0x200
        assert v.bat.chunk_ratio == 0x80
        assert v.id == UUID("788015f0-5e93-4bd2-a5de-b0cd8459db11")

        assert v.read(512) == bytes.fromhex(
            "33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400"
            "bdbe07807e00007c0b0f850e0183c510e2f1cd1888560055c6461105c6461000"
            "b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074"
            "2666680000000066ff760868000068007c680100681000b4428a56008bf4cd13"
            "9f83c4109eeb14b80102bb007c8a56008a76018a4e028a6e03cd136661731cfe"
            "4e11750c807e00800f848a00b280eb845532e48a5600cd135deb9e813efe7d55"
            "aa756eff7600e88d007517fab0d1e664e88300b0dfe660e87c00b0ffe664e875"
            "00fbb800bbcd1a6623c0753b6681fb54435041753281f90201722c666807bb00"
            "006668000200006668080000006653665366556668000000006668007c000066"
            "6168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e4"
            "0500078bf0ac3c007409bb0700b40ecd10ebf2f4ebfd2bc9e464eb002402e0f8"
            "2402c3496e76616c696420706172746974696f6e207461626c65004572726f72"
            "206c6f6164696e67206f7065726174696e672073797374656d004d697373696e"
            "67206f7065726174696e672073797374656d000000637b9af93dad8c00000002"
            "030007e525008000000000380000000000000000000000000000000000000000"
            "00000000000000000000000000000000000000000000000000000000000055aa"
        )

        v.seek(0x200000)
        assert v.read(512) == b"\xff" * 512


def test_vhdx_differencing() -> None:
    with (
        pytest.raises(IOError, match="Failed to open parent disk with locator"),
        gzip.open(absolute_path("_data/disk/vhdx/differencing.avhdx.gz"), "rb") as fh,
    ):
        VHDX(fh)


@pytest.mark.parametrize(
    ("test_input", "expected"),
    [
        ((b"\xff", 0, 8), [(1, 8)]),
        ((b"\xff", 4, 4), [(1, 4)]),
        ((b"\x00", 0, 8), [(0, 8)]),
        ((b"\x00", 4, 4), [(0, 4)]),
        ((b"\xff\x00", 0, 8), [(1, 8)]),
        ((b"\xff\x00", 4, 8), [(1, 4), (0, 4)]),
        ((b"\x00\x00", 0, 12), [(0, 12)]),
        ((b"\x00\xff", 4, 8), [(0, 4), (1, 4)]),
        ((b"\xf0\xf0", 0, 16), [(0, 4), (1, 4), (0, 4), (1, 4)]),
        ((b"\x0f\x0f", 0, 16), [(1, 4), (0, 4), (1, 4), (0, 4)]),
        ((b"\x00", 0, 6), [(0, 6)]),
        ((b"\x00", 1, 6), [(0, 6)]),
    ],
)
def test_vhdx_partial_runs(test_input: tuple[bytes, int, int], expected: list[tuple[int, int]]) -> None:
    assert list(_iter_partial_runs(*test_input)) == expected


def _patched_fixed_vhdx(bat_changes: dict[int, tuple[int, int | None]]) -> tuple[VHDX, list[bytes]]:
    """Return the fixed test VHDX with a distinct fill pattern per payload block and a modified BAT.

    Args:
        bat_changes: Maps a block number to a tuple of the new payload block state and the block whose payload
            the entry should point to, or ``None`` to keep the block's own payload.

    Returns:
        The patched VHDX and the expected content of every virtual block.
    """
    with gzip.open(absolute_path("_data/disk/vhdx/fixed.vhdx.gz"), "rb") as fh:
        buf = bytearray(fh.read())

    vhdx = VHDX(io.BytesIO(bytes(buf)))
    block_size = vhdx.block_size
    entries = [vhdx.bat.pb(block) for block in range(vhdx.bat._pb_count)]
    patterns = [bytes([0x11 * (block + 1)]) * block_size for block in range(len(entries))]

    # Give every payload block a recognizable content
    for block, entry in enumerate(entries):
        offset = entry.file_offset_mb * 1024 * 1024
        buf[offset : offset + block_size] = patterns[block]

    expected = list(patterns)
    for block, (state, source) in bat_changes.items():
        file_offset_mb = entries[block if source is None else source].file_offset_mb
        value = state | (file_offset_mb << 20)
        struct.pack_into("<Q", buf, vhdx.bat.offset + (block + block // vhdx.bat.chunk_ratio) * 8, value)

        if state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT:
            expected[block] = patterns[block if source is None else source]
        else:
            expected[block] = b"\x00" * block_size

    return VHDX(io.BytesIO(bytes(buf))), expected


@pytest.mark.parametrize(
    "bat_changes",
    [
        pytest.param({}, id="contiguous"),
        pytest.param({1: (c_vhdx.PAYLOAD_BLOCK_ZERO, None)}, id="present-to-zero"),
        pytest.param({0: (c_vhdx.PAYLOAD_BLOCK_ZERO, None)}, id="zero-to-present"),
        pytest.param({1: (c_vhdx.PAYLOAD_BLOCK_NOT_PRESENT, None)}, id="not-present"),
        pytest.param(
            {
                1: (c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT, 2),
                2: (c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT, 1),
            },
            id="non-contiguous-payload",
        ),
    ],
)
@pytest.mark.parametrize(
    ("offset", "length"),
    [
        (0, None),  # everything in one read
        (0x200000 - 512, 1024),  # straddle a single block boundary
        (0x100000, 0x300000),  # start mid-block, span multiple blocks
    ],
)
def test_vhdx_read_across_block_boundaries(
    bat_changes: dict[int, tuple[int, int | None]], offset: int, length: int | None
) -> None:
    """Test reads crossing block boundaries next to zero, absent and non-contiguous payload blocks."""
    vhdx, expected = _patched_fixed_vhdx(bat_changes)
    expected_data = b"".join(expected)
    length = len(expected_data) - offset if length is None else length

    vhdx.seek(offset)
    assert vhdx.read(length) == expected_data[offset : offset + length]
    assert vhdx.read_sectors(offset // 512, length // 512) == expected_data[offset : offset + length]
