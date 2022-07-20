from uuid import UUID

import pytest

from dissect.hypervisor.disk.vhdx import VHDX, c_vhdx, _iter_partial_runs


def test_fixed_vhdx(fixed_vhdx):
    v = VHDX(fixed_vhdx)

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
    assert v.read(512) == b"\xFF" * 512

    for block in range(v.bat._pb_count):
        block_entry = v.bat.pb(block)
        assert block_entry.state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT


def test_dynamic_vhdx(dynamic_vhdx):
    v = VHDX(dynamic_vhdx)

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
    assert v.read(512) == b"\xFF" * 512


def test_differencing_vhdx(differencing_vhdx):
    with pytest.raises(IOError):
        VHDX(differencing_vhdx)


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ((b"\xFF", 0, 8), [(1, 8)]),
        ((b"\xFF", 4, 4), [(1, 4)]),
        ((b"\x00", 0, 8), [(0, 8)]),
        ((b"\x00", 4, 4), [(0, 4)]),
        ((b"\xFF\x00", 0, 8), [(1, 8)]),
        ((b"\xFF\x00", 4, 8), [(1, 4), (0, 4)]),
        ((b"\x00\x00", 0, 12), [(0, 12)]),
        ((b"\x00\xFF", 4, 8), [(0, 4), (1, 4)]),
        ((b"\xF0\xF0", 0, 16), [(0, 4), (1, 4), (0, 4), (1, 4)]),
        ((b"\x0F\x0F", 0, 16), [(1, 4), (0, 4), (1, 4), (0, 4)]),
        ((b"\x00", 0, 6), [(0, 6)]),
        ((b"\x00", 1, 6), [(0, 6)]),
    ],
)
def test_partial_runs(test_input, expected):
    assert list(_iter_partial_runs(*test_input)) == expected
