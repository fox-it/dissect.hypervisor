from __future__ import annotations

import gzip
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, TextIO

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator


def absolute_path(filename: str) -> Path:
    return Path(__file__).parent / filename


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with absolute_path(name).open(mode) as fh:
        yield fh


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as fh:
        yield fh


@pytest.fixture
def encrypted_vmx() -> Iterator[BinaryIO]:
    yield from open_file("_data/descriptor/vmx/encrypted.vmx")


@pytest.fixture
def vmcx() -> Iterator[BinaryIO]:
    yield from open_file("_data/descriptor/hyperv/test.vmcx")


@pytest.fixture
def vmrs() -> Iterator[BinaryIO]:
    yield from open_file("_data/descriptor/hyperv/test.VMRS")


@pytest.fixture
def fixed_vhd() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vhd/fixed.vhd.gz")


@pytest.fixture
def dynamic_vhd() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vhd/dynamic.vhd.gz")


@pytest.fixture
def fixed_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vhdx/fixed.vhdx.gz")


@pytest.fixture
def dynamic_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vhdx/dynamic.vhdx.gz")


@pytest.fixture
def differencing_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vhdx/differencing.avhdx.gz")


@pytest.fixture
def sesparse_vmdk() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/disk/vmdk/sesparse.vmdk.gz")


@pytest.fixture
def plain_hdd() -> Iterator[str]:
    return absolute_path("_data/disk/hdd/plain.hdd")


@pytest.fixture
def expanding_hdd() -> Iterator[str]:
    return absolute_path("_data/disk/hdd/expanding.hdd")


@pytest.fixture
def split_hdd() -> Iterator[str]:
    return absolute_path("_data/disk/hdd/split.hdd")


@pytest.fixture
def envelope() -> Iterator[BinaryIO]:
    yield from open_file("_data/util/envelope/local.tgz.ve")


@pytest.fixture
def keystore() -> Iterator[TextIO]:
    yield from open_file("_data/util/envelope/encryption.info", "r")


@pytest.fixture
def vgz() -> Iterator[BinaryIO]:
    yield from open_file("_data/util/vmtar/test.vgz")
