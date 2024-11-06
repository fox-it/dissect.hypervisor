import gzip
import os
from typing import BinaryIO, Iterator, TextIO

import pytest


def absolute_path(filename) -> str:
    return os.path.join(os.path.dirname(__file__), filename)


def open_file(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with open(absolute_path(name), mode) as f:
        yield f


def open_file_gz(name: str, mode: str = "rb") -> Iterator[BinaryIO]:
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def encrypted_vmx() -> Iterator[BinaryIO]:
    yield from open_file("data/encrypted.vmx")


@pytest.fixture
def vmcx() -> Iterator[BinaryIO]:
    yield from open_file("data/test.vmcx")


@pytest.fixture
def vmrs() -> Iterator[BinaryIO]:
    yield from open_file("data/test.VMRS")


@pytest.fixture
def fixed_vhd() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/fixed.vhd.gz")


@pytest.fixture
def dynamic_vhd() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/dynamic.vhd.gz")


@pytest.fixture
def fixed_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/fixed.vhdx.gz")


@pytest.fixture
def dynamic_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/dynamic.vhdx.gz")


@pytest.fixture
def differencing_vhdx() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/differencing.avhdx.gz")


@pytest.fixture
def sesparse_vmdk() -> Iterator[BinaryIO]:
    yield from open_file_gz("data/sesparse.vmdk.gz")


@pytest.fixture
def plain_hdd() -> Iterator[str]:
    yield absolute_path("data/plain.hdd")


@pytest.fixture
def expanding_hdd() -> Iterator[str]:
    yield absolute_path("data/expanding.hdd")


@pytest.fixture
def split_hdd() -> Iterator[str]:
    yield absolute_path("data/split.hdd")


@pytest.fixture
def envelope() -> Iterator[BinaryIO]:
    yield from open_file("data/local.tgz.ve")


@pytest.fixture
def keystore() -> Iterator[TextIO]:
    yield from open_file("data/encryption.info", "r")


@pytest.fixture
def vgz() -> Iterator[BinaryIO]:
    yield from open_file("data/test.vgz")
