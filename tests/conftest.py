import os
import gzip

import pytest


def absolute_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def open_file(name, mode="rb"):
    with open(absolute_path(name), mode) as f:
        yield f


def open_file_gz(name, mode="rb"):
    with gzip.GzipFile(absolute_path(name), mode) as f:
        yield f


@pytest.fixture
def encrypted_vmx():
    yield from open_file("data/encrypted.vmx")


@pytest.fixture
def vmcx():
    yield from open_file("data/test.vmcx")


@pytest.fixture
def vmrs():
    yield from open_file("data/test.VMRS")


@pytest.fixture
def fixed_vhdx():
    yield from open_file_gz("data/fixed.vhdx.gz")


@pytest.fixture
def dynamic_vhdx():
    yield from open_file_gz("data/dynamic.vhdx.gz")


@pytest.fixture
def differencing_vhdx():
    yield from open_file_gz("data/differencing.avhdx.gz")


@pytest.fixture
def sesparse_vmdk():
    yield from open_file_gz("data/sesparse.vmdk.gz")


@pytest.fixture
def simple_vma():
    yield from open_file_gz("data/test.vma.gz")


@pytest.fixture
def envelope():
    yield from open_file("data/local.tgz.ve")


@pytest.fixture
def keystore():
    yield from open_file("data/encryption.info", "r")


@pytest.fixture
def vgz():
    yield from open_file("data/test.vgz")
