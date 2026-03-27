from __future__ import annotations


class Error(Exception):
    pass


class InvalidHeaderError(Error):
    pass


class InvalidSignature(Error):
    pass


class InvalidVirtualDisk(Error):
    pass
