# References:
# - /bin/vmtar

from __future__ import annotations

import struct
import tarfile


class VisorTarInfo(tarfile.TarInfo):
    """Implements TarInfo for use with Visor Tar files (vmtar).

    The main difference is that file data is located at the end of the tar file, on
    an offset specified in the header.
    """

    is_visor: bool
    offset_data: int | None
    textPgs: int | None
    fixUpPgs: int | None

    @classmethod
    def frombuf(cls, buf: bytes, encoding: str, errors: str) -> VisorTarInfo:
        obj = super().frombuf(buf, encoding, errors)

        obj.is_visor = buf[257:264] == b"visor  "
        if obj.is_visor:
            obj.offset_data = struct.unpack("<I", buf[496:500])[0]
            obj.textPgs = struct.unpack("<I", buf[504:508])[0]
            obj.fixUpPgs = struct.unpack("<I", buf[508:512])[0]
        else:
            obj.offset_data = None
            obj.textPgs = None
            obj.fixUpPgs = None

        return obj

    def _proc_member(self, tarfile: tarfile.TarFile) -> VisorTarInfo | tarfile.TarInfo:
        if self.is_visor and self.offset_data:
            # Don't advance the offset with the filesize
            tarfile.offset = tarfile.fileobj.tell()

            # Patch the TarInfo object with saved global
            # header information.
            self._apply_pax_info(tarfile.pax_headers, tarfile.encoding, tarfile.errors)

            return self

        return super()._proc_member(tarfile)


def VisorTarFile(*args, **kwargs) -> tarfile.TarFile:
    return tarfile.TarFile(*args, **kwargs, tarinfo=VisorTarInfo)


def open(*args, **kwargs) -> tarfile.TarFile:
    return tarfile.open(*args, **kwargs, tarinfo=VisorTarInfo)
