# References:
# - /bin/vmtar

from __future__ import annotations

import struct
import tarfile
from io import BytesIO
from typing import BinaryIO, Final


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


class VisorTarFile(tarfile.TarFile):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs, tarinfo=VisorTarInfo)

    @classmethod
    def visoropen(cls, name: str, mode: str = "r", fileobj: BinaryIO | None = None, **kwargs) -> VisorTarFile:
        """Open a visor tar file for reading. Supports gzip and lzma compression."""
        if mode not in ("r",):
            raise tarfile.TarError("visor currently only supports read mode")

        try:
            from gzip import GzipFile
        except ImportError:
            raise tarfile.CompressionError("gzip module is not available") from None

        try:
            from lzma import LZMAError, LZMAFile
        except ImportError:
            raise tarfile.CompressionError("lzma module is not available") from None

        compressed = False

        try:
            t = cls.taropen(name, mode, fileobj, **kwargs)
        except Exception:
            try:
                fileobj = GzipFile(name, mode + "b", fileobj=fileobj)
            except OSError as e:
                if fileobj is not None and mode == "r":
                    raise tarfile.ReadError("not a visor file") from e
                raise

            try:
                t = cls.taropen(name, mode, fileobj, **kwargs)
            except Exception:
                fileobj.seek(0)
                fileobj = LZMAFile(fileobj or name, mode)  # noqa: SIM115

                try:
                    t = cls.taropen(name, mode, fileobj, **kwargs)
                except (LZMAError, EOFError, OSError) as e:
                    fileobj.close()
                    if mode == "r":
                        raise tarfile.ReadError("not a visor file") from e
                    raise
                except:
                    fileobj.close()
                    raise

            compressed = True

        # If we get here, we have a valid visor tar file
        if fileobj is not None and compressed:
            # Just read the entire file into memory, it's probably small
            fileobj.seek(0)
            fileobj = BytesIO(fileobj.read())

        t = cls.taropen(name, mode, fileobj, **kwargs)

        t._extfileobj = False
        return t

    # Only allow opening visor tar files
    OPEN_METH: Final[dict[str, str]] = {"visor": "visoropen"}


open = VisorTarFile.open

is_tarfile = type(tarfile.is_tarfile)(tarfile.is_tarfile.__code__, tarfile.is_tarfile.__globals__ | {"open": open})
