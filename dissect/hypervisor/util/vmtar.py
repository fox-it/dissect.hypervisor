# References:
# - /bin/vmtar

import struct
import tarfile


class VisorTarInfo(tarfile.TarInfo):
    """Implements TarInfo for use with Visor Tar files (vmtar).

    The main difference is that file data is located at the end of the tar file, on
    an offset specified in the header.
    """

    @classmethod
    def frombuf(cls, buf, encoding, errors):
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

    def _proc_member(self, tarfile):
        if self.is_visor and self.offset_data:
            # Don't advance the offset with the filesize
            tarfile.offset = tarfile.fileobj.tell()

            # Patch the TarInfo object with saved global
            # header information.
            self._apply_pax_info(tarfile.pax_headers, tarfile.encoding, tarfile.errors)

            return self
        else:
            return super()._proc_member(tarfile)


def VisorTarFile(*args, **kwargs):
    return tarfile.TarFile(tarinfo=VisorTarInfo, *args, **kwargs)


def open(*args, **kwargs):
    return tarfile.open(tarinfo=VisorTarInfo, *args, **kwargs)
