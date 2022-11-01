import array

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vdi import SPARSE, UNALLOCATED, VDI_SIGNATURE, c_vdi
from dissect.hypervisor.exceptions import Error


class VDI(AlignedStream):
    def __init__(self, fh, parent=None):
        self.fh = fh
        self.parent = parent
        self.header = c_vdi.HeaderDescriptor(fh)

        if self.header.Signature != VDI_SIGNATURE:
            raise Error("Not a VDI header")

        fh.seek(-1, 2)
        self.file_size = fh.tell()

        self.fh.seek(self.header.BlocksOffset)

        mapbuf = self.fh.read(4 * self.header.BlocksInHDD)
        self.map = array.array("i")
        try:
            self.map.frombytes(mapbuf)
        except AttributeError:
            self.map.fromstring(mapbuf)

        self.data_offset = self.header.DataOffset
        self.block_size = self.header.BlockSize
        self.sector_size = self.header.SectorSize
        super().__init__(size=self.header.DiskSize)

    def _read(self, offset, length):
        block_idx, block_offset = divmod(offset, self.block_size)

        bytes_read = []
        while length > 0:
            read_len = min(length, max(length, self.block_size))

            block = self.map[block_idx]

            if block == UNALLOCATED:
                if self.parent:
                    bytes_read.append(self.parent._read(offset, read_len))
                else:
                    bytes_read.append(b"\x00" * read_len)
            elif block == SPARSE:
                bytes_read.append(b"\x00" * read_len)
            else:
                self.fh.seek(self.data_offset + (block * self.block_size) + block_offset)
                bytes_read.append(self.fh.read(read_len))

            offset += read_len
            length -= read_len
            block_idx += 1

        return b"".join(bytes_read)
