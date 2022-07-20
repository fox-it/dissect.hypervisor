import io
import struct
from functools import lru_cache

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vhd import c_vhd, SECTOR_SIZE


def read_footer(fh):
    fh.seek(-512, io.SEEK_END)
    footer = c_vhd.footer(fh)
    if not footer.features & 0x00000002:
        # Versions previous to Microsoft Virtual PC 2004 can have a 511 byte footer
        fh.seek(-511, io.SEEK_END)
        footer = c_vhd.footer(fh)
    return footer


class VHD(AlignedStream):
    # Note: split VHD files are currently unsupported.
    def __init__(self, fh):
        self.fh = fh

        footer = read_footer(fh)
        if footer.data_offset == 0xFFFFFFFFFFFFFFFF:
            # Fixed size, data starts at 0
            self.disk = FixedDisk(fh, footer)
        else:
            self.disk = DynamicDisk(fh, footer)

        super().__init__(self.disk.size)

    def _read(self, offset, length):
        sector = offset // SECTOR_SIZE
        count = (length + SECTOR_SIZE - 1) // SECTOR_SIZE

        return self.disk.read_sectors(sector, count)


class Disk:
    def __init__(self, fh, footer=None):
        self.fh = fh
        self.footer = footer if footer else read_footer(fh)
        self.size = self.footer.current_size
        self.block_size = None

    def read_sectors(self, sector, count):
        raise NotImplementedError()


class FixedDisk(Disk):
    def read_sectors(self, sector, count):
        self.fh.seek(sector * SECTOR_SIZE)
        return self.fh.read(count * SECTOR_SIZE)


class DynamicDisk(Disk):
    def __init__(self, fh, footer=None):
        super().__init__(fh, footer)
        fh.seek(self.footer.data_offset)
        self.header = c_vhd.dynamic_header(fh)
        self.bat = BlockAllocationTable(fh, self.header.table_offset, self.header.max_table_entries)

        self._sectors_per_block = self.header.block_size // SECTOR_SIZE
        # Sector bitmaps are padded to SECTOR_SIZE boundaries
        # Save bitmap size in sectors
        self._sector_bitmap_size = ((self._sectors_per_block // 8) + SECTOR_SIZE - 1) // SECTOR_SIZE

    def read_sectors(self, sector, count):
        sectors_read = []
        while count > 0:
            read_count = min(count, self._sectors_per_block)

            block, remaining = divmod(sector, self._sectors_per_block)
            sector_offset = self.bat[block]

            if sector_offset:
                self.fh.seek((sector_offset + self._sector_bitmap_size + remaining) * SECTOR_SIZE)
                sectors_read.append(self.fh.read(read_count * SECTOR_SIZE))
            else:
                # Sparse
                sectors_read.append((b"\x00" * SECTOR_SIZE) * read_count)

            sector += read_count
            count -= read_count

        return b"".join(sectors_read)


class BlockAllocationTable:
    """Implementation of the BAT.

    Entries are uint32 sector offsets to blocks in the file.
    """

    ENTRY = struct.Struct(">I")

    def __init__(self, fh, offset, max_entries):
        self.fh = fh
        self.offset = offset
        self.max_entries = max_entries

    @lru_cache(4096)
    def get(self, block):
        # This could be improved by caching the entire BAT (or chunks if too large)
        if block + 1 > self.max_entries:
            raise ValueError("Invalid block {} (max block is {})".format(block, self.max_entries - 1))

        self.fh.seek(self.offset + block * 4)
        sector_offset = self.ENTRY.unpack(self.fh.read(4))[0]
        if sector_offset == 0xFFFFFFFF:
            sector_offset = None
        return sector_offset

    def __getitem__(self, block):
        return self.get(block)
