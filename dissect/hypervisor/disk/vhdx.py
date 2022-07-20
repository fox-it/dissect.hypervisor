# References:
# - [MS-VHDX] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477

import logging
import os
from functools import lru_cache
from pathlib import Path
from uuid import UUID

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vhdx import (
    ALIGNMENT,
    BAT_REGION_GUID,
    FILE_PARAMETERS_GUID,
    LOGICAL_SECTOR_SIZE_GUID,
    MB,
    METADATA_REGION_GUID,
    PARENT_LOCATOR_GUID,
    PHYSICAL_SECTOR_SIZE_GUID,
    VHDX_PARENT_LOCATOR_GUID,
    VIRTUAL_DISK_ID_GUID,
    VIRTUAL_DISK_SIZE_GUID,
    c_vhdx,
)
from dissect.hypervisor.exceptions import InvalidSignature, InvalidVirtualDisk

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_VHDX", "CRITICAL"))


class VHDX(AlignedStream):
    """Hyper-V VHDX implementation.

    Supports fixed, dynamic and differencing VHDX files.

    Currently, differencing VHDX files must be passed as a pathlib.Path object, with
    the parent VHDX in the same directory, or the registered absolute directory.
    """

    def __init__(self, fh):
        if hasattr(fh, "read"):
            name = getattr(fh, "name", None)
            path = Path(name) if name else None
        else:
            if not isinstance(fh, Path):
                fh = Path(fh)
            path = fh
            fh = path.open("rb")

        self.fh = fh
        self.path = path

        self.file_identifier = c_vhdx.file_identifier(fh)
        if self.file_identifier.signature != b"vhdxfile":
            raise InvalidSignature(f"Invalid file identifier signature: {self.file_identifier.signature}")

        fh.seek(1 * ALIGNMENT)
        header1 = c_vhdx.header(fh)
        fh.seek(2 * ALIGNMENT)
        header2 = c_vhdx.header(fh)

        self.header = header1 if header1.sequence_number > header2.sequence_number else header2
        self.headers = [header1, header2]

        if self.header.signature != b"head":
            raise InvalidSignature(f"Invalid header signature: {self.header.signature}")

        region_table1 = RegionTable(fh, 3 * ALIGNMENT)
        region_table2 = RegionTable(fh, 4 * ALIGNMENT)

        self.region_table = region_table1
        self.region_tables = [region_table1, region_table2]

        metadata_entry = self.region_table.get(METADATA_REGION_GUID)
        self.metadata = MetadataTable(fh, metadata_entry.file_offset, metadata_entry.length)

        self.size = self.metadata.get(VIRTUAL_DISK_SIZE_GUID)
        file_parameters = self.metadata.get(FILE_PARAMETERS_GUID)
        self.block_size = file_parameters.block_size
        self.has_parent = file_parameters.has_parent
        self.sector_size = self.metadata.get(LOGICAL_SECTOR_SIZE_GUID)
        self.id = UUID(bytes_le=self.metadata.get(VIRTUAL_DISK_ID_GUID).virtual_disk_id)
        self._sectors_per_block = self.block_size // self.sector_size
        self._chunk_ratio = ((2**23) * self.sector_size) // self.block_size

        self.parent = None
        self.parent_locator = None
        if self.has_parent:
            self.parent_locator = self.metadata.get(PARENT_LOCATOR_GUID)
            if self.parent_locator.type != VHDX_PARENT_LOCATOR_GUID:
                raise ValueError(f"Unknown parent locator type: {self.parent_locator.type}")
            self.parent = open_parent(self.path.parent, self.parent_locator.entries)

        bat_entry = self.region_table.get(BAT_REGION_GUID)
        self.bat = BlockAllocationTable(self, bat_entry.file_offset)

        super().__init__(self.size)

    def read_sectors(self, sector, count):
        log.debug("VHDX::read_sectors(0x%x, 0x%x)", sector, count)
        sectors_read = []

        while count > 0:
            read_count = min(count, self._sectors_per_block)
            read_size = read_count * self.sector_size
            block, sector_in_block = divmod(sector, self._sectors_per_block)
            bat_entry = self.bat.pb(block)

            if bat_entry.state == c_vhdx.PAYLOAD_BLOCK_NOT_PRESENT:
                # The block is not present in this file
                # If we have a parent, read it from there, otherwise keep it empty
                if self.parent:
                    sectors_read.append(self.parent.read_sectors(sector, read_count))
                else:
                    sectors_read.append(b"\x00" * read_size)
            elif bat_entry.state in (c_vhdx.PAYLOAD_BLOCK_UNDEFINED, c_vhdx.PAYLOAD_BLOCK_UNMAPPED):
                # The block is not allocated at all
                # Keep it empty
                sectors_read.append(b"\x00" * read_size)
            elif bat_entry.state == c_vhdx.PAYLOAD_BLOCK_FULLY_PRESENT:
                # The block is fully present in this file
                # Read everything from this file.
                self.fh.seek((bat_entry.file_offset_mb * MB) + (sector_in_block * self.sector_size))
                sectors_read.append(self.fh.read(read_size))
            elif bat_entry.state == c_vhdx.PAYLOAD_BLOCK_PARTIALLY_PRESENT:
                # The block is only partially present in this file
                # Read the sector bitmap to know what to read from this file and what to read from the parent
                sector_bitmap_entry = self.bat.sb(block)

                # A chunk is a group of blocks, the amount of which is determined by the chunk ratio
                # The sector bitmap spans an entire chunk, so we calculate the absolute sector number
                # in the chunk we're in.
                block_in_chunk = block % self._chunk_ratio
                sector_in_chunk = (block_in_chunk * self._sectors_per_block) + sector_in_block

                byte_idx, bit_idx = divmod(sector_in_chunk, 8)
                # Seek into the bitmap to where we are relative in the cluster
                self.fh.seek((sector_bitmap_entry.file_offset_mb * MB) + byte_idx)
                # Read the bitmap for the amount of sectors we're interested in, rounded up
                sector_bitmap = self.fh.read((read_count + 8 - 1) // 8)

                # Calculate runs from the bitmap and read from the correct source
                relative_sector = 0
                for run_type, run_count in _iter_partial_runs(sector_bitmap, bit_idx, read_count):
                    if run_type == 0:
                        # Read from parent
                        sectors_read.append(self.parent.read_sectors(sector + relative_sector, run_count))
                    else:
                        # Read from this file
                        # Here we are calculating relative to the block again
                        self.fh.seek(
                            (bat_entry.file_offset_mb * MB) + ((sector_in_block + relative_sector) * self.sector_size)
                        )
                        sectors_read.append(self.fh.read(run_count * self.sector_size))

                    relative_sector += run_count

            sector += read_count
            count -= read_count

        return b"".join(sectors_read)

    def _read(self, offset, length):
        sector = offset // self.sector_size
        count = (length + self.sector_size - 1) // self.sector_size

        return self.read_sectors(sector, count)


class RegionTable:
    def __init__(self, fh, offset):
        self.fh = fh
        self.offset = offset

        fh.seek(offset)
        self.header = c_vhdx.region_table_header(fh)
        if self.header.signature != b"regi":
            raise InvalidSignature(f"Invalid region table signature: {self.header.signature}")

        self.entries = c_vhdx.region_table_entry[self.header.entry_count](fh)
        self.lookup = {UUID(bytes_le=e.guid): e for e in self.entries}

    def get(self, guid, required=True):
        data = self.lookup.get(guid)
        if not data and required:
            raise InvalidVirtualDisk(f"Missing required region: {guid}")
        return data


class BlockAllocationTable:
    def __init__(self, vhdx, offset):
        self.vhdx = vhdx
        self.offset = offset
        self.chunk_ratio = vhdx._chunk_ratio

        self._pb_count = (vhdx.size + vhdx.block_size - 1) // vhdx.block_size
        self._sb_count = (self._pb_count + self.chunk_ratio - 1) // self.chunk_ratio

        if vhdx.parent:
            self.entry_count = self._sb_count * (self.chunk_ratio + 1)
        else:
            self.entry_count = self._pb_count + ((self._pb_count - 1) // self.chunk_ratio)

    @lru_cache(4096)
    def get(self, entry):
        """Get a BAT entry."""
        if entry + 1 > self.entry_count:
            raise ValueError(f"Invalid entry for BAT lookup: {entry} (max entry is {self.entry_count - 1})")

        self.vhdx.fh.seek(self.offset + entry * 8)
        return c_vhdx.bat_entry(self.vhdx.fh)

    def pb(self, block):
        """Get a payload block entry for a given block."""
        # Calculate how many interleaved sector bitmap entries there must be for this block
        sb_entries = block // self.chunk_ratio
        return self.get(block + sb_entries)

    def sb(self, block):
        """Get a sector bitmap entry for a given block."""
        # Calculate how many interleaved sector bitmap entries there must be for this block
        num_sb = block // self.chunk_ratio
        return self.get(((num_sb + 1) * self.chunk_ratio) + num_sb)


class ParentLocator:
    def __init__(self, fh):
        self.fh = fh
        self.offset = fh.tell()
        self.header = c_vhdx.parent_locator_header(fh)
        self.type = UUID(bytes_le=self.header.locator_type)
        self._entries = c_vhdx.parent_locator_entry[self.header.key_value_count](fh)

        self.entries = {}
        for entry in self._entries:
            fh.seek(self.offset + entry.key_offset)
            key = fh.read(entry.key_length).decode("utf-16-le")
            fh.seek(self.offset + entry.value_offset)
            value = fh.read(entry.value_length).decode("utf-16-le")

            self.entries[key] = value


class MetadataTable:
    METADATA_MAP = {
        FILE_PARAMETERS_GUID: c_vhdx.file_parameters,
        VIRTUAL_DISK_SIZE_GUID: c_vhdx.virtual_disk_size,
        VIRTUAL_DISK_ID_GUID: c_vhdx.virtual_disk_id,
        LOGICAL_SECTOR_SIZE_GUID: c_vhdx.logical_sector_size,
        PHYSICAL_SECTOR_SIZE_GUID: c_vhdx.physical_sector_size,
        PARENT_LOCATOR_GUID: ParentLocator,
    }

    def __init__(self, fh, offset, length):
        self.fh = fh
        self.offset = offset
        self.length = length

        fh.seek(offset)
        self.header = c_vhdx.metadata_table_header(fh)
        if self.header.signature != b"metadata":
            raise InvalidSignature(f"Invalid metadata table signature: {self.header.signature}")

        self.entries = c_vhdx.metadata_table_entry[self.header.entry_count](fh)

        self.lookup = {}
        for entry in self.entries:
            item_id = UUID(bytes_le=entry.item_id)

            fh.seek(self.offset + entry.offset)
            value = self.METADATA_MAP[item_id](fh)
            self.lookup[item_id] = value

    def get(self, guid, required=True):
        data = self.lookup.get(guid)
        if not data and required:
            raise InvalidVirtualDisk(f"Missing required region: {guid}")
        return data


def _iter_partial_runs(bitmap, start_idx, length):
    current_type = (bitmap[0] & (1 << start_idx)) >> start_idx
    current_count = 0

    for byte in bitmap:
        if (current_type, byte) == (0, 0) or (current_type, byte) == (1, 0xFF):
            max_count = min(length, 8 - start_idx)
            current_count += max_count
            length -= max_count
            start_idx = 0
        else:
            for bit_idx in range(start_idx, min(length, 8)):
                sector_type = (byte & (1 << bit_idx)) >> bit_idx

                if sector_type == current_type:
                    current_count += 1
                else:
                    yield (current_type, current_count)
                    current_type = sector_type
                    current_count = 1

                length -= 1

    if current_count:
        yield (current_type, current_count)


def open_parent(path, locator):
    try:
        filepath = path.joinpath(locator["relative_path"].replace("\\", "/"))
        if not filepath.exists():
            filepath = path.joinpath("/" + locator["absolute_win32_path"].replace("\\", "/"))
        return VHDX(filepath)
    except Exception as e:
        raise IOError(f"Failed to open parent disk with locator {locator} from path {path}: {e}")
