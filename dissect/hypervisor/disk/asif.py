from __future__ import annotations

import plistlib
from functools import cached_property, lru_cache
from typing import Any, BinaryIO
from uuid import UUID

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_asif import c_asif
from dissect.hypervisor.exceptions import InvalidSignature


class ASIF:
    """Apple Sparse Image Format (ASIF) disk image.

    ASIF disk images are a virtual disk format introduced in macOS Tahoe. They can be used in Apple's Virtualization
    framework, as well as through Disk Utility.

    An ASIF file is pretty straight forward. There's a small header which, among some other details, contains two
    directory offsets. Each directory contains a list of tables, and each table contains a list of data and bitmap
    entries. Each data entry points to a chunk of data in the ASIF file, and each bitmap entry points to a bitmap that
    covers a group of data entries. We call the combined number of data entries plus the bitmap entry a "chunk group".

    The chunk size is defined in the header and is typically 1 MiB. The chunk size is always a multiple of the block
    size, which is also defined in the header (typically 512 bytes).

    Each directory has a version number, and the directory with the highest version number is the active directory. This
    allows for atomic updates of the directory/table data.

    The maximum virtual disk size seems to be just under 4 PiB, with a small portion at the end reserved for metadata.
    The actual size of the virtual disk is defined in the header, as well as the maximum size the disk can grow to.

    The offset to the metadata block is typically ``(4 PiB - 1 chunk)``, meaning it's within the reserved area.
    The metadata block contains a small header and a plist. The plist should contain an ``internal metadata`` and
    ``user metadata`` dictionary. Besides a "stable uuid", it's unclear what the metadata is used for or how to set it.

    Args:
        fh: File-like object containing the ASIF image.

    Resources:
        - Reversing ``diskimagescontroller``
        - https://developer.apple.com/documentation/virtualization/vzdiskimagestoragedeviceattachment/
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        self.header = c_asif.asif_header(fh)
        if self.header.header_signature != c_asif.ASIF_HEADER_SIGNATURE:
            raise InvalidSignature(
                f"Not a valid ASIF image (expected {c_asif.ASIF_HEADER_SIGNATURE:#x}, "
                f"got {self.header.header_signature:#x})"
            )

        self.guid = UUID(bytes=self.header.guid)
        self.block_size = self.header.block_size
        self.chunk_size = self.header.chunk_size
        self.size = self.header.sector_count * self.block_size
        self.max_size = self.header.max_sector_count * self.block_size

        self._blocks_per_chunk = self.chunk_size // self.block_size

        # Table entries are grouped into "chunk groups", with each group followed by a bitmap that covers that group
        # We need to calculate how large a chunk group is, and how many chunk groups we can fit in a table

        # A bitmap uses 2 bits per block (not chunk), so a single byte in the bitmap covers 4 blocks
        # A bitmap is 1 chunk large in bytes, so a single bitmap can cover 4 * chunk_size blocks
        # A bitmap covers one chunk group, so the number of blocks per chunk group is equal to the bitmap coverage
        num_blocks_per_group = 4 * self.chunk_size

        # Derive the number of chunks per group from this
        self._num_chunks_per_group = max(1, num_blocks_per_group // self._blocks_per_chunk)

        # A table is 1 chunk large, so we start with the number of entries (uint64) that fit inside a single chunk
        num_words_per_chunk = self.chunk_size // 8
        # A chunk group has one entry for each chunk, plus one entry for the bitmap
        num_entries_per_group = self._num_chunks_per_group + 1

        num_groups_per_table, num_remaining = divmod(num_words_per_chunk, num_entries_per_group)
        # The number of total entries in a table, including both chunk and bitmap entries
        self._num_table_entries = num_words_per_chunk - num_remaining

        # Calculate the size in bytes of data covered by a single table
        num_chunk_entries_per_table = self._num_table_entries - num_groups_per_table
        self._size_per_table = num_chunk_entries_per_table * self.chunk_size

        # Calculate the maximum size of the virtual disk, and the number of tables needed to cover that size
        max_size = self.block_size * self.header.max_sector_count
        self._num_tables = (self._size_per_table + max_size - 1) // self._size_per_table

        self.directories = sorted(
            (Directory(self, offset) for offset in self.header.directory_offsets),
            key=lambda d: d.version,
            reverse=True,
        )
        self.active_directory = self.directories[0]

        self.metadata_header = None
        self.metadata: dict[str, Any] = {}
        if self.header.metadata_chunk:
            # Open the file in reserved mode to read from the reserved area
            with self.open(reserved=True) as disk:
                metadata_offset = self.header.metadata_chunk * self.chunk_size
                disk.seek(metadata_offset)
                self.metadata_header = c_asif.asif_meta_header(disk)

                if self.metadata_header.header_signature != c_asif.ASIF_META_HEADER_SIGNATURE:
                    raise InvalidSignature(
                        f"Invalid a ASIF metadata header (expected {c_asif.ASIF_META_HEADER_SIGNATURE:#x}, "
                        f"got {self.metadata_header.header_signature:#x})"
                    )

                disk.seek(metadata_offset + self.metadata_header.header_size)
                self.metadata = plistlib.loads(disk.read(self.metadata_header.data_size).strip(b"\x00"))

    @property
    def internal_metadata(self) -> dict[str, Any]:
        """Get internal metadata from the ASIF image.

        Returns:
            A dictionary containing the internal metadata.
        """
        return self.metadata.get("internal metadata", {})

    @property
    def user_metadata(self) -> dict[str, Any]:
        """Get user metadata from the ASIF image.

        Returns:
            A dictionary containing the user metadata.
        """
        return self.metadata.get("user metadata", {})

    def open(self, reserved: bool = False) -> DataStream:
        """Open a stream to read the ASIF image data.

        Args:
            reserved: Whether to allow reading into the reserved area of the ASIF image.

        Returns:
            A stream-like object that can be used to read the image data.
        """
        return DataStream(self, reserved)


class Directory:
    """ASIF Directory.

    A directory has a version (``uint64``) followed by a list of table entries (``uint64[]``).
    The version number is used to determine the active directory, with the highest version being the active one.
    Each table entry is a chunk number and points to a table in the ASIF image.

    Args:
        asif: The ASIF image this directory belongs to.
        offset: Offset of the directory in the ASIF image.
    """

    def __init__(self, asif: ASIF, offset: int):
        self.asif = asif
        self.offset = offset

        self.asif.fh.seek(offset)
        self.version = c_asif.uint64(self.asif.fh)

        self.table = lru_cache(128)(self.table)

    def __repr__(self) -> str:
        return f"<Directory offset={self.offset:#x} version={self.version}>"

    @cached_property
    def entries(self) -> list[int]:
        """List of table entries in the directory."""
        # Seek over the version
        self.asif.fh.seek(self.offset + 8)
        return c_asif.uint64[self.asif._num_tables](self.asif.fh)

    def table(self, index: int) -> Table | None:
        """Get a table from the directory.

        Args:
            index: Index of the table in the directory.
        """
        if index >= self.asif._num_tables:
            raise IndexError("Table index out of range")

        if (entry := self.entries[index]) == 0:
            return None

        return Table(self.asif, index, entry * self.asif.chunk_size)


class Table:
    """ASIF Table.

    A table contains a list of data entries (``uint64[]``). Each data entry is a chunk number and points to a chunk of
    data in the ASIF image. Each table covers a fixed amount of data in the virtual disk.

    Data entries have 55 bits usable for the chunk number and 9 bits for flags, 7 of which are reserved.

    .. rubric :: Encoding
    .. code-block:: c

        0b00000000 01111111 11111111 11111111 11111111 11111111 11111111 11111111  (chunk number)
        0b00111111 10000000 00000000 00000000 00000000 00000000 00000000 00000000  (reserved)
        0b11000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (flags)

    The following flags are known for data entries:

    .. rubric :: Flags
    .. code-block:: c

        0b00  (uninitialized)
        0b01  (fully initialized)
        0b10  (unmapped)
        0b11  (has bitmap)

    Args:
        asif: The ASIF image this table belongs to.
        index: Index of the table in the directory.
        offset: Offset of the table in the ASIF image.
    """

    def __init__(self, asif: ASIF, index: int, offset: int):
        self.asif = asif
        self.index = index
        self.offset = offset

        self.virtual_offset = index * self.asif._size_per_table

    def __repr__(self) -> str:
        return f"<Table index={self.index} offset={self.offset:#x} virtual_offset={self.virtual_offset:#x}>"

    @cached_property
    def entries(self) -> list[int]:
        """List of data entries in the table."""
        self.asif.fh.seek(self.offset)
        return c_asif.uint64[self.asif._num_table_entries](self.asif.fh)


class DataStream(AlignedStream):
    """Stream to read data from an ASIF image.

    Args:
        asif: The ASIF image to read from.
        reserved: Whether to allow reading into the reserved area of the ASIF image.
    """

    def __init__(self, asif: ASIF, reserved: bool = False):
        super().__init__(asif.max_size if reserved else asif.size, align=asif.chunk_size)
        self.asif = asif
        self.reserved = reserved
        self.directory = asif.active_directory

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        while length:
            table_index, offset_in_table = divmod(offset, self.asif._size_per_table)
            if (table := self.directory.table(table_index)) is None:
                read_length = min(length, self.asif._size_per_table - offset_in_table)
                result.append(b"\x00" * read_length)
            else:
                # Calculate the relative chunk index within the table
                relative_block_index = offset_in_table // self.asif.block_size
                relative_chunk_index = relative_block_index // self.asif._blocks_per_chunk

                # Calculate the chunk group
                chunk_group = relative_chunk_index // self.asif._num_chunks_per_group
                # Each chunk group has a bitmap entry, so we need to account for that in the entry index
                entry_index = relative_chunk_index + chunk_group

                read_length = min(length, self.asif.chunk_size)

                status = table.entries[entry_index] >> 62
                chunk = table.entries[entry_index] & 0x7FFFFFFFFFFFFF

                if status in (0b00, 0b10) and chunk == 0:
                    # uninitialized or unmapped
                    result.append(b"\x00" * read_length)
                elif status == 0b01:
                    # fully initialized
                    self.asif.fh.seek(chunk * self.asif.chunk_size)
                    result.append(self.asif.fh.read(read_length))
                elif status == 0b11:
                    # has bitmap

                    # Calculate which entry has the bitmap for this chunk group
                    bitmap_entry_index = (
                        chunk_group * (self.asif._num_chunks_per_group + 1) + self.asif._num_chunks_per_group
                    )

                    # Read the bitmap
                    bitmap_chunk = table.entries[bitmap_entry_index] & 0x7FFFFFFFFFFFFF
                    self.asif.fh.seek(bitmap_chunk * self.asif.chunk_size)
                    bitmap = self.asif.fh.read(self.asif.chunk_size)

                    # Calculate the offset of the chunk within the chunk group
                    chunk_offset_in_group = relative_chunk_index % self.asif._num_chunks_per_group
                    # Calculate the offset of the block within the chunk
                    block_offset_in_chunk = relative_block_index % self.asif._blocks_per_chunk
                    # Calculate the offset of the block within the bitmap
                    block_offset_in_bitmap = chunk_offset_in_group * self.asif._blocks_per_chunk + block_offset_in_chunk

                    for i in range(read_length // self.asif.block_size):
                        # Bitmap entries are LSB first, with 2 bits per block
                        block_index = block_offset_in_bitmap + i
                        byte_index, bit_index = divmod(block_index, 4)
                        bitmap_byte = bitmap[byte_index]
                        block_status = (bitmap_byte >> (bit_index * 2)) & 0b11

                        if block_status == 0b00:
                            # uninitialized
                            result.append(b"\x00" * self.asif.block_size)
                        elif block_status == 0b01:
                            # fully initialized
                            self.asif.fh.seek((chunk * self.asif.chunk_size) + (i * self.asif.block_size))
                            result.append(self.asif.fh.read(self.asif.block_size))
                        elif block_status == 0b10:
                            # unmapped
                            result.append(b"\x00" * self.asif.block_size)
                        elif block_status == 0b11:
                            raise ValueError(f"Invalid bitmap entry {block_status:#b} at offset {offset:#x}")
                else:
                    raise ValueError(f"Unknown status {status:#x} at offset {offset:#x}")

            offset += read_length
            length -= read_length

        return b"".join(result)
