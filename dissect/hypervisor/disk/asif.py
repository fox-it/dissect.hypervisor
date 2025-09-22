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
    directory offsets. Each directory contains a list of tables, which in turn contain a list of data entries. Each data
    entry points to a chunk of data in the ASIF file. The chunk size is defined in the header and is typically 1 MiB.
    The chunk size is always a multiple of the block size, which is also defined in the header (typically 512 bytes).
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

        # The following math is taken from the assembly with some creative variable naming
        # It's possible that some of this can be simplified or the names improved
        self._blocks_per_chunk = self.chunk_size // self.block_size

        # This check doesn't really make sense, but keep it in for now
        reserved_size = 4 * self.chunk_size
        self._num_reserved_table_entries = (
            1 if reserved_size < self._blocks_per_chunk else reserved_size // self._blocks_per_chunk
        )

        self._max_table_entries = self.chunk_size >> 3
        self._num_table_entries = self._max_table_entries - (
            self._max_table_entries % (self._num_reserved_table_entries + 1)
        )
        self._num_reserved_directory_entries = (self._num_reserved_table_entries + self._num_table_entries) // (
            self._num_reserved_table_entries + 1
        )
        self._num_usable_entries = self._num_table_entries - self._num_reserved_directory_entries
        # This is the size in bytes of data covered by a single table
        self._size_per_table = self._num_usable_entries * self.chunk_size

        max_size = self.block_size * self.header.max_sector_count
        self._num_directory_entries = (self._size_per_table + max_size - 1) // self._size_per_table

        self._aligned_table_size = (
            (self.block_size + 8 * self._num_table_entries - 1) // self.block_size * self.block_size
        )

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
        return c_asif.uint64[self.asif._num_directory_entries](self.asif.fh)

    def table(self, index: int) -> Table:
        """Get a table from the directory.

        Args:
            index: Index of the table in the directory.
        """
        if index >= self.asif._num_directory_entries:
            raise IndexError("Table index out of range")
        return Table(self, index)


class Table:
    """ASIF Table.

    A table contains a list of data entries (``uint64[]``). Each data entry is a chunk number and points to a chunk of
    data in the ASIF image. Each table covers a fixed amount of data in the virtual disk.

    Data entries have 55 bits usable for the chunk number and 9 bits reserved for flags.

    .. rubric :: Encoding
    .. code-block:: c

        0b00000000 01111111 11111111 11111111 11111111 11111111 11111111 11111111  (chunk number)
        0b00111111 10000000 00000000 00000000 00000000 00000000 00000000 00000000  (reserved)
        0b01000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (entry dirty)
        0b10000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000  (content dirty)

    Args:
        directory: The directory this table belongs to.
        index: Index of the table in the directory.
    """

    def __init__(self, directory: Directory, index: int):
        self.asif = directory.asif
        self.directory = directory
        self.index = index

        self.offset = self.directory.entries[index] * self.asif.chunk_size
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
            table = self.directory.table(offset // self.asif._size_per_table)
            relative_block_index = (offset // self.asif.block_size) - (table.virtual_offset // self.asif.block_size)
            data_idx = (
                relative_block_index // self.asif._blocks_per_chunk
                + relative_block_index // self.asif._blocks_per_chunk * self.asif._num_reserved_table_entries
            ) // self.asif._num_reserved_table_entries

            # 0x8000000000000000 = content dirty bit
            # 0x4000000000000000 = entry dirty bit
            # 0x3F80000000000000 = reserved bits
            chunk = table.entries[data_idx] & 0x7FFFFFFFFFFFFF
            raw_offset = chunk * self.asif.chunk_size

            read_length = min(length, self.asif.chunk_size)
            if chunk == 0:
                result.append(b"\x00" * read_length)
            else:
                self.asif.fh.seek(raw_offset)
                result.append(self.asif.fh.read(read_length))

            offset += read_length
            length -= read_length

        return b"".join(result)
