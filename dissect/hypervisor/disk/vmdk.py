from __future__ import annotations

import io
import logging
import os
import re
import zlib
from bisect import bisect_right
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vmdk import (
    COWD_MAGIC,
    SESPARSE_MAGIC,
    SPARSE_MAGIC,
    c_vmdk,
)

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_VMDK", "CRITICAL"))


SECTOR_SIZE = 512


class VMDK:
    """VMware Virtual Machine Disk (VMDK) implementation.

    In most cases, parent disk lookup will be done automatically when provided with a ``Path`` object.
    Sometimes you may need to provide the parent disk manually (e.g. VirtualBox snapshots disks).

    Args:
        fh: File-like object or path for the VMDK file.
        parent: Optional file-like object for the parent disk.
    """

    def __init__(self, fh: BinaryIO | Path, parent: BinaryIO | VMDK | None = None):
        self.fh = fh
        self.parent = parent
        self.descriptor: DiskDescriptor | None = None
        self.extents: list[Extent] = []
        self._extents_offsets: list[int] = []

        opened_fh = False
        if isinstance(fh, Path):
            path = fh
            fh = path.open("rb")
            opened_fh = True
        else:
            path = None

        fh.seek(0)
        if fh.read(4) == b"# Di":
            if path is None:
                # Try to get the path from the file handle if possible
                name = getattr(fh, "name", None)
                path = Path(name) if name else None

            if path is None:
                # If we don't have a path, we can't open the linked extents
                raise TypeError("Providing a path is required to read VMDK descriptor files")

            # Try reading the disk files from this descriptor
            # Otherwise we assume that the other file handles are the appropriate disks
            fh.seek(0)
            self.descriptor = DiskDescriptor(fh.read().decode())
            if opened_fh:
                # Clean up the file handle if we opened it ourselves
                fh.close()

            # The descriptor file determines the parent
            if self.parent is None and self.descriptor.attributes["parentCID"] != "ffffffff":
                self.parent = open_parent(path.parent, self.descriptor.attributes["parentFileNameHint"])

            # Open all extents listed in the descriptor
            for extent_descriptor in self.descriptor.extents:
                extent_path = path.with_name(extent_descriptor.filename)
                extent = Extent.from_fh(extent_path.open("rb"), extent_path)

                self.extents.append(extent)
        else:
            # Single file VMDK
            extent = Extent.from_fh(fh, path)

            # The single file VMDK may have a parent in the embedded descriptor
            if extent.descriptor and extent.descriptor.attributes["parentCID"] != "ffffffff":
                self.parent = open_parent(path.parent, extent.descriptor.attributes["parentFileNameHint"])

            self.extents.append(extent)

        # Make a lookup table of extent offsets and calculate total size
        offset = 0
        for extent in self.extents:
            offset += extent.size
            self._extents_offsets.append(offset)

        self.size = offset

    def __repr__(self) -> str:
        return f"<VMDK size={self.size} extents={len(self.extents)} parent={self.parent is not None}>"

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def open(self) -> ExtentStream:
        """Open a stream to read the VMDK file."""
        return ExtentStream(self)

    def close(self) -> None:
        """Close the VMDK file and any associated resources we opened."""
        for extent in self.extents:
            extent.close()


class ExtentStream(AlignedStream):
    def __init__(self, vmdk: VMDK):
        self.vmdk = vmdk
        self.parent = vmdk.parent.open() if isinstance(vmdk.parent, VMDK) else vmdk.parent

        self.extents = vmdk.extents
        self._offsets = vmdk._extents_offsets

        # Try to determine optimal alignment from the grain size of the first sparse extent
        # This should reduce the amount of slicing we need to do when reading
        align = SECTOR_SIZE
        for extent in self.extents:
            if isinstance(extent, SparseExtent):
                align = extent._grain_size
                break

        super().__init__(vmdk.size, align=align)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        while length > 0:
            idx = bisect_right(self._offsets, offset)
            if idx > len(self._offsets) - 1:
                break

            extent = self.extents[idx]
            extent_offset = 0 if idx == 0 else self._offsets[idx - 1]
            offset_in_extent = offset - extent_offset
            read_size = min(length, extent.size - offset_in_extent)

            if isinstance(extent, RawExtent):
                extent.fh.seek(extent.offset + offset_in_extent)
                result.append(extent.fh.read(read_size))
            elif isinstance(extent, SparseExtent):
                grain_idx, offset_in_grain = divmod(offset_in_extent, extent._grain_size)
                grain_size = extent._last_grain_size if grain_idx == extent._last_grain_index else extent._grain_size

                if offset_in_grain >= grain_size:
                    break

                read_size = min(read_size, grain_size - offset_in_grain)

                grain = extent._grain(grain_idx)
                # Unallocated grain
                if grain == 0:
                    if self.parent is not None:
                        self.parent.seek(offset)
                        buf = self.parent.read(read_size)
                    else:
                        buf = b"\x00" * read_size

                # Sparse grain
                elif grain == 1:
                    buf = b"\x00" * read_size

                # Allocated grain
                else:
                    buf = extent._read_grain(grain)[offset_in_grain : offset_in_grain + read_size]

                result.append(buf)

            offset += read_size
            length -= read_size

        return b"".join(result)


class Extent:
    """Base class for VMDK extents.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
        size: Size of the extent in bytes.
    """

    def __init__(self, fh: BinaryIO, path: Path | None, size: int):
        self.fh = fh
        self.path = path
        self.size = size

    def __repr__(self) -> str:
        return f"<Extent size={self.size} path={self.path}>"

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    @cached_property
    def descriptor(self) -> DiskDescriptor | None:
        """The disk descriptor if available."""
        return None

    @classmethod
    def from_fh(
        cls,
        fh: BinaryIO,
        path: Path | None,
        size: int | None = None,
        offset: int | None = None,
    ) -> RawExtent | HostedSparseExtent | SESparseExtent | COWDisk:
        """Create an extent from a file-like object.

        Args:
            fh: File-like object for the extent.
            path: Optional path for the extent.
            size: Optional size hint of the extent in bytes.
            offset: Optional offset of the extent in bytes.
        """
        fh.seek(0)
        magic = fh.read(4)
        fh.seek(0)

        if magic == SPARSE_MAGIC:
            return HostedSparseExtent(fh, path)
        if magic == SESPARSE_MAGIC:
            return SESparseExtent(fh, path)
        if magic == COWD_MAGIC:
            return COWDisk(fh, path)

        return RawExtent(fh, path, size, offset)

    def close(self) -> None:
        """Close the extent and any associated resources we opened."""
        if self.path is not None:
            self.fh.close()


class RawExtent(Extent):
    """Raw extent implementation.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
        size: Optional size of the extent in bytes. If not provided, it will be determined from the file size.
        offset: Optional offset of the extent in bytes in the source file.
    """

    def __init__(self, fh: BinaryIO, path: Path | None, size: int | None = None, offset: int | None = None):
        self.offset = offset or 0

        if size is None:
            fh.seek(0, io.SEEK_END)
            size = fh.tell() - self.offset
            fh.seek(0)

        super().__init__(fh, path, size)


class SparseExtent(Extent):
    """Base class for sparse extents.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
    """

    def __init__(self, fh: BinaryIO, path: Path | None):
        super().__init__(fh, path, self._capacity)
        self._last_grain_index, self._last_grain_size = divmod(self._capacity, self._grain_size)

        self._gt = lru_cache(128)(self._gt)

    @cached_property
    def _capacity(self) -> int:
        """The extent capacity in bytes."""
        raise NotImplementedError

    @cached_property
    def _grain_size(self) -> int:
        """The grain size in bytes."""
        raise NotImplementedError

    @cached_property
    def _num_gte(self) -> int:
        """The total number of grain table entries."""
        return self._last_grain_index + (1 if self._last_grain_size > 0 else 0)

    @cached_property
    def _num_gte_per_gt(self) -> int:
        """The number of grain table entries per grain table."""
        raise NotImplementedError

    @cached_property
    def _gd(self) -> list[int]:
        """The grain directory."""
        raise NotImplementedError

    def _gt(self, idx: int) -> list[int] | None:
        """Get the grain table at the specified index.

        Args:
            idx: The grain table index.
        """
        raise NotImplementedError

    def _grain(self, idx: int) -> int:
        """Get the grain number (sector) for the specified grain index.

        Args:
            idx: The grain index.
        """
        table, entry = divmod(idx, self._num_gte_per_gt)
        if (gt := self._gt(table)) is None:
            return 0
        return gt[entry]

    def _read_grain(self, grain: int) -> bytes:
        """Read the specified grain.

        Args:
            grain: The grain number.
        """
        self.fh.seek(grain * SECTOR_SIZE)
        return self.fh.read(self._grain_size)


class HostedSparseExtent(SparseExtent):
    """Hosted sparse extent implementation.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
    """

    def __init__(self, fh: BinaryIO, path: Path | None):
        fh.seek(0)
        self.header = c_vmdk.SparseExtentHeader(fh)
        if self.header.gdOffset == c_vmdk.SPARSE_GD_AT_END:
            # Sparse extents can have a footer at the end of the file
            # TODO: find test data for this
            fh.seek(-3 * SECTOR_SIZE, io.SEEK_END)
            if (marker := c_vmdk.SparseMetaDataMarker(fh)).size == 0 and marker.type == c_vmdk.GRAIN_MARKER_FOOTER:
                self.header = c_vmdk.SparseExtentHeader(fh)

        super().__init__(fh, path)

    @cached_property
    def _capacity(self) -> int:
        return self.header.capacity * SECTOR_SIZE

    @cached_property
    def _grain_size(self) -> int:
        return self.header.grainSize * SECTOR_SIZE

    @cached_property
    def _num_gte_per_gt(self) -> int:
        return self.header.numGTEsPerGT

    @cached_property
    def _gd(self) -> list[int]:
        num_gt = (self._num_gte + self._num_gte_per_gt - 1) // self._num_gte_per_gt
        self.fh.seek(self.header.gdOffset * SECTOR_SIZE)
        return c_vmdk.uint32[num_gt](self.fh)

    def _gt(self, idx: int) -> list[int] | None:
        if (offset := self._gd[idx]) == 0:
            return None

        self.fh.seek(offset * SECTOR_SIZE)
        return c_vmdk.uint32[self._num_gte_per_gt](self.fh)

    @cached_property
    def descriptor(self) -> DiskDescriptor | None:
        if self.header.descriptorSize > 0:
            self.fh.seek(self.header.descriptorOffset * SECTOR_SIZE)
            buf = self.fh.read(self.header.descriptorSize * SECTOR_SIZE)
            return DiskDescriptor(buf.split(b"\x00", 1)[0].decode())
        return None

    def _read_grain(self, grain: int) -> bytes:
        buf = super()._read_grain(grain)
        if self.header.flags & c_vmdk.SPARSEFLAG_COMPRESSED:
            if self.header.flags & c_vmdk.SPARSEFLAG_EMBEDDED_LBA:
                header_size = 12
                header = c_vmdk.SparseGrainLBAHeader(buf)
                compressed_size = header.cmpSize
            else:
                header_size = 4
                compressed_size = c_vmdk.uint32(buf)

            buf = zlib.decompress(buf[header_size : header_size + compressed_size])

        return buf


class SESparseExtent(SparseExtent):
    """SESparse extent implementation.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
    """

    def __init__(self, fh: BinaryIO, path: Path | None):
        fh.seek(0)
        self.header = c_vmdk.SESparseConstHeader(fh)

        super().__init__(fh, path)

    @cached_property
    def _capacity(self) -> int:
        return self.header.capacity * SECTOR_SIZE

    @cached_property
    def _grain_size(self) -> int:
        return self.header.grainSize * SECTOR_SIZE

    @cached_property
    def _num_gte_per_gt(self) -> int:
        return (self.header.grainTableSize * SECTOR_SIZE) // 8

    @cached_property
    def _gd(self) -> list[int]:
        num_gt = (self.header.grainDirectory.size * SECTOR_SIZE) // 8
        self.fh.seek(self.header.grainDirectory.offset * SECTOR_SIZE)
        return c_vmdk.uint64[num_gt](self.fh)

    def _gt(self, idx: int) -> list[int] | None:
        offset = self._gd[idx]

        # qemu/block/vmdk.c:
        # Top most nibble is 0x1 if grain table is allocated.
        # strict check - top most 4 bytes must be 0x10000000 since max
        # supported size is 64TB for disk - so no more than 64TB / 16MB
        # grain directories which is smaller than uint32,
        # where 16MB is the only supported default grain table coverage.
        if offset == 0 or offset & 0xFFFFFFFF00000000 != 0x1000000000000000:
            return None

        offset &= 0x00000000FFFFFFFF
        self.fh.seek((self.header.grainTables.offset * SECTOR_SIZE) + (offset * (self._num_gte_per_gt * 8)))
        return c_vmdk.uint64[self._num_gte_per_gt](self.fh)

    def _grain(self, idx: int) -> int:
        # SESparse uses a different method of specifying unallocated/sparse/allocated grains
        # However, we can re-use the normal sparse logic of returning 0 for unallocated, 1 for
        # sparse and >1 for allocated grains, since a grain of 0 or 1 isn't possible in SESparse.
        table, entry = divmod(idx, self._num_gte_per_gt)
        if (gt := self._gt(table)) is None:
            return 0
        grain = gt[entry]

        grain_type = grain & c_vmdk.SESPARSE_GRAIN_TYPE_MASK
        if grain_type in (c_vmdk.SESPARSE_GRAIN_TYPE_UNALLOCATED, c_vmdk.SESPARSE_GRAIN_TYPE_FALLTHROUGH):
            # Unallocated or scsi unmapped, fallthrough
            return 0
        if grain_type == c_vmdk.SESPARSE_GRAIN_TYPE_ZERO:
            # Sparse, zero grain
            return 1
        if grain_type == c_vmdk.SESPARSE_GRAIN_TYPE_ALLOCATED:
            # Allocated
            cluster_sector_hi = (grain & 0x0FFF000000000000) >> 48
            cluster_sector_lo = (grain & 0x0000FFFFFFFFFFFF) << 12
            cluster_sector = cluster_sector_hi | cluster_sector_lo
            # We need to return the sector
            return self.header.grain.offset + cluster_sector * self.header.grainSize

        raise ValueError("Unknown grain type")


class COWDisk(SparseExtent):
    """COW disk extent implementation.

    TODO: Regenerate test data and fix implementation.

    Args:
        fh: File-like object for the extent.
        path: Optional path for the extent.
    """

    def __init__(self, fh: BinaryIO, path: Path | None):
        fh.seek(0)
        self.header = c_vmdk.COWDisk_Header(fh)
        super().__init__(fh, path)

    @cached_property
    def _capacity(self) -> int:
        return self.header.numSectors * SECTOR_SIZE

    @cached_property
    def _grain_size(self) -> int:
        return self.header.grainSize * SECTOR_SIZE

    @cached_property
    def _gte_type(self) -> c_vmdk.uint32 | c_vmdk.uint64:
        return c_vmdk.uint32

    @cached_property
    def _num_gte_per_gt(self) -> int:
        return 4096

    @cached_property
    def _gd_size(self) -> int:
        return self.header.numGDEntries

    @cached_property
    def _gd_offset(self) -> int:
        return self.header.gdOffset * SECTOR_SIZE


RE_EXTENT_DESCRIPTOR = re.compile(
    r"""
    ^
    (?P<access>RW|RDONLY|NOACCESS)\s
    (?P<size>\d+)\s
    (?P<type>[^\s]+)
    (\s(?P<filename>\".+\"))?
    (\s(?P<offset>\d+))?
    """,
    re.VERBOSE,
)


class ExtentDescriptor(NamedTuple):
    access: str
    """The access mode of the extent (RW, RDONLY, NOACCESS)."""
    size: int
    """The size of the extent in sectors."""
    type: str
    """The type of the extent (e.g., SPARSE, FLAT, ZERO)."""
    filename: str | None = None
    """The filename of the extent."""
    offset: int | None = None
    """Optional offset of the extent data in the extent file."""


class DiskDescriptor:
    """VMDK disk descriptor.

    Args:
        raw: The raw descriptor data as a string.
    """

    def __init__(self, raw: str):
        self.raw = raw
        self.attributes = {}
        self.extents: list[ExtentDescriptor] = []

        for line in raw.splitlines():
            if not (line := line.strip()) or line.startswith("#"):
                continue

            if line.startswith(("RW ", "RDONLY ", "NOACCESS ")):
                if not (match := RE_EXTENT_DESCRIPTOR.search(line)):
                    log.warning("Unexpected ExtentDescriptor format in vmdk config: %s, ignoring", line)
                    continue

                self.extents.append(
                    ExtentDescriptor(
                        access=match.group("access"),
                        size=int(match.group("size")),
                        type=match.group("type"),
                        filename=match.group("filename").strip('"') if match.group("filename") else None,
                        offset=int(match.group("offset")) if match.group("offset") else None,
                    )
                )
            else:
                key, _, value = line.partition("=")
                self.attributes[key.strip()] = value.strip(' "')


def open_parent(path: Path, hint: str) -> VMDK:
    """Open the parent VMDK disk based on the filename hint.

    Args:
        path: The directory path to look for the parent disk.
        hint: The filename hint for the parent disk.
    """
    try:
        hint = hint.replace("\\", "/")
        hint_path, _, filename = hint.rpartition("/")

        if not (file_path := path.joinpath(filename)).exists():
            file_path = path.joinpath(hint)
            if not file_path.exists():
                _, _, hint_path_name = hint_path.rpartition("/")
                file_path = path.parent.joinpath(hint_path_name).joinpath(filename)

        return VMDK(file_path)
    except Exception as err:
        raise IOError(f"Failed to open parent disk with hint {hint} from path {path}: {err}")
