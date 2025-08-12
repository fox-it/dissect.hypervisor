# References:
# - https://github.com/qemu/qemu/blob/master/block/qcow2.c
# - https://github.com/qemu/qemu/blob/master/docs/interop/qcow2.txt
from __future__ import annotations

import zlib
from functools import cached_property, lru_cache
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_qcow2 import (
    NORMAL_SUBCLUSTER_TYPES,
    QCOW2_MAGIC,
    QCOW2_MAGIC_BYTES,
    UNALLOCATED_SUBCLUSTER_TYPES,
    ZERO_SUBCLUSTER_TYPES,
    QCow2ClusterType,
    QCow2SubclusterType,
    c_qcow2,
    ctz,
)
from dissect.hypervisor.exceptions import Error, InvalidHeaderError

if TYPE_CHECKING:
    from collections.abc import Iterator

try:
    import zstandard as zstd

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


class QCow2:
    """QCOW2 virtual disk implementation.

    If a data-file is required and ``fh`` is not a ``Path``, it's required to manually pass a file like object
    in the `data_file` argument. Otherwise, the data file will be automatically opened if it exists in the same directory.
    It's possible to defer opening the data file by passing ``allow_no_data_file=True``.

    The same applies to the backing-file. This too can be deferred by passing ``allow_no_backing_file=True``.

    Args:
        fh: File handle or path to the QCOW2 file.
        data_file: Optional file handle for the data file. If not provided and ``fh`` is a ``Path``, it will try to open it automatically.
        backing_file: Optional file handle for the backing file. If not provided and ``fh`` is a ``Path``, it will try to open it automatically.
        allow_no_data_file: If True, allows the QCOW2 file to be opened without a data file.
        allow_no_backing_file: If True, allows the QCOW2 file to be opened without a backing file.
    """  # noqa: E501

    def __init__(
        self,
        fh: BinaryIO | Path,
        data_file: BinaryIO | None = None,
        backing_file: BinaryIO | None = None,
        *,
        allow_no_data_file: bool = False,
        allow_no_backing_file: bool = False,
    ):
        self.fh = fh.open("rb") if isinstance(fh, Path) else fh
        self.fh.seek(0)

        self.header = c_qcow2.QCowHeader(self.fh)
        if self.header.magic != QCOW2_MAGIC:
            raise InvalidHeaderError("Invalid qcow2 header magic")

        if self.header.version < 2 or self.header.version > 3:
            raise InvalidHeaderError(f"Unsupported qcow2 version: {self.header.version}")

        if self.header.cluster_bits < c_qcow2.MIN_CLUSTER_BITS or self.header.cluster_bits > c_qcow2.MAX_CLUSTER_BITS:
            raise InvalidHeaderError(f"Unsupported cluster size: 2**{self.header.cluster_bits}")

        self.size = self.header.size

        self.cluster_bits = self.header.cluster_bits
        self.cluster_size = 1 << self.cluster_bits
        self.subclusters_per_cluster = c_qcow2.QCOW_EXTL2_SUBCLUSTERS_PER_CLUSTER if self.has_subclusters else 1
        self.subcluster_size = self.cluster_size // self.subclusters_per_cluster
        self.subcluster_bits = ctz(self.subcluster_size)

        self._l2_entry_size = c_qcow2.L2E_SIZE_EXTENDED if self.has_subclusters else c_qcow2.L2E_SIZE_NORMAL
        self.l2_bits = self.cluster_bits - ctz(self._l2_entry_size)
        self.l2_size = 1 << self.l2_bits

        # 104 = byte offset of compression_type
        if self.header.header_length > 104:
            self.compression_type = self.header.compression_type
        else:
            self.compression_type = c_qcow2.QCOW2_COMPRESSION_TYPE_ZLIB

        if self.compression_type == c_qcow2.QCOW2_COMPRESSION_TYPE_ZSTD and not HAS_ZSTD:
            raise RuntimeError("zstandard module not available")

        self.csize_shift = 62 - (self.cluster_bits - 8)
        self.csize_mask = (1 << (self.cluster_bits - 8)) - 1
        self.cluster_offset_mask = (1 << self.csize_shift) - 1

        if self.subcluster_size < (1 << c_qcow2.MIN_CLUSTER_BITS):
            raise InvalidHeaderError(f"Unsupported subcluster size: 0x{self.subcluster_size:x}")

        if self.header.crypt_method:
            raise NotImplementedError("Encrypted qcow2 files are not supported")

        self.backing_format = None
        self.feature_table = None
        self.crypto_header = None
        self.bitmap_header = None
        self.image_data_file = None
        self.unknown_extensions = []
        self._read_extensions()

        if self.needs_data_file:
            data_file_path = None
            if data_file is None:
                if isinstance(fh, Path):
                    if (data_file_path := fh.with_name(self.image_data_file)).exists():
                        data_file = data_file_path.open("rb")
                    elif not allow_no_data_file:
                        raise Error(
                            f"data-file {str(data_file_path)!r} not found (image_data_file = {self.image_data_file!r})"
                        )
                elif not allow_no_data_file:
                    raise Error(f"data-file required but not provided (image_data_file = {self.image_data_file!r})")

            self.data_file = data_file
        else:
            self.data_file = self.fh

        self.backing_file = None
        self.auto_backing_file = None
        self.image_backing_file = None
        if self.header.backing_file_offset:
            self.fh.seek(self.header.backing_file_offset)
            self.auto_backing_file = self.fh.read(self.header.backing_file_size).decode()
            self.image_backing_file = self.auto_backing_file.upper()

            backing_file_path = None
            if backing_file is None:
                if isinstance(fh, Path):
                    if (backing_file_path := fh.with_name(self.auto_backing_file)).exists():
                        backing_file = backing_file_path.open("rb")
                    elif not allow_no_backing_file:
                        raise Error(
                            f"backing-file {str(backing_file_path)!r} not found (auto_backing_file = {self.auto_backing_file!r})"  # noqa: E501
                        )
                elif not allow_no_backing_file:
                    raise Error(
                        f"backing-file required but not provided (auto_backing_file = {self.auto_backing_file!r})"
                    )

            if backing_file:
                if backing_file.read(4) == QCOW2_MAGIC_BYTES:
                    if backing_file_path:
                        backing_file.close()
                        backing_file = QCow2(backing_file_path).open()
                    else:
                        backing_file = QCow2(backing_file).open()
                else:
                    backing_file.seek(0)

            self.backing_file = backing_file

        self.l2_table = lru_cache(128)(self.l2_table)

    def _read_extensions(self) -> None:
        start_offset = self.header.header_length
        end_offset = self.header.backing_file_offset or 1 << self.cluster_bits

        offset = start_offset
        while offset < end_offset:
            self.fh.seek(offset)
            ext = c_qcow2.QCowExtension(self.fh)
            offset += len(c_qcow2.QCowExtension)

            if offset > end_offset or ext.len > end_offset - offset:
                break  # Invalid extension, just ignore

            if ext.magic == c_qcow2.QCOW2_EXT_MAGIC_END:
                break

            if ext.magic == c_qcow2.QCOW2_EXT_MAGIC_BACKING_FORMAT:
                self.backing_format = self.fh.read(ext.len).decode().upper()
                self.image_backing_format = self.backing_format.upper()
            elif ext.magic == c_qcow2.QCOW2_EXT_MAGIC_FEATURE_TABLE:
                self.feature_table = self.fh.read(ext.len)
            elif ext.magic == c_qcow2.QCOW2_EXT_MAGIC_CRYPTO_HEADER:
                self.crypto_header = c_qcow2.Qcow2CryptoHeaderExtension(self.fh)
            elif ext.magic == c_qcow2.QCOW2_EXT_MAGIC_BITMAPS:
                self.bitmap_header = c_qcow2.Qcow2BitmapHeaderExt(self.fh)
            elif ext.magic == c_qcow2.QCOW2_EXT_MAGIC_DATA_FILE:
                self.image_data_file = self.fh.read(ext.len).decode()
            else:
                self.unknown_extensions.append((ext, self.fh.read(ext.len)))

            # Align to nearest 8 byte boundary
            offset += (ext.len + 7) & 0xFFFFFFF8

    @cached_property
    def snapshots(self) -> list[QCow2Snapshot]:
        snapshots: list[QCow2Snapshot] = []

        offset = self.header.snapshots_offset
        for _ in range(self.header.nb_snapshots):
            snapshots.append(QCow2Snapshot(self, offset))
            offset += (snapshots[-1].entry_size + 7) & ~7  # Round up to 8 bytes

        return snapshots

    @cached_property
    def l1_table(self) -> list[int]:
        # L1 table is usually relatively small, it can be at most 32MB on PB or EB size disks
        self.fh.seek(self.header.l1_table_offset)
        return c_qcow2.uint64[self.header.l1_size](self.fh)

    def l2_table(self, l2_offset: int) -> L2Table:
        return L2Table(self, l2_offset)

    @property
    def has_backing_file(self) -> bool:
        return self.backing_file is not None

    @property
    def needs_backing_file(self) -> bool:
        return self.header.backing_file_offset != 0

    @property
    def has_data_file(self) -> bool:
        return self.data_file is not None and self.data_file != self.fh

    @property
    def needs_data_file(self) -> bool:
        return bool(self.header.incompatible_features & c_qcow2.QCOW2_INCOMPAT_DATA_FILE)

    @property
    def has_subclusters(self) -> bool:
        return bool(self.header.incompatible_features & c_qcow2.QCOW2_INCOMPAT_EXTL2)

    def open(self) -> QCow2Stream:
        """Open the QCow2 file for reading."""
        if self.needs_data_file and not self.has_data_file:
            raise Error(f"data-file required but not provided (image_data_file = {self.image_data_file!r})")
        if self.needs_backing_file and not self.has_backing_file:
            raise Error(f"backing-file required but not provided (auto_backing_file = {self.auto_backing_file!r})")
        return QCow2Stream(self)


class QCow2Snapshot:
    """Wrapper class for snapshot table entries."""

    def __init__(self, qcow2: QCow2, offset: int):
        self.qcow2 = qcow2
        self.offset = offset

        self.qcow2.fh.seek(offset)
        self.header = c_qcow2.QCowSnapshotHeader(self.qcow2.fh)

        # Older versions may not have all the extra data fields
        # Instead of reading them manually, just pad the extra data to fit our struct
        extra_data = self.qcow2.fh.read(self.header.extra_data_size)
        self.extra = c_qcow2.QCowSnapshotExtraData(extra_data.ljust(len(c_qcow2.QCowSnapshotExtraData), b"\x00"))

        unknown_extra_size = self.header.extra_data_size - len(c_qcow2.QCowSnapshotExtraData)
        self.unknown_extra = self.qcow2.fh.read(unknown_extra_size) if unknown_extra_size > 0 else None

        self.id = self.qcow2.fh.read(self.header.id_str_size).decode()
        self.name = self.qcow2.fh.read(self.header.name_size).decode()

        self.entry_size = self.qcow2.fh.tell() - offset

    def open(self) -> QCow2Stream:
        """Open the snapshot for reading."""
        return QCow2Stream(self.qcow2, self.l1_table)

    @cached_property
    def l1_table(self) -> list[int]:
        # L1 table is usually relatively small, it can be at most 32MB on PB or EB size disks
        self.qcow2.fh.seek(self.header.l1_table_offset)
        return c_qcow2.uint64[self.header.l1_size](self.qcow2.fh)


class QCow2Stream(AlignedStream):
    """Aligned stream for reading QCow2 files."""

    def __init__(self, qcow2: QCow2, l1_table: list[int] | None = None):
        super().__init__(qcow2.header.size, align=qcow2.cluster_size)
        self.qcow2 = qcow2
        self.l1_table = l1_table or qcow2.l1_table

    def _yield_runs(self, offset: int, length: int) -> Iterator[tuple[QCow2SubclusterType, int, int, int]]:
        # reference: qcow2_get_host_offset
        while length > 0:
            sc_type = None
            host_offset = 0
            read_count = 0

            l1_index = offset_to_l1_index(self.qcow2, offset)
            l2_index = offset_to_l2_index(self.qcow2, offset)
            sc_index = offset_to_sc_index(self.qcow2, offset)

            offset_in_cluster = offset_into_cluster(self.qcow2, offset)

            bytes_needed = length + offset_in_cluster
            # at the time being we just use the entire l2 table and not cached slices
            # this is actually the bytes available/remaining in this l2 table
            bytes_available = (self.qcow2.l2_size - l2_index) << self.qcow2.cluster_bits
            bytes_needed = min(bytes_needed, bytes_available)

            if l1_index > self.qcow2.header.l1_size:
                # bytes_needed is already the smaller value here
                read_count = bytes_needed - offset_in_cluster

                yield (QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN, offset, host_offset, read_count)

                length -= read_count
                offset += read_count
                continue

            l2_offset = self.l1_table[l1_index] & c_qcow2.L1E_OFFSET_MASK
            if not l2_offset:
                # bytes_needed is already the smaller value here
                read_count = bytes_needed - offset_in_cluster

                yield (QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN, offset, host_offset, read_count)

                length -= read_count
                offset += read_count
                continue

            l2_table = self.qcow2.l2_table(l2_offset)
            l2_entry = l2_table.entry(l2_index)
            l2_bitmap = l2_table.bitmap(l2_index)

            sc_type = get_subcluster_type(self.qcow2, l2_entry, l2_bitmap, sc_index)

            if sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED:
                host_offset = l2_entry & c_qcow2.L2E_COMPRESSED_OFFSET_SIZE_MASK
            elif sc_type in NORMAL_SUBCLUSTER_TYPES:
                host_cluster_offset = l2_entry & c_qcow2.L2E_OFFSET_MASK
                host_offset = host_cluster_offset + offset_in_cluster

            nb_clusters = size_to_clusters(self.qcow2, bytes_needed)
            sc_count = count_contiguous_subclusters(self.qcow2, nb_clusters, sc_index, l2_table, l2_index)
            # this is the amount of contiguous bytes available of the same subcluster type
            bytes_available = (sc_count + sc_index) << self.qcow2.subcluster_bits

            # account for the offset in the cluster
            read_count = min(bytes_available, bytes_needed) - offset_in_cluster

            yield (sc_type, offset, host_offset, read_count)
            length -= read_count
            offset += read_count

    def _read_compressed(self, cluster_descriptor: int, offset: int, length: int) -> bytes:
        offset_in_cluster = offset_into_cluster(self.qcow2, offset)
        coffset = cluster_descriptor & self.qcow2.cluster_offset_mask
        nb_csectors = ((cluster_descriptor >> self.qcow2.csize_shift) & self.qcow2.csize_mask) + 1
        # Original source uses the mask ~(~(QCOW2_COMPRESSED_SECTOR_SIZE - 1ULL))
        # However bit inversion is weird in Python, and this evaluates to 511, so we use that value instead.
        csize = nb_csectors * c_qcow2.QCOW2_COMPRESSED_SECTOR_SIZE - (coffset & 511)

        self.qcow2.fh.seek(coffset)
        buf = self.qcow2.fh.read(csize)
        decompressed = self._decompress(buf)

        return decompressed[offset_in_cluster : offset_in_cluster + length]

    def _decompress(self, buf: bytes) -> bytes:
        if self.qcow2.compression_type == c_qcow2.QCOW2_COMPRESSION_TYPE_ZLIB:
            dctx = zlib.decompressobj(-12)
            return dctx.decompress(buf, self.qcow2.cluster_size)

        if self.qcow2.compression_type == c_qcow2.QCOW2_COMPRESSION_TYPE_ZSTD:
            result = []

            dctx = zstd.ZstdDecompressor()
            reader = dctx.stream_reader(BytesIO(buf))
            while reader.tell() < self.qcow2.cluster_size:
                chunk = reader.read(self.qcow2.cluster_size - reader.tell())
                if not chunk:
                    break
                result.append(chunk)
            return b"".join(result)

        raise Error(f"Invalid compression type: {self.qcow2.compression_type}")

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        for sc_type, read_offset, run_offset, run_length in self._yield_runs(offset, length):
            unalloc_zeroed = sc_type in UNALLOCATED_SUBCLUSTER_TYPES and not self.qcow2.has_backing_file

            if sc_type in ZERO_SUBCLUSTER_TYPES or unalloc_zeroed:
                result.append(b"\x00" * run_length)
            elif sc_type in UNALLOCATED_SUBCLUSTER_TYPES and self.qcow2.has_backing_file:
                self.qcow2.backing_file.seek(read_offset)
                result.append(self.qcow2.backing_file.read(run_length))
            elif sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED:
                result.append(self._read_compressed(run_offset, read_offset, run_length))
            elif sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL:
                self.qcow2.data_file.seek(run_offset)
                result.append(self.qcow2.data_file.read(run_length))

        return b"".join(result)


class L2Table:
    """Convenience class for accessing the L2 table."""

    def __init__(self, qcow2: QCow2, offset: int):
        self.qcow2 = qcow2
        self.offset = offset

        l2_table_size = self.qcow2.l2_size * (self.qcow2._l2_entry_size // 8)
        self.qcow2.fh.seek(offset)
        self._table = c_qcow2.uint64[l2_table_size](self.qcow2.fh)

    def entry(self, idx: int) -> int:
        return self._table[idx * self.qcow2._l2_entry_size // 8]

    def bitmap(self, idx: int) -> int:
        if self.qcow2.has_subclusters:
            return self._table[(idx * self.qcow2._l2_entry_size // 8) + 1]
        return 0


def offset_into_cluster(qcow2: QCow2, offset: int) -> int:
    return offset & (qcow2.cluster_size - 1)


def offset_into_subcluster(qcow2: QCow2, offset: int) -> int:
    return offset & (qcow2.subcluster_size - 1)


def size_to_clusters(qcow2: QCow2, size: int) -> int:
    return (size + (qcow2.cluster_size - 1)) >> qcow2.cluster_bits


def size_to_subclusters(qcow2: QCow2, size: int) -> int:
    return (size + (qcow2.subcluster_size - 1)) >> qcow2.subcluster_bits


def offset_to_l1_index(qcow2: QCow2, offset: int) -> int:
    return offset >> (qcow2.l2_bits + qcow2.cluster_bits)


def offset_to_l2_index(qcow2: QCow2, offset: int) -> int:
    return (offset >> qcow2.cluster_bits) & (qcow2.l2_size - 1)


def offset_to_sc_index(qcow2: QCow2, offset: int) -> int:
    return (offset >> qcow2.subcluster_bits) & (qcow2.subclusters_per_cluster - 1)


def get_cluster_type(qcow2: QCow2, l2_entry: int) -> QCow2ClusterType:
    if l2_entry & c_qcow2.QCOW_OFLAG_COMPRESSED:
        return QCow2ClusterType.QCOW2_CLUSTER_COMPRESSED

    if (l2_entry & c_qcow2.QCOW_OFLAG_ZERO) and not qcow2.has_subclusters:
        if l2_entry & c_qcow2.L2E_OFFSET_MASK:
            return QCow2ClusterType.QCOW2_CLUSTER_ZERO_ALLOC
        return QCow2ClusterType.QCOW2_CLUSTER_ZERO_PLAIN

    if not l2_entry & c_qcow2.L2E_OFFSET_MASK:
        if qcow2.has_data_file and l2_entry & c_qcow2.QCOW_OFLAG_COPIED:
            return QCow2ClusterType.QCOW2_CLUSTER_NORMAL
        return QCow2ClusterType.QCOW2_CLUSTER_UNALLOCATED

    return QCow2ClusterType.QCOW2_CLUSTER_NORMAL


def get_subcluster_type(qcow2: QCow2, l2_entry: int, l2_bitmap: int, sc_index: int) -> QCow2SubclusterType:
    c_type = get_cluster_type(qcow2, l2_entry)

    sc_alloc_mask = 1 << sc_index
    sc_zero_mask = sc_alloc_mask << 32

    if qcow2.has_subclusters:
        if c_type == QCow2ClusterType.QCOW2_CLUSTER_COMPRESSED:
            return QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED
        if c_type == QCow2ClusterType.QCOW2_CLUSTER_NORMAL:
            if (l2_bitmap >> 32) & l2_bitmap:
                return QCow2SubclusterType.QCOW2_SUBCLUSTER_INVALID
            if l2_bitmap & sc_zero_mask:  # QCOW_OFLAG_SUB_ZERO(sc_index)
                return QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_ALLOC
            if l2_bitmap & sc_alloc_mask:  # QCOW_OFLAG_SUB_ALLOC(sc_index)
                return QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL
            return QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC
        if c_type == QCow2ClusterType.QCOW2_CLUSTER_UNALLOCATED:
            if l2_bitmap & ((1 << 32) - 1):
                return QCow2SubclusterType.QCOW2_SUBCLUSTER_INVALID
            if l2_bitmap & sc_zero_mask:  # QCOW_OFLAG_SUB_ZERO(sc_index)
                return QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_PLAIN
            return QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN

        raise Error(f"Invalid cluster type: {c_type}")

    if c_type == QCow2ClusterType.QCOW2_CLUSTER_COMPRESSED:
        return QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED
    if c_type == QCow2ClusterType.QCOW2_CLUSTER_ZERO_PLAIN:
        return QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_PLAIN
    if c_type == QCow2ClusterType.QCOW2_CLUSTER_ZERO_ALLOC:
        return QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_ALLOC
    if c_type == QCow2ClusterType.QCOW2_CLUSTER_NORMAL:
        return QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL
    if c_type == QCow2ClusterType.QCOW2_CLUSTER_UNALLOCATED:
        return QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN

    raise Error(f"Invalid cluster type: {c_type}")


def get_subcluster_range_type(
    qcow2: QCow2, l2_entry: int, l2_bitmap: int, sc_from: int
) -> tuple[QCow2SubclusterType, int]:
    sc_type = get_subcluster_type(qcow2, l2_entry, l2_bitmap, sc_from)

    # No subclusters, so count the entire cluster
    if not qcow2.has_subclusters or sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED:
        return sc_type, qcow2.subclusters_per_cluster - sc_from

    sc_mask = (1 << sc_from) - 1
    if sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL:
        val = l2_bitmap | sc_mask  # QCOW_OFLAG_SUB_ALLOC_RANGE(0, sc_from)
        return sc_type, ctz(val) - sc_from
    if sc_type in ZERO_SUBCLUSTER_TYPES:
        val = (l2_bitmap | sc_mask) >> 32  # QCOW_OFLAG_SUB_ZERO_RANGE(0, sc_from)
        return sc_type, ctz(val) - sc_from
    if sc_type in UNALLOCATED_SUBCLUSTER_TYPES:
        # We need to mask it with a 64bit mask because Python flips the sign bit
        inv_mask = ~sc_mask & ((1 << 64) - 1)  # ~QCOW_OFLAG_SUB_ALLOC_RANGE(0, sc_from)

        val = ((l2_bitmap >> 32) | l2_bitmap) & inv_mask
        return sc_type, ctz(val) - sc_from

    raise Error(f"Invalid subcluster type: {sc_type}")


def count_contiguous_subclusters(
    qcow2: QCow2, nb_clusters: int, sc_index: int, l2_table: L2Table, l2_index: int
) -> int:
    count = 0
    expected_type = None
    expected_offset = None

    check_offset = False
    check_offset_types = (
        QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL,
        QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_ALLOC,
        QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
    )

    for i in range(nb_clusters):
        first_sc = sc_index if i == 0 else 0
        l2_entry = l2_table.entry(l2_index + i)
        l2_bitmap = l2_table.entry(l2_index + i)

        sc_type, sc_count = get_subcluster_range_type(qcow2, l2_entry, l2_bitmap, first_sc)

        if i == 0:
            if sc_type == QCow2SubclusterType.QCOW2_SUBCLUSTER_COMPRESSED:
                return sc_count

            expected_type = sc_type
            expected_offset = l2_entry & c_qcow2.L2E_OFFSET_MASK
            check_offset = sc_type in check_offset_types
        elif sc_type != expected_type:
            break
        elif check_offset:
            expected_offset += qcow2.cluster_size
            if expected_offset != l2_entry & c_qcow2.L2E_OFFSET_MASK:
                break

        count += sc_count
        if first_sc + sc_count < qcow2.subclusters_per_cluster:
            break

    return count
