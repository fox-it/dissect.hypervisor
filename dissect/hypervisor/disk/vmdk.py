from __future__ import annotations

import ctypes
import io
import logging
import os
import re
import textwrap
import zlib
from bisect import bisect_right
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, BinaryIO

from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_vmdk import (
    COWD_MAGIC,
    SECTOR_SIZE,
    SESPARSE_MAGIC,
    VMDK_MAGIC,
    c_vmdk,
)

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_VMDK", "CRITICAL"))


class VMDK(AlignedStream):
    def __init__(self, fh: BinaryIO | Path | str | list[BinaryIO | Path | str]):
        """
        Input can be a file handle to a Disk Descriptor file or a list of file handles to multiple VMDK files.
        """
        fhs = [fh] if not isinstance(fh, list) else fh

        self.disks = []
        self.parent = None
        self.descriptor = None
        self._disk_offsets = []
        self.sector_count = 0

        for fh in fhs:
            if hasattr(fh, "read"):
                name = getattr(fh, "name", None)
                path = Path(name) if name else None
            else:
                if not isinstance(fh, Path):
                    fh = Path(fh)
                path = fh
                fh = path.open("rb")

            magic = fh.read(4)
            fh.seek(-4, io.SEEK_CUR)

            if magic == b"# Di" and len(fhs) == 1:
                # Try reading the disk files from this descriptor
                # Otherwise we assume that the other file handles are the appropriate disks
                self.descriptor = DiskDescriptor.parse(fh.read().decode())

                if self.descriptor.attr["parentCID"] != "ffffffff":
                    self.parent = open_parent(path.parent, self.descriptor.attr["parentFileNameHint"])

                for extent in self.descriptor.extents:
                    if extent.type in ["SPARSE", "VMFSSPARSE", "SESPARSE"]:
                        sdisk_fh = path.with_name(extent.filename).open("rb")
                        self.disks.append(SparseDisk(sdisk_fh, parent=self.parent))
                    elif extent.type in ["VMFS", "FLAT"]:
                        rdisk_fh = path.with_name(extent.filename).open("rb")
                        self.disks.append(RawDisk(rdisk_fh, extent.sectors * SECTOR_SIZE))

            elif magic in (COWD_MAGIC, VMDK_MAGIC, SESPARSE_MAGIC):
                sparse_disk = SparseDisk(fh)

                if sparse_disk.descriptor and sparse_disk.descriptor.attr["parentCID"] != "ffffffff":
                    sparse_disk.parent = open_parent(path.parent, sparse_disk.descriptor.attr["parentFileNameHint"])
                self.disks.append(sparse_disk)

            else:
                self.disks.append(RawDisk(fh))

        size = 0
        for disk in self.disks:
            if size != 0:
                self._disk_offsets.append(self.sector_count)
            disk.offset = size
            disk.sector_offset = self.sector_count
            size += disk.size
            self.sector_count += disk.sector_count

        super().__init__(size)

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("VMDK::read_sectors(0x%x, 0x%x)", sector, count)

        sectors_read = []

        disk_idx = bisect_right(self._disk_offsets, sector)

        while count > 0:
            disk = self.disks[disk_idx]

            disk_remaining_sectors = disk.sector_count - (sector - disk.sector_offset)
            disk_sectors = min(disk_remaining_sectors, count)

            sectors_read.append(disk.read_sectors(sector, disk_sectors))

            sector += disk_sectors
            count -= disk_sectors
            disk_idx += 1

        return b"".join(sectors_read)

    def _read(self, offset: int, length: int) -> bytes:
        log.debug("VMDK::_read(0x%x, 0x%x)", offset, length)

        sector = offset // SECTOR_SIZE
        count = (length + SECTOR_SIZE - 1) // SECTOR_SIZE

        return self.read_sectors(sector, count)


class RawDisk:
    def __init__(self, fh: BinaryIO, size: int | None = None, offset: int = 0, sector_offset: int = 0):
        self.fh = fh
        self.offset = offset
        self.sector_offset = sector_offset

        if not size:
            fh.seek(0, io.SEEK_END)
            self.size = fh.tell()
            fh.seek(0)
        else:
            self.size = size

        self.sector_count = self.size // SECTOR_SIZE

        self.read = fh.read
        self.seek = fh.seek
        self.tell = fh.tell

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("RawDisk::read_sectors(0x%x)", sector)

        self.fh.seek((sector - self.sector_offset) * SECTOR_SIZE)
        return self.fh.read(count * SECTOR_SIZE)


class SparseDisk:
    def __init__(
        self, fh: BinaryIO, parent: VMDK | RawDisk | SparseDisk | None = None, offset: int = 0, sector_offset: int = 0
    ):
        self.fh = fh
        self.parent = parent
        self.offset = offset
        self.sector_offset = sector_offset

        fh.seek(0, io.SEEK_END)
        self.filesize = fh.tell()
        fh.seek(0, io.SEEK_SET)
        self.descriptor = None

        self.header = SparseExtentHeader(fh)
        if self.header.magic in (VMDK_MAGIC, COWD_MAGIC):
            self.is_sesparse = False

            if ctypes.c_int64(self.header.primary_grain_directory_offset).value == -1:
                # Footer starts -1024 from the end
                fh.seek(-1024, io.SEEK_END)
                self.header = SparseExtentHeader(fh)

            if self.header.magic == VMDK_MAGIC:
                grain_table_coverage = self.header.num_grain_table_entries * self.header.grain_size
                self._grain_directory_size = (self.header.capacity + grain_table_coverage - 1) // grain_table_coverage
                self._grain_table_size = self.header.num_grain_table_entries

                if self.header.descriptor_size > 0:
                    fh.seek(self.header.descriptor_offset * SECTOR_SIZE)
                    descriptor_buf = fh.read(self.header.descriptor_size * SECTOR_SIZE)
                    self.descriptor = DiskDescriptor.parse(descriptor_buf.split(b"\x00", 1)[0].decode())

            elif self.header.magic == COWD_MAGIC:
                self._grain_directory_size = self.header.num_grain_directory_entries
                self._grain_table_size = 4096

            grain_directory_offset = self.header.primary_grain_directory_offset
            self._grain_entry_type = c_vmdk.uint32

            self._grain_directory = c_vmdk.uint32[self._grain_directory_size](fh)

        elif self.header.magic == c_vmdk.SESPARSE_CONST_HEADER_MAGIC:
            self.is_sesparse = True

            self._grain_directory_size = self.header.grain_directory_size * SECTOR_SIZE // 8
            self._grain_table_size = self.header.grain_table_size * SECTOR_SIZE // 8

            grain_directory_offset = self.header.grain_directory_offset
            self._grain_entry_type = c_vmdk.uint64

        self.fh.seek(grain_directory_offset * SECTOR_SIZE)
        self._grain_directory = self._grain_entry_type[self._grain_directory_size](fh)

        self.size = self.header.capacity * SECTOR_SIZE
        self.sector_count = self.header.capacity

        self._lookup_grain_table = lru_cache(128)(self._lookup_grain_table)

    def _lookup_grain_table(self, directory: int) -> list[int]:
        gtbl_offset = self._grain_directory[directory]

        if self.is_sesparse:
            # qemu/block/vmdk.c:
            # Top most nibble is 0x1 if grain table is allocated.
            # strict check - top most 4 bytes must be 0x10000000 since max
            # supported size is 64TB for disk - so no more than 64TB / 16MB
            # grain directories which is smaller than uint32,
            # where 16MB is the only supported default grain table coverage.
            if not gtbl_offset or gtbl_offset & 0xFFFFFFFF00000000 != 0x1000000000000000:
                table = None
            else:
                gtbl_offset &= 0x00000000FFFFFFFF
                gtbl_offset = (
                    self.header.grain_tables_offset + gtbl_offset * (self._grain_table_size * 8) // SECTOR_SIZE
                )
                self.fh.seek(gtbl_offset * SECTOR_SIZE)
                table = self._grain_entry_type[self._grain_table_size](self.fh)
        else:
            if gtbl_offset:
                self.fh.seek(gtbl_offset * SECTOR_SIZE)
                table = self._grain_entry_type[self._grain_table_size](self.fh)
            else:
                table = None

        return table

    def _lookup_grain(self, grain: int) -> int:
        gdir_entry, gtbl_entry = divmod(grain, self._grain_table_size)
        table = self._lookup_grain_table(gdir_entry)

        if table:
            grain_entry = table[gtbl_entry]
            if self.is_sesparse:
                # SESparse uses a different method of specifying unallocated/sparse/allocated grains
                # However, we can re-use the normal sparse logic of returning 0 for unallocated, 1 for
                # sparse and >1 for allocated grains, since a grain of 0 or 1 isn't possible in SESparse.
                grain_type = grain_entry & c_vmdk.SESPARSE_GRAIN_TYPE_MASK
                if grain_type in (c_vmdk.SESPARSE_GRAIN_TYPE_UNALLOCATED, c_vmdk.SESPARSE_GRAIN_TYPE_FALLTHROUGH):
                    # Unallocated or scsi unmapped, fallthrough
                    return 0
                if grain_type == c_vmdk.SESPARSE_GRAIN_TYPE_ZERO:
                    # Sparse, zero grain
                    return 1
                if grain_type == c_vmdk.SESPARSE_GRAIN_TYPE_ALLOCATED:
                    # Allocated
                    cluster_sector_hi = (grain_entry & 0x0FFF000000000000) >> 48
                    cluster_sector_lo = (grain_entry & 0x0000FFFFFFFFFFFF) << 12
                    cluster_sector = cluster_sector_hi | cluster_sector_lo
                    return self.header.grains_offset + cluster_sector * self.header.grain_size

                raise ValueError("Unknown grain type")

            return grain_entry

        return 0

    def get_runs(self, sector: int, count: int) -> list[tuple[int, int, int, int | None]]:
        disk_sector = sector - self.sector_offset

        run_type = None
        run_offset = 0
        run_count = 0
        run_parent = None
        next_grain_sector = 0

        read_sector = disk_sector
        read_count = count

        runs = []

        if read_count == 0:
            return runs

        while read_count > 0:
            grain, grain_offset = divmod(read_sector, self.header.grain_size)
            grain_sector = self._lookup_grain(grain)
            read_sector_count = min(read_count, self.header.grain_size - grain_offset)

            if (run_type == 0 and grain_sector == 0) or (run_type == 1 and grain_sector == 1):
                run_count += read_sector_count
            elif run_type and run_type > 1 and grain_sector == next_grain_sector:
                next_grain_sector += self.header.grain_size
                run_count += read_sector_count
            else:
                if run_type is not None:
                    runs.append((run_type, run_offset, run_count, run_parent))
                    run_type = None
                    run_count = 0
                    run_parent = None
                if grain_sector == 0:
                    run_type = 0
                    run_count += read_sector_count
                    run_parent = self.sector_offset + read_sector
                elif grain_sector == 1:
                    run_type = 1
                    run_count += read_sector_count
                else:
                    run_type = grain_sector
                    run_offset = grain_offset
                    run_count += read_sector_count
                    next_grain_sector = grain_sector + self.header.grain_size

            read_count -= read_sector_count
            read_sector += read_sector_count

        assert run_type is not None
        runs.append((run_type, run_offset, run_count, run_parent))

        return runs

    def read_sectors(self, sector: int, count: int) -> bytes:
        log.debug("SparseDisk::read_sectors(0x%x, 0x%x)", sector, count)

        runs = self.get_runs(sector, count)
        sectors_read = []

        for run_type, run_offset, run_count, run_parent in runs:
            # Grain not present
            if run_type == 0:
                if self.parent:
                    sector_data = self.parent.read_sectors(run_parent, run_count)
                else:
                    sector_data = b"\x00" * (run_count * SECTOR_SIZE)
                sectors_read.append(sector_data)
                continue

            # Sparse grain
            if run_type == 1:
                sectors_read.append(b"\x00" * (run_count * SECTOR_SIZE))
                continue

            # Uncompressed grain
            if self.header.flags & c_vmdk.SPARSEFLAG_COMPRESSED == 0:
                self.fh.seek((run_type + run_offset) * SECTOR_SIZE)
                sector_data = self.fh.read(run_count * SECTOR_SIZE)
                sectors_read.append(sector_data)
                continue

            # Compressed grain
            while run_count > 0:
                # We consolidate grain runs in get_runs, but we can't read a contiguous stream of compressed grains
                # So loop over the consolidated grains
                offset = run_offset * SECTOR_SIZE
                grain_remaining = self.header.grain_size - run_offset
                read_count = min(run_count, grain_remaining)

                buf = self._read_compressed_grain(run_type)
                sectors_read.append(buf[offset : offset + read_count * SECTOR_SIZE])

                # If we loop, we're going to the next run, which means we'll start at offset 0
                run_offset = 0
                run_type += self.header.grain_size
                run_count -= read_count

        return b"".join(sectors_read)

    def _read_compressed_grain(self, sector: int) -> bytes:
        self.fh.seek(sector * SECTOR_SIZE)
        buf = self.fh.read(SECTOR_SIZE)

        if self.header.flags & c_vmdk.SPARSEFLAG_EMBEDDED_LBA:
            header_len = 12
            lba_header = c_vmdk.SparseGrainLBAHeaderOnDisk(buf)
            compressed_len = lba_header.cmp_size
        else:
            header_len = 4
            compressed_len = c_vmdk.uint32(buf)

        if compressed_len + header_len > SECTOR_SIZE:
            # Officially this is padded to SECTOR_SIZE, but we don't really care
            remaining_len = header_len + compressed_len - SECTOR_SIZE
            self.fh.seek((sector + 1) * SECTOR_SIZE)
            buf += self.fh.read(remaining_len)

        return zlib.decompress(buf[header_len : header_len + compressed_len])


class SparseExtentHeader:
    def __init__(self, fh: BinaryIO):
        magic = fh.read(4)
        fh.seek(-4, io.SEEK_CUR)

        if magic == VMDK_MAGIC:
            self.hdr = c_vmdk.VMDKSparseExtentHeader(fh)
        elif magic == SESPARSE_MAGIC:
            self.hdr = c_vmdk.VMDKSESparseConstHeader(fh)
        elif magic == COWD_MAGIC:
            self.hdr = c_vmdk.COWDSparseExtentHeader(fh)
        else:
            raise NotImplementedError("Unsupported sparse extent")

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.hdr, attr)


RE_EXTENT_DESCRIPTOR = re.compile(
    r"""
    ^
    (?P<access_mode>RW|RDONLY|NOACCESS)\s
    (?P<sectors>\d+)\s
    (?P<type>SPARSE|ZERO|FLAT|VMFS|VMFSSPARSE|VMFSRDM|VMFSRAW)
    (\s(?P<filename>\".+\"))?
    (\s(?P<start_sector>\d+))?
    (\s(?P<partition_uuid>\S+))?
    (\s(?P<device_identifier>\S+))?
    $
    """,
    re.VERBOSE,
)


@dataclass
class ExtentDescriptor:
    raw: str
    access_mode: str
    sectors: int
    type: str
    filename: str | None = None
    start_sector: int | None = None
    partition_uuid: str | None = None
    device_identifier: str | None = None

    def __post_init__(self) -> None:
        self.sectors = int(self.sectors)

        if self.filename:
            self.filename = self.filename.strip('"')

        if self.start_sector:
            self.start_sector = int(self.start_sector)

    def __repr__(self) -> str:
        return f"<ExtentDescriptor {self.raw}>"

    def __str__(self) -> str:
        return self.raw


class DiskDescriptor:
    def __init__(
        self, attr: dict, extents: list[ExtentDescriptor], disk_db: dict, sectors: int, raw_config: str | None = None
    ):
        self.attr = attr
        self.extents = extents
        self.ddb = disk_db
        self.sectors = sectors
        self.raw = raw_config

    @classmethod
    def parse(cls, vmdk_config: str) -> DiskDescriptor:
        """Return :class:`DiskDescriptor` based on the provided ``vmdk_config``.

        Resources:
            - https://github.com/libyal/libvmdk/blob/main/documentation/VMWare%20Virtual%20Disk%20Format%20(VMDK).asciidoc
        """

        descriptor_settings = {}
        extents: list[ExtentDescriptor] = []
        disk_db = {}
        sectors = 0

        for line in vmdk_config.split("\n"):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith(("RW ", "RDONLY ", "NOACCESS ")):
                match = RE_EXTENT_DESCRIPTOR.search(line)

                if not match:
                    log.warning("Unexpected ExtentDescriptor format in vmdk config: %s, ignoring", line)
                    continue

                extent = ExtentDescriptor(raw=line, **match.groupdict())
                sectors += extent.sectors
                extents.append(extent)
                continue

            setting, _, value = line.partition("=")
            setting = setting.strip()
            value = value.strip(' "')

            if setting.startswith("ddb."):
                disk_db[setting] = value
            else:
                descriptor_settings[setting] = value

        return cls(descriptor_settings, extents, disk_db, sectors, vmdk_config)

    def __str__(self) -> str:
        str_template = textwrap.dedent(
            """\
        # Disk DescriptorFile
        version=1
        {}

        # Extent Description
        {}

        # The Disk Data Base
        #DDB

        {}"""
        )

        descriptor_settings = []
        for setting, value in self.attr.items():
            if setting != "version":
                descriptor_settings.append(f"{setting}={value}")
        descriptor_settings = "\n".join(descriptor_settings)

        extents = "\n".join(map(str, self.extents))

        disk_db = []
        for setting, value in self.ddb.items():
            disk_db.append(f'{setting} = "{value}"')
        disk_db = "\n".join(disk_db)

        return str_template.format(descriptor_settings, extents, disk_db)


def open_parent(path: Path, filename_hint: str) -> VMDK:
    try:
        filename_hint = filename_hint.replace("\\", "/")
        hint_path, _, filename = filename_hint.rpartition("/")
        filepath = path.joinpath(filename)
        if not filepath.exists():
            _, _, hint_path_name = hint_path.rpartition("/")
            filepath = path.parent.joinpath(hint_path_name).joinpath(filename)
        vmdk = VMDK(filepath)
    except Exception as err:
        raise IOError(f"Failed to open parent disk with hint {filename_hint} from path {path}: {err}")

    return vmdk
