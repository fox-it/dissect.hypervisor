# References:
# - https://git.proxmox.com/?p=pve-qemu.git;a=blob;f=vma_spec.txt
# - https://lists.gnu.org/archive/html/qemu-devel/2013-02/msg03667.html

import hashlib
import struct
from collections import defaultdict
from functools import lru_cache
from uuid import UUID

from dissect.util import ts
from dissect.util.stream import AlignedStream

from dissect.hypervisor.backup.c_vma import c_vma, VMA_MAGIC, VMA_EXTENT_MAGIC
from dissect.hypervisor.exceptions import InvalidHeaderError


class VMA:
    """Proxmox VMA.

    Parse and provide a readable object for devices in a Proxmox VMA backup file.
    VMA is designed to be streamed for extraction, so we need to do some funny stuff to create a readable
    object from it. Performance is not optimal, so it's generally advised to extract a VMA instead.
    The vma-extract utility can be used for that.
    """

    def __init__(self, fh):
        self.fh = fh

        offset = fh.tell()
        self.header = c_vma.VmaHeader(fh)
        if self.header.magic != VMA_MAGIC:
            raise InvalidHeaderError("Invalid VMA header magic")

        fh.seek(offset)
        header_data = bytearray(fh.read(self.header.header_size))
        header_data[32:48] = b"\x00" * 16
        if hashlib.md5(header_data).digest() != self.header.md5sum:
            raise InvalidHeaderError("Invalid VMA checksum")

        self.version = self.header.version
        self.uuid = UUID(bytes=self.header.uuid)

        blob_start = self.header.blob_buffer_offset
        blob_end = self.header.blob_buffer_offset + self.header.blob_buffer_size
        self._blob = memoryview(bytes(header_data))[blob_start:blob_end]

        blob_offset = 1
        self._blob_data = {}
        while blob_offset + 2 <= self.header.blob_buffer_size:
            # The header is in big endian, but this is little...
            size = struct.unpack("<H", self._blob[blob_offset : blob_offset + 2])[0]
            if blob_offset + 2 + size <= blob_end:
                self._blob_data[blob_offset] = self._blob[blob_offset + 2 : blob_offset + 2 + size].tobytes()
            blob_offset += size + 2

        self._config = {}
        for conf_name, conf_data in zip(self.header.config_names, self.header.config_data):
            if (conf_name, conf_data) == (0, 0):
                continue

            self._config[self.blob_string(conf_name)] = self.blob_data(conf_data)

        self._devices = {}
        for dev_id, dev_info in enumerate(self.header.dev_info):
            if dev_id == 0 or dev_info.devname_ptr == 0:
                continue

            self._devices[dev_id] = Device(self, dev_id, self.blob_string(dev_info.devname_ptr), dev_info.size)

    @property
    def creation_time(self):
        return ts.from_unix(self.header.ctime)

    def blob_data(self, offset):
        if offset not in self._blob_data:
            raise KeyError(f"No blob data for offset {offset}")
        return self._blob_data[offset]

    def blob_string(self, offset):
        return self.blob_data(offset).decode().rstrip("\x00")

    def config(self, name):
        return self._config[name]

    def configs(self):
        return self._config

    def device(self, dev_id):
        return self._devices[dev_id]

    def devices(self):
        return list(self._devices.values())

    @lru_cache(65536)
    def _extent(self, offset):
        return Extent(self.fh, offset)

    def extents(self):
        offset = self.header.header_size
        while True:
            try:
                extent = self._extent(offset)
            except EOFError:
                break

            yield extent

            offset += c_vma.VMA_EXTENT_HEADER_SIZE + extent.size


class Device:
    def __init__(self, vma, dev_id, name, size):
        self.vma = vma
        self.id = dev_id
        self.name = name
        self.size = size

    def __repr__(self):
        return f"<Device id={self.id} name={self.name} size={self.size}>"

    def open(self):
        return DeviceDataStream(self)


class Extent:
    def __init__(self, fh, offset):
        self.fh = fh
        self.offset = offset
        self.data_offset = offset + c_vma.VMA_EXTENT_HEADER_SIZE

        self.fh.seek(offset)
        header_data = bytearray(fh.read(c_vma.VMA_EXTENT_HEADER_SIZE))
        self.header = c_vma.VmaExtentHeader(header_data)
        if self.header.magic != VMA_EXTENT_MAGIC:
            raise InvalidHeaderError("Invalid VMA extent header magic")

        header_data[24:40] = b"\x00" * 16
        if hashlib.md5(header_data).digest() != self.header.md5sum:
            raise InvalidHeaderError("Invalid VMA extent checksum")

        self.uuid = UUID(bytes=self.header.uuid)
        self.size = self.header.block_count * c_vma.VMA_BLOCK_SIZE

        # Keep track of the lowest and highest cluster we have for any device
        # We can use this to speed up extent lookup later on
        # There are at most 59 entries, so safe to parse ahead of use
        self._min = {}
        self._max = {}
        self.blocks = defaultdict(list)
        for block_info in self.header.blockinfo:
            cluster_num = block_info & 0xFFFFFFFF
            dev_id = (block_info >> 32) & 0xFF
            mask = block_info >> (32 + 16)

            if dev_id == 0:
                continue

            if dev_id not in self._min:
                self._min[dev_id] = cluster_num
                self._max[dev_id] = cluster_num
            elif cluster_num < self._min[dev_id]:
                self._min[dev_id] = cluster_num
            elif cluster_num > self._max[dev_id]:
                self._max[dev_id] = cluster_num

            self.blocks[dev_id].append((dev_id, cluster_num, mask))

    def __repr__(self):
        return f"<Extent offset=0x{self.offset:x} size=0x{self.size:x}>"


class DeviceDataStream(AlignedStream):
    def __init__(self, device):
        self.device = device
        self.vma = device.vma
        super().__init__(size=device.size, align=c_vma.VMA_CLUSTER_SIZE)

    def _read(self, offset, length):
        cluster_offset = offset // c_vma.VMA_CLUSTER_SIZE
        cluster_count = (length + c_vma.VMA_CLUSTER_SIZE - 1) // c_vma.VMA_CLUSTER_SIZE
        block_count = (length + c_vma.VMA_BLOCK_SIZE - 1) // c_vma.VMA_BLOCK_SIZE

        result = []
        for _, mask, block_offset in _iter_clusters(self.vma, self.device.id, cluster_offset, cluster_count):
            read_count = min(block_count, 16)

            # Optimize reading fully set and fully sparse masks
            if mask == 0xFFFF:
                self.vma.fh.seek(block_offset)
                result.append(self.vma.fh.read(c_vma.VMA_BLOCK_SIZE * read_count))
            elif mask == 0:
                result.append(b"\x00" * read_count * c_vma.VMA_BLOCK_SIZE)
            else:
                self.vma.fh.seek(block_offset)
                for allocated, count in _iter_mask(mask, read_count):
                    if allocated:
                        result.append(self.vma.fh.read(c_vma.VMA_BLOCK_SIZE * count))
                    else:
                        result.append(b"\x00" * count * c_vma.VMA_BLOCK_SIZE)

            block_count -= read_count
            if block_count == 0:
                break

        return b"".join(result)


def _iter_clusters(vma, dev_id, cluster, count):
    # Find clusters and starting offsets in all extents
    temp = {}
    end = cluster + count

    for extent in vma.extents():
        if dev_id not in extent.blocks:
            continue

        if end < extent._min[dev_id] or cluster > extent._max[dev_id]:
            continue

        block_offset = extent.data_offset
        for _, cluster_num, mask in extent.blocks[dev_id]:
            if cluster_num == cluster:
                yield cluster_num, mask, block_offset
                cluster += 1

                while cluster in temp:
                    yield temp[cluster]
                    del temp[cluster]
                    cluster += 1
            elif cluster < cluster_num <= end:
                temp[cluster_num] = (cluster_num, mask, block_offset)

            if mask == 0xFFFF:
                block_offset += 16 * c_vma.VMA_BLOCK_SIZE
            elif mask == 0:
                pass
            else:
                block_offset += bin(mask).count("1") * c_vma.VMA_BLOCK_SIZE

            if cluster == end:
                break

        if cluster == end:
            break

    while cluster in temp:
        yield temp[cluster]
        del temp[cluster]
        cluster += 1


def _iter_mask(mask, length):
    # Yield consecutive bitmask values
    current_status = mask & 1
    current_count = 0

    for bit_idx in range(length):
        status = (mask & (1 << bit_idx)) >> bit_idx
        if status == current_status:
            current_count += 1
        else:
            yield current_status, current_count
            current_status = status
            current_count = 1

    if current_count:
        yield current_status, current_count
