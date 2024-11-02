# References:
# - Veeam extract utility
# - Veeam agent
from __future__ import annotations

from functools import cached_property, lru_cache
from io import BytesIO
from typing import BinaryIO, Generic, Iterator, TypeVar
from zlib import crc32

from dissect.cstruct import Structure
from dissect.hypervisor.backup.c_vbk import c_vbk
from dissect.hypervisor.exceptions import Error
from dissect.util.compression import lz4
from dissect.util.crc32c import crc32c
from dissect.util.stream import AlignedStream
from dissect.util.xmemoryview import xmemoryview

PAGE_SIZE = 4096
"""VBK page size."""


class VBKError(Error):
    pass


class NotAFileError(VBKError):
    pass


class NotADirectoryError(VBKError):
    pass


class VBK:
    """Veeam Backup (VBK) file implementation.

    References:
        - CMeta
        - CStgFormat

    Notes:
        - **TODO**: Encryption
        - **TODO**: Incrememental backups

    Args:
        fh: The file handle of the VBK file to read.
        verify: Whether to verify checksums.
    """

    def __init__(self, fh: BinaryIO, verify: bool = True):
        self.fh = fh

        fh.seek(0)
        self.header = c_vbk.StorageHeader(fh)

        self.format_version = self.header.FormatVersion
        self.block_size = self.header.StandardBlockSize

        # First slot starts at PAGE_SIZE because StorageHeader is considered to be PAGE_SIZE large
        self.slot1 = SnapshotSlot(self, PAGE_SIZE)
        # Second slot starts at PAGE_SIZE + slot1 size
        self.slot2 = SnapshotSlot(self, PAGE_SIZE + self.slot1.size)

        populated_slots = filter(lambda slot: slot.header.ContainsSnapshot, (self.slot1, self.slot2))

        if verify:
            populated_slots = filter(lambda slot: slot.verify(), populated_slots)

        if not (active_slot := max(populated_slots, key=lambda slot: slot.descriptor.Version, default=None)):
            raise VBKError("No active VBK metadata slot found")

        self.active_slot: SnapshotSlot = active_slot

        self.root = RootDirectory(
            self,
            self.active_slot.descriptor.DirectoryRoot.RootPage,
            self.active_slot.descriptor.DirectoryRoot.Count,
        )
        self.block_store = MetaVector(
            self,
            StgBlockDescriptorV7 if self.is_v7 else StgBlockDescriptor,
            self.active_slot.descriptor.BlocksStore.RootPage,
            self.active_slot.descriptor.BlocksStore.Count,
        )

    def is_v7(self) -> bool:
        return self.format_version == 7 or self.format_version == 0x10008 or self.format_version >= 9

    def page(self, idx: int) -> bytes:
        """Read a page from the VBK file.

        Args:
            idx: The index of the page to read.
        """
        return self.active_slot.page(idx)

    def get_meta_blob(self, page: int) -> MetaBlob:
        """Read a meta blob from the VBK file.

        Args:
            page: The starting page number of the meta blob to read.
        """
        return self.active_slot._get_meta_blob(page)

    def get(self, path: str, item: DirItem | None = None) -> DirItem:
        """Get a directory item from the VBK file."""
        item = item or self.root

        for part in path.split("/"):
            if not part:
                continue

            for entry in item.iterdir():
                if entry.name == part:
                    item = entry
                    break
            else:
                raise FileNotFoundError(f"File not found: {path}")

        return item


class SnapshotSlot:
    """A snapshot slot in the VBK file.

    References:
        - CSlotHdr
        - SSnapshotDescriptor
        - CSnapshotSlot
        - CMetaStore
        - CMetaObjs
        - SMetaObjRefs
        - SDirRootRec
        - SBlocksStoreHdr

    Notes:
        - **TODO**: Free blocks index (CFreeBlocksIndex, SFreeBlockIndexItem)
        - **TODO**: Deduplication index (CDedupIndex, SDedupIndexItem)
        - **TODO**: Crypto store (CCryptoStore, SCryptoStoreRec)

    Args:
        vbk: The VBK object that the snapshot slot is part of.
        offset: The offset of the snapshot slot in the file.
    """

    def __init__(self, vbk: VBK, offset: int):
        self.vbk = vbk
        self.offset = offset

        self.vbk.fh.seek(offset)
        self.header = c_vbk.SnapshotSlotHeader(vbk.fh)
        self.descriptor = None
        self.grain = None
        self.valid_max_banks = 0
        self.banks = []

        if self.header.ContainsSnapshot:
            self.descriptor = c_vbk.SnapshotDescriptor(vbk.fh)
            self.grain = c_vbk.BanksGrain(vbk.fh)

            self.valid_max_banks = 0xF8 if self.vbk.header.SnapshotSlotFormat == 0 else 0x7F00

            if self.grain.MaxBanks > self.valid_max_banks:
                raise VBKError("Invalid SnapshotSlot: MaxBanks is not valid")
            if self.grain.StoredBanks > self.grain.MaxBanks:
                raise VBKError("Invalid SnapshotSlot: StoredBanks is greater than MaxBanks")

            self.banks = [
                Bank(self.vbk, entry.Offset, entry.Size)
                for entry in c_vbk.BankDescriptor[self.grain.StoredBanks](vbk.fh)
            ]

    def __repr__(self) -> str:
        return f"<SnapshotSlot offset={self.offset:#x}>"

    @cached_property
    def size(self) -> int:
        """The size of the snapshot slot in the file."""
        slot_size = len(c_vbk.SnapshotSlotHeader) + len(c_vbk.SnapshotDescriptor)
        if self.header.ContainsSnapshot:
            slot_size += self.grain.MaxBanks * len(c_vbk.BankDescriptor)
        else:
            slot_size += self.valid_max_banks * len(c_vbk.BankDescriptor)

        if slot_size & (PAGE_SIZE - 1):
            # Round to next page boundary
            slot_size = (slot_size & ~(PAGE_SIZE - 1)) + PAGE_SIZE

        return slot_size

    def verify(self) -> bool:
        """Verify the snapshot slot's CRC.

        Args:
            crc: The CRC to verify against.
        """
        if not self.header.ContainsSnapshot:
            return False

        crc = crc32c if self.vbk.header.SnapshotSlotFormat > 5 else crc32

        # Remainder of SnapshotSlotHeader + SnapshotDescriptor + BanksGrain
        length = 4 + len(c_vbk.SnapshotDescriptor) + 8 + self.grain.MaxBanks * len(c_vbk.BankDescriptor)

        self.vbk.fh.seek(self.offset + 4)  # Skip CRC
        return crc(self.vbk.fh.read(length)) == self.header.CRC

    def page(self, page: int) -> bytes:
        """Read a page from the snapshot slot.

        Args:
            idx: The page number to read.
        """
        return self.banks[page >> 32].page(page & 0xFFFFFFFF)

    def _get_meta_blob(self, page: int) -> MetaBlob:
        """Get a meta blob from the snapshot slot.

        Args:
            page: The page of the first page in the meta blob.
        """
        return MetaBlob(self, page)


class Bank:
    """A bank in the snapshot slot. A bank is a collection of pages.

    References:
        - SBankHdr
        - CBankHdrPage

    Args:
        vbk: The VBK object that the bank is part of.
        offset: The offset of the bank in the file.
        size: The size of the bank in the file.
    """

    def __init__(self, vbk: VBK, offset: int, size: int):
        self.vbk = vbk
        self.offset = offset
        self.size = size

        self.vbk.fh.seek(offset)
        self.header = c_vbk.BankHeader(vbk.fh)

        self.page = lru_cache(128)(self.page)

    def __repr__(self) -> str:
        return f"<Bank offset={self.offset:#x} size={self.size:#x}>"

    def verify(self, crc: int) -> bool:
        """Verify the bank's CRC.

        Args:
            crc: The CRC to verify against.
        """
        crc = crc32c if self.vbk.format_version >= 12 and self.vbk.format_version != 0x10008 else crc32

        self.vbk.fh.seek(self.offset)
        return crc(self.vbk.fh.read(self.size)) == crc

    def page(self, page: int) -> memoryview:
        """Read a page from the bank.

        Args:
            page: The page number to read.
        """
        # Data starts at PAGE_SIZE from bank offset
        self.vbk.fh.seek(self.offset + PAGE_SIZE + (page * PAGE_SIZE))
        return memoryview(self.vbk.fh.read(PAGE_SIZE))


class MetaItem:
    """Base class for value types in a meta vector."""

    __struct__: Structure = None

    def __init__(self, vbk: VBK, buf: bytes):
        self.vbk = vbk
        self.buf = buf
        self.entry = None

        if self.__struct__:
            self.entry = self.__struct__(buf)

    @classmethod
    def from_bytes(cls, vbk: VBK, buf: bytes) -> MetaItem:
        return cls(vbk, buf)


class DirItem(MetaItem):
    """Base class for directory items.

    References:
        - SDirItemRec
        - CDir
    """

    __struct__ = c_vbk.DirItemRecord

    def __init__(self, vbk: VBK, buf: bytes):
        super().__init__(vbk, buf)
        self.name = self.entry.Name[: self.entry.NameLength].decode("utf-8")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    @classmethod
    def from_bytes(
        cls, vbk: VBK, buf: bytes
    ) -> SubFolderItem | ExtFibItem | IntFibItem | PatchItem | IncrementItem | DirItem:
        cls_map = {
            c_vbk.DirItemType.SubFolder: SubFolderItem,
            c_vbk.DirItemType.ExtFib: ExtFibItem,
            c_vbk.DirItemType.IntFib: IntFibItem,
            c_vbk.DirItemType.Patch: PatchItem,
            c_vbk.DirItemType.Increment: IncrementItem,
        }

        type = c_vbk.DirItemType(buf[:4])
        return cls_map.get(type, cls)(vbk, buf)

    @cached_property
    def type(self) -> c_vbk.DirItemType:
        """The type of the directory item."""
        return self.entry.Type

    @cached_property
    def size(self) -> int:
        raise VBKError(f"Size not available for {self!r}")

    @cached_property
    def properties(self) -> PropertiesDictionary | None:
        """The properties of the directory item, if it has them."""
        if self.entry.PropsRootPage == -1:
            return None

        return PropertiesDictionary(self.vbk, self.entry.PropsRootPage)

    def is_dir(self) -> bool:
        """Return whether the directory item is a directory."""
        return False

    def is_file(self) -> bool:
        """Return whether the directory item is a file."""
        return self.is_internal_file() or self.is_external_file()

    def is_internal_file(self) -> bool:
        """Return whether the directory item is an internal file."""
        return False

    def is_external_file(self) -> bool:
        """Return whether the directory item is an external file."""
        return False

    def listdir(self) -> dict[str, DirItem]:
        """Return a dictionary of the items in the directory."""
        return {item.name: item for item in self.iterdir()}

    def iterdir(self) -> Iterator[DirItem]:
        """Iterate over the items in the directory."""
        raise NotADirectoryError(f"{self!r} is not a directory")

    def open(self) -> BinaryIO:
        """Open the file for reading."""
        raise NotAFileError(f"{self!r} is not a file")


class RootDirectory(DirItem):
    """Special directory item for the root directory. Does not actually exist in the VBK file."""

    def __init__(self, vbk: VBK, page: int, count: int):
        super().__init__(vbk, b"\x00" * len(c_vbk.DirItemRecord))
        self.name = "/"
        self.root = page
        self.count = count

    def __repr__(self) -> str:
        return f"<RootDirectory root={self.root} count={self.count}>"

    def is_dir(self) -> bool:
        return True

    def iterdir(self) -> Iterator[DirItem]:
        yield from MetaVector(self.vbk, DirItem, self.root, self.count)


class SubFolderItem(DirItem):
    """Directory item for a subfolder (directory type).

    References:
        - CSubFolderHdr
        - CFolderMeta
    """

    def __init__(self, vbk: VBK, buf: bytes):
        super().__init__(vbk, buf)
        self.root = self.entry.SubFolder.RootPage
        self.count = self.entry.SubFolder.Count

    def __repr__(self) -> str:
        return f"<SubFolderItem name={self.name!r} root={self.root} count={self.count}>"

    def is_dir(self) -> bool:
        return True

    def iterdir(self) -> Iterator[DirItem]:
        yield from MetaVector(self.vbk, DirItem, self.root, self.count)


class ExtFibItem(DirItem):
    """Directory item for an external file.

    References:
        - SFibHdr
        - CExtFibMeta
    """

    def __repr__(self) -> str:
        return f"<ExtFibItem name={self.name!r} size={self.size}>"

    @cached_property
    def size(self) -> int:
        return self.entry.ExtFib.FibSize

    def is_external_file(self) -> bool:
        return True


class IntFibItem(DirItem):
    """Directory item for an internal file.

    References:
        - SFibHdr
        - CIntFibMeta
    """

    def __init__(self, vbk: VBK, buf: bytes):
        super().__init__(vbk, buf)

    def __repr__(self) -> str:
        return f"<IntFibItem name={self.name!r} size={self.size}>"

    @cached_property
    def size(self) -> int:
        return self.entry.IntFib.FibSize

    def is_internal_file(self) -> bool:
        return True

    def open(self) -> FibStream:
        return FibStream(
            self.vbk,
            self.entry.IntFib.BlocksVector.RootPage,
            self.entry.IntFib.BlocksVector.Count,
            self.size,
        )


class PatchItem(DirItem):
    """Directory item for a patch.

    Notes:
        - **TODO**: SPatchHdr
        - **TODO**: CPatchMeta
    """

    def __repr__(self) -> str:
        return f"<PatchItem name={self.name!r} size={self.size}>"

    @cached_property
    def size(self) -> int:
        return self.entry.Patch.FibSize


class IncrementItem(DirItem):
    """Directory item for an increment.

    Notes:
        - **TODO**: SIncrementHdr
        - **TODO**: CIncrementMeta
    """

    def __repr__(self) -> str:
        return f"<IncrementItem name={self.name!r} size={self.size}>"

    @cached_property
    def size(self) -> int:
        return self.entry.Increment.FibSize


class MetaTableDescriptor(MetaItem):
    """A descriptor for a meta table in the VBK file.

    References:
        - SMetaTableDescriptor
    """

    __struct__ = c_vbk.MetaTableDescriptor

    def __repr__(self) -> str:
        return f"<MetaTableDescriptor page={self.page} block_size={self.block_size:#x} count={self.count}>"

    @cached_property
    def page(self) -> int:
        """The page number of the first page in the meta table."""
        return self.entry.RootPage

    @cached_property
    def block_size(self) -> int:
        """The block size of the meta table."""
        return self.entry.BlockSize

    @cached_property
    def count(self) -> int:
        """The number of entries in the meta table."""
        return self.entry.Count


class FibBlockDescriptor(MetaItem):
    """A descriptor for a FIB (File In Backup) block in the VBK file.

    References:
        - SFibBlockDescriptor
    """

    __struct__ = c_vbk.FibBlockDescriptor

    def __repr__(self) -> str:
        return f"<FibBlockDescriptor block_size={self.block_size:#x} type={self.type.name} block_id={self.block_id}>"

    def is_normal(self) -> bool:
        """Return whether the block is a normal block."""
        return self.type == c_vbk.BlockLocationType.Normal

    def is_sparse(self) -> bool:
        """Return whether the block is a sparse block."""
        return self.type == c_vbk.BlockLocationType.Sparse

    def is_reserved(self) -> bool:
        """Return whether the block is a reserved block."""
        return self.type == c_vbk.BlockLocationType.Reserved

    def is_archived(self) -> bool:
        """Return whether the block is an archived block.

        If the block is archived, the compressed size and compression type are stored in the block ID::

            BlockId = CompressedSize | (CompressionType << 32)

        Notes:
            - **TODO**: Verify the above
        """
        return self.type == c_vbk.BlockLocationType.Archived

    def is_block_in_blob(self) -> bool:
        """Return whether the block is a block in a blob.

        If the block is in a blob, the block ID, blob ID and offset are stored in the block ID::

            BlockId = BlockId? & 0x3FFFFFF | (BlobId << 26) | ((Offset >> 9) << 42)

        Notes:
            - **TODO**: Verify the above
        """
        return self.type == c_vbk.BlockLocationType.BlockInBlob

    def is_block_in_blob_reserved(self) -> bool:
        """Return whether the block is a reserved block in a blob.

        If the block is a reserved block in a blob, the block ID is stored in the block ID::

            BlockId = BlockId? | 0xFFFFFFFFFC000000

        Notes:
            - **TODO**: Verify the above
        """
        return self.type == c_vbk.BlockLocationType.BlockInBlobReserved

    @cached_property
    def block_size(self) -> int:
        """The size of the block."""
        return self.entry.BlockSize

    @cached_property
    def type(self) -> c_vbk.BlockLocationType:
        """The type of the block."""
        return self.entry.Type

    @cached_property
    def digest(self) -> bytes:
        """The digest of the block."""
        return self.entry.Digest

    @cached_property
    def block_id(self) -> int:
        """The ID of the block."""
        return self.entry.BlockId

    @cached_property
    def flags(self) -> c_vbk.BlockFlags:
        """The flags of the block."""
        return self.entry.Flags


class FibBlockDescriptorV7(FibBlockDescriptor):
    """A descriptor for a FIB (File In Backup) block in the VBK file. Version 7.

    References:
        - SFibBlockDescriptorV7
    """

    __struct__ = c_vbk.FibBlockDescriptorV7

    def __repr__(self) -> str:
        return f"<FibBlockDescriptorV7 block_size={self.block_size:#x} type={self.type.name} block_id={self.block_id}>"

    @cached_property
    def keyset_id(self) -> bytes:
        return self.entry.KeySetId


class StgBlockDescriptor(MetaItem):
    """A descriptor for a storage block in the VBK file.

    References:
        - SStgBlockDescriptor
    """

    __struct__ = c_vbk.StgBlockDescriptor

    def __repr__(self) -> str:
        return (
            f"<StgBlockDescriptor format={self.format} usage_counter={self.usage_counter} offset={self.offset:#x}"
            f" allocated_size={self.allocated_size:#x} deduplication={self.deduplication}"
            f" compression_type={self.compression_type.name} compressed_size={self.compressed_size}"
            f" source_size={self.source_size}>"
        )

    def is_legacy(self) -> bool:
        """Return whether the block is a legacy block."""
        return self.format != 4

    def is_data_block(self) -> bool:
        """Return whether the block is a data block.

        A data block is a block that has a usage counter greater than 0.
        """
        return self.usage_counter != 0

    def is_dedup_block(self) -> bool:
        """Return whether the block is a dedup block.

        Notes:
            - **TODO**: What is this?
        """
        return self.deduplication != 0

    def is_compressed(self) -> bool:
        """Return whether the block is compressed."""
        return self.compression_type != c_vbk.CompressionType.Plain

    @cached_property
    def format(self) -> int:
        """The format of the block."""
        return self.entry.Format

    @cached_property
    def usage_counter(self) -> int:
        """The usage counter of the block."""
        return self.entry.UsageCounter

    @cached_property
    def offset(self) -> int:
        """The offset of the block."""
        return self.entry.Offset

    @cached_property
    def allocated_size(self) -> int:
        """The allocated size of the block."""
        return self.entry.AllocatedSize

    @cached_property
    def deduplication(self) -> int:
        """The deduplication of the block."""
        return self.entry.Deduplication

    @cached_property
    def digest(self) -> bytes:
        """The digest of the block."""
        return self.entry.Digest

    @cached_property
    def compression_type(self) -> c_vbk.CompressionType:
        """The compression type of the block."""
        return self.entry.CompressionType

    @cached_property
    def compressed_size(self) -> int:
        """The compressed size of the block."""
        return self.entry.CompressedSize

    @cached_property
    def source_size(self) -> int:
        """The source size of the block."""
        return self.entry.SourceSize


class StgBlockDescriptorV7(StgBlockDescriptor):
    """A descriptor for a storage block in the VBK file. Version 7.

    References:
        - SStgBlockDescriptorV7
    """

    __struct__ = c_vbk.StgBlockDescriptorV7

    def __repr__(self) -> str:
        return (
            f"<StgBlockDescriptorV7 format={self.format} usage_counter={self.usage_counter} offset={self.offset:#x}"
            f" allocated_size={self.allocated_size:#x} deduplication={self.deduplication}"
            f" compression_type={self.compression_type.name} compressed_size={self.compressed_size:#x}"
            f" source_size={self.source_size:#x}>"
        )

    @cached_property
    def keyset_id(self) -> bytes:
        """The keyset ID of the block."""
        return self.entry.KeySetId


class PropertiesDictionary(dict):
    """A dictionary of properties in the VBK file.

    References:
        - CPropsDictionary
        - CDirElemPropsRW

    Args:
        vbk: The VBK object that the properties dictionary is part of.
        page: The page number of the meta blob of the properties dictionary.
    """

    def __init__(self, vbk: VBK, page: int):
        self.vbk = vbk
        self.page = page

        buf = BytesIO(self.vbk.get_meta_blob(page).data())
        buf.seek(len(c_vbk.MetaBlobHeader))

        while True:
            value_type = c_vbk.PropertyType(buf)
            if value_type == c_vbk.PropertyType.End:
                break

            name_length = c_vbk.uint32(buf)
            name = buf.read(name_length).decode("utf-8")

            if value_type == c_vbk.PropertyType.UInt32:
                value = c_vbk.uint32(buf)
            elif value_type == c_vbk.PropertyType.UInt64:
                value = c_vbk.uint64(buf)
            elif value_type == c_vbk.PropertyType.AString:
                value = buf.read(c_vbk.uint32(buf)).decode("utf-8")
            elif value_type == c_vbk.PropertyType.WString:
                value = buf.read(c_vbk.uint32(buf)).decode("utf-16-le")
            elif value_type == c_vbk.PropertyType.Binary:
                value = buf.read(c_vbk.uint32(buf))
            elif value_type == c_vbk.PropertyType.Boolean:
                value = bool(c_vbk.uint32(buf))
            else:
                raise VBKError(f"Unsupported property type: {value_type}")

            self[name] = value


class MetaBlob:
    """A meta blob in the VBK file.

    A meta blob is a list of pages that are linked together. Each page has a header (``MetaBlobHeader``) with
    a ``NextPage`` field that points to the next page in the blob. The last page has a ``NextPage`` field of -1.

    References:
        - CMetaBlobRW

    Args:
        slot: The snapshot slot that the meta blob is part of.
        root: The page number of the first page in the meta blob.
    """

    def __init__(self, slot: SnapshotSlot, root: int):
        self.slot = slot
        self.root = root

    def __repr__(self) -> str:
        return f"<MetaBlob root={self.root}>"

    def _read(self) -> Iterator[int, memoryview]:
        page = self.root

        while page != -1:
            buf = self.slot.page(page)
            yield page, buf

            page = int.from_bytes(buf[:8], "little", signed=True)

    def pages(self) -> Iterator[int]:
        return (page for page, _ in self._read())

    def data(self) -> bytes:
        return b"".join(buf for _, buf in self._read())


T = TypeVar("T", bound=MetaItem)


class MetaVector(Generic[T]):
    """A vector of meta items in the VBK file.

    References:
        - CMetaVec

    Args:
        vbk: The VBK object that the vector is part of.
        type_: The type of the items in the vector.
        page: The page number of the first page in the vector.
        count: The number of items in the vector.
    """

    def __new__(cls, vbk: VBK, *args, **kwargs):
        if vbk.format_version >= 12 and vbk.format_version != 0x10008:
            cls = MetaVector2
        return super().__new__(cls)

    def __init__(self, vbk: VBK, type_: type[T], page: int, count: int):
        self.vbk = vbk
        self.type = type_
        self.page = page
        self.count = count

        self._entry_size = len(self.type.__struct__)
        self._entries_per_page = PAGE_SIZE // self._entry_size
        self._pages = list(self.vbk.get_meta_blob(page).pages())

        self.get = lru_cache(128)(self.get)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} type={self.type.__name__} count={self.count}>"

    def __iter__(self) -> Iterator[T]:
        return (self.get(i) for i in range(self.count))

    def data(self, idx: int) -> bytes:
        """Read the data for an entry in the vector.

        Args:
            idx: The index of the entry to read.
        """
        page_id, offset = divmod(idx, self._entries_per_page)
        page = self._pages[page_id]
        offset = (offset * self._entry_size) + 8

        buf = self.vbk.page(page)
        entry = buf[offset : offset + self._entry_size]
        return entry

    def get(self, idx: int) -> T:
        """Get an entry from the vector.

        Args:
            idx: The index of the entry to get.
        """
        if idx >= self.count:
            raise IndexError("MetaVector2 index out of range")
        return self.type.from_bytes(self.vbk, self.data(idx))


class MetaVector2(MetaVector[T]):
    """A vector of meta items in the VBK file. Version 2.

    MetaVector2 is essentially a table of page numbers that contain the vector entries.
    The table pages of a MetaVector2 have a 8-32 byte header, so we can hold a maximum of 508-511 entries per page.
    Read the comments in _lookup_page for more information.

    References:
        - CMetaVec2

    Args:
        vbk: The VBK object that the vector is part of.
        type_: The type of the items in the vector.
        page: The page number of the first page in the vector.
        count: The number of items in the vector.
    """

    _MAX_TABLE_ENTRIES_PER_PAGE = PAGE_SIZE // 8
    _MAX_TABLE_ENTRIES_LOOKUP = (
        _MAX_TABLE_ENTRIES_PER_PAGE - 1,
        _MAX_TABLE_ENTRIES_PER_PAGE - 4,
        _MAX_TABLE_ENTRIES_PER_PAGE - 1,
    )

    def __init__(self, vbk: VBK, type_: type[T], page: int, count: int):
        super().__init__(vbk, type_, page, count)

        # It's not actually a meta blob, but the same mechanism is used (next page pointer in the header)
        # The table itself is essentially a big array of 64 bit integers, so cast it to a memoryview of that
        self._table = xmemoryview(self.vbk.get_meta_blob(page).data(), "<q")
        self._lookup_page = lru_cache(128)(self._lookup_page)

    def _lookup_page(self, idx: int) -> int:
        """Look up the page number for an entry in the vector.

        Args:
            idx: The page index to lookup the page number for.
        """

        # MetaVec2 pages are a little special
        # The first page has a 16 byte header:
        # - 8 bytes for the next page number
        # - 8 bytes for the root page number
        # The second page has a 32 byte header:
        # - 8 bytes for the next page number
        # - 8 bytes for the second page number (this page)
        # - 8 bytes for the third page number
        # - 8 bytes for the fourth page number
        # The third and fourth pages only have a 8 byte header:
        # - 8 bytes for the next page number
        # The fifth page has a 32 byte header again containing the next 3 page numbers
        # We've not seen a table large enough to see this repeat more than once, but presumably it does
        #
        # This means that the first page can hold 510 entries, the second 508, and the third and fourth 511 each
        # The fifth page can hold 508 entries again, and so on

        if idx < self._MAX_TABLE_ENTRIES_PER_PAGE - 2:
            return self._table[idx + 2]  # Skip the header

        idx -= self._MAX_TABLE_ENTRIES_PER_PAGE - 2
        table_idx = 1
        while True:
            max_entries = self._MAX_TABLE_ENTRIES_LOOKUP[table_idx % 3]

            if idx < max_entries:
                table_offset = table_idx * self._MAX_TABLE_ENTRIES_PER_PAGE
                return self._table[table_offset + (self._MAX_TABLE_ENTRIES_PER_PAGE - max_entries) + idx]

            idx -= max_entries
            table_idx += 1

    def data(self, idx: int) -> bytes:
        """Read the data for an entry in the vector.

        Args:
            idx: The index of the entry to read.
        """
        page_idx, offset = divmod(idx, self._entries_per_page)
        offset *= self._entry_size

        page_no = self._lookup_page(page_idx)
        return self.vbk.page(page_no)[offset : offset + self._entry_size]


class FibMetaSparseTable:
    """A sparse table of FIB (File In Backup) blocks in the VBK file.

    References:
        - CFibMetaSparseTable

    Args:
        vbk: The VBK object that the sparse table is part of.
        page: The page number of the first page in the table.
        count: The number of entries in the table.
    """

    # This seems hardcoded? Probably calculated from something but unknown for now
    MAX_ENTRIES_PER_TABLE = 1088

    def __init__(self, vbk: VBK, page: int, count: int):
        self.vbk = vbk
        self.page = page
        self.count = count

        # Newer versions use a different block descriptor
        self.type = FibBlockDescriptorV7 if self.vbk.is_v7() else FibBlockDescriptor
        self._fake_sparse = self.type(
            self.vbk,
            self.type.__struct__(
                BlockSize=self.vbk.block_size,
                Type=c_vbk.BlockLocationType.Sparse,
            ).dumps(),
        )

        self._table_count = (count + self.MAX_ENTRIES_PER_TABLE - 1) // self.MAX_ENTRIES_PER_TABLE
        self._vec = MetaVector(vbk, MetaTableDescriptor, page, self._table_count)

        self._open_table = lru_cache(128)(self._open_table)

    def _open_table(self, page: int, count: int) -> MetaVector[FibBlockDescriptor | FibBlockDescriptorV7]:
        return MetaVector(self.vbk, self.type, page, count)

    def get(self, idx: int) -> FibBlockDescriptor | FibBlockDescriptorV7:
        """Get a block descriptor from the sparse table.

        Args:
            idx: The index of the block descriptor to get.
        """
        if idx >= self.count:
            raise IndexError("MetaSparseTable index out of range")

        table_idx, entry_idx = divmod(idx, self.MAX_ENTRIES_PER_TABLE)

        table_entry = self._vec.get(table_idx)
        if table_entry.page == -1:
            return self._fake_sparse

        return self._open_table(table_entry.page, table_entry.count).get(entry_idx)


class FibStream(AlignedStream):
    """A stream for reading FIB (File In Backup) blocks in the VBK file.

    Args:
        vbk: The VBK object that the stream is part of.
        page: The page number of the :class:`FibMetaSparseTable`.
        count: The number of entries in the meta sparse table.
        size: The size of the stream.
    """

    def __init__(self, vbk: VBK, page: int, count: int, size: int):
        self.vbk = vbk
        self.page = page
        self.count = count

        self.table = FibMetaSparseTable(vbk, page, count)

        super().__init__(size, align=vbk.block_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []
        # TODO: Can the block size change per file?
        block_size = self.vbk.block_size

        while length > 0:
            block_idx = offset // block_size
            offset_in_block = offset % block_size

            read_size = min(length, block_size - offset_in_block)

            block_desc = self.table.get(block_idx)

            if block_desc.is_normal():
                block = self.vbk.block_store.get(block_desc.block_id)

                self.vbk.fh.seek(block.offset)
                buf = self.vbk.fh.read(block.compressed_size)

                if block.is_compressed():
                    if block.compression_type == c_vbk.CompressionType.LZ4:
                        # First 12 bytes are Lz4BlockHeader
                        buf = lz4.decompress(memoryview(buf)[12:], block.source_size)
                    else:
                        raise VBKError(f"Unsupported compression type: {block.compression_type}")

                result.append(buf[offset_in_block : offset_in_block + read_size])
            elif block_desc.is_sparse():
                result.append(b"\x00" * read_size)
            else:
                raise VBKError(f"Unsupported block type: {block_desc.type}")

            offset += read_size
            length -= read_size

        return b"".join(result)
