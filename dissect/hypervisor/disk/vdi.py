from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.util.stream import AlignedStream
from dissect.util.xmemoryview import xmemoryview

from dissect.hypervisor.disk.c_vdi import VDI_IMAGE_BLOCK_FREE, VDI_IMAGE_BLOCK_ZERO, VDI_IMAGE_SIGNATURE, c_vdi
from dissect.hypervisor.exceptions import Error

if TYPE_CHECKING:
    from types import TracebackType

    from typing_extensions import Self


class VDI:
    """VirtualBox Virtual Disk Image (VDI) implementation.

    Use :method:`open` to get a stream for reading from the VDI file. The stream will handle reading
    from the parent disk if necessary (and provided).

    If provided with a file-like object, the caller is responsible for closing it.
    When provided with a path, the VDI class will manage the file handle.

    If providing a parent file-like object, the caller is responsible for the lifecycle of that object.

    Args:
        fh: File-like object or path of the VDI file.
        parent: Optional file-like object for the parent disk (for differencing disks).
    """

    def __init__(self, fh: BinaryIO | Path, parent: BinaryIO | None = None):
        if isinstance(fh, Path):
            self.path = fh
            self.fh = self.path.open("rb")
        else:
            self.path = None
            self.fh = fh

        self.parent = parent

        self.fh.seek(0)
        self.preheader = c_vdi.VDIPREHEADER(self.fh)
        if self.preheader.u32Signature != VDI_IMAGE_SIGNATURE:
            raise Error(
                f"Invalid VDI signature, expected {VDI_IMAGE_SIGNATURE:#08X}, got {self.preheader.u32Signature:#08X}"
            )

        self.header = c_vdi.VDIHEADER1PLUS(self.fh)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    @property
    def type(self) -> c_vdi.VDI_IMAGE_TYPE:
        """The type of the VDI file."""
        return self.header.u32Type

    @property
    def flags(self) -> c_vdi.VDI_IMAGE_FLAGS:
        """The flags of the VDI file."""
        return self.header.fFlags

    @property
    def size(self) -> int:
        """The size of the virtual disk."""
        return self.header.cbDisk

    @property
    def block_size(self) -> int:
        """The size of each block in the VDI file."""
        return self.header.cbBlock

    @property
    def data_offset(self) -> int:
        """The offset to the data blocks."""
        return self.header.offData

    @property
    def blocks_offset(self) -> int:
        """The offset to the block allocation table."""
        return self.header.offBlocks

    @property
    def number_of_blocks(self) -> int:
        """The number of blocks in the VDI file."""
        return self.header.cBlocks

    def open(self) -> VDIStream:
        """Open a stream to read from the VDI file."""
        return VDIStream(self)

    def close(self) -> None:
        """Close the VDI file handle."""
        if self.path is not None:
            self.fh.close()


class VDIStream(AlignedStream):
    def __init__(self, vdi: VDI):
        self.vdi = vdi
        self.block_size = vdi.block_size

        self.fh = self.vdi.fh
        self.fh.seek(self.vdi.blocks_offset)
        self.map = xmemoryview(self.fh.read(4 * self.vdi.number_of_blocks), "<i")
        super().__init__(vdi.size, align=self.block_size)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        block_idx, offset_in_block = divmod(offset, self.block_size)
        while length > 0:
            read_len = min(length, max(length, self.block_size - offset_in_block))

            block = self.map[block_idx]
            if block == VDI_IMAGE_BLOCK_FREE:
                if self.vdi.parent is not None:
                    self.vdi.parent.seek(offset)
                    result.append(self.vdi.parent.read(read_len))
                else:
                    result.append(b"\x00" * read_len)
            elif block == VDI_IMAGE_BLOCK_ZERO:
                result.append(b"\x00" * read_len)
            else:
                self.fh.seek(self.vdi.data_offset + (block * self.block_size) + offset_in_block)
                result.append(self.fh.read(read_len))

            offset += read_len
            length -= read_len
            block_idx += 1

        return b"".join(result)
