from __future__ import annotations

import bz2
import hashlib
import hmac
import io
import lzma
import plistlib
import struct
import zlib
from bisect import bisect_right
from functools import cached_property, lru_cache
from typing import BinaryIO, NamedTuple
from uuid import UUID

from dissect.util.compression import adc, lzfse
from dissect.util.stream import AlignedStream

from dissect.hypervisor.disk.c_dmg import (
    BLOCK_TYPE,
    ENCRCDSA_MAGIC,
    KOLY_MAGIC,
    KOLY_SIZE,
    MISH_MAGIC,
    SECTOR_SIZE,
    c_dmg,
)
from dissect.hypervisor.exceptions import Error, InvalidSignature

try:
    from Crypto.Cipher import AES

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

# Block types that carry no sector data and can be skipped while building the chunk map.
_SKIP_TYPES = frozenset({BLOCK_TYPE.COMMENT, BLOCK_TYPE.TERMINATOR})

# Block types that read back as zeroes without consuming any bytes from the data fork.
_ZERO_TYPES = frozenset({BLOCK_TYPE.ZERO_FILL, BLOCK_TYPE.IGNORE})


class Chunk(NamedTuple):
    """A single, contiguous run of sectors in the (decompressed) disk image."""

    sector: int
    count: int
    type: BLOCK_TYPE
    offset: int
    length: int


class DMG:
    """Apple Universal Disk Image Format (UDIF) disk image.

    A DMG (``.dmg``) file is a container that exposes a raw disk image (typically wrapping an APFS or HFS+ volume). The
    actual disk data lives in a "data fork" at the start of the file, optionally split into compressed chunks, and is
    described by a set of ``BLKX`` (``mish``) tables stored in an XML property list. A fixed 512 byte ``koly`` trailer
    at the very end of the file ties everything together.

    Currently supported (UDIF) variants are uncompressed (``UDRW``/``UDRO``), zlib (``UDZO``), bzip2 (``UDBZ``),
    LZFSE (``ULFO``), LZMA (``ULMO``) and ADC (``UDCO``), including the zeroed and unallocated runs such an image
    uses to describe empty space. Note that the sparse image containers (``.sparseimage`` and ``.sparsebundle``)
    are a different format and are not supported.

    Password-encrypted (``encrcdsa``, AES-128 and AES-256) DMGs are transparently decrypted when a ``password`` is
    provided. This requires the optional ``pycryptodome`` dependency.

    Args:
        fh: File-like object containing the DMG image.
        password: Optional password to decrypt an encrypted (``encrcdsa``) DMG.

    Raises:
        InvalidSignature: If the file does not have a valid UDIF trailer (koly block).
        Error: If the DMG has no property list to describe the image with.
        RuntimeError: If the DMG is encrypted and the ``pycryptodome`` dependency is not available.
        ValueError: If the DMG is encrypted and no or a wrong password was provided.

    Resources:
        - https://newosxbook.com/DMG.html
        - https://github.com/nlitsme/encrypteddmg
        - https://github.com/Lekensteyn/dmg2img
    """

    def __init__(self, fh: BinaryIO, password: str | bytes | None = None):
        fh.seek(0)
        if fh.read(len(ENCRCDSA_MAGIC)) == ENCRCDSA_MAGIC:
            fh = _open_encrypted(fh, password)

        self.fh = fh

        # Only the koly trailer is read up front. It is a fixed 512 byte block at the very end of the file and holds
        # everything needed to describe the image; the (potentially large) XML property list is only parsed on demand.
        fh.seek(-KOLY_SIZE, io.SEEK_END)
        self.koly = c_dmg.UDIFResourceFile(fh)
        if self.koly.Signature != KOLY_MAGIC:
            raise InvalidSignature(f"Not a valid UDIF image (expected {KOLY_MAGIC!r}, got {self.koly.Signature!r})")

        if not self.koly.XMLLength:
            raise Error("DMG has no XML property list")

        self.guid = UUID(bytes=self.koly.SegmentID)
        self.sector_count = self.koly.SectorCount
        self.size = self.sector_count * SECTOR_SIZE

    @cached_property
    def chunks(self) -> list[Chunk]:
        """The flattened, sorted list of :class:`Chunk` runs that make up the disk image."""
        self.fh.seek(self.koly.XMLOffset)
        plist = plistlib.loads(self.fh.read(self.koly.XMLLength))

        try:
            blkx = plist["resource-fork"]["blkx"]
        except KeyError:
            raise Error("DMG property list does not contain any blkx resources")

        chunks: list[Chunk] = []
        for resource in blkx:
            table = c_dmg.BLKXTable(resource["Data"])
            if table.Signature != MISH_MAGIC:
                continue

            for entry in table.Entries:
                if entry.EntryType in _SKIP_TYPES:
                    continue

                chunks.append(
                    Chunk(
                        sector=table.SectorNumber + entry.SectorNumber,
                        count=entry.SectorCount,
                        type=entry.EntryType,
                        offset=self.koly.DataForkOffset + entry.CompressedOffset,
                        length=entry.CompressedLength,
                    )
                )

        # Despite that the blocks are usually in the correct order,
        # this is not guaranteed, so sort them just to be safe.
        chunks.sort(key=lambda chunk: chunk.sector)
        return chunks

    def open(self) -> DMGStream:
        """Open the reconstructed raw disk image as a file-like object."""
        return DMGStream(self.fh, self.chunks, self.size)

    def __repr__(self) -> str:
        return f"<DMG guid={self.guid} size={self.size} sectors={self.sector_count}>"


class DMGStream(AlignedStream):
    """A file-like object that transparently decompresses a UDIF DMG data fork into a raw disk image.

    Args:
        fh: File-like object of the DMG file.
        chunks: The list of :class:`Chunk` runs, sorted by start sector.
        size: The total size of the (decompressed) disk image in bytes.
    """

    def __init__(self, fh: BinaryIO, chunks: list[Chunk], size: int):
        super().__init__(size)
        self.fh = fh
        self.chunks = chunks

        # Precompute the start sectors so the read path can binary search them.
        self._sectors = [chunk.sector for chunk in chunks]

        # Decompressing a chunk is relatively expensive, and a single chunk usually spans several aligned reads, so we
        # cache the most recently used decompressed chunks. Only compressed chunks are cached, as sparse and raw runs
        # (which may cover many gigabytes in a single chunk) are served without ever materializing the full chunk.
        self._read_compressed_chunk = lru_cache(maxsize=8)(self._read_compressed_chunk)

    def _read(self, offset: int, length: int) -> bytes:
        result = []

        length = min(length, self.size - offset)
        pos = offset

        # Find the first chunk that could contain ``offset``.
        idx = max(bisect_right(self._sectors, offset // SECTOR_SIZE) - 1, 0)

        while length > 0:
            if idx >= len(self.chunks):
                # Past the last described chunk, pad with zeroes.
                result.append(b"\x00" * length)
                break

            chunk = self.chunks[idx]
            chunk_start = chunk.sector * SECTOR_SIZE
            chunk_size = chunk.count * SECTOR_SIZE
            chunk_end = chunk_start + chunk_size

            if pos < chunk_start:
                # There is a gap before this chunk that is not described, treat it as sparse (zeroes).
                gap = min(chunk_start - pos, length)
                result.append(b"\x00" * gap)
                pos += gap
                length -= gap
                continue

            if pos >= chunk_end:
                idx += 1
                continue

            inner = pos - chunk_start
            take = min(chunk_size - inner, length)

            if chunk.type in _ZERO_TYPES:
                # Sparse/zeroed run, no data in the data fork. Only emit the bytes we actually need.
                result.append(b"\x00" * take)
            elif chunk.type == BLOCK_TYPE.RAW:
                # Uncompressed, read only the requested slice straight from the data fork.
                self.fh.seek(chunk.offset + inner)
                result.append(self.fh.read(take))
            else:
                # Compressed, the whole chunk has to be decompressed. This is cached, so slicing it is cheap.
                result.append(self._read_compressed_chunk(idx)[inner : inner + take])

            pos += take
            length -= take
            idx += 1

        return b"".join(result)

    def _read_compressed_chunk(self, idx: int) -> bytes:
        chunk = self.chunks[idx]
        size = chunk.count * SECTOR_SIZE

        self.fh.seek(chunk.offset)
        data = self.fh.read(chunk.length)

        if chunk.type == BLOCK_TYPE.ZLIB:
            buf = zlib.decompress(data)
        elif chunk.type == BLOCK_TYPE.BZLIB:
            buf = bz2.decompress(data)
        elif chunk.type == BLOCK_TYPE.LZFSE:
            buf = lzfse.decompress(data)
        elif chunk.type == BLOCK_TYPE.LZMA:
            buf = lzma.decompress(data)
        elif chunk.type == BLOCK_TYPE.ADC:
            buf = adc.decompress(data)
        else:
            raise Error(f"Unsupported DMG block type: {chunk.type}")

        if len(buf) != size:
            raise Error(f"Decompressed chunk size mismatch: got {len(buf)}, expected {size}")

        return buf


# Marker at the end of a correctly unwrapped keyblob, right before the PKCS#7 padding.
_CKIE_MARKER = b"CKIE\x00"


def _open_encrypted(fh: BinaryIO, password: str | bytes | None) -> EncryptedStream:
    """Derive the encryption keys of an ``encrcdsa`` DMG and return a stream that decrypts the wrapped UDIF image.

    The key derivation follows Apple's version 2 password-wrapped scheme: a key-encryption-key is derived from the
    password with PBKDF2-HMAC-SHA1, used to AES-unwrap a keyblob holding the AES data key and the HMAC-SHA1 key.

    Args:
        fh: File-like object positioned at an ``encrcdsa`` image.
        password: The password to decrypt the image with.
    """
    if not HAS_PYCRYPTODOME:
        raise RuntimeError("No crypto module available")
    if password is None:
        raise ValueError("DMG is encrypted but no password was provided")
    if isinstance(password, str):
        password = password.encode()

    fh.seek(0)
    header = c_dmg.EncrcdsaHeader(fh)
    # The key blob(s) are located through a small pointer table that follows the header.
    pointer = c_dmg.EncrcdsaKeyPointer(fh)
    fh.seek(pointer.Offset)
    blob = c_dmg.EncrcdsaKeyBlob(fh)

    # Derive the key-encryption-key and AES-unwrap the keyblob.
    kek = hashlib.pbkdf2_hmac(
        "sha1", password, blob.KDFSalt[: blob.KDFSaltLen], blob.KDFIterationCount, blob.BlobEncKeyBits // 8
    )
    unwrapped = AES.new(kek, AES.MODE_CBC, blob.BlobEncIV[:16]).decrypt(blob.EncryptedKeyblob)

    # A correct unwrap ends in PKCS#7 padding followed by a fixed marker. Anything else means a wrong password.
    pad = unwrapped[-1] if unwrapped else 0
    if not 1 <= pad <= 16 or unwrapped[:-pad][-len(_CKIE_MARKER) :] != _CKIE_MARKER:
        raise ValueError("Failed to decrypt DMG keyblob (wrong password?)")

    keydata = unwrapped[: -pad - len(_CKIE_MARKER)]
    key_bytes = header.KeyBits // 8
    aes_key = keydata[:key_bytes]
    hmac_key = keydata[key_bytes : key_bytes + 20]

    return EncryptedStream(fh, aes_key, hmac_key, header.DataOffset, header.BlockSize, header.DataSize)


class EncryptedStream(AlignedStream):
    """A file-like object that transparently decrypts the UDIF image inside an ``encrcdsa`` DMG.

    The data is stored as independently AES-CBC encrypted blocks of ``block_size`` bytes. The IV for each block is
    derived from an HMAC-SHA1 of its (big-endian) block number, which makes random access straightforward.

    Args:
        fh: File-like object of the encrypted DMG.
        aes_key: The AES key for the data blocks.
        hmac_key: The HMAC-SHA1 key used to derive the per-block IVs.
        data_offset: Offset in the file where the encrypted data starts.
        block_size: Size of each independently encrypted block.
        size: Size of the decrypted image in bytes.
    """

    def __init__(self, fh: BinaryIO, aes_key: bytes, hmac_key: bytes, data_offset: int, block_size: int, size: int):
        super().__init__(size, align=block_size)
        self.fh = fh
        self.aes_key = aes_key
        self.hmac_key = hmac_key
        self.data_offset = data_offset
        self.block_size = block_size

    def _read(self, offset: int, length: int) -> bytes:
        length = min(length, self.size - offset)

        first = offset // self.block_size
        count = (length + self.block_size - 1) // self.block_size

        self.fh.seek(self.data_offset + first * self.block_size)
        encrypted = self.fh.read(count * self.block_size)

        result = []
        for i in range(count):
            block = encrypted[i * self.block_size : (i + 1) * self.block_size]
            iv = hmac.new(self.hmac_key, struct.pack(">L", first + i), hashlib.sha1).digest()[:16]
            result.append(AES.new(self.aes_key, AES.MODE_CBC, iv).decrypt(block))

        return b"".join(result)[:length]
