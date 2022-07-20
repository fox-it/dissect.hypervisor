# References:
# - /bin/crypto-util
# - /usr/lib/vmware/tpm/bin/keypersist
# - /lib/libvmlibs.so

import hashlib
import io
from base64 import b64decode
from collections import namedtuple
from typing import BinaryIO, Dict
from urllib.parse import unquote
from uuid import UUID

try:
    import _pystandalone

    HAS_PYSTANDALONE = True
except ImportError:
    HAS_PYSTANDALONE = False

try:
    from Crypto.Cipher import AES

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

from dissect import cstruct
from dissect.util.stream import RangeStream


c_def = """
struct EnvelopeFileHeader {
    char    magic[21];
    char    _pad[483];
    uint32  size;
    uint32  version;
};

struct DataTransformAeadFooter {
    char    magic[23];
    char    _pad[9];
    char    data[4056];
    uint32  size;
    uint32  version;
};

struct DataTransformCryptoFooter {
    char    magic[25];
    char    _pad[479];
    uint32  padding;
    uint32  version;
};

enum AttributeType : uint8 {
    Invalid = 0x0,
    // These are guesses based on size and used attributes
    UInt8 = 0x1,
    UInt16 = 0x2,
    UInt32 = 0x3,
    UInt64 = 0x4,
    Int8 = 0x5,
    Int16 = 0x6,
    Int32 = 0x7,
    Int64 = 0x8,
    Float = 0x9,
    Double = 0xA,
    // These are certain
    String = 0xB,
    Bytes = 0xC
};
"""
c_envelope = cstruct.cstruct()
c_envelope.load(c_def)

FILE_HEADER_MAGIC = b"DataTransformEnvelope"
FOOTER_AEAD_MAGIC = b"DataTransformAeadFooter"
FOOTER_CRYPTO_MAGIC = b"DataTransformCryptoFooter"

PBKDF2_SALT = b"This is obfuscation, not encryption. If you want encryption, use TPM."

ENVELOPE_BLOCK_SIZE = 4096
ENVELOPE_ATTRIBUTE_TYPE_MAP = {
    c_envelope.AttributeType.Invalid: None,
    c_envelope.AttributeType.UInt8: c_envelope.uint8,
    c_envelope.AttributeType.UInt16: c_envelope.uint16,
    c_envelope.AttributeType.UInt32: c_envelope.uint32,
    c_envelope.AttributeType.UInt64: c_envelope.uint64,
    c_envelope.AttributeType.Int8: c_envelope.int8,
    c_envelope.AttributeType.Int16: c_envelope.int16,
    c_envelope.AttributeType.Int32: c_envelope.int32,
    c_envelope.AttributeType.Int64: c_envelope.int64,
    c_envelope.AttributeType.Float: c_envelope.float,
    c_envelope.AttributeType.Double: c_envelope.double,
    c_envelope.AttributeType.String: None,
    c_envelope.AttributeType.Bytes: None,
}

DECRYPT_CHUNK_SIZE = 1024 * 1024 * 4


EnvelopeAttribute = namedtuple("EnvelopeAttribute", ("type", "flag", "value"))


class Envelope:
    """Implements an encryption envelope as used within ESXi."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh

        header_buf = io.BytesIO(self.fh.read(ENVELOPE_BLOCK_SIZE))
        self.header = c_envelope.EnvelopeFileHeader(header_buf)

        if self.header.magic != FILE_HEADER_MAGIC:
            raise ValueError("Invalid envelope file")

        if self.header.version != 2:
            raise ValueError("Unsupported envelope type")

        self.version = self.header.version
        self.attributes = _read_envelope_attributes(header_buf)
        for req in ("vmware.keyInfo", "vmware.cipherName", "vmware.keyHash"):
            if req not in self.attributes:
                raise ValueError(f"Missing required {req} attribute")

        self.key_info = self.attributes["vmware.keyInfo"].value
        self.cipher_name = self.attributes["vmware.cipherName"].value
        self.key_hash = self.attributes["vmware.keyHash"].value
        self.iv = self.attributes.get("vmware.iv", EnvelopeAttribute(None, None, None)).value
        self.digest = None

        if self.cipher_name == "AES-256-GCM":
            self.fh.seek(-ENVELOPE_BLOCK_SIZE, io.SEEK_END)
            aead_footer = c_envelope.DataTransformAeadFooter(self.fh)
            if aead_footer.version != 1:
                raise ValueError("Invalid AEAD footer")
            self.digest = aead_footer.data[: aead_footer.size]
        else:
            raise NotImplementedError(f"Unsupported cipher: {self.cipher_name}")

        self.fh.seek(0, io.SEEK_END)
        size = self.fh.tell()
        self.size = size - (2 * ENVELOPE_BLOCK_SIZE)
        self.data = RangeStream(self.fh, ENVELOPE_BLOCK_SIZE, self.size)

    def decrypt(self, key: bytes, aad: bytes = None) -> bytes:
        """Decrypt the data in this envelope.

        Arguments:
            key: decryption key to use
            aad: optional associated data to include for AEAD ciphers
        """
        if not HAS_PYSTANDALONE and not HAS_PYCRYPTODOME:
            raise RuntimeError("No crypto module available")

        key_hash = hashlib.sha256(self.cipher_name.encode() + key).digest()
        if key_hash != self.key_hash:
            raise ValueError("Key hash doesn't match")

        is_aead = False
        if self.cipher_name == "AES-256-GCM":
            is_aead = True

            if not self.iv:
                raise ValueError("Missing IV")

            if HAS_PYSTANDALONE:
                cipher = _pystandalone.aes_256_gcm(key, self.iv)
            else:
                cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv)
        else:
            raise NotImplementedError(f"Unsupported cipher: {self.cipher_name}")

        if is_aead:
            # The file header is included in the AAD, as well as any optional variable data
            cipher.update(_pack_envelope_header(self))
            if aad:
                cipher.update(aad)

        self.data.seek(0)
        offset = 0
        decrypted = bytearray(self.size)
        while True:
            chunk = self.data.read(DECRYPT_CHUNK_SIZE)
            if not chunk:
                break

            chunk_size = len(chunk)
            decrypted[offset : offset + chunk_size] = cipher.decrypt(chunk)
            offset += chunk_size

        footer = c_envelope.DataTransformCryptoFooter(bytes(decrypted[-512:]))
        decrypted = decrypted[: -4096 - footer.padding]

        cipher.verify(self.digest)

        return bytes(decrypted)


class KeyStore:
    """Implements a file based keystore as used in ESXi."""

    def __init__(self, store: Dict[str, str]):
        self.store = store

        self.mode = self.store.get("mode", None)
        if not self.mode:
            raise ValueError("Keystore has no mode")

        self._id = None
        self._key = None

        if self.mode == "NONE":
            data = self.store["ConfigEncData"]
            obj = {}
            for opt in data.split(":"):
                name, _, value = opt.partition("=")
                obj[name.strip()] = unquote(value.strip())

            self._id = str(UUID(bytes=b64decode(obj["keyId"])))

            data1 = b64decode(obj["data1"])
            data2 = b64decode(obj["data2"])

            self._key = hashlib.pbkdf2_hmac("sha256", data1 + PBKDF2_SALT, data2, 100000)
        else:
            raise NotImplementedError("Only NONE is implemented")

    @property
    def id(self) -> str:
        return self._id

    @property
    def key(self) -> bytes:
        return self._key

    @classmethod
    def from_text(cls, text: str):
        """Parse a key store from a string.

        Arguments:
            text: string to parse a key store from
        """
        store = {}

        for line in text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            name, _, value = line.partition("=")

            name = name.strip()
            value = value.strip(' "')

            if name.startswith("."):
                store[name] = value
            else:
                node = store
                parts = name.strip().split(".")
                for part in parts[:-1]:
                    if part not in node:
                        node[part] = {}
                    node = node[part]

                node[parts[-1]] = value.strip(' "')

        return cls(store)


def _read_envelope_attributes(buf: BinaryIO) -> Dict[str, EnvelopeAttribute]:
    attributes = {}
    while True:
        try:
            attr_type = c_envelope.AttributeType(buf)
            if attr_type == c_envelope.AttributeType.Invalid:
                break

            flag = c_envelope.uint8(buf)
            buf.read(2)

            name = c_envelope.char[None](buf).decode()
            if attr_type in ENVELOPE_ATTRIBUTE_TYPE_MAP:
                if attr_type == c_envelope.AttributeType.String:
                    value = c_envelope.char[None](buf).decode()
                elif attr_type == c_envelope.AttributeType.Bytes:
                    value = buf.read(c_envelope.uint64(buf))
                else:
                    value = ENVELOPE_ATTRIBUTE_TYPE_MAP[attr_type](buf)
            else:
                raise NotImplementedError(f"Unknown attribute type: {attr_type}")

            attributes[name] = EnvelopeAttribute(attr_type, flag, value)
        except EOFError:
            break

    return attributes


def _pack_envelope_header(envelope: Envelope, block_size: int = ENVELOPE_BLOCK_SIZE) -> bytes:
    stream = io.BytesIO()

    stream.write(b"\x00" * 512)

    _pack_attributes(stream, envelope.attributes)

    size = stream.tell()
    remainder = size % block_size
    if remainder:
        stream.write(b"\x00" * (block_size - remainder))
    size = stream.tell()

    stream.seek(0)
    c_envelope.EnvelopeFileHeader(
        magic=b"DataTransformEnvelope",
        size=size - len(c_envelope.EnvelopeFileHeader),
        version=envelope.version,
    ).write(stream)

    return stream.getvalue()


def _pack_attributes(stream: BinaryIO, attributes: Dict[str, EnvelopeAttribute]):
    for name, attribute in attributes.items():
        c_envelope.AttributeType.write(stream, attribute.type)
        c_envelope.uint8.write(stream, attribute.flag)
        c_envelope.uint16.write(stream, 0)
        c_envelope.char[None].write(stream, name.encode())

        if attribute.type == c_envelope.AttributeType.String:
            c_envelope.char[None].write(stream, attribute.value.encode())
        elif attribute.type == c_envelope.AttributeType.Bytes:
            c_envelope.uint64.write(stream, len(attribute.value))
            stream.write(attribute.value)
        else:
            ENVELOPE_ATTRIBUTE_TYPE_MAP[attribute.type].write(stream, attribute.value)

    # Null terminate attributes
    stream.write(b"\x00" * 4)
