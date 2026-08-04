# References:
# - https://newosxbook.com/DMG.html
# - https://github.com/nlitsme/encrypteddmg
# - https://github.com/Lekensteyn/dmg2img
from __future__ import annotations

from dissect.cstruct import cstruct

dmg_def = """
#define KOLY_MAGIC          b"koly"     /* Marks the trailer at the very end of the file */
#define MISH_MAGIC          0x6d697368  /* Marks a BLKX table inside the property list */
#define ENCRCDSA_MAGIC      b"encrcdsa" /* Marks a password encrypted image */
#define SECTOR_SIZE         512

enum BLOCK_TYPE : uint32 {
    ZERO_FILL   = 0x00000000,           /* Written out as zeroes, nothing stored in the data fork */
    RAW         = 0x00000001,           /* Stored verbatim, used by UDRW and UDRO */
    IGNORE      = 0x00000002,           /* Never allocated, reads back as zeroes */
    COMMENT     = 0x7ffffffe,           /* Marker carrying no sector data */
    ADC         = 0x80000004,           /* Apple Data Compression, used by UDCO */
    ZLIB        = 0x80000005,           /* zlib deflate, used by UDZO */
    BZLIB       = 0x80000006,           /* bzip2, used by UDBZ */
    LZFSE       = 0x80000007,           /* LZFSE, used by ULFO */
    LZMA        = 0x80000008,           /* LZMA, used by ULMO */
    TERMINATOR  = 0xffffffff,           /* Closes a BLKX table, carries no sector data */
};

typedef struct {
    uint32  Type;                       /* Algorithm the checksum was calculated with, 2 for CRC-32 */
    uint32  Size;                       /* How many bits of Data are meaningful */
    uint32  Data[32];                   /* The checksum itself, zero padded to a fixed 128 bytes */
} UDIFChecksum;

typedef struct {
    char        Signature[4];           /* Always 'koly' */
    uint32      Version;                /* 4 for every image seen so far */
    uint32      HeaderSize;             /* Size of this trailer, fixed at 512 */
    uint32      Flags;                  /* Image wide flags, bit 0 marks the image as flattened */
    uint64      RunningDataForkOffset;  /* Offset of this segment's data within the combined data fork */
    uint64      DataForkOffset;         /* Where the data fork starts, 0 for a single segment image */
    uint64      DataForkLength;         /* How many bytes of data fork follow, normally up to XMLOffset */
    uint64      RsrcForkOffset;         /* Binary resource fork holding the blkx tables, 0 when XML is used */
    uint64      RsrcForkLength;         /* Length of that resource fork, 0 when XML is used */
    uint32      SegmentNumber;          /* 1 based index of this segment within the set */
    uint32      SegmentCount;           /* Total segments, anything above 1 means a split .dmgpart set */
    char        SegmentID[16];          /* GUID shared by every segment of the same image */

    UDIFChecksum DataChecksum;          /* Covers the data fork bytes as stored, still compressed */

    uint64      XMLOffset;              /* Where the property list holding the blkx tables begins */
    uint64      XMLLength;              /* Byte length of that property list */
    char        Reserved1[120];         /* Padding, zeroed */

    UDIFChecksum Checksum;              /* Covers the concatenated checksums of all blkx tables */

    uint32      ImageVariant;           /* 1 for a whole device image, 2 for a single partition */
    uint64      SectorCount;            /* Length of the reconstructed disk, in sectors */

    uint32      reserved2;
    uint32      reserved3;
    uint32      reserved4;
} UDIFResourceFile;

typedef struct {
    BLOCK_TYPE  EntryType;              /* How this run is stored, see BLOCK_TYPE */
    uint32      Comment;                /* Holds "+beg" or "+end" for COMMENT runs, otherwise unused */
    uint64      SectorNumber;           /* First sector of this run, counted from the table start */
    uint64      SectorCount;            /* Length of this run, in sectors */
    uint64      CompressedOffset;       /* Position of the stored bytes within the data fork */
    uint64      CompressedLength;       /* How many bytes are stored there */
} BLKXChunkEntry;

typedef struct {
    uint32      Signature;              /* Always 'mish' */
    uint32      Version;                /* 1 for every image seen in the wild */
    uint64      SectorNumber;           /* First sector of the region this table describes */
    uint64      SectorCount;            /* Length of that region, in sectors */

    uint64      DataOffset;             /* Base offset the entries below are relative to */
    uint32      BuffersNeeded;          /* Decompression buffer hint, unused when reading */
    uint32      BlockDescriptors;       /* Index of the descriptor this table belongs to */

    uint32      reserved1;
    uint32      reserved2;
    uint32      reserved3;
    uint32      reserved4;
    uint32      reserved5;
    uint32      reserved6;

    UDIFChecksum checksum;              /* Covers this table's decompressed data, skipping IGNORE runs */

    uint32      NumberOfBlockChunks;    /* How many entries follow */
    BLKXChunkEntry Entries[NumberOfBlockChunks];
} BLKXTable;

typedef struct {
    char        Signature[8];           /* Always 'encrcdsa' */
    uint32      Version;                /* 2 for the password wrapped scheme handled here */
    uint32      BlockIVSize;            /* Length of the per block IV, 16 for AES-CBC */
    uint32      EncryptionMode;
    uint32      EncryptionAlgorithm;
    uint32      KeyBits;                /* Bit size of the data AES key (128 or 256) */
    uint32      PRNGAlgorithm;
    uint32      PRNGKeyBits;
    char        UUID[16];
    uint32      BlockSize;              /* Size of each independently encrypted data block (typically 512) */
    uint64      DataSize;               /* Size of the (decrypted) UDIF image in bytes */
    uint64      DataOffset;             /* Offset in the file where the encrypted data starts */
    uint32      KeyCount;               /* Number of key blobs that follow */
} EncrcdsaHeader;

typedef struct {
    uint32      Type;                   /* Key blob type (1 for a passphrase-wrapped key) */
    uint32      _reserved1;
    uint32      Offset;                 /* Offset in the file to the key blob (password header) */
    uint32      _reserved2;
    uint32      Size;                   /* Size of the key blob */
} EncrcdsaKeyPointer;

typedef struct {
    uint32      KDFAlgorithm;           /* 103 = PKCS#5 PBKDF2 */
    uint64      KDFIterationCount;
    uint32      KDFSaltLen;
    char        KDFSalt[32];
    uint32      BlobEncIVSize;
    char        BlobEncIV[32];
    uint32      BlobEncKeyBits;         /* Bit size of the key-encryption key (192 -> AES-192) */
    uint32      BlobEncAlgorithm;
    uint32      BlobEncPadding;
    uint32      BlobEncMode;
    uint32      EncryptedKeyblobSize;
    char        EncryptedKeyblob[EncryptedKeyblobSize];
} EncrcdsaKeyBlob;
"""

c_dmg = cstruct(endian=">").load(dmg_def)

BLOCK_TYPE = c_dmg.BLOCK_TYPE
KOLY_MAGIC = c_dmg.KOLY_MAGIC
MISH_MAGIC = c_dmg.MISH_MAGIC
SECTOR_SIZE = c_dmg.SECTOR_SIZE
ENCRCDSA_MAGIC = c_dmg.ENCRCDSA_MAGIC
KOLY_SIZE = c_dmg.UDIFResourceFile.size
