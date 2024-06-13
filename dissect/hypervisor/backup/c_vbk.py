from dissect.cstruct import cstruct

vbk_def = """
#define PAGE_SIZE 4096

/* Storage header */

struct StorageHeader {
    uint32              FormatVersion;              /* 0x0000 */
    uint32              Initialized;                /* 0x0004 */
    uint32              DigestTypeLength;           /* 0x0008 */
    char                DigestType[251];            /* 0x000C */
    uint32              SnapshotSlotFormat;         /* 0x0107 format > 5 -> crc32c */
    uint32              StandardBlockSize;          /* 0x010B */
    uint8               ClusterAlign;               /* 0x010F */
    char                Unk0[16];                   /* 0x0120 */
    char                ExternalStorageId[16];      /* 0x0130 */
};

/* Snapshot header */

struct SnapshotSlotHeader {
    uint32              CRC;
    uint32              ContainsSnapshot;
};

struct DirectoryRootRecord {
    int64               RootPage;                   /* Root page of the directory */
    uint64              Count;                      /* Number of children */
};

struct BlocksStoreHeader {
    int64               RootPage;                   /* Root of the blocks store */
    uint64              Count;                      /* Number of blocks store entries */
    int64               FreeRootPage;               /* Root of the free blocks tree */
    int64               DeduplicationRootPage;      /* Root of the deduplication tree */
    int64               Unk0;
    int64               Unk1;
};

struct CryptoStoreRecord {
    int64               RootPage;                   /* Root of the crypto store */
};

struct SnapshotDescriptor {
    uint64              Version;                    /* Acts as a sequence number, highest is active slot */
    uint64              StorageEOF;                 /* End of file, aka file size */
    uint32              BanksCount;                 /* Number of banks */
    DirectoryRootRecord DirectoryRoot;              /* Directory root record */
    BlocksStoreHeader   BlocksStore;                /* Blocks store header */
    CryptoStoreRecord   CryptoStore;                /* Crypto store record */
    uint64              Unk0;
    uint64              Unk1;
};

struct BankDescriptor {
    uint32              CRC;
    uint64              Offset;
    uint32              Size;
};

struct BanksGrain {
    uint32              MaxBanks;
    uint32              StoredBanks;
    // BankDescriptor      Banks[StoredBanks];
};

/* Block headers */

struct BankHeader {
    uint16              PageCount;
    uint16              Flags;
    char                Unk0[3064];
    uint64              Unk1;
    char                Unk2[1020];
};

struct BankHeaderV71 {
    uint16              PageCount;
    uint16              Flags;                      /* 2 == encrypted */
    char                Unk0[3072];
    char                KeySetId[16];
    char                Unk1[16];
    char                Unk2[16];
    uint32              Unk3;
    char                Unk4[968];
};

struct MetaBlobHeader {
    int64               NextPage;
    int32               Unk0;
};

struct Lz4BlockHeader {
    uint32              Magic;                      /* 0xF800000F */
    uint32              CRC;                        /* CRC32C of the compressed data */
    uint32              SourceSize;
};

/* DirItem headers */
struct BlocksVectorHeader {
    uint64              RootPage;
    uint64              Count;
};

struct SubFolderHeader {
    uint64              RootPage;                   /* 0x94 */
    uint32              Count;                      /* 0x9C */
    char                Data[32];                   /* 0xA0 */
};                                                  /* 0xC0 */

struct ExtFibHeader {
    uint16              UpdateInProgress;           /* 0x94 */
    uint8               Unk3;                       /* 0x96 */
    uint8               Format;                     /* 0x97 Bit 3 == 1 */
    BlocksVectorHeader  BlocksVector;               /* 0x98 */
    uint64              FibSize;                    /* 0xA8 */
    uint64              Size;                       /* 0xB0 */
    uint8               FsObjAttachState;           /* 0xB8 */
    char                Data[7];                    /* 0xB9 */
};                                                  /* 0xC0 */

struct IntFibHeader {
    uint16              UpdateInProgress;           /* 0x94 */
    uint8               Unk3;                       /* 0x96 */
    uint8               Format;                     /* 0x97 Bit 3 == 1 */
    BlocksVectorHeader  BlocksVector;               /* 0x98 */
    uint64              FibSize;                    /* 0xA8 */
    uint64              Size;                       /* 0xB0 */
    uint8               FsObjAttachState;           /* 0xB8 */
    char                Data[7];                    /* 0xB9 */
};                                                  /* 0xC0 */

struct PatchHeader {
    uint32              Unk0;                       /* 0x94 */
    BlocksVectorHeader  BlocksVector;               /* 0x98 */
    uint64              FibSize;                    /* 0xA8 Source file size */
    uint64              Unk4;                       /* 0xB0 */
    char                Data[8];                    /* 0xB8 */
};                                                  /* 0xC0 */

struct IncrementHeader {
    uint32              Unk0;                       /* 0x94 */
    BlocksVectorHeader  BlocksVector;               /* 0x98 */
    uint64              FibSize;                    /* 0xA8 Original FIB size */
    uint64              Unk4;                       /* 0xB0 */
    char                Data[8];                    /* 0xB8 */
};                                                  /* 0xC0 */

enum DirItemType : uint32 {
    None                = 0,
    SubFolder           = 1,
    ExtFib              = 2,
    IntFib              = 3,
    Patch               = 4,
    Increment           = 5,
};

struct DirItemRecord {
    DirItemType         Type;                       /* 0x00 */
    uint32              NameLength;                 /* 0x04 */
    char                Name[128];                  /* 0x08 */
    int64               PropsRootPage;              /* 0x88 */
    uint32              Unk1;                       /* 0x90 */
    union {                                         /* 0x94 */
        char            Data[44];
        SubFolderHeader SubFolder;
        ExtFibHeader    ExtFib;
        IntFibHeader    IntFib;
        PatchHeader     Patch;
        IncrementHeader Increment;
    };
};

/* Block descriptors */

flag BlockFlags : uint8 {
    None                = 0x00,
    Updated             = 0x01,
    CommitInProgress    = 0x02,
};

enum BlockLocationType : uint8 {
    Normal              = 0x00,
    Sparse              = 0x01,
    Reserved            = 0x02,
    Archived            = 0x03,                     /* CompressedSize | (CompressionType << 32) */
    BlockInBlob         = 0x04,                     /* BlockId? & 0x3FFFFFF | (BlobId << 26) | ((Offset >> 9) << 42) */
    BlockInBlobReserved = 0x05,                     /* BlockId? | 0xFFFFFFFFFC000000 */
};

enum CompressionType : int8 {
    Plain               = -1,
    RL                  =  2,
    ZLH                 =  3,
    ZLL                 =  4,
    LZ4                 =  7,
};

struct MetaTableDescriptor {
    int64               RootPage;
    uint64              BlockSize;
    uint64              Count;
};

struct StgBlockDescriptor {
    uint8               Format;                     /* Format != 4 == legacy */
    uint32              UsageCounter;
    uint64              Offset;
    uint32              AllocatedSize;
    uint8               Deduplication;
    char                Digest[16];
    CompressionType     CompressionType;
    uint8               Unk0;
    uint32              CompressedSize;
    uint32              SourceSize;
};

struct StgBlockDescriptorV7 {
    uint8               Format;                     /* Format != 4 == legacy */
    uint32              UsageCounter;
    uint64              Offset;
    uint32              AllocatedSize;
    uint8               Deduplication;
    char                Digest[16];
    CompressionType     CompressionType;
    uint8               Unk0;
    uint32              CompressedSize;
    uint32              SourceSize;
    char                KeySetId[16];
};

struct FibBlockDescriptor {
    uint32              BlockSize;
    BlockLocationType   Type;
    char                Digest[16];
    // union {
    //     struct {
    //         uint32 ArchiveUsedSize;
    //         uint8 ArchiveCompressionType;
    //         uint8 Unk3;
    //         uint16 Unk4;
    //     } Archived;
    //     uint64  Offset;
    // };
    uint64              BlockId;                    /* For performance reasons we just put a uint64 here, but this is actually a union */
    BlockFlags          Flags;
};

struct FibBlockDescriptorV7 {
    uint32              BlockSize;
    BlockLocationType   Type;
    char                Digest[16];
    // union {
    //     struct {
    //         uint32   ArchiveUsedSize;
    //         uint8    ArchiveCompressionType;
    //         uint8    Unk3;
    //         uint16   Unk4;
    //     } Archived;
    //     uint64       Offset;
    // };
    uint64              BlockId;                    /* For performance reasons we just put a uint64 here, but this is actually a union */
    BlockFlags          Flags;
    char                KeySetId[16];
};

struct PatchBlockDescriptor {
};

struct PatchBlockDescriptorV7 {
};

/* Property dictionary */

enum PropertyType : int32 {
    UInt32              = 1,
    UInt64              = 2,
    AString             = 3,
    WString             = 4,
    Binary              = 5,
    Boolean             = 6,
    End                 = -1,
};
"""  # noqa: E501
c_vbk = cstruct()
c_vbk.load(vbk_def)
