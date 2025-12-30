from __future__ import annotations

from dissect.cstruct import cstruct

# https://github.com/vmware/open-vmdk/blob/master/vmdk/vmware_vmdk.h
vmdk_def = """
typedef struct SparseExtentHeader {
    uint32      magicNumber;
    uint32      version;
    uint32      flags;
    uint64      capacity;
    uint64      grainSize;
    uint64      descriptorOffset;
    uint64      descriptorSize;
    uint32      numGTEsPerGT;
    uint64      rgdOffset;
    uint64      gdOffset;
    uint64      overHead;
    uint8       uncleanShutdown;
    char        singleEndLineChar;
    char        nonEndLineChar;
    char        doubleEndLineChar1;
    char        doubleEndLineChar2;
    uint16      compressAlgorithm;
    char        pad[433];
} SparseExtentHeader;

typedef struct {
    uint64      lba;
    uint32      cmpSize;
} SparseGrainLBAHeader;

typedef struct {
    uint64      lba;
    uint32      cmpSize;
    uint32      type;
} SparseSpecialLBAHeader;

typedef struct {
    uint64      numSectors;
    uint32      size;
    uint32      type;
    char        pad[496];
    char        metadata[0];
} SparseMetaDataMarker;

#define SPARSE_MAGICNUMBER                  0x564d444b  /* VMDK */
#define SPARSE_VERSION_INCOMPAT_FLAGS       3
#define SPARSE_GTE_EMPTY                    0x00000000
#define SPARSE_GD_AT_END                    0xFFFFFFFFFFFFFFFF
#define SPARSE_SINGLE_END_LINE_CHAR         '\n'
#define SPARSE_NON_END_LINE_CHAR            ' '
#define SPARSE_DOUBLE_END_LINE_CHAR1        '\r'
#define SPARSE_DOUBLE_END_LINE_CHAR2        '\n'
#define SPARSEFLAG_COMPAT_FLAGS             0x0000FFFF
#define SPARSEFLAG_VALID_NEWLINE_DETECTOR   1
#define SPARSEFLAG_USE_REDUNDANT            2
#define SPARSEFLAG_MAGIC_GTE                4
#define SPARSEFLAG_INCOMPAT_FLAGS           0xFFFF0000
#define SPARSEFLAG_COMPRESSED               0x10000
#define SPARSEFLAG_EMBEDDED_LBA             0x20000
#define SPARSE_COMPRESSALGORITHM_NONE       0x0000
#define SPARSE_COMPRESSALGORITHM_DEFLATE    0x0001

#define GRAIN_MARKER_EOS                    0
#define GRAIN_MARKER_GRAIN_TABLE            1
#define GRAIN_MARKER_GRAIN_DIRECTORY        2
#define GRAIN_MARKER_FOOTER                 3
#define GRAIN_MARKER_PROGRESS               4

#define COWDISK_MAX_PARENT_FILELEN          1024
#define COWDISK_MAX_NAME_LEN                60
#define COWDISK_MAX_DESC_LEN                512

typedef struct COWDisk_Header {
    uint32      magicNumber;
    uint32      version;
    uint32      flags;
    uint32      numSectors;
    uint32      grainSize;
    uint32      gdOffset;
    uint32      numGDEntries;
    uint32      freeSector;
    union {
        struct {
            uint32  cylinders;
            uint32  heads;
            uint32  sectors;
        } root;
        struct {
            char    parentFileName[COWDISK_MAX_PARENT_FILELEN];
            uint32  parentGeneration;
        } child;
    } u;
    uint32      generation;
    char        name[COWDISK_MAX_NAME_LEN];
    char        description[COWDISK_MAX_DESC_LEN];
    uint32      savedGeneration;
    char        reserved[8];
    uint32      uncleanShutdown;
    char        padding[396];
} COWDisk_Header;

#define COWDISK_MAGIC                       0x44574f43  /* COWD */
#define COWDISK_ROOT                        0x01
#define COWDISK_CHECKCAPABLE                0x02
#define COWDISK_INCONSISTENT                0x04

// Confusingly, these seem to be called extents too
typedef struct SESparseExtent {
    uint64      offset;
    uint64      size;
} SESparseExtent;

typedef struct {
    uint64      constMagic;
    uint64      version;
    uint64      capacity;
    uint64      grainSize;
    uint64      grainTableSize;
    uint64      flags;
    uint64      reserved1;
    uint64      reserved2;
    uint64      reserved3;
    uint64      reserved4;
    SESparseExtent  volatileHeader;
    SESparseExtent  journalHeader;
    SESparseExtent  journal;
    SESparseExtent  grainDirectory;
    SESparseExtent  grainTables;
    SESparseExtent  freeBitmap;
    SESparseExtent  backMap;
    SESparseExtent  grain;
    char        pad[304];
} SESparseConstHeader;

typedef struct {
    uint64      volatileMagic;
    uint64      freeGTNumber;
    uint64      nextTxnSeqNumber;
    uint64      replayJournal;
    char        pad[480];
} SESparseVolatileHeader;

#define SESPARSE_CONST_HEADER_MAGIC         0x00000000CAFEBABE
#define SESPARSE_VOLATILE_HEADER_MAGIC      0x00000000CAFEBABE

#define SESPARSE_GRAIN_TYPE_MASK            0xF000000000000000
#define SESPARSE_GRAIN_TYPE_UNALLOCATED     0x0000000000000000
#define SESPARSE_GRAIN_TYPE_FALLTHROUGH     0x1000000000000000
#define SESPARSE_GRAIN_TYPE_ZERO            0x2000000000000000
#define SESPARSE_GRAIN_TYPE_ALLOCATED       0x3000000000000000
"""

c_vmdk = cstruct().load(vmdk_def)

SPARSE_MAGIC = c_vmdk.uint32(c_vmdk.SPARSE_MAGICNUMBER).dumps()
COWD_MAGIC = c_vmdk.uint32(c_vmdk.COWDISK_MAGIC).dumps()
# Technically a 8 byte header, but it's little endian so everything after the first 4 bytes is 0
SESPARSE_MAGIC = c_vmdk.uint32(c_vmdk.SESPARSE_CONST_HEADER_MAGIC).dumps()
