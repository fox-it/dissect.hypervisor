import struct
from dissect import cstruct


vmdk_def = """
typedef struct {
    char    magic[4];                           // Magic "KDMV" LE
    uint32  version;                            // Version
    uint32  flags;                              // Flags
    uint64  capacity;                           // The maximum data number of sectors (capacity)
    uint64  grain_size;                         // The grain number of sectors
    uint64  descriptor_offset;                  // The descriptor sector number
    uint64  descriptor_size;                    // The descriptor number of sectors
    uint32  num_grain_table_entries;            // The number of grain table entries
    uint64  secondary_grain_directory_offset;   // The secondary grain directory sector number
    uint64  primary_grain_directory_offset;     // The primary grain directory sector number
    uint64  overhead;                           // The metadata (overhead) number of sectors
    uint8   is_dirty;                           // Value to indicate the VMDK was cleanly closed
    char    single_end_line_char;               // The single end of line character
    char    non_end_line_char;                  // A non end of line character
    char    double_end_line_chars[2];           // The double end of line characters
    uint16  compress_algorithm;                 // The compression method
    char    pad[433];                           // Padding
} VMDKSparseExtentHeader;

typedef struct {
    char    magic[4];                           // Magic "COWD" LE
    uint32  version;                            // Version
    uint32  flags;                              // Flags
    uint32  capacity;                           // The maximum data number of sectors (capacity)
    uint32  grain_size;                         // The grain number of sectors
    uint32  primary_grain_directory_offset;     // The primary grain directory sector number
    uint32  num_grain_directory_entries;        // The number of grain table entries
    uint32  next_free_grain;                    // The next free grain

    //uint32  num_cylinders;                      // The number of cylinders
    //uint32  num_heads;                          // The number of heads
    //uint32  num_sectors;                        // The number of sectors

    //char    parent_filename[1024];              // The parent filename
    //uint32  parent_generation;                  // The parent generation

    //uint32  generation;                         // The generation
    //char    name[60];                           // The name
    //char    description[512];                   // The description
    //uint32  saved_generation;                   // The saved generation
    //uint64  reserved;                           // Reserved
    //uint8   is_dirty;                           // Value to indicate the COWD was cleanly closed
    //char    padding[396];                       // Padding
} COWDSparseExtentHeader;

typedef struct {
    uint64  magic;
    uint64  version;
    uint64  capacity;
    uint64  grain_size;
    uint64  grain_table_size;
    uint64  flags;
    uint64  reserved1;
    uint64  reserved2;
    uint64  reserved3;
    uint64  reserved4;
    uint64  volatile_header_offset;
    uint64  volatile_header_size;
    uint64  journal_header_offset;
    uint64  journal_header_size;
    uint64  journal_offset;
    uint64  journal_size;
    uint64  grain_directory_offset;
    uint64  grain_directory_size;
    uint64  grain_tables_offset;
    uint64  grain_tables_size;
    uint64  free_bitmap_offset;
    uint64  free_bitmap_size;
    uint64  backmap_offset;
    uint64  backmap_size;
    uint64  grains_offset;
    uint64  grains_size;
    uint8   pad[304];
} VMDKSESparseConstHeader;

typedef struct {
    uint64  magic;
    uint64  free_gt_number;
    uint64  next_txn_seq_number;
    uint64  replay_journal;
    uint8   pad[480];
} VMDKSESparseVolatileHeader;

#define SPARSE_MAGICNUMBER                  0x564D444B
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

#define SESPARSE_CONST_HEADER_MAGIC         0x00000000CAFEBABE
#define SESPARSE_VOLATILE_HEADER_MAGIC      0x00000000CAFEBABE

#define SESPARSE_GRAIN_TYPE_MASK            0xF000000000000000
#define SESPARSE_GRAIN_TYPE_UNALLOCATED     0x0000000000000000
#define SESPARSE_GRAIN_TYPE_FALLTHROUGH     0x1000000000000000
#define SESPARSE_GRAIN_TYPE_ZERO            0x2000000000000000
#define SESPARSE_GRAIN_TYPE_ALLOCATED       0x3000000000000000

typedef struct {
    uint64  lba;
    uint32  cmp_size;
} SparseGrainLBAHeaderOnDisk;

typedef struct {
    uint64  lba;
    uint32  cmp_size;
    uint32  type;
} SparseSpecialLBAHeaderOnDisk;

#define GRAIN_MARKER_EOS                0
#define GRAIN_MARKER_GRAIN_TABLE        1
#define GRAIN_MARKER_GRAIN_DIRECTORY    2
#define GRAIN_MARKER_FOOTER             3
#define GRAIN_MARKER_PROGRESS           4
"""

c_vmdk = cstruct.cstruct()
c_vmdk.load(vmdk_def)

SECTOR_SIZE = 512

COWD_MAGIC = b"COWD"
VMDK_MAGIC = b"KDMV"
# Technically a 8 byte header, but it's little endian so everything after the first 4 bytes is 0
SESPARSE_MAGIC = struct.pack("<I", c_vmdk.SESPARSE_CONST_HEADER_MAGIC)
