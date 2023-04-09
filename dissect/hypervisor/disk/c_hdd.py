from dissect import cstruct

hdd_def = """
/* Compressed disk (version 1) */
#define PRL_IMAGE_COMPRESSED            2

/* Compressed disk v1 signature */
#define SIGNATURE_STRUCTURED_DISK_V1    b"WithoutFreeSpace"

/* Compressed disk v2 signature */
#define SIGNATURE_STRUCTURED_DISK_V2    b"WithouFreSpacExt"

/* Sign that the disk is in "using" state */
#define SIGNATURE_DISK_IN_USE           0x746F6E59

/**
 * Compressed disk image flags
 */
#define CIF_NoFlags                     0x00000000  /* No any flags */
#define CIF_Empty                       0x00000001  /* No any data was written */
#define CIF_FmtVersionConvert           0x00000002  /* Version Convert in progree  */
#define CIF_FlagsMask                   (CIF_Empty | CIF_FmtVersionConvert)
#define CIF_Invalid                     0xFFFFFFFF  /* Invalid flag */

#define SECTOR_LOG                      9
#define DEF_CLUSTER_LOG                 11          /* 1M cluster-block */
#define DEF_CLUSTER                     (1 << (DEF_CLUSTER_LOG + SECTOR_LOG))

/* Helpers to generate PVD-header based on requested bdsize */

#define DEFAULT_HEADS_COUNT             16
#define DEFAULT_SECTORS_COUNT           63
#define SECTOR_SIZE                     (1 << SECTOR_LOG)

struct pvd_header {
    char    m_Sig[16];                              /* Signature */
    uint32  m_Type;                                 /* Disk type */
    uint32  m_Heads;                                /* heads count */
    uint32  m_Cylinders;                            /* tracks count */
    uint32  m_Sectors;                              /* Sectors per track count */
    uint32  m_Size;                                 /* Size of disk in tracks */
    union {                                         /* Size of disk in 512-byte sectors */
        struct {
            uint32  m_SizeInSectors_v1;
            uint32  Unused;
        };
        uint64  m_SizeInSectors_v2;
    };
    uint32  m_DiskInUse;                            /* Disk in use */
    uint32  m_FirstBlockOffset;                     /* First data block offset (in sectors) */
    uint32  m_Flags;                                /* Misc flags */
    uint64  m_FormatExtensionOffset;                /* Optional header offset in bytes */
};

struct pvd_ext_block_check {
    // Format Extension magic = 0xAB234CEF23DCEA87
    uint64  m_Magic;
    // Md5 checksum of the whole (without top 24 bytes of block check)
    // Format Extension Block.
    uint8   m_Md5[16];
};

struct pvd_ext_block_element_header {
    uint64  magic;
    uint64  flags;
    uint32  size;
    uint32  unused32;
};

struct pvd_dirty_bitmap_raw {
    uint64  m_Size;
    uint8   m_Id[16];
    uint32  m_Granularity;
    uint32  m_L1Size;
    uint64  m_L1[m_L1Size];
};
"""

c_hdd = cstruct.cstruct()
c_hdd.load(hdd_def)

SECTOR_SIZE = c_hdd.SECTOR_SIZE
