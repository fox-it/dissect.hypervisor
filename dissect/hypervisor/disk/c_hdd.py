# References:
# - https://src.openvz.org/projects/OVZ/repos/ploop/browse/include/ploop1_image.h
# - https://github.com/qemu/qemu/blob/master/docs/interop/parallels.txt


from dissect import cstruct

hdd_def = """
/* Compressed disk v1 signature */
#define SIGNATURE_STRUCTURED_DISK_V1    b"WithoutFreeSpace"

/* Compressed disk v2 signature */
#define SIGNATURE_STRUCTURED_DISK_V2    b"WithouFreSpacExt"

/* Sign that the disk is in "using" state */
#define SIGNATURE_DISK_IN_USE           0x746F6E59

#define SECTOR_LOG                      9
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
