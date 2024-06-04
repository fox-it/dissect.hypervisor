from dissect.cstruct import cstruct

vma_def = """
#define VMA_BLOCK_BITS          12
#define VMA_BLOCK_SIZE          (1 << VMA_BLOCK_BITS)
#define VMA_CLUSTER_BITS        (VMA_BLOCK_BITS + 4)
#define VMA_CLUSTER_SIZE        (1 << VMA_CLUSTER_BITS)

#define VMA_EXTENT_HEADER_SIZE  512
#define VMA_BLOCKS_PER_EXTENT   59
#define VMA_MAX_CONFIGS         256

#define VMA_MAX_EXTENT_SIZE     (VMA_EXTENT_HEADER_SIZE + VMA_CLUSTER_SIZE * VMA_BLOCKS_PER_EXTENT)

/* File Format Definitions */

struct VmaDeviceInfoHeader {
    uint32  devname_ptr;    /* offset into blob_buffer table */
    uint32  reserved0;
    uint64  size;           /* device size in bytes */
    uint64  reserved1;
    uint64  reserved2;
};

struct VmaHeader {
    char    magic[4];
    uint32  version;
    char    uuid[16];
    int64   ctime;
    char    md5sum[16];

    uint32  blob_buffer_offset;
    uint32  blob_buffer_size;
    uint32  header_size;

    char    _reserved1[1984];

    uint32  config_names[VMA_MAX_CONFIGS]; /* offset into blob_buffer table */
    uint32  config_data[VMA_MAX_CONFIGS];  /* offset into blob_buffer table */

    char    _reserved2[4];

    VmaDeviceInfoHeader     dev_info[256];
};

struct VmaExtentHeader {
    char    magic[4];
    uint16  reserved1;
    uint16  block_count;
    char    uuid[16];
    char    md5sum[16];
    uint64  blockinfo[VMA_BLOCKS_PER_EXTENT];
};
"""

c_vma = cstruct(endian=">").load(vma_def)


VMA_MAGIC = b"VMA\x00"
VMA_EXTENT_MAGIC = b"VMAE"
