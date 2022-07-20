from dissect import cstruct


qcow2_def = """
#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21

#define QCOW2_COMPRESSED_SECTOR_SIZE    512
#define QCOW2_COMPRESSION_TYPE_ZLIB     0
#define QCOW2_COMPRESSION_TYPE_ZSTD     1

#define L1E_SIZE            8   // (sizeof(uint64_t))

#define L2E_SIZE_NORMAL     8   // (sizeof(uint64_t))
#define L2E_SIZE_EXTENDED   16  // (sizeof(uint64_t) * 2)

#define L1E_OFFSET_MASK 0x00fffffffffffe00
#define L2E_OFFSET_MASK 0x00fffffffffffe00
#define L2E_COMPRESSED_OFFSET_SIZE_MASK 0x3fffffffffffffff

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW_OFLAG_COPIED       (1 << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW_OFLAG_COMPRESSED   (1 << 62)
/* The cluster reads as all zeros */
#define QCOW_OFLAG_ZERO         (1 << 0)

#define QCOW_EXTL2_SUBCLUSTERS_PER_CLUSTER 32

#define QCOW2_INCOMPAT_DIRTY_BITNR          0
#define QCOW2_INCOMPAT_CORRUPT_BITNR        1
#define QCOW2_INCOMPAT_DATA_FILE_BITNR      2
#define QCOW2_INCOMPAT_COMPRESSION_BITNR    3
#define QCOW2_INCOMPAT_EXTL2_BITNR          4
#define QCOW2_INCOMPAT_DIRTY                1 << QCOW2_INCOMPAT_DIRTY_BITNR
#define QCOW2_INCOMPAT_CORRUPT              1 << QCOW2_INCOMPAT_CORRUPT_BITNR
#define QCOW2_INCOMPAT_DATA_FILE            1 << QCOW2_INCOMPAT_DATA_FILE_BITNR
#define QCOW2_INCOMPAT_COMPRESSION          1 << QCOW2_INCOMPAT_COMPRESSION_BITNR
#define QCOW2_INCOMPAT_EXTL2                1 << QCOW2_INCOMPAT_EXTL2_BITNR

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;
    uint32_t l1_size; /* XXX: save number of clusters instead ? */
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;

    /* The following fields are only valid for version >= 3 */
    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;

    uint32_t refcount_order;
    uint32_t header_length;

    /* Additional fields */
    uint8_t compression_type;

    /* header must be a multiple of 8 */
    uint8_t padding[7];
} QCowHeader;

#define QCOW2_EXT_MAGIC_END             0
#define QCOW2_EXT_MAGIC_BACKING_FORMAT  0xe2792aca
#define QCOW2_EXT_MAGIC_FEATURE_TABLE   0x6803f857
#define QCOW2_EXT_MAGIC_CRYPTO_HEADER   0x0537be77
#define QCOW2_EXT_MAGIC_BITMAPS         0x23852875
#define QCOW2_EXT_MAGIC_DATA_FILE       0x44415441

typedef struct {
    uint32_t magic;
    uint32_t len;
} QCowExtension;

typedef struct {
    uint64_t offset;
    uint64_t length;
} Qcow2CryptoHeaderExtension;

typedef struct {
    uint32_t nb_bitmaps;
    uint32_t reserved32;
    uint64_t bitmap_directory_size;
    uint64_t bitmap_directory_offset;
} Qcow2BitmapHeaderExt;

typedef struct {
    /* header is 8 byte aligned */
    uint64_t l1_table_offset;

    uint32_t l1_size;
    uint16_t id_str_size;
    uint16_t name_size;

    uint32_t date_sec;
    uint32_t date_nsec;

    uint64_t vm_clock_nsec;

    uint32_t vm_state_size;
    uint32_t extra_data_size; /* for extension */
    /* extra data follows */
    /* id_str follows */
    /* name follows  */
} QCowSnapshotHeader;

typedef struct {
    uint64_t vm_state_size_large;
    uint64_t disk_size;
    uint64_t icount;
} QCowSnapshotExtraData;

enum QCow2ClusterType {
    QCOW2_CLUSTER_UNALLOCATED,
    QCOW2_CLUSTER_ZERO_PLAIN,
    QCOW2_CLUSTER_ZERO_ALLOC,
    QCOW2_CLUSTER_NORMAL,
    QCOW2_CLUSTER_COMPRESSED,
};

enum QCow2SubclusterType {
    QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN,
    QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
    QCOW2_SUBCLUSTER_ZERO_PLAIN,
    QCOW2_SUBCLUSTER_ZERO_ALLOC,
    QCOW2_SUBCLUSTER_NORMAL,
    QCOW2_SUBCLUSTER_COMPRESSED,
    QCOW2_SUBCLUSTER_INVALID,
};
"""

c_qcow2 = cstruct.cstruct(endian=">")
c_qcow2.load(qcow2_def)

QCOW2_MAGIC = 0x514649FB
QCOW2_MAGIC_BYTES = c_qcow2.uint32.dumps(QCOW2_MAGIC)

QCOW2_INCOMPAT_MASK = (
    c_qcow2.QCOW2_INCOMPAT_DIRTY
    | c_qcow2.QCOW2_INCOMPAT_CORRUPT
    | c_qcow2.QCOW2_INCOMPAT_DATA_FILE
    | c_qcow2.QCOW2_INCOMPAT_COMPRESSION
    | c_qcow2.QCOW2_INCOMPAT_EXTL2
)

QCow2ClusterType = c_qcow2.QCow2ClusterType
QCow2SubclusterType = c_qcow2.QCow2SubclusterType

NORMAL_SUBCLUSTER_TYPES = (
    QCow2SubclusterType.QCOW2_SUBCLUSTER_NORMAL,
    QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_ALLOC,
    QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
)

ZERO_SUBCLUSTER_TYPES = (
    QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_PLAIN,
    QCow2SubclusterType.QCOW2_SUBCLUSTER_ZERO_ALLOC,
)

UNALLOCATED_SUBCLUSTER_TYPES = (
    QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN,
    QCow2SubclusterType.QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
)


def ctz(value, size=32):
    """Count the number of zero bits in an integer of a given size."""
    for i in range(size):
        if value & (1 << i):
            return i
