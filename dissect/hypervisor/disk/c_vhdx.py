from uuid import UUID

from dissect import cstruct


vhdx_def = """
#define PAYLOAD_BLOCK_NOT_PRESENT           0
#define PAYLOAD_BLOCK_UNDEFINED             1
#define PAYLOAD_BLOCK_ZERO                  2
#define PAYLOAD_BLOCK_UNMAPPED              3
#define PAYLOAD_BLOCK_FULLY_PRESENT         6
#define PAYLOAD_BLOCK_PARTIALLY_PRESENT     7

#define SB_BLOCK_NOT_PRESENT                0
#define SB_BLOCK_PRESENT                    6

struct file_identifier {
    char    signature[8];
    char    creator[512];
};

struct header {
    char    signature[4];
    uint32  checksum;
    uint64  sequence_number;
    char    file_write_guid[16];
    char    data_write_guid[16];
    char    log_guid[16];
    uint16  log_version;
    uint16  version;
    uint32  log_length;
    uint64  log_offset;
    char    reserved[4096];
};

struct region_table_header {
    char    signature[4];
    uint32  checksum;
    uint32  entry_count;
    char    reserved[4];
};

struct region_table_entry {
    char    guid[16];
    uint64  file_offset;
    uint32  length;
    uint32  required;
};

struct bat_entry {
    uint64  state:3;
    uint64  reserved:17;
    uint64  file_offset_mb:44;
};

struct metadata_table_header {
    char    signature[8];
    char    reserved[2];
    uint16  entry_count;
    char    reserved2[20];
};

struct metadata_table_entry {
    char    item_id[16];
    uint32  offset;
    uint32  length;
    uint32  is_user:1;
    uint32  is_virtual_disk:1;
    uint32  is_required:1;
    uint32  reserved:29;
    uint32  reserved2:2;
};

struct file_parameters {
    uint32  block_size;
    uint32  leave_block_allocated:1;
    uint32  has_parent:1;
    uint32  reserved:30;
};

struct virtual_disk_id {
    char    virtual_disk_id[16];            // typedef of an array is still broken
};

typedef uint64      virtual_disk_size;
typedef uint32      logical_sector_size;
typedef uint32      physical_sector_size;

struct parent_locator_header {
    char    locator_type[16];
    uint16  reserved;
    uint16  key_value_count;
};

struct parent_locator_entry {
    uint32  key_offset;
    uint32  value_offset;
    uint16  key_length;
    uint16  value_length;
};
"""

c_vhdx = cstruct.cstruct()
c_vhdx.load(vhdx_def)

ALIGNMENT = 64 * 1024
MB = 1024 * 1024

BAT_REGION_GUID = UUID("2DC27766-F623-4200-9D64-115E9BFD4A08")
FILE_PARAMETERS_GUID = UUID("CAA16737-FA36-4D43-B3B6-33F0AA44E76B")
LOGICAL_SECTOR_SIZE_GUID = UUID("8141BF1D-A96F-4709-BA47-F233A8FAAB5F")
METADATA_REGION_GUID = UUID("8B7CA206-4790-4B9A-B8FE-575F050F886E")
PARENT_LOCATOR_GUID = UUID("A8D35F2D-B30B-454D-ABF7-D3D84834AB0C")
PHYSICAL_SECTOR_SIZE_GUID = UUID("CDA348C7-445D-4471-9CC9-E9885251C556")
VIRTUAL_DISK_ID_GUID = UUID("BECA12AB-B2E6-4523-93EF-C309E000C746")
VIRTUAL_DISK_SIZE_GUID = UUID("2FA54224-CD1B-4876-B211-5DBED83BF4B8")

VHDX_PARENT_LOCATOR_GUID = UUID("B04AEFB7-D19E-4A81-B789-25B8E9445913")
