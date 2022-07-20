from dissect import cstruct


vhd_def = """
struct footer {
    char            cookie[8];
    uint32          features;
    uint32          version;
    uint64          data_offset;
    uint32          timestamp;
    uint32          creator_application;
    uint32          creator_version;
    uint32          creator_host_os;
    uint64          original_size;
    uint64          current_size;
    uint32          disk_geometry;
    uint32          disk_type;
    uint32          checksum;
    char            unique_id[16];
    char            saved_state;
    char            reserved[426];          // Actually 427, but old versions can have a 511 byte footer
};

struct parent_locator {
    uint32          platform_code;
    uint32          platform_data_space;
    uint32          platform_data_length;
    uint32          reserved;
    uint64          platform_data_offset;
};

struct dynamic_header {
    char            cookie[8];
    uint64          data_offset;
    uint64          table_offset;
    uint32          header_version;
    uint32          max_table_entries;
    uint32          block_size;
    uint32          checksum;
    char            parent_unique_id[16];
    uint32          parent_timestamp;
    uint32          reserved;
    char            parent_unicode_name[512];
    parent_locator  parent_locators[8];
    char            reserved[256];
};
"""

c_vhd = cstruct.cstruct(endian=">")
c_vhd.load(vhd_def)

SECTOR_SIZE = 512
