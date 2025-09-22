from __future__ import annotations

from dissect.cstruct import cstruct

asif_def = """
#define ASIF_HEADER_SIGNATURE       0x73686477  // 'shdw'
#define ASIF_META_HEADER_SIGNATURE  0x6D657461  // 'meta'

struct asif_header {
    uint32  header_signature;
    uint32  header_version;
    uint32  header_size;
    uint32  header_flags;
    uint64  directory_offsets[2];
    char    guid[16];
    uint64  sector_count;
    uint64  max_sector_count;
    uint32  chunk_size;
    uint16  block_size;
    uint16  total_segments;
    uint64  metadata_chunk;
    char    unk_50[16];
    uint32  read_only_flags;
    uint32  metadata_flags;
    uint32  metadata_read_only_flags;
};

struct asif_meta_header {
    uint32  header_signature;
    uint32  header_version;
    uint32  header_size;
    uint64  data_size;
    uint64  unk_14;
};
"""

c_asif = cstruct(endian=">").load(asif_def)
