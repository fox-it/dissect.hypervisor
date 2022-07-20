from dissect import cstruct


wim_def = """
typedef char[16] GUID;
typedef uint64 LARGE_INTEGER;

#define FLAG_HEADER_RESERVED            0x00000001
#define FLAG_HEADER_COMPRESSION         0x00000002
#define FLAG_HEADER_READONLY            0x00000004
#define FLAG_HEADER_SPANNED             0x00000008
#define FLAG_HEADER_RESOURCE_ONLY       0x00000010
#define FLAG_HEADER_METADATA_ONLY       0x00000020
#define FLAG_HEADER_WRITE_IN_PROGRESS   0x00000040
#define FLAG_HEADER_RP_FIX              0x00000080 // reparse point fixup
#define FLAG_HEADER_COMPRESS_RESERVED   0x00010000
#define FLAG_HEADER_COMPRESS_XPRESS     0x00020000
#define FLAG_HEADER_COMPRESS_LZX        0x00040000

typedef struct _RESHDR_BASE_DISK
{
    union
    {
        ULONGLONG ullSize;
        struct
        {
           BYTE sizebytes[7];
           BYTE bFlags;
        };
    };
    LARGE_INTEGER liOffset;
} RESHDR_BASE_DISK;

typedef struct _RESHDR_DISK_SHORT
{
    RESHDR_BASE_DISK    Base;               // Must be first.
    LARGE_INTEGER       liOriginalSize;
} RESHDR_DISK_SHORT;

typedef struct _WIMHEADER_V1_PACKED
{
    CHAR                ImageTag[8];        // "MSWIM\0\0"
    DWORD               cbSize;
    DWORD               dwVersion;
    DWORD               dwFlags;
    DWORD               dwCompressionSize;
    GUID                gWIMGuid;
    USHORT              usPartNumber;
    USHORT              usTotalParts;
    DWORD               dwImageCount;
    RESHDR_DISK_SHORT   rhOffsetTable;
    RESHDR_DISK_SHORT   rhXmlData;
    RESHDR_DISK_SHORT   rhBootMetadata;
    DWORD               dwBootIndex;
    RESHDR_DISK_SHORT   rhIntegrity;
    BYTE                bUnused[60];
} WIMHEADER_V1_PACKED;
"""

c_wim = cstruct.cstruct()
c_wim.load(wim_def)

WIM_IMAGE_TAG = b"MSWIM\x00\x00\x00"
