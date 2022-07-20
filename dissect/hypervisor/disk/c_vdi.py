from dissect import cstruct


# https://www.virtualbox.org/browser/vbox/trunk/src/VBox/Storage/VDICore.h
# https://forums.virtualbox.org/viewtopic.php?t=8046
# 0000      3C 3C 3C 20 53 75 6E 20 78 56 4D 20 56 69 72 74    <<< Sun xVM Virt
# 0010      75 61 6C 42 6F 78 20 44 69 73 6B 20 49 6D 61 67    ualBox Disk Imag
# 0020      65 20 3E 3E 3E 0A 00 00 00 00 00 00 00 00 00 00    e >>>
# 0030      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
#
# 0040      7F 10 DA BE                                        Image Signature
#                       01 00 01 00                            Version 1.1
#                                   90 01 00 00                Size of Header(0x190)
#                                               01 00 00 00    Image Type (Dynamic VDI)
# 0050      00 00 00 00                                        Image Flags
#                       00 00 00 00 00 00 00 00 00 00 00 00    Image Description
# 0060-001F 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
# 0150      00 00 00 00
#                       00 02 00 00                            offsetBlocks
#                                   00 20 00 00                offsetData
#                                               00 00 00 00    #Cylinders (0)
# 0160      00 00 00 00                                        #Heads (0)
#                       00 00 00 00                            #Sectors (0)
#                                   00 02 00 00                SectorSize (512)
#                                               00 00 00 00     -- unused --
# 0170      00 00 00 78 00 00 00 00                            DiskSize (Bytes)
#                                   00 00 10 00                BlockSize
#                                               00 00 00 00    Block Extra Data (0)
# 0180      80 07 00 00                                        #BlocksInHDD
#                       0B 02 00 00                            #BlocksAllocated
#                                   5A 08 62 27 A8 B6 69 44    UUID of this VDI
# 0190      A1 57 E2 B2 43 A5 8F CB
#                                   0C 5C B1 E3 C5 73 ED 40    UUID of last SNAP
# 01A0      AE F7 06 D6 20 69 0C 96
#                                   00 00 00 00 00 00 00 00    UUID link
# 01B0      00 00 00 00 00 00 00 00
#                                   00 00 00 00 00 00 00 00    UUID Parent
# 01C0      00 00 00 00 00 00 00 00
#                                   CF 03 00 00 00 00 00 00    -- garbage / unused --
# 01D0      3F 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00    -- garbage / unused --
# 01E0      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    -- unused --
# 01F0      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    -- unused --

vdi_def = """
enum ImageType : uint32 {
    Dynamic         = 0x01,
    Fixed           = 0x02,
    Undo            = 0x03,
    Differencing    = 0x04
};

flag ImageFlags : uint32 {
    None            = 0x00000000,
    Split2G         = 0x00000001,
    ZeroExpand      = 0x00000002
};

struct HeaderDescriptor {
    char        FileInfo[64];
    uint32      Signature;
    uint32      Version;
    uint32      HeaderSize;
    ImageType   ImageType;
    ImageFlags  ImageFlags;
    char        ImageDescription[256];
    uint32      BlocksOffset;
    uint32      DataOffset;
    uint32      NumCylinders;
    uint32      NumHeads;
    uint32      NumSectors;
    uint32      SectorSize;
    uint32      Unused1;
    uint64      DiskSize;
    uint32      BlockSize;
    uint32      BlockExtraData;
    uint32      BlocksInHDD;
    uint32      BlocksAllocated;
    char        UUIDVDI[16];
    char        UUIDSNAP[16];
    char        UUIDLink[16];
    char        UUIDParent[16];
};
"""

c_vdi = cstruct.cstruct()
c_vdi.load(vdi_def)

VDI_SIGNATURE = 0xBEDA107F

UNALLOCATED = -1
SPARSE = -2
