from __future__ import annotations

from dissect.cstruct import cstruct

# https://github.com/VirtualBox/virtualbox/blob/main/src/VBox/Storage/VDICore.h
vdi_def = """
enum VDI_IMAGE_TYPE {
    /** Normal dynamically growing base image file. */
    NORMAL          = 1,
    /** Preallocated base image file of a fixed size. */
    FIXED,
    /** Dynamically growing image file for undo/commit changes support. */
    UNDO,
    /** Dynamically growing image file for differencing support. */
    DIFF,
};

flag VDI_IMAGE_FLAGS {
    /** Fill new blocks with zeroes while expanding image file. Only valid
     * for newly created images, never set for opened existing images. */
    ZERO_EXPAND     = 0x0100,
};

typedef struct VDIDISKGEOMETRY {
    /** Cylinders. */
    uint32_t        Cylinders;
    /** Heads. */
    uint32_t        Heads;
    /** Sectors per track. */
    uint32_t        Sectors;
    /** Sector size. (bytes per sector) */
    uint32_t        Sector;
} VDIDISKGEOMETRY, *PVDIDISKGEOMETRY;

typedef struct VDIPREHEADER {
    /** Just text info about image type, for eyes only. */
    char            szFileInfo[64];
    /** The image signature (VDI_IMAGE_SIGNATURE). */
    uint32_t        u32Signature;
    /** The image version (VDI_IMAGE_VERSION). */
    uint32_t        u32Version;
} VDIPREHEADER, *PVDIPREHEADER;

/**
 * Size of Comment field of HDD image header.
 */
#define VDI_IMAGE_COMMENT_SIZE      256

/* NOTE: All the header versions are additive, so just use the latest one. */
typedef struct VDIHEADER1PLUS {
    /** Size of this structure in bytes. */
    uint32_t        cbHeader;
    /** The image type (VDI_IMAGE_TYPE_*). */
    VDI_IMAGE_TYPE  u32Type;
    /** Image flags (VDI_IMAGE_FLAGS_*). */
    VDI_IMAGE_FLAGS fFlags;
    /** Image comment. (UTF-8) */
    char            szComment[VDI_IMAGE_COMMENT_SIZE];
    /** Offset of blocks array from the beginning of image file.
     * Should be sector-aligned for HDD access optimization. */
    uint32_t        offBlocks;
    /** Offset of image data from the beginning of image file.
     * Should be sector-aligned for HDD access optimization. */
    uint32_t        offData;
    /** Legacy image geometry (previous code stored PCHS there). */
    VDIDISKGEOMETRY LegacyGeometry;
    /** Was BIOS HDD translation mode, now unused. */
    uint32_t        u32Dummy;
    /** Size of disk (in bytes). */
    uint64_t        cbDisk;
    /** Block size. (For instance VDI_IMAGE_BLOCK_SIZE.) Should be a power of 2! */
    uint32_t        cbBlock;
    /** Size of additional service information of every data block.
     * Prepended before block data. May be 0.
     * Should be a power of 2 and sector-aligned for optimization reasons. */
    uint32_t        cbBlockExtra;
    /** Number of blocks. */
    uint32_t        cBlocks;
    /** Number of allocated blocks. */
    uint32_t        cBlocksAllocated;
    /** UUID of image. */
    char            uuidCreate[16];
    /** UUID of image's last modification. */
    char            uuidModify[16];
    /** Only for secondary images - UUID of previous image. */
    char            uuidLinkage[16];
    /** Only for secondary images - UUID of previous image's last modification. */
    char            uuidParentModify[16];
    /** LCHS image geometry (new field in VDI1.2 version. */
    VDIDISKGEOMETRY Geometry;
} VDIHEADER1PLUS, *PVDIHEADER1PLUS;
"""

c_vdi = cstruct().load(vdi_def)

VDI_IMAGE_SIGNATURE = 0xBEDA107F
VDI_IMAGE_BLOCK_FREE = ~0
VDI_IMAGE_BLOCK_ZERO = ~1
