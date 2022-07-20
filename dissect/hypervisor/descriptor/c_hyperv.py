from dissect import cstruct


hyperv_def = """
/* ======== File header ======== */

#define SIGNATURE_STORAGE_HEADER            0x01282014
#define FIRST_HEADER_OFFSET                 0x00000000
#define SECOND_HEADER_OFFSET                0x00001000

struct HyperVStorageHeader {
    uint32      signature;                  // 0x01282014
    uint32      checksum;                   // Checksum of this header (0x2e), with this field set to 0
    uint16      sequence_number;            // Header sequence number
    uint32      version;                    // Format version
    uint64      unknown2;                   //
    uint32      alignment;                  // Can't be over 0x10000
    uint64      replay_log_offset;          // Offset of the HyperVStorageReplayLog header
    uint64      replay_log_size;            // Log size
    uint32      header_size;                // File header size
};

/* ======== Replay log ======== */

#define SIGNATURE_REPLAY_LOG_HEADER         0x01110003

struct HyperVStorageReplayLog {
    uint32      signature;                  // 0x01110003
    uint32      checksum;                   // Checksum of this header (0x22), with this field set to 0
    uint32      num_entries;
    uint8       unknown1;
    uint32      max_entries;
    uint32      unknown2;
    uint32      unknown3;
    uint32      unknown4;
    uint32      unknown5;
    uint8       unknown6;
};

struct HyperVStorageReplayLogEntry {
    uint64      offset;
    uint32      size;
    uint32      unknown2;
    uint32      unknown3;
    uint32      checksum;                   // Checksum of this entry (0x1C), with this field set to 0
    uint32      data_checksum;              // Checksum of the data for this log entry
};

/* ======== Object tables ======== */

#define SIGNATURE_OBJECT_TABLE_HEADER       0x01110001
#define OBJECT_TABLE_OFFSET                 0x00002000

enum ObjectEntryType : uint8 {
    Unknown0 = 0,                           // <unknown(0)>
    ObjectTable = 1,                        // Object Table
    KeyTable = 2,                           // Key File
    File = 3,                               // File
    Free = 4,                               // Free
    Unknown5Header = 5,                     // <unknown(5)>Header
    ReplayLog = 6,                          // Replay Log
    ChangeTrackingBuffer = 7,               // Change Tracking Buffer
};

struct HyperVStorageObjectTable {
    uint32      signature;                  // 0x01110001
    uint32      num_entries;
};

struct HyperVStorageObjectTableEntry {
    ObjectEntryType type;                   // Entry Type
    uint32      checksum;                   // Checksum of this entry (0x12), with this field set to 0
    uint64      offset;                     // Entry offset
    uint32      size;                       // Entry size
    uint8       allocated;                  // Allocated flag
};

/* ======== Key tables ======== */

#define SIGNATURE_KEY_TABLE_HEADER          0x0002

enum KeyDataType : uint8 {
    Free = 1,
    Unknown = 2,
    Int = 3,
    UInt = 4,
    Double = 5,
    String = 6,
    Array = 7,
    Bool = 8,
    Node = 9,
};

flag KeyDataFlag : uint8 {
    FileObjectPointer = 0x01,
};

struct HyperVStorageKeyTable {
    uint16      signature;                  // 0x0002
    uint16      index;                      // Table index
    uint16      sequence_number;            // Table sequence number
    uint32      checksum;                   // Checksum of this header (0xA), with this field set to 0
};

struct HyperVStorageKeyTableEntryHeader {
    uint16      type;                       // Must be <= KeyDataType.Node
    uint32      size;                       // Size of this entry
    uint16      parent_table_idx;           // Table index of the parent node
    uint32      parent_offset;              // Offset of the parent node in the parent table
    uint32      checksum;                   // Reference: HyperVStorageKeyTableEntry::CalculateChecksum
    uint32      insertion_sequence;         // Reference: HyperVStorageKeyTableEntry::SetInsertionSequence
    uint8       data_offset;                // Offset into the entry data to get to the value data
};
"""

c_hyperv = cstruct.cstruct()
c_hyperv.load(hyperv_def)

ObjectEntryType = c_hyperv.ObjectEntryType
KeyDataType = c_hyperv.KeyDataType
KeyDataFlag = c_hyperv.KeyDataFlag
