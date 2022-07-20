# References:
# - VmDataStore.dll

import struct

from dissect.util.stream import RangeStream

from dissect.hypervisor.descriptor.c_hyperv import KeyDataFlag, KeyDataType, ObjectEntryType, c_hyperv
from dissect.hypervisor.exceptions import InvalidSignature


class HyperVFile:
    """HyperVFile implementation.

    I think, technically, the underlying container is called HyperVStorage, and the HyperVFile adds
    some features on top of that. We just call it HyperVFile for convenience.

    A HyperVFile has 2 headers, one at 0x0000 and one at 0x1000. The active header is determined
    by a sequence number.

    A replay log is located at an offset specified in the header. This replay log functions as a journal
    for changes made to the file. A file is dirty if it contains outstanding entries in the replay log,
    and replaying the specified log entries is necessary. This is not currently implemented.

    An object table seems to be located at 0x2000, but it's unclear if this is always the case. The offset
    might be related to the header size, log size or data alignment. This will need some more research.
    This table contains entries that describe the various "objects" contained within this file. The available
    types are listed in the ObjectEntryType enum.

    HyperVFile's have a version number, and it looks like there are some slight differences between
    different versions. The key tables are at least stored in a different manner, because there's code
    to handle loading them differently, and also to update them to the new format if an old version is
    encountered. However, I haven't seen any files with older versions yet, so we guard this implementation
    to only version 0x0400 at this time.
    """

    def __init__(self, fh):
        self.fh = fh

        self.fh.seek(c_hyperv.FIRST_HEADER_OFFSET)
        header1 = c_hyperv.HyperVStorageHeader(self.fh)
        self.fh.seek(c_hyperv.SECOND_HEADER_OFFSET)
        header2 = c_hyperv.HyperVStorageHeader(self.fh)

        self.header = header1 if header1.sequence_number > header2.sequence_number else header2
        self.headers = [header1, header2]

        if self.header.signature != c_hyperv.SIGNATURE_STORAGE_HEADER:
            raise InvalidSignature(f"Invalid header signature: 0x{self.header.signature:x}")

        if self.header.version != 0x400:
            # Need test files to know how the keys are stored.
            raise NotImplementedError(f"Unsupported version: 0x{self.header.version:x}")

        self.replay_logs = [HyperVStorageReplayLog(self, self.header.replay_log_offset)]
        self.object_tables = [HyperVStorageObjectTable(self, c_hyperv.OBJECT_TABLE_OFFSET)]
        self.key_tables = {}
        self.file_objects = {}

        for object_table in self.object_tables:
            for entry in object_table.entries:
                if entry.allocated == 0:
                    continue

                if entry.type == ObjectEntryType.ObjectTable:
                    # Haven't seen a file yet with additional object tables, but I assume this is how it'd work
                    new_object_table = HyperVStorageObjectTable(self, entry.offset)
                    self.object_tables.append(new_object_table)

                if entry.type == ObjectEntryType.KeyTable:
                    key_table = HyperVStorageKeyTable(self, entry.offset, entry.size)
                    if key_table.index not in self.key_tables:
                        self.key_tables[key_table.index] = []
                    # Haven't seen a file yet with multiple tables of the same index, but different
                    # sequence number, but I assume this is how it'd work.
                    self.key_tables[key_table.index].append(key_table)
                    self.key_tables[key_table.index].sort(key=lambda table: table.sequence_number, reverse=True)

                if entry.type == ObjectEntryType.File:
                    self.file_objects[entry.offset] = HyperVStorageFileObject(self, entry.offset, entry.size)

                if entry.type == ObjectEntryType.ReplayLog:
                    # Haven't seen a file yet with additional replay logs, but I assume this is how it'd work
                    replay_log = HyperVStorageReplayLog(self, entry.offset)
                    self.replay_logs.append(replay_log)

        self.root = {}
        # Link all the children to their parents
        for key_tables in self.key_tables.values():
            active_table = key_tables[0]
            for entry in active_table.entries:
                if entry.type == KeyDataType.Free:
                    continue

                parent = entry.parent
                if parent:
                    parent.children[entry.key] = entry
                else:
                    self.root[entry.key] = entry

    def __getitem__(self, key):
        return self.root[key]

    def keys(self):
        return self.root.keys()

    def items(self):
        return self.root.items()

    def values(self):
        return self.root.values()

    def as_dict(self):
        obj = {}

        for key, entry in self.root.items():
            obj[key] = entry.as_dict()

        return obj

    @property
    def version(self):
        return self.header.version

    def _align(self, offset):
        remainder = offset % self.header.alignment
        if remainder == 0:
            return offset
        return offset + self.header.alignment - remainder


class HyperVStorageReplayLog:
    """The replay log tracks changes in the file.

    Old changes are actually still resident in the log, but not counted in the num_entries field.
    """

    def __init__(self, hyperv_file, offset):
        self.file = hyperv_file
        self.offset = offset

        self.file.fh.seek(offset)
        self.header = c_hyperv.HyperVStorageReplayLog(self.file.fh)

        if self.header.signature != c_hyperv.SIGNATURE_REPLAY_LOG_HEADER:
            raise InvalidSignature(f"Invalid replay log signature: 0x{self.header.signature:x}")

        self.entries = c_hyperv.HyperVStorageReplayLogEntry[self.header.num_entries](self.file.fh)


class HyperVStorageObjectTable:
    """The object table tracks all "objects".

    Objects are specific blocks in the file that have been designated a specific type.
    For example, the object table can list one or more key tables.
    """

    def __init__(self, hyperv_file, offset):
        self.file = hyperv_file
        self.offset = offset

        self.file.fh.seek(offset)
        self.header = c_hyperv.HyperVStorageObjectTable(self.file.fh)

        if self.header.signature != c_hyperv.SIGNATURE_OBJECT_TABLE_HEADER:
            raise InvalidSignature(f"Invalid object table signature: 0x{self.header.signature:x}")

        self.entries = c_hyperv.HyperVStorageObjectTableEntry[self.header.num_entries](self.file.fh)


class HyperVStorageKeyTable:
    """The key table stores key value pairs and their relation to parent keys.

    A table has a specific table index and one or more key entries.
    """

    def __init__(self, hyperv_file, offset, size):
        self.file = hyperv_file
        self.offset = offset
        self.size = size

        fh = self.file.fh
        fh.seek(offset)
        self.raw = memoryview(fh.read(size))

        self.header = c_hyperv.HyperVStorageKeyTable(self.raw)

        if self.header.signature != c_hyperv.SIGNATURE_KEY_TABLE_HEADER:
            raise InvalidSignature(f"Invalid key table signature: 0x{self.header.signature:x}")

        self.entries = []
        self._lookup = {}

        entry_offset = len(c_hyperv.HyperVStorageKeyTable)
        while entry_offset < size:
            entry = HyperVStorageKeyTableEntry(self, entry_offset)
            if entry.size == 0:
                break

            self.entries.append(entry)
            self._lookup[entry_offset] = entry

            entry_offset = entry_offset + entry.size

    @property
    def index(self):
        """Return the table index."""
        return self.header.index

    @property
    def sequence_number(self):
        """Return the table sequence number."""
        return self.header.sequence_number


class HyperVStorageKeyTableEntry:
    """Entry in a key table.

    The first 16 bytes are a combined flag and type field. The high 8 bits are flags, the low 8 bits are type.

    Only one flag is currently known, which we've called FileObjectPointer. It's the lowest bit of the flag bits.
    If this flag is set, it means the value of this entry is located in a file object. File objects pointers are
    12 bytes and consist of a uint32 size and a uint64 offset value. The offset is the absolute offset into the
    file. This method is similar to how parent keys are referenced.

    Values are stored in a file object if their size >= 0x800. As only strings and "arrays" are of variable size,
    these are the only data types that can be stored in file objects.

    Data type summary:

    - KeyDataType.Free:
        - Allocated but free.

    - KeyDataType.Unknown:
        - Unknown entry type. Anything greater than 9 and exactly 2 is unknown.

    - KeyDataType.Int:
        - Signed 64 bit integer.

    - KeyDataType.UInt:
        - Unsigned 64 bit integer.

    - KeyDataType.Double:
        - 64 bit double.

    - KeyDataType.String:
        - UTF-16-LE encoded string

    - KeyDataType.Array:
        - Bytes?

    - KeyDataType.Bool:
        - Boolean encoded as 32 bit integer.

    - KeyDataType.Node:
        - Tree nodes. Value size is coded as 8, but actual size is 12.
        - First 8 bytes are unknown, but latter 4 bytes is the insertion sequence number.
    """

    def __init__(self, table, offset):
        self.table = table
        self.offset = offset
        self.header = c_hyperv.HyperVStorageKeyTableEntryHeader(table.raw[offset:])
        self.children = {}

    def __getitem__(self, key):
        return self.children[key]

    def __repr__(self):
        return f"<HyperVStorageKeyTableEntry type={self.type} size={self.size}>"

    @property
    def parent(self):
        """Return the entry parent, if there is any.

        Requires that all key tables are loaded."""
        if not self.header.parent_table_idx:
            return None

        return self.table.file.key_tables[self.header.parent_table_idx][0]._lookup[self.header.parent_offset]

    @property
    def flags(self):
        """Return the entry flags."""
        return (self.header.type & 0xFF00) >> 8

    @property
    def type(self):
        """Return the entry type."""
        return KeyDataType(self.header.type & 0xFF)

    @property
    def size(self):
        """Return the entry size."""
        return self.header.size

    @property
    def is_file_object_pointer(self):
        """Return whether the value is a file object pointer."""
        return bool(KeyDataFlag(self.flags) & KeyDataFlag.FileObjectPointer)

    @property
    def file_object_pointer(self):
        """Return the file object pointer information."""
        if not self.is_file_object_pointer:
            raise TypeError(f"KeyTableEntry is not a file object pointer: {self}")

        data = self.raw[self.header.data_offset :]
        size, offset = struct.unpack("<IQ", data[:12])
        # We swap the values since that is a bit more logical
        return offset, size

    @property
    def raw(self):
        """Returns the raw data for this entry."""
        data_offset = self.offset + len(c_hyperv.HyperVStorageKeyTableEntryHeader)
        return self.table.raw[data_offset : self.offset + self.size]

    @property
    def data(self):
        """Returns the data portion for this entry."""
        if self.is_file_object_pointer:
            _, size = self.file_object_pointer
            file_object = self.get_file_object()
            # This memoryview has no purpose, only do it so the return value type is consistent
            return memoryview(file_object.read(size))
        else:
            return self.raw[self.header.data_offset :]

    @property
    def key(self):
        """Returns the key name for this entry."""
        # Subtract 1 for the terminating null byte
        return self.raw.tobytes()[: self.header.data_offset - 1].decode("utf-8")

    @property
    def value(self):
        """Return a Python native value for this entry."""
        data = self.data

        if self.type == KeyDataType.Int:
            return struct.unpack("<q", data[:8])[0]

        if self.type == KeyDataType.UInt:
            return struct.unpack("<Q", data[:8])[0]

        if self.type == KeyDataType.Double:
            return struct.unpack("<d", data[:8])[0]

        if self.type in (KeyDataType.String, KeyDataType.Array):
            if not self.is_file_object_pointer:
                data_len = struct.unpack("<I", data[:4])[0]
                data = data[4 : 4 + data_len]

            data = data.tobytes()
            if self.type == KeyDataType.String:
                return data.decode("utf-16-le")
            return data

        if self.type == KeyDataType.Bool:
            return struct.unpack("<I", data[:4])[0] != 0

    @property
    def data_size(self):
        """Return the total amount of data bytes, including the key name.

        Reference:
        - HyperVStorageKeyTableEntry::GetDataSizeInBytes
        """
        if self.type == KeyDataType.Node:
            return self.header.data_offset + 12
        return self.header.data_offset + self.value_size

    @property
    def value_size(self):
        """Return the amount of bytes a value occupies.

        Reference:
        - HyperVStorageKeyTableEntry::GetValueSizeInBytes
        """
        if self.type == KeyDataType.Free:
            return self.header.size - len(c_hyperv.HyperVStorageKeyTableEntryHeader)

        if self.is_file_object_pointer:
            return 12

        if self.type == KeyDataType.Node:
            # The code returns 8 here, but it's actually 12?
            # First 8 bytes is an unknown value, but the latter 4 bytes are an insertion sequence number
            return 8

        if self.type in (KeyDataType.String, KeyDataType.Array):
            return struct.unpack("<I", self.raw[self.header.data_offset : self.header.data_offset + 4])[0]

        if self.type in (KeyDataType.Int, KeyDataType.UInt):
            return 8

        if self.type == KeyDataType.Double:
            return 8

        if self.type == KeyDataType.Bool:
            return 4

        raise TypeError(f"Unknown data type: {self.type}")

    def keys(self):
        return self.children.keys()

    def items(self):
        return self.children.items()

    def values(self):
        return self.children.values()

    def as_dict(self):
        if self.type != KeyDataType.Node:
            raise TypeError(f"KeyTableEntry can't be dumped as dictionary: {self.type}")

        obj = {}
        for key, child in self.children.items():
            if child.type == KeyDataType.Node:
                value = child.as_dict()
            else:
                value = child.value

            obj[key] = value

        return obj

    def get_file_object(self):
        if not self.is_file_object_pointer:
            raise TypeError(f"Entry is not a file object pointer: {self}")

        offset, size = self.file_object_pointer
        file_object = self.table.file.file_objects.get(offset)
        if not file_object:
            raise ValueError(f"Unknown file object: 0x{offset:x} (0x{size:x})")

        return file_object


class HyperVStorageFileObject:
    """File object from the object table.

    File objects are referenced by their absolute offset in the file. The object table also stores
    a size, but this size will always be aligned with the data alignment of the Hyper-V file.
    The actual size of the data stored is located in the data portion of the HyperVStorageKeyTableEntry
    that references that file object.
    """

    def __init__(self, hyperv_file, offset, size):
        self.file = hyperv_file
        self.offset = offset
        self.size = size

    def read(self, n=-1):
        if n is not None and n < -1:
            raise ValueError("invalid number of bytes to read")

        if n == -1:
            read_length = self.size
        else:
            read_length = min(n, self.size)

        self.file.fh.seek(self.offset)
        return self.file.fh.read(read_length)

    def open(self, size=None):
        return RangeStream(self.file.fh, self.offset, size or self.size)
