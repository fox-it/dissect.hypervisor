import hashlib
import tarfile
from bisect import bisect_right
from xml.etree import ElementTree

from dissect.util.stream import AlignedStream

BLOCK_SIZE = 1024 * 1024


class XVA:
    """XVA reader.

    XenCenter export format. Basically a tar file with "blocks" of 1MB.
    """

    def __init__(self, fh):
        # We don't have to cache tar members, tarfile already does that for us
        self.tar = tarfile.open(fileobj=fh)
        self._ova = None

    @property
    def ova(self):
        if not self._ova:
            ova_member = self.tar.getmember("ova.xml")
            ova_fh = self.tar.extractfile(ova_member)
            self._ova = ElementTree.fromstring(ova_fh.read())
        return self._ova

    def disks(self):
        return [
            el.text
            for el in self.ova.findall(
                "*//member/name[.='VDI']/../..//name[.='type']/..value[.='Disk']/../..//name[.='VDI']/../value"
            )
        ]

    def open(self, ref, verify=False):
        size = int(
            self.ova.find(f"*//member/name[.='id']/../value[.='{ref}']/../..//name[.='virtual_size']/../value").text
        )
        return XVAStream(self, ref, size, verify)


class XVAStream(AlignedStream):
    """XVA stream.

    XenServer usually just streams an XVA file right into an output file, so our use-case requires a bit
    more trickery. We generally don't stream directly into an output file, but try to create a file-like
    object for other code to use.

    The numbers for the block files (weirdly) don't represent offsets. It's possible for a block file
    to be 0 sized, in which case you should "add" that block to the stream, and continue on to the next.
    The next block might have a number + 1 of what your current offset is, but it will still contain the
    data for that current offset. For this reason we build a lookup list with offsets.
    """

    def __init__(self, xva, ref, size, verify=False):
        self.xva = xva
        self.ref = ref
        self.verify = verify

        index = 0
        offset = 0
        self._lookup = []
        self._members = []
        for block_index, block_member, checksum_member in _iter_block_files(xva, ref):
            if block_index > index + 1:
                skipped = block_index - (index + 1)
                offset += skipped * BLOCK_SIZE

            if block_member.size != 0:
                self._lookup.append(offset)
                self._members.append((block_member, checksum_member))

                offset += block_member.size

            index = block_index

        super().__init__(size, align=BLOCK_SIZE)

    def _read(self, offset, length):
        result = []

        while length > 0:
            # This method is probably sub-optimal, but it's fairly low effort and we rarely encounter XVA anyway
            block_idx = bisect_right(self._lookup, offset)
            nearest_offset = self._lookup[block_idx - 1]

            if offset >= nearest_offset + BLOCK_SIZE:
                result.append(b"\x00" * BLOCK_SIZE)
            else:
                block_member, checksum_member = self._members[block_idx - 1]
                buf = self.xva.tar.extractfile(block_member).read()

                if self.verify:
                    if checksum_member is None:
                        raise ValueError(f"No checksum for {block_member.name}")

                    if (
                        checksum_member.name.endswith("checksum")
                        and hashlib.sha1(buf).hexdigest() != self.xva.tar.extractfile(checksum_member).read().decode()
                    ):
                        raise ValueError(f"Invalid checksum for {checksum_member.name}")
                    else:
                        raise NotImplementedError(f"Unsupported checksum: {checksum_member.name}")

                result.append(buf)

            offset += BLOCK_SIZE
            length -= BLOCK_SIZE

        return b"".join(result)


def _iter_block_files(xva, ref):
    member_index = None
    block_member = None
    checksum_member = None

    for member in xva.tar.getmembers():
        if not member.name.startswith(ref):
            continue

        index = int(member.name.split("/")[-1].split(".")[0])
        if member_index is None:
            member_index = index

        if member_index != index:
            yield (member_index, block_member, checksum_member)
            member_index = index

        if member.name.endswith(("checksum", "xxhash")):
            checksum_member = member
        else:
            block_member = member
