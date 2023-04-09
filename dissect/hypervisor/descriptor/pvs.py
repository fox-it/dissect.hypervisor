from typing import IO, Iterator
from xml.etree.ElementTree import Element

try:
    from defusedxml import ElementTree
except ImportError:
    from xml.etree import ElementTree


class PVS:
    """Parallels VM settings file.

    Args:
        fh: The file-like object to a PVS file.
    """

    def __init__(self, fh: IO):
        self._xml: Element = ElementTree.fromstring(fh.read())

    def disks(self) -> Iterator[str]:
        """Yield the disk file names."""
        for hdd_elem in self._xml.iterfind(".//Hdd"):
            system_name = hdd_elem.find("SystemName")
            if system_name is not None:
                yield system_name.text
