from __future__ import annotations

from typing import TYPE_CHECKING, TextIO

from defusedxml import ElementTree

if TYPE_CHECKING:
    from collections.abc import Iterator
    from xml.etree.ElementTree import Element


class PVS:
    """Parallels VM settings file.

    Args:
        fh: The file-like object to a PVS file.
    """

    def __init__(self, fh: TextIO):
        self._xml: Element = ElementTree.fromstring(fh.read())

    def disks(self) -> Iterator[str]:
        """Yield the disk file names."""
        for hdd_elem in self._xml.iterfind(".//Hdd"):
            system_name = hdd_elem.find("SystemName")
            if system_name is not None:
                yield system_name.text
