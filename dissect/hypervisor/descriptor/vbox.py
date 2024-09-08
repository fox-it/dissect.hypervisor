from typing import IO, Iterator
from xml.etree.ElementTree import Element

from defusedxml import ElementTree


class VBox:
    VBOX_XML_NAMESPACE = "{http://www.virtualbox.org/}"

    def __init__(self, fh: IO):
        self._xml: Element = ElementTree.fromstring(fh.read())

    def disks(self) -> Iterator[str]:
        for hdd_elem in self._xml.findall(f".//{self.VBOX_XML_NAMESPACE}HardDisk[@location][@type='Normal']"):
            # Allow format specifier to be case-insensitive (i.e. VDI, vdi)
            if (format := hdd_elem.get("format")) and format.lower() == "vdi":
                yield hdd_elem.attrib["location"]
