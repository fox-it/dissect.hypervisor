from typing import IO, Iterator
from xml.etree.ElementTree import Element

try:
    from defusedxml import ElementTree
except ImportError:
    from xml.etree import ElementTree


class VBox:
    VBOX_XML_NAMESPACE = "{http://www.virtualbox.org/}"

    def __init__(self, fh: IO):
        self._xml: Element = ElementTree.fromstring(fh.read())

    def disks(self) -> Iterator[str]:
        for hdd_elem in self._xml.findall(
            f".//{self.VBOX_XML_NAMESPACE}HardDisk[@location][@format='VDI'][@type='Normal']"
        ):
            yield hdd_elem.attrib["location"]
