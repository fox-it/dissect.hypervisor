from xml.etree import ElementTree


class VBox:

    VBOX_XML_NAMESPACE = "{http://www.virtualbox.org/}"

    def __init__(self, fh):
        self._xml = ElementTree.fromstring(fh.read())

    def disks(self):
        for hdd_elem in self._xml.findall(
            f".//{self.VBOX_XML_NAMESPACE}HardDisk[@location][@format='VDI'][@type='Normal']"
        ):
            yield hdd_elem.attrib["location"]
