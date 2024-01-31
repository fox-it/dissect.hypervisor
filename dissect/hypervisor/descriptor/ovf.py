from typing import Iterator, TextIO
from xml.etree.ElementTree import Element

from defusedxml import ElementTree


class OVF:
    NS = {
        "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
        "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
    }

    FILE_XPATH = "ovf:References/ovf:File"
    DISK_XPATH = "ovf:DiskSection/ovf:Disk"
    DISK_DRIVE_XPATH = 'ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item/[rasd:ResourceType="17"]'

    def __init__(self, fh: TextIO):
        self.fh = fh
        self.xml: Element = ElementTree.fromstring(fh.read())

        self.references = {}
        for file_ in self.xml.findall(self.FILE_XPATH, self.NS):
            file_id = file_.get("{{{ovf}}}id".format(**self.NS))
            href = file_.get("{{{ovf}}}href".format(**self.NS))
            self.references[file_id] = href

        self._disks = {}
        for disk in self.xml.findall(self.DISK_XPATH, self.NS):
            disk_id = disk.get("{{{ovf}}}diskId".format(**self.NS))
            file_ref = disk.get("{{{ovf}}}fileRef".format(**self.NS))
            self._disks[disk_id] = self.references[file_ref]

    def disks(self) -> Iterator[str]:
        for disk in self.xml.findall(self.DISK_DRIVE_XPATH, self.NS):
            resource = disk.find("{{{rasd}}}HostResource".format(**self.NS))
            xpath = resource.text
            if xpath.startswith("ovf:"):
                xpath = xpath[4:]

            if xpath.startswith("/disk/"):
                disk_ref = xpath.split("/")[-1]
                yield self._disks[disk_ref]
            elif xpath.startswith("/file/"):
                file_ref = xpath.split("/")[-1]
                yield self.references[file_ref]
            else:
                raise NotImplementedError(resource)
