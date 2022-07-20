from xml.etree import ElementTree


class OVF:
    NS = {
        "ovf": "http://schemas.dmtf.org/ovf/envelope/1",
        "rasd": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData",
    }

    FILE_XPATH = "ovf:References/ovf:File"
    DISK_XPATH = "ovf:DiskSection/ovf:Disk"
    DISK_DRIVE_XPATH = 'ovf:VirtualSystem/ovf:VirtualHardwareSection/ovf:Item/[rasd:ResourceType="17"]'

    def __init__(self, fh):
        self.fh = fh
        self.xml = ElementTree.fromstring(fh.read())

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

    def disks(self):
        for disk in self.xml.findall(self.DISK_DRIVE_XPATH, self.NS):
            resource = disk.find("{{{rasd}}}HostResource".format(**self.NS))
            _, _, xpath = resource.text.partition(":")
            if xpath.startswith("/disk/"):
                disk_ref = xpath.split("/")[-1]
                yield self._disks[disk_ref]
            else:
                raise NotImplementedError(resource)
