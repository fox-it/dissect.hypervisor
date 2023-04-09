from io import StringIO

from dissect.hypervisor.descriptor.pvs import PVS


def test_pvs():
    xml = """
    <?xml version="1.0" encoding="UTF-8"?>
    <ParallelsVirtualMachine dyn_lists="VirtualAppliance 0" schemaVersion="1.0">
        <Hardware dyn_lists="Fdd 0 CdRom 1 Hdd 9 Serial 0 Parallel 0 Printer 1 NetworkAdapter 4 Sound 1 USB 1 PciVideoAdapter 0 GenericDevice 0 GenericPciDevice 0 GenericScsiDevice 0 GenericNvmeDevice 0">
            <Hdd dyn_lists="Partition 0" id="0">
                <SystemName>Fedora-0.hdd</SystemName>
            </Hdd>
        </Hardware>
    </ParallelsVirtualMachine>
    """  # noqa: E501

    with StringIO(xml.strip()) as fh:
        pvs = PVS(fh)
        assert next(pvs.disks()) == "Fedora-0.hdd"
