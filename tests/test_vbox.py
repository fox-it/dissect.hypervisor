from io import StringIO

from dissect.hypervisor.descriptor.vbox import VBox


def test_vbox():

    xml = """
    <?xml version="1.0"?>
    <VirtualBox xmlns="http://www.virtualbox.org/">
        <Machine>
            <MediaRegistry>
                <HardDisks>
                    <HardDisk location="os2warp4.vdi" format="VDI" type="Normal" />
                </HardDisks>
            </MediaRegistry>
        </Machine>
    </VirtualBox>
    """

    with StringIO(xml.strip()) as fh:
        vbox = VBox(fh)
        assert next(vbox.disks()) == "os2warp4.vdi"
