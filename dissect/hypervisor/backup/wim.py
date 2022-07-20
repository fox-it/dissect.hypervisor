from dissect.hypervisor.backup.c_wim import c_wim, WIM_IMAGE_TAG
from dissect.hypervisor.exceptions import InvalidHeaderError


class WIM:
    def __init__(self, fh):
        self.fh = fh
        self.header = c_wim.WIMHEADER_V1_PACKED(fh)

        if self.header.ImageTag != WIM_IMAGE_TAG:
            raise InvalidHeaderError("Expected MSWIM header, got: {!r}".format(self.header.ImageTag))
