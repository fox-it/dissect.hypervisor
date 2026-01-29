from __future__ import annotations

from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, TextIO
from uuid import UUID

from defusedxml import ElementTree

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

NS = "{http://www.virtualbox.org/}"


class VBox:
    """VirtualBox XML descriptor parser.

    Args:
        fh: A file-like object of the VirtualBox XML descriptor.
    """

    def __init__(self, fh: TextIO):
        self._xml: Element = ElementTree.fromstring(fh.read())
        if self._xml.tag != f"{NS}VirtualBox":
            raise ValueError("Invalid VirtualBox XML descriptor: root element is not VirtualBox")

        if (machine := self._xml.find(f"./{NS}Machine")) is None:
            raise ValueError("Invalid VirtualBox XML descriptor: no Machine element found")

        if machine.find(f"./{NS}Hardware") is None:
            raise ValueError("Invalid VirtualBox XML descriptor: no Hardware element found")

        self.machine = Machine(self, machine)

    def __repr__(self) -> str:
        return f"<VBox uuid={self.uuid} name={self.name}>"

    @property
    def uuid(self) -> UUID | None:
        """The VM UUID."""
        return self.machine.uuid

    @property
    def name(self) -> str | None:
        """The VM name."""
        return self.machine.name

    @property
    def media(self) -> dict[UUID, HardDisk]:
        """The media (disks) registry."""
        return self.machine.media

    @property
    def hardware(self) -> Hardware:
        """The current machine hardware state."""
        return self.machine.hardware

    @property
    def snapshots(self) -> dict[UUID, Snapshot]:
        """All snapshots."""
        return self.machine.snapshots


class Machine:
    def __init__(self, vbox: VBox, element: Element):
        self.vbox = vbox
        self.element = element

    def __repr__(self) -> str:
        return f"<Machine uuid={self.uuid} name={self.name}>"

    @property
    def uuid(self) -> UUID:
        """The machine UUID."""
        return UUID(self.element.get("uuid").strip("{}"))

    @property
    def name(self) -> str:
        """The machine name."""
        return self.element.get("name")

    @property
    def current_snapshot(self) -> UUID | None:
        """The current snapshot UUID."""
        if (value := self.element.get("currentSnapshot")) is not None:
            return UUID(value.strip("{}"))
        return None

    @cached_property
    def media(self) -> dict[UUID, HardDisk]:
        """The media (disks) registry."""
        result = {}

        stack = [(None, element) for element in self.element.find(f"./{NS}MediaRegistry/{NS}HardDisks")]
        while stack:
            parent, element = stack.pop()
            hdd = HardDisk(self, element, parent)
            result[hdd.uuid] = hdd

            stack.extend([(hdd, child) for child in element.findall(f"./{NS}HardDisk")])

        return result

    @cached_property
    def hardware(self) -> Hardware:
        """The machine hardware state."""
        return Hardware(self.vbox, self.element.find(f"./{NS}Hardware"))

    @cached_property
    def snapshots(self) -> dict[UUID, Snapshot]:
        """All snapshots."""
        result = {}

        if (element := self.element.find(f"./{NS}Snapshot")) is None:
            return result

        stack = [(None, element)]
        while stack:
            parent, element = stack.pop()
            snapshot = Snapshot(self.vbox, element, parent)
            result[snapshot.uuid] = snapshot

            if (snapshots := element.find(f"./{NS}Snapshots")) is not None:
                stack.extend([(snapshot, child) for child in list(snapshots)])

        return result

    @property
    def parent(self) -> Snapshot | None:
        if (uuid := self.current_snapshot) is not None:
            return self.vbox.snapshots[uuid]
        return None


class HardDisk:
    def __init__(self, vbox: VBox, element: Element, parent: HardDisk | None = None):
        self.vbox = vbox
        self.element = element
        self.parent = parent

    def __repr__(self) -> str:
        return f"<HardDisk uuid={self.uuid} location={self.location}>"

    @property
    def uuid(self) -> UUID:
        """The disk UUID."""
        return UUID(self.element.get("uuid").strip("{}"))

    @property
    def location(self) -> str:
        """The disk location."""
        return self.element.get("location")

    @property
    def type(self) -> str | None:
        """The disk type."""
        return self.element.get("type")

    @property
    def format(self) -> str:
        """The disk format."""
        return self.element.get("format")

    @cached_property
    def properties(self) -> dict[str, str]:
        """The disk properties."""
        return {prop.get("name"): prop.get("value") for prop in self.element.findall(f"./{NS}Property")}

    @property
    def is_encrypted(self) -> bool:
        """Whether the disk is encrypted."""
        disk = self
        while disk is not None:
            if "CRYPT/KeyId" in disk.properties or "CRYPT/KeyStore" in disk.properties:
                return True
            disk = disk.parent

        return False


class Snapshot:
    def __init__(self, vbox: VBox, element: Element, parent: Snapshot | Machine | None = None):
        self.vbox = vbox
        self.element = element
        self.parent = parent

    def __repr__(self) -> str:
        return f"<Snapshot uuid={self.uuid} name={self.name}>"

    @property
    def uuid(self) -> UUID:
        """The snapshot UUID."""
        return UUID(self.element.get("uuid").strip("{}"))

    @property
    def name(self) -> str:
        """The snapshot name."""
        return self.element.get("name")

    @property
    def ts(self) -> datetime:
        """The snapshot timestamp."""
        return datetime.strptime(self.element.get("timeStamp"), "%Y-%m-%dT%H:%M:%S%z")

    @cached_property
    def hardware(self) -> Hardware:
        """The snapshot hardware state."""
        return Hardware(self.vbox, self.element.find(f"./{NS}Hardware"))


class Hardware:
    def __init__(self, vbox: VBox, element: Element):
        self.vbox = vbox
        self.element = element

    def __repr__(self) -> str:
        return f"<Hardware disks={len(self.disks)}>"

    @property
    def disks(self) -> list[HardDisk]:
        """All attached hard disks."""
        images = self.element.findall(
            f"./{NS}StorageControllers/{NS}StorageController/{NS}AttachedDevice[@type='HardDisk']/{NS}Image"
        )
        return [self.vbox.media[UUID(image.get("uuid").strip("{}"))] for image in images]
