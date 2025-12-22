from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, TextIO
from uuid import UUID

from defusedxml import ElementTree

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

NS = "{http://www.virtualbox.org/}"


class VBox:
    def __init__(self, fh: TextIO):
        self._xml: Element = ElementTree.fromstring(fh.read())
        if self._xml.tag != f"{NS}VirtualBox":
            raise ValueError("Invalid VirtualBox XML descriptor: root element is not VirtualBox")

        self.machine = self._xml.find(f"./{NS}Machine")
        if self.machine is None:
            raise ValueError("Invalid VirtualBox XML descriptor: no Machine element found")

        self.media: dict[str, HardDisk] = {}

        stack = [(None, element) for element in self.machine.find(f"./{NS}MediaRegistry/{NS}HardDisks")]
        while stack:
            parent, element = stack.pop()
            hdd = HardDisk(self, element, parent)

            self.media[hdd.uuid] = hdd
            stack.extend([(hdd, child) for child in list(element)])

        if (element := self.machine.find(f"./{NS}Hardware")) is None:
            raise ValueError("Invalid VirtualBox XML descriptor: no Hardware element found")
        self.hardware = Hardware(self, element)

    @property
    def uuid(self) -> UUID | None:
        """The VM UUID."""
        if self.machine is not None:
            return UUID(self.machine.get("uuid").strip("{}"))
        return None

    @property
    def name(self) -> str | None:
        """The VM name."""
        if self.machine is not None:
            return self.machine.get("name")
        return None

    @property
    def snapshots(self) -> list[Snapshot]:
        """All snapshots."""
        # Snapshots have a weird structure, since we don't do much with it for now, just get them flatly
        # TODO: Implement proper snapshot tree structure
        return [Snapshot(self, element) for element in self.machine.findall(f".//{NS}Snapshot")]


class HardDisk:
    def __init__(self, vbox: VBox, element: Element, parent: HardDisk | None = None):
        self.vbox = vbox
        self.element = element
        self.parent = parent

    @property
    def uuid(self) -> UUID:
        """The disk UUID."""
        return UUID(self.element.get("uuid").strip("{}"))

    @property
    def location(self) -> str:
        """The disk location."""
        return self.element.get("location")


class Snapshot:
    def __init__(self, vbox: VBox, element: Element):
        self.vbox = vbox
        self.element = element

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

    @property
    def hardware(self) -> Hardware:
        """The snapshot hardware state."""
        return Hardware(self.vbox, self.element.find(f"./{NS}Hardware"))


class Hardware:
    def __init__(self, vbox: VBox, element: Element):
        self.vbox = vbox
        self.element = element

    @property
    def disks(self) -> list[HardDisk]:
        """All attached hard disks."""
        images = self.element.findall(
            f"./{NS}StorageControllers/{NS}StorageController/{NS}AttachedDevice[@type='HardDisk']/{NS}Image"
        )
        return [self.vbox.media[UUID(image.get("uuid").strip("{}"))] for image in images]
