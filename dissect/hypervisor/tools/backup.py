import argparse
import logging
import sys
from pathlib import Path

from dissect.hypervisor.backup.c_vma import c_vma
from dissect.hypervisor.backup.vbk import VBK, DirItem
from dissect.hypervisor.backup.vma import VMA, _iter_mask

try:
    from rich.logging import RichHandler
    from rich.progress import (
        BarColumn,
        DownloadColumn,
        Progress,
        TextColumn,
        TimeRemainingColumn,
        TransferSpeedColumn,
    )

    progress = Progress(
        TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.1f}%",
        "•",
        DownloadColumn(),
        "•",
        TransferSpeedColumn(),
        "•",
        TimeRemainingColumn(),
        transient=True,
    )
except ImportError:
    RichHandler = logging.StreamHandler

    class Progress:
        def __init__(self):
            self.filename = None
            self.total = None

            self._task_id = 0
            self._info = {}

        def __enter__(self):
            pass

        def __exit__(self, *args, **kwargs) -> None:
            sys.stderr.write("\n")
            sys.stderr.flush()

        def add_task(self, name: str, filename: str, total: int, **kwargs) -> int:
            task_id = self._task_id
            self._task_id += 1

            self._info[task_id] = {"filename": filename, "total": total, "position": 0}

            return task_id

        def update(self, task_id: int, advance: int) -> None:
            self._info[task_id]["position"] += advance
            self.draw()

        def draw(self) -> None:
            infos = []
            for info in self._info.values():
                infos.append(f"{info['filename']} {(info['position'] / info['total']) * 100:0.2f}%")
            sys.stderr.write("\r" + " | ".join(infos))
            sys.stderr.flush()

    progress = Progress()


log = logging.getLogger(__name__)


def setup_logging(logger: logging.Logger, verbosity: int) -> None:
    if verbosity == 1:
        level = logging.ERROR
    elif verbosity == 2:
        level = logging.WARNING
    elif verbosity == 3:
        level = logging.INFO
    elif verbosity >= 4:
        level = logging.DEBUG
    else:
        level = logging.CRITICAL

    handler = RichHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.setLevel(level)
    logger.addHandler(handler)
    logger.setLevel(level)


def extract_vma(vma: VMA, out_dir: Path) -> None:
    log.info("Extracting config files")
    for config_name, config_data in vma.configs().items():
        out_file = out_dir.joinpath(config_name)

        log.info("%s -> %s (%d bytes)", config_name, out_file, len(config_data))
        out_file.write_bytes(config_data)

    log.info("Extracting device data")
    tasks = {}
    handles = {}
    for device in vma.devices():
        task_id = progress.add_task("extract", filename=device.name, total=device.size)
        tasks[device.id] = task_id
        handles[device.id] = out_dir.joinpath(device.name).open("wb")

    with progress:
        try:
            for extent in vma.extents():
                vma.fh.seek(extent.data_offset)
                for block_info in extent.header.blockinfo:
                    cluster_num = block_info & 0xFFFFFFFF
                    dev_id = (block_info >> 32) & 0xFF
                    mask = block_info >> (32 + 16)

                    if dev_id == 0:
                        continue

                    fh_out = handles[dev_id]
                    fh_out.seek(cluster_num * c_vma.VMA_CLUSTER_SIZE)

                    if mask == 0xFFFF:
                        fh_out.write(vma.fh.read(c_vma.VMA_CLUSTER_SIZE))
                    elif mask == 0:
                        fh_out.write(b"\x00" * c_vma.VMA_CLUSTER_SIZE)
                    else:
                        for allocated, count in _iter_mask(mask, 16):
                            if allocated:
                                fh_out.write(vma.fh.read(count * c_vma.VMA_BLOCK_SIZE))
                            else:
                                fh_out.write(b"\x00" * count * c_vma.VMA_BLOCK_SIZE)

                    progress.update(tasks[dev_id], advance=c_vma.VMA_CLUSTER_SIZE)
        except Exception as e:
            log.exception("Exception during extraction")
            log.debug("", exc_info=e)
        finally:
            for handle in handles.values():
                handle.close()


def extract_vbk(vbk: VBK, out_dir: Path) -> None:
    def extract_directory(directory: DirItem, out_dir: Path) -> None:
        out_dir.mkdir(exist_ok=True)
        for entry in directory.iterdir():
            out_path = out_dir.joinpath(entry.name)
            if entry.is_dir():
                extract_directory(entry, out_path)
            else:
                task_id = progress.add_task("extract", filename=entry.name, total=entry.size)
                with entry.open() as fh_in, out_path.open("wb") as fh_out:
                    for chunk in iter(lambda: fh_in.read(vbk.block_size), b""):
                        fh_out.write(chunk)
                        progress.update(task_id, advance=len(chunk))

    with progress:
        try:
            extract_directory(vbk.get("/"), out_dir)
        except Exception as e:
            log.exception("Exception during extraction")
            log.debug("", exc_info=e)


def main() -> None:
    parser = argparse.ArgumentParser(description="Hypervisor backup extractor")
    parser.add_argument("input", type=Path, help="path to backup file")
    parser.add_argument("-o", "--output", type=Path, required=True, help="path to output directory")
    parser.add_argument("-v", "--verbose", action="count", default=3, help="increase output verbosity")
    args = parser.parse_args()

    setup_logging(log, args.verbose)

    in_file = args.input.resolve()
    if not in_file.exists():
        log.error("Input file does not exist: %s", in_file)
        parser.exit()

    out_dir = args.output.resolve()
    if not out_dir.exists():
        log.error("Output path does not exist: %s", out_dir)
        parser.exit()

    if not out_dir.is_dir():
        log.error("Output path is not a directory: %s", out_dir)
        parser.exit()

    with in_file.open("rb") as fh:
        for klass, extract in ((VMA, extract_vma), (VBK, extract_vbk)):
            try:
                backup = klass(fh)
                extract(backup, out_dir)
                break
            except Exception as e:
                log.debug("Failed to extract using %s", klass.__name__, exc_info=e)
        else:
            log.error("Unknown backup format")
            parser.exit()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
