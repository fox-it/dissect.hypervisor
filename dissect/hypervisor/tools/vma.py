import argparse
import logging
import sys
from pathlib import Path

from dissect.hypervisor.backup.vma import VMA, _iter_mask
from dissect.hypervisor.backup.c_vma import c_vma

try:
    from rich.logging import RichHandler
    from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn, TransferSpeedColumn

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

        def __exit__(self, *args, **kwargs):
            sys.stderr.write("\n")
            sys.stderr.flush()

        def add_task(self, name, filename, total, **kwargs):
            task_id = self._task_id
            self._task_id += 1

            self._info[task_id] = {"filename": filename, "total": total, "position": 0}

            return task_id

        def update(self, task_id, advance):
            self._info[task_id]["position"] += advance
            self.draw()

        def draw(self):
            infos = []
            for info in self._info.values():
                infos.append(f"{info['filename']} {(info['position'] / info['total']) * 100:0.2f}%")
            sys.stderr.write("\r" + " | ".join(infos))
            sys.stderr.flush()

    progress = Progress()


log = logging.getLogger(__name__)


def setup_logging(logger, verbosity):
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


def main():
    parser = argparse.ArgumentParser(description="VMA extractor")
    parser.add_argument("input", type=Path, help="path to vma file")
    parser.add_argument("-o", "--output", type=Path, help="path to output directory")
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
        vma = VMA(fh)

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
                    data_offset = extent.data_offset
                    for block_info in extent.header.blockinfo:
                        cluster_num = block_info & 0xFFFFFFFF
                        dev_id = (block_info >> 32) & 0xFF
                        mask = block_info >> (32 + 16)

                        if dev_id == 0:
                            continue

                        fh_out = handles[dev_id]
                        fh_out.seek(cluster_num * c_vma.VMA_CLUSTER_SIZE)

                        vma.fh.seek(data_offset)
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
            except Exception:
                log.exception("Exception during extraction")
            finally:
                for handle in handles.values():
                    handle.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
