import tarfile

from dissect.hypervisor.util import vmtar


def main() -> None:
    # We just want to run the main function of the tarfile module, but with our VisorTarFile and is_tarfile functions
    type(tarfile.main)(
        tarfile.main.__code__,
        tarfile.main.__globals__
        | {
            "TarFile": vmtar.VisorTarFile,
            "is_tarfile": vmtar.is_tarfile,
            "open": vmtar.open,
        },
    )()


if __name__ == "__main__":
    main()
