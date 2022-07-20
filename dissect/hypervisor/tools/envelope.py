import argparse
import sys
from pathlib import Path

from dissect.hypervisor.util.envelope import Envelope, KeyStore


def main():
    parser = argparse.ArgumentParser(description="ESXi envelope file decrypter")
    parser.add_argument("envelope", type=Path, help="envelope file")
    parser.add_argument("-ks", "--keystore", type=Path, required=True, help="keystore file")
    parser.add_argument("-o", "--output", type=Path, required=True, help="output file")
    args = parser.parse_args()

    if not args.envelope.exists() or not args.keystore.exists():
        parser.exit("Need both envelope and keystore file")

    with args.envelope.open("rb") as fh:
        envelope = Envelope(fh)
        keystore = KeyStore.from_text(args.keystore.read_text())

        with args.output.open("wb") as fhout:
            fhout.write(envelope.decrypt(keystore.key))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
