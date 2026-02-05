#!/usr/bin/python3

from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Union


@dataclass
class Patch:
    """Represents a patch data for the intended offset"""

    offset: int
    data: bytes


@dataclass
class RLEPatch:
    """Represents a Run Length Encoding (RLE) patch for the intended offset"""

    offset: int
    run_length: int
    value: int


def parse_ips_file(data: bytes) -> list[Union[Patch, RLEPatch]]:
    if len(data) < 8:
        raise ValueError("IPS File too short")

    patches = []

    # Verify file magic header
    if data[:5] != b"PATCH":
        raise ValueError("Invalid file header, not an IPS file.")

    offset = 5

    while True:
        if offset + 5 > len(data):
            raise ValueError("Truncated or corrupt IPS file: incomplete patch record")

        # Parse patch header.
        # 3 Bytes target offset.
        # 2 Bytes patch length
        target_offset = int.from_bytes(data[offset : offset + 3])
        length = int.from_bytes(data[offset + 3 : offset + 5])

        offset += 5

        # RLE Patch
        if length == 0:
            run_length = int.from_bytes(data[offset : offset + 2])
            value = data[offset + 2]
            offset += 3
            patches.append(RLEPatch(target_offset, run_length, value))
        else:
            patch = data[offset : offset + length]
            offset += length
            patches.append(Patch(target_offset, patch))

        # Check for EOF
        if data[offset : offset + 3] == b"EOF":
            break

    return patches


# Adds a .patched extension before the actual file extension.
# file.rom -> file.patched.rom
def filename(name: str) -> Path:
    path = Path(name)

    return path.with_suffix(".patched" + path.suffix)


def patch(rom: bytes, patches: list[Union[Patch, RLEPatch]]) -> bytes:
    data = bytearray(rom)

    for patch in patches:
        offset = patch.offset

        if isinstance(patch, RLEPatch):
            run_length = patch.run_length
            data[offset : offset + run_length] = bytes([patch.value] * run_length)
        else:
            data[offset : offset + len(patch.data)] = patch.data

    return bytes(data)


def main() -> None:
    parser = ArgumentParser(description="Patch files using a .ips patch file.")

    parser.add_argument("input", help="Input file to patch")
    parser.add_argument("patch", help="The IPS patch file to apply")
    parser.add_argument("output", help="Output File", nargs="?")

    args = parser.parse_args()

    input_file = Path(args.input)
    patch_file = Path(args.patch)
    output_file = Path(args.output or filename(args.input))

    try:
        print(f"Parsing IPS file '{patch_file}'")
        patches = parse_ips_file(patch_file.read_bytes())
        print(f"Found {len(patches)} patch records")

        print(f"Patching file '{input_file}'")
        patched = patch(input_file.read_bytes(), patches)

        print(f"Writing output to '{output_file}'")
        output_file.write_bytes(patched)
    except FileNotFoundError as e:
        print(f"Error: File not found - {e.filename}")
    except ValueError as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
