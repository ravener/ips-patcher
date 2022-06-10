#!/usr/bin/python3

import struct
import sys
from io import BytesIO

def parse_ips_file(data):
    patches = []
    (P, A, T, C, H) = struct.unpack_from(">ccccc", data)

    if P != b'P' or A != b'A' or T != b'T' or C != b'C' or H != b'H':
        raise Exception("Invalid file header, not an IPS file.")

    offset = 5
    EOF = False

    while not EOF:
        # Parse patch header.
        # 3 Bytes target offset.
        # 2 Bytes patch length
        (a, b, c, length) = struct.unpack_from(">BBBH", data, offset)
        offset += 5

        # Because there's no integer type for 3 bytes
        # we parsed the individual bytes and combine it here
        target_offset = int.from_bytes([a, b, c], "big")

        # RLE Patch
        if length == 0:
            (run_len, value) = struct.unpack_from(">HB", data, offset)
            offset += 3
            patches.append((target_offset, length, run_len, value))
        else:
            patch = data[offset:offset + length]
            offset += length
            patches.append((target_offset, length, patch))

        # Check for EOF
        if offset + 3 <= len(data):
            (E, O, F) = struct.unpack_from(">ccc", data, offset)
            if E == b'E' and O == b'O' and F == b'F':
                EOF = True

    return patches

# Adds a .patched extension before the actual file extension.
# file.rom -> file.patched.rom
def filename(name):
    split = name.split(".")

    if len(split) > 1:
        split.insert(-1, "patched")
        return ".".join(split)
    else:
        return split[0] + ".patched"


def patch(rom, patches):
    data = BytesIO(rom)

    for (offset, length, *patch) in patches:
        # RLE
        if length == 0:
            (run_len, value) = patch
            data.seek(offset)
            data.write(bytes([value] * run_len))
        else:
            data.seek(offset)
            data.write(patch[0])

    return data.getvalue()


def main(argv):
    print("IPS Patcher by ravener https://github.com/ravener")

    if len(argv) < 2:
        print("Usage: <IPS Patch File> <ROM> [Output file]")
        return 1

    (ips_name, rom_name, *out) = argv

    output = out[0] if out else filename(rom_name)
    print(f"Output File: {output}")

    try:
        with open(ips_name, "rb") as ips:
            print(f"Parsing IPS file '{ips_name}'")
            patches = parse_ips_file(ips.read())

            with open(rom_name, "rb") as rom:
                print(f"Patching ROM '{rom_name}'")
                patched = patch(rom.read(), patches)

                print("Writing output.")
                with open(output, "wb") as outfile:
                    outfile.write(patched)
    except Exception as e:
        print(e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
