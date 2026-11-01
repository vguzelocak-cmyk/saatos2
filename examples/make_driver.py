"""Generate a tiny Native AMD64 PE test image; no third-party binary required."""

import argparse
from pathlib import Path
import struct
import sys


def make_image(status=0, behavior="return"):
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 3, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    base = 0x140000000
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, base)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HH", data, optional + 40, 6, 0)
    struct.pack_into("<HH", data, optional + 48, 6, 0)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    struct.pack_into("<H", data, optional + 68, 1)
    struct.pack_into("<QQQQ", data, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", data, optional + 108, 16)
    code = bytearray()
    branches = []
    # DriverEntry receives the DRIVER_OBJECT in RCX and registry path in RDX.
    for instruction in (b"\x66\x83\x39\x04",       # cmp word [rcx], 4
                        b"\x66\x81\x79\x02\x50\x01"):  # cmp word [rcx+2], 0x150
        code.extend(instruction)
        code.extend(b"\x75\x00")                    # jne failure
        branches.append(len(code) - 1)
    code.extend(b"\x48\x85\xd2\x74\x00")         # test rdx, rdx; je failure
    branches.append(len(code) - 1)
    code.extend(b"\x66\x83\x3a\x00\x74\x00")     # cmp word [rdx], 0; je failure
    branches.append(len(code) - 1)
    relocation_offset = len(code) + 2
    code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2000))  # movabs rax, &status
    code.extend(b"\x8b\x00\xc3")                   # mov eax, [rax]; ret
    failure = len(code)
    code.extend(b"\xb8\x0d\x00\x00\xc0\xc3")     # STATUS_INVALID_PARAMETER
    for offset in branches:
        code[offset] = failure - (offset + 1)
    relocation = struct.pack("<IIHH", 0x1000, 12, 0xA000 | relocation_offset, 0)
    if behavior != "return":
        code = {"loop": b"\xeb\xfe", "crash": b"\x0f\x0b"}[behavior]
        relocation = struct.pack("<II", 0x1000, 8)
    struct.pack_into("<II", data, optional + 112 + 5 * 8, 0x3000, len(relocation))
    for index, (name, rva, offset, length, flags) in enumerate((
        (b".text", 0x1000, 0x200, len(code), 0x60000020),
        (b".data", 0x2000, 0x400, 4, 0xC0000040),
        (b".reloc", 0x3000, 0x600, len(relocation), 0x42000040),
    )):
        section = 0x188 + index * 40
        struct.pack_into("<8sIIIIIIHHI", data, section, name, length, rva, 0x200, offset, 0, 0, 0, 0, flags)
    data[0x200:0x200 + len(code)] = code
    struct.pack_into("<I", data, 0x400, status)
    data[0x600:0x600 + len(relocation)] = relocation
    return bytes(data)


def write_image(path, data):
    try:
        try:
            with path.open("xb") as destination:
                destination.write(data)
            print(f"Created test driver: {path}")
        except FileExistsError:
            with path.open("rb") as source:
                existing = source.read(len(data) + 1)
            if existing != data:
                print(f"Refusing to overwrite different file: {path}", file=sys.stderr)
                return 2
            print(f"Using matching existing test driver: {path}")
    except OSError as error:
        print(f"Cannot create test driver: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raise SystemExit(write_image(args.output, make_image()))
