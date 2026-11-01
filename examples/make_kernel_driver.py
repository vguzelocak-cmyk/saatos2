"""Build an AMD64 test driver which calls real NT-compatibility imports."""

import argparse
from pathlib import Path
import struct

if __package__:
    from .make_driver import make_image as base_image, write_image
else:
    from make_driver import make_image as base_image, write_image


def make_image(*, missing_import=False):
    data = bytearray(0x1600)
    data[:0x200] = base_image()[:0x200]
    nt_names = ["ExAllocatePoolWithTag", "ExFreePoolWithTag", "RtlInitUnicodeString", "RtlCompareMemory",
                "KeInitializeEvent", "KeSetEvent", "KeWaitForSingleObject", "MmGetSystemRoutineAddress"]
    if missing_import:
        nt_names.append("UnimplementedTestRoutine")
    modules = [("ntoskrnl.exe", nt_names), ("HAL.dll", ["KeQueryPerformanceCounter"])]
    lookup, iat, names = 0x2100, 0x2200, 0x2400
    slots = {}

    def put(rva, payload):
        offset = rva - 0x2000 + 0x400
        data[offset:offset + len(payload)] = payload

    for index, (module, imports) in enumerate(modules):
        module_rva = 0x2080 + index * 32
        put(module_rva, module.encode("ascii") + b"\0")
        put(0x2000 + index * 20, struct.pack("<IIIII", lookup, 0, 0, module_rva, iat))
        for name in imports:
            put(lookup, struct.pack("<Q", names))
            put(iat, struct.pack("<Q", names))
            slots[name] = iat
            encoded = b"\0\0" + name.encode("ascii") + b"\0"
            put(names, encoded)
            names += (len(encoded) + 1) & ~1
            lookup += 8
            iat += 8
        lookup += 8
        iat += 8
    struct.pack_into("<II", data, 0x98 + 120, 0x2000, (len(modules) + 1) * 20)
    code = bytearray(b"\x53\x48\x83\xec\x30")  # preserve RBX; aligned shadow space + fifth argument
    branches = []

    def emit(raw): code.extend(raw)

    def relative(prefix, target, suffix=b""):
        after = 0x1000 + len(code) + len(prefix) + 4 + len(suffix)
        emit(prefix + struct.pack("<i", target - after) + suffix)

    def call(name): relative(b"\xff\x15", slots[name])
    def lea_rcx(rva): relative(b"\x48\x8d\x0d", rva)
    def lea_rdx(rva): relative(b"\x48\x8d\x15", rva)
    def fail_unless_equal():
        emit(b"\x0f\x85\0\0\0\0")
        branches.append(len(code) - 4)
    def fail_if_zero():
        emit(b"\x0f\x84\0\0\0\0")
        branches.append(len(code) - 4)

    emit(b"\xb9\x00\x02\x00\x00\xba\x40\x00\x00\x00\x41\xb8TEST")
    call("ExAllocatePoolWithTag")
    emit(b"\x48\x85\xc0")  # test rax,rax
    fail_if_zero()
    emit(b"\x48\x89\xc3\xc7\x03\xd4\xc3\xb2\xa1\x48\x89\xd9")  # rbx=pool; *pool=magic; rcx=pool
    lea_rdx(0x2900)
    emit(b"\x41\xb8\x04\0\0\0")
    call("RtlCompareMemory")
    emit(b"\x48\x83\xf8\x04")
    fail_unless_equal()
    emit(b"\x48\x89\xd9\xbaTEST")
    call("ExFreePoolWithTag")

    lea_rcx(0x2920)
    lea_rdx(0x2940)
    call("RtlInitUnicodeString")
    relative(b"\x66\x83\x3d", 0x2920, b"\x08")  # UTF-16 byte length, not Linux wchar_t length
    fail_unless_equal()
    lea_rcx(0x2960)
    emit(b"\xba\x01\0\0\0\x45\x31\xc0")  # synchronization event, initially not signaled
    call("KeInitializeEvent")
    lea_rcx(0x2960)
    emit(b"\x31\xd2\x45\x31\xc0")
    call("KeSetEvent")
    emit(b"\x85\xc0")
    fail_unless_equal()
    for expected in (0, 0x102):
        relative(b"\x48\x8d\x05", 0x2980)
        emit(b"\x48\x89\x44\x24\x20")  # fifth argument: zero timeout
        lea_rcx(0x2960)
        emit(b"\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        call("KeWaitForSingleObject")
        emit(b"\x3d" + struct.pack("<I", expected))
        fail_unless_equal()
    lea_rcx(0x29A0)
    call("KeQueryPerformanceCounter")
    emit(b"\x48\x85\xc0")
    fail_if_zero()
    relative(b"\x48\x81\x3d", 0x29A0, struct.pack("<I", 1000000000))
    fail_unless_equal()
    lea_rcx(0x2920)
    lea_rdx(0x29C0)
    call("RtlInitUnicodeString")
    lea_rcx(0x2920)
    call("MmGetSystemRoutineAddress")
    relative(b"\x48\x3b\x05", slots["KeSetEvent"])
    fail_unless_equal()
    emit(b"\x31\xc0\x48\x83\xc4\x30\x5b\xc3")
    failure = len(code)
    emit(b"\xb8\x01\x00\x00\xc0\x48\x83\xc4\x30\x5b\xc3")
    for offset in branches:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) <= 512
    data[0x200:0x200 + len(code)] = code
    put(0x2900, struct.pack("<I", 0xA1B2C3D4))
    put(0x2940, "A€😀\0".encode("utf-16-le"))
    put(0x29C0, "KeSetEvent\0".encode("utf-16-le"))
    relocation = struct.pack("<II", 0x1000, 8)  # RIP-relative code needs no absolute fixups
    data[0x1400:0x1408] = relocation
    struct.pack_into("<II", data, 0x98 + 112 + 5 * 8, 0x3000, len(relocation))
    for index, (name, rva, offset, raw_size, virtual_size, flags) in enumerate((
        (b".text", 0x1000, 0x200, 512, len(code), 0x60000020),
        (b".data", 0x2000, 0x400, 4096, 4096, 0xC0000040),
        (b".reloc", 0x3000, 0x1400, 512, 8, 0x42000040),
    )):
        struct.pack_into("<8sIIIIIIHHI", data, 0x188 + index * 40, name, virtual_size, rva,
                         raw_size, offset, 0, 0, 0, 0, flags)
    return bytes(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raise SystemExit(write_image(args.output, make_image()))
