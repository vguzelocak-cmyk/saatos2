"""Generate a PE which exercises file I/O, registry, CNG hashing and MDLs."""
import argparse
from pathlib import Path
import struct

if __package__:
    from .make_driver import make_image as base_image, write_image
else:
    from make_driver import make_image as base_image, write_image


def make_image():
    data = bytearray(0x2400)
    data[:0x200] = base_image()[:0x200]
    modules = [("ntoskrnl.exe", ["RtlInitUnicodeString", "RtlCompareMemory", "ZwCreateFile", "ZwWriteFile",
        "ZwReadFile", "ZwFlushBuffersFile", "ZwClose", "ZwCreateKey", "ZwSetValueKey", "ZwQueryValueKey",
        "IoAllocateMdl", "MmProbeAndLockPages", "MmUnlockPages", "MmMapLockedPagesSpecifyCache", "MmUnmapLockedPages", "IoFreeMdl"]),
        ("cng.sys", ["BCryptOpenAlgorithmProvider", "BCryptCreateHash", "BCryptHashData", "BCryptFinishHash",
                     "BCryptDestroyHash", "BCryptCloseAlgorithmProvider"])]

    def put(rva, payload):
        offset = rva - 0x2000 + 0x1200
        data[offset:offset + len(payload)] = payload

    lookup, iat, names = 0x2100, 0x2300, 0x2500
    slots = {}
    for index, (module, symbols) in enumerate(modules):
        module_rva = 0x2080 + index * 32
        put(module_rva, module.encode() + b"\0")
        put(0x2000 + index * 20, struct.pack("<IIIII", lookup, 0, 0, module_rva, iat))
        for symbol in symbols:
            encoded = b"\0\0" + symbol.encode() + b"\0"
            put(names, encoded)
            put(lookup, struct.pack("<Q", names)); put(iat, struct.pack("<Q", names))
            slots[symbol] = iat
            names += (len(encoded) + 1) & ~1
            lookup += 8; iat += 8
        lookup += 8; iat += 8
    assert names < 0x2B00 and lookup < 0x2300 and iat < 0x2500
    struct.pack_into("<II", data, 0x98 + 120, 0x2000, 60)
    code = bytearray(b"\x48\x81\xec\x88\0\0\0")  # 16-byte alignment, home area and stack arguments
    branches = []

    def relative(prefix, target):
        after = 0x1000 + len(code) + len(prefix) + 4
        code.extend(prefix + struct.pack("<i", target - after))

    def argument(value, register):
        if isinstance(value, tuple):
            kind, rva = value
            prefixes = ({"rcx": b"\x48\x8d\x0d", "rdx": b"\x48\x8d\x15", "r8": b"\x4c\x8d\x05", "r9": b"\x4c\x8d\x0d", "rax": b"\x48\x8d\x05"}
                        if kind == "address" else
                        {"rcx": b"\x48\x8b\x0d", "rdx": b"\x48\x8b\x15", "r8": b"\x4c\x8b\x05", "r9": b"\x4c\x8b\x0d", "rax": b"\x48\x8b\x05"})
            relative(prefixes[register], rva)
        else:
            code.extend({"rcx": b"\x48\xb9", "rdx": b"\x48\xba", "r8": b"\x49\xb8", "r9": b"\x49\xb9", "rax": b"\x48\xb8"}[register])
            code.extend(struct.pack("<Q", value))

    def fail(condition):
        code.extend(b"\x0f" + bytes([condition]) + b"\0" * 4)
        branches.append(len(code) - 4)

    def invoke(name, args, result="status"):
        for i, value in enumerate(args):
            argument(value, ("rcx", "rdx", "r8", "r9")[i] if i < 4 else "rax")
            if i >= 4: code.extend(b"\x48\x89\x44\x24" + bytes([0x20 + (i - 4) * 8]))
        relative(b"\xff\x15", slots[name])
        if result == "status": code.extend(b"\x85\xc0"); fail(0x85)
        elif result == "pointer": code.extend(b"\x48\x85\xc0"); fail(0x84)

    def address(rva): return ("address", rva)
    def loaded(rva): return ("loaded", rva)
    def store_rax(rva): relative(b"\x48\x89\x05", rva)
    def compare(left, right, size):
        invoke("RtlCompareMemory", [address(left), address(right), size], None)
        code.extend(b"\x48\x3d" + struct.pack("<I", size)); fail(0x85)

    invoke("BCryptOpenAlgorithmProvider", [address(0x2B00), address(0x2CE0), 0, 0])
    invoke("BCryptCreateHash", [loaded(0x2B00), address(0x2B08), 0, 0, 0, 0, 0])
    invoke("BCryptHashData", [loaded(0x2B08), address(0x2D00), 3, 0])
    invoke("BCryptFinishHash", [loaded(0x2B08), address(0x2D20), 32, 0])
    compare(0x2D20, 0x2D40, 32)
    invoke("BCryptDestroyHash", [loaded(0x2B08)])
    invoke("BCryptCloseAlgorithmProvider", [loaded(0x2B00), 0])

    invoke("RtlInitUnicodeString", [address(0x2B60), address(0x2C00)], None)
    invoke("ZwCreateFile", [address(0x2B10), 0xC0000000, address(0x2BA0), address(0x2B40), 0, 0x80, 3, 3, 0x60, 0, 0])
    invoke("ZwWriteFile", [loaded(0x2B10), 0, 0, 0, address(0x2B40), address(0x2D00), 3, address(0x2D80), 0])
    invoke("ZwFlushBuffersFile", [loaded(0x2B10), address(0x2B40)])
    invoke("ZwReadFile", [loaded(0x2B10), 0, 0, 0, address(0x2B40), address(0x2D60), 3, address(0x2D80), 0])
    compare(0x2D60, 0x2D00, 3)
    invoke("ZwClose", [loaded(0x2B10)])

    invoke("RtlInitUnicodeString", [address(0x2B70), address(0x2C60)], None)
    invoke("RtlInitUnicodeString", [address(0x2B80), address(0x2CC0)], None)
    invoke("ZwCreateKey", [address(0x2B18), 0x10000000, address(0x2BD0), 0, 0, 1, address(0x2DB4)])
    invoke("ZwSetValueKey", [loaded(0x2B18), address(0x2B80), 0, 4, address(0x2D90), 4])
    invoke("ZwQueryValueKey", [loaded(0x2B18), address(0x2B80), 2, address(0x2DA0), 16, address(0x2DB0)])
    compare(0x2DAC, 0x2D90, 4)
    invoke("ZwClose", [loaded(0x2B18)])

    invoke("IoAllocateMdl", [address(0x2E00), 64, 0, 0, 0], "pointer"); store_rax(0x2B20)
    invoke("MmProbeAndLockPages", [loaded(0x2B20), 0, 2], None)
    invoke("MmMapLockedPagesSpecifyCache", [loaded(0x2B20), 0, 1, 0, 0, 16], "pointer"); store_rax(0x2B28)
    argument(address(0x2E00), "rdx"); code.extend(b"\x48\x39\xd0"); fail(0x85)
    code.extend(b"\xc7\x00\x78\x56\x34\x12")
    compare(0x2E00, 0x2D90, 4)
    invoke("MmUnmapLockedPages", [loaded(0x2B28), loaded(0x2B20)], None)
    invoke("MmUnlockPages", [loaded(0x2B20)], None)
    invoke("IoFreeMdl", [loaded(0x2B20)], None)
    code.extend(b"\x31\xc0\x48\x81\xc4\x88\0\0\0\xc3")
    failure = len(code)
    code.extend(b"\xb8\x01\0\0\xc0\x48\x81\xc4\x88\0\0\0\xc3")
    for offset in branches: struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) <= 4096
    data[0x200:0x200 + len(code)] = code
    for rva, text in ((0x2C00, "\\??\\C:\\services.bin"), (0x2C60, "\\Registry\\Machine\\Software\\DriverLabServices"),
                      (0x2CC0, "Value"), (0x2CE0, "SHA256")):
        put(rva, (text + "\0").encode("utf-16-le"))
    put(0x2D00, b"abc")
    put(0x2D40, bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
    put(0x2D90, struct.pack("<I", 0x12345678))
    for rva, descriptor in ((0x2BA0, 0x2B60), (0x2BD0, 0x2B70)):
        put(rva, struct.pack("<I4xQQI4xQQ", 48, 0, 0x140000000 + descriptor, 0x40, 0, 0))
    relocation = struct.pack("<IIHH", 0x2000, 12, 0xA000 | 0xBB0, 0xA000 | 0xBE0)
    data[0x2200:0x220C] = relocation
    struct.pack_into("<II", data, 0x98 + 112 + 5 * 8, 0x3000, len(relocation))
    for index, (name, rva, offset, size, virtual_size, flags) in enumerate((
        (b".text", 0x1000, 0x200, 4096, len(code), 0x60000020),
        (b".data", 0x2000, 0x1200, 4096, 4096, 0xC0000040),
        (b".reloc", 0x3000, 0x2200, 512, 12, 0x42000040),
    )):
        struct.pack_into("<8sIIIIIIHHI", data, 0x188 + index * 40, name, virtual_size, rva, size, offset, 0, 0, 0, 0, flags)
    return bytes(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    raise SystemExit(write_image(args.output, make_image()))
