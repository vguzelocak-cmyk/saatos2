"""Bounded PE32+ import reader. Does not load or execute the input."""

from dataclasses import dataclass
import hashlib
import struct


class PEError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    offset: int
    size: int


class PE:
    def __init__(self, data: bytes):
        self.data = data
        self.sections = []
        if self.read(0, 2) != b"MZ":
            raise PEError("DOS MZ signature missing")
        pe = self.unpack("I", 0x3C)[0]
        if self.read(pe, 4) != b"PE\0\0":
            raise PEError("PE signature missing")
        self.machine, count = self.unpack("HH", pe + 4)
        optional_size = self.unpack("H", pe + 20)[0]
        optional = pe + 24
        self.read(optional, optional_size)
        if optional_size < 112 or self.unpack("H", optional)[0] != 0x20B:
            raise PEError("Only PE32+ images are supported")
        self.entry = self.unpack("I", optional + 16)[0]
        self.image_base = self.unpack("Q", optional + 24)[0]
        self.header_size = self.unpack("I", optional + 60)[0]
        self.subsystem = self.unpack("H", optional + 68)[0]
        directories = self.unpack("I", optional + 108)[0]
        if directories > (optional_size - 112) // 8:
            raise PEError("Data directories exceed optional header")
        self.directories = [self.unpack("II", optional + 112 + n * 8)
                            for n in range(directories)]
        table = optional + optional_size
        if not 1 <= count <= 96:
            raise PEError("Invalid section count (expected 1..96)")
        self.read(table, count * 40)
        if not table + count * 40 <= self.header_size <= len(data):
            raise PEError("Invalid SizeOfHeaders")
        for n in range(count):
            off = table + n * 40
            name = self.read(off, 8).split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, rva, size, offset = self.unpack("IIII", off + 8)
            if size:
                self.read(offset, size)
                if offset < self.header_size:
                    raise PEError("Section raw data overlaps headers")
            extent = max(virtual_size, size)
            if extent and (rva < self.header_size or rva + extent > 2**32):
                raise PEError("Invalid section RVA range")
            for other in self.sections:
                if extent and max(other.virtual_size, other.size):
                    if max(rva, other.rva) < min(rva + extent, other.rva + max(other.virtual_size, other.size)):
                        raise PEError("Overlapping section RVA ranges")
                if size and other.size and max(offset, other.offset) < min(offset + size, other.offset + other.size):
                    raise PEError("Overlapping section file ranges")
            self.sections.append(Section(name, rva, virtual_size, offset, size))

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise PEError("Read outside file bounds")
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack("<" + fmt, self.read(offset, struct.calcsize("<" + fmt)))

    def mapped(self, rva):
        if rva < 0:
            raise PEError("Invalid negative RVA")
        if rva < self.header_size:
            return rva, self.header_size - rva
        for section in self.sections:
            delta = rva - section.rva
            if 0 <= delta < section.size:
                return section.offset + delta, section.size - delta
        raise PEError(f"RVA 0x{rva:x} has no file-backed data")

    def at_rva(self, rva, size):
        offset, available = self.mapped(rva)
        if size > available:
            raise PEError("RVA read crosses mapped region")
        return self.read(offset, size)

    def string(self, rva):
        offset, available = self.mapped(rva)
        raw = self.read(offset, min(available, 4096))
        end = raw.find(b"\0")
        if end < 0:
            raise PEError("Unterminated or oversized import string")
        try:
            return raw[:end].decode("ascii")
        except UnicodeDecodeError as exc:
            raise PEError("Non-ASCII import string") from exc

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def imports(self, *, include_iat=False):
        rva, size = self.directory(1)
        if not rva and not size:
            return []
        if not rva or size < 20:
            raise PEError("Invalid import directory")
        self.at_rva(rva, size)
        result = []
        symbol_budget = 100000
        for n in range(min(size // 20, 4096)):
            original, stamp, chain, name, first = struct.unpack("<IIIII", self.at_rva(rva + n * 20, 20))
            if not any((original, stamp, chain, name, first)):
                return result
            if not name or not (original or first):
                raise PEError("Incomplete import descriptor")
            if include_iat and (not first or first % 8):
                raise PEError("Import descriptor has no aligned IAT")
            if not original and stamp:
                raise PEError("Bound imports without a lookup table are unsupported")
            dll = self.string(name)
            if not dll:
                raise PEError("Empty imported module name")
            symbols = []
            thunk = original or first
            for index in range(65536):
                value = struct.unpack("<Q", self.at_rva(thunk + index * 8, 8))[0]
                if not value:
                    break
                symbol_budget -= 1
                if symbol_budget < 0:
                    raise PEError("Import count exceeds analysis limit")
                if value & (1 << 63):
                    if value & 0x7FFFFFFFFFFF0000:
                        raise PEError("Invalid ordinal import")
                    symbols.append({"ordinal": value & 0xFFFF})
                else:
                    if value > 0xFFFFFFFF:
                        raise PEError("Invalid import name RVA")
                    hint = struct.unpack("<H", self.at_rva(value, 2))[0]
                    symbol = self.string(value + 2)
                    if not symbol:
                        raise PEError("Empty imported symbol name")
                    symbols.append({"name": symbol, "hint": hint})
                if include_iat:
                    slot = first + index * 8
                    self.at_rva(slot, 8)
                    symbols[-1]["iat_rva"] = slot
            else:
                raise PEError("Unterminated or oversized import lookup table")
            result.append({"module": dll, "symbols": symbols})
        raise PEError("Unterminated or oversized import directory")

    def report(self):
        imports = self.imports()
        limitations = [
            "Static imports do not capture dynamically resolved dependencies or runtime behavior.",
            "This is static analysis only; no driver is loaded or executed and runtime API coverage is not checked.",
            "Authenticode signatures and Riot service acceptance are not verified.",
        ]
        if any(self.directory(13)):
            limitations.append("Delay-load directory is present and is not decoded by this version.")
        return {
            "schema_version": 1,
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "machine": {0x8664: "AMD64", 0xAA64: "ARM64"}.get(self.machine, f"0x{self.machine:04x}"),
            "subsystem": "Native" if self.subsystem == 1 else self.subsystem,
            "entry_point_rva": self.entry,
            "image_base": self.image_base,
            "sections": [s.name for s in self.sections],
            "imports": imports,
            "import_symbol_count": sum(len(m["symbols"]) for m in imports),
            "execution_supported": False,
            "limitations": limitations,
        }
