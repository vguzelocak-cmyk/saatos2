"""Experimental user-mode PE execution with a limited NT compatibility runtime."""

import argparse
import ctypes
import json
import mmap
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile

from .pe import PE, PEError
from .native import compiler_command


def round_page(value):
    return (value + mmap.PAGESIZE - 1) // mmap.PAGESIZE * mmap.PAGESIZE


class Image:
    def __init__(self, data):
        self.pe = pe = PE(data)
        if pe.machine != 0x8664 or pe.subsystem != 1:
            raise PEError("Execution requires an AMD64 Native image")
        self.imports = pe.imports(include_iat=True)
        self.iat_slots = set()
        for module in self.imports:
            for symbol in module["symbols"]:
                slot = symbol["iat_rva"]
                if slot in self.iat_slots:
                    raise PEError("Overlapping IAT slots")
                self.iat_slots.add(slot)
        for index, label in ((9, "TLS"), (13, "delay imports"), (14, "CLR")):
            if any(pe.directory(index)):
                raise PEError(f"{label} is not supported by this experimental executor")
        optional = pe.unpack("I", 0x3C)[0] + 24
        self.size = pe.unpack("I", optional + 56)[0]
        alignment = pe.unpack("I", optional + 32)[0]
        if not 0 < self.size <= 256 * 1024 * 1024 or self.size % mmap.PAGESIZE:
            raise PEError("SizeOfImage must be page aligned and at most 256 MiB")
        if alignment < mmap.PAGESIZE or alignment % mmap.PAGESIZE:
            raise PEError("Sub-page section alignment is not supported")
        if pe.header_size > self.size:
            raise PEError("Headers exceed SizeOfImage")
        table = optional + pe.unpack("H", optional - 4)[0]
        self.regions = []
        occupied = [(0, round_page(pe.header_size))]
        entry_executable = False
        for n, section in enumerate(pe.sections):
            length = max(section.size, section.virtual_size)
            if not length:
                continue
            if section.rva % mmap.PAGESIZE:
                raise PEError("Section RVA must be page aligned")
            end = section.rva + round_page(length)
            if end > self.size:
                raise PEError("Section exceeds SizeOfImage")
            if any(max(start, section.rva) < min(stop, end) for start, stop in occupied):
                raise PEError("Section page ranges overlap")
            occupied.append((section.rva, end))
            flags = pe.unpack("I", table + n * 40 + 36)[0]
            protection = 0
            for flag, prot in ((0x40000000, mmap.PROT_READ), (0x80000000, mmap.PROT_WRITE), (0x20000000, mmap.PROT_EXEC)):
                if flags & flag:
                    protection |= prot
            if protection & mmap.PROT_WRITE and protection & mmap.PROT_EXEC:
                raise PEError("Writable executable sections are not supported")
            self.regions.append((section, round_page(length), protection))
            if section.rva <= pe.entry < section.rva + section.size and protection & mmap.PROT_EXEC:
                entry_executable = True
        if not entry_executable:
            raise PEError("Entry point must be in an executable file-backed section")
        self.relocations = self.read_relocations()

    def read_relocations(self):
        pe = self.pe
        rva, size = pe.directory(5)
        if not rva or size < 8:
            raise PEError("A base relocation directory is required by this executor")
        block = pe.at_rva(rva, size)
        cursor = 0
        targets = set()
        while cursor < size:
            if size - cursor < 8:
                raise PEError("Truncated relocation block")
            page, length = struct.unpack_from("<II", block, cursor)
            if length < 8 or length % 4 or cursor + length > size or page % 4096:
                raise PEError("Invalid relocation block")
            for offset in range(cursor + 8, cursor + length, 2):
                item = struct.unpack_from("<H", block, offset)[0]
                kind, delta = item >> 12, item & 0xFFF
                if kind == 0:
                    continue
                if kind != 10:
                    raise PEError(f"Unsupported base relocation type {kind}")
                target = page + delta
                pe.at_rva(target, 8)
                if target in targets:
                    raise PEError("Duplicate relocation target")
                targets.add(target)
            cursor += length
        return sorted(targets)

    def resolve_imports(self, bridge):
        bridge.driverlab_resolve.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        bridge.driverlab_resolve.restype = ctypes.c_void_p
        resolved, missing = [], []
        for module in self.imports:
            for symbol in module["symbols"]:
                name = symbol.get("name", f"#{symbol.get('ordinal')}")
                pointer = bridge.driverlab_resolve(module["module"].encode("ascii"), name.encode("ascii"))
                if pointer is None:
                    missing.append(f"{module['module']}!{name}")
                else:
                    resolved.append((symbol["iat_rva"], pointer))
        if missing:
            raise PEError("Unsupported kernel imports (driver was not executed): " + ", ".join(missing))
        return resolved

    def execute(self, bridge):
        bindings = self.resolve_imports(bridge)
        with mmap.mmap(-1, self.size, prot=mmap.PROT_READ | mmap.PROT_WRITE) as memory:
            address = ctypes.addressof(ctypes.c_char.from_buffer(memory))
            pe = self.pe
            memory[:pe.header_size] = pe.data[:pe.header_size]
            for section, _, _ in self.regions:
                memory[section.rva:section.rva + section.size] = pe.read(section.offset, section.size)
            delta = address - pe.image_base
            for target in self.relocations:
                original = struct.unpack_from("<Q", memory, target)[0]
                struct.pack_into("<Q", memory, target, (original + delta) & 0xFFFFFFFFFFFFFFFF)
            for slot, pointer in bindings:
                struct.pack_into("<Q", memory, slot, pointer)
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.mprotect.restype = ctypes.c_int

            def protect(offset, length, flags):
                if libc.mprotect(address + offset, length, flags):
                    raise OSError(ctypes.get_errno(), "mprotect failed")

            protect(0, self.size, 0)
            protect(0, round_page(pe.header_size), mmap.PROT_READ)
            for section, length, flags in self.regions:
                protect(section.rva, length, flags)
            bridge.driverlab_call.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
            bridge.driverlab_call.restype = ctypes.c_uint32
            return bridge.driverlab_call(address + pe.entry, address, self.size)


def worker(path, state_dir=None):
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise PEError("Execution is supported only on x86-64 Linux")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with Path(path).open("rb") as source:
        data = source.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024:
        raise PEError("Input exceeds 128 MiB")
    image = Image(data)
    compiler = shutil.which("cc") or shutil.which("gcc")
    if not compiler:
        raise PEError("Install a C compiler (cc or gcc) to build the ABI bridge")
    with tempfile.TemporaryDirectory(prefix="driverlab-") as directory:
        output = Path(directory) / "bridge.so"
        result = subprocess.run(compiler_command(compiler, output, shared=True), capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise PEError("Native runtime compilation failed (requires C headers and OpenSSL 3 development files): " + result.stderr.strip())
        bridge = ctypes.CDLL(str(output))
        bridge.driverlab_io_initialize.argtypes = [ctypes.c_char_p]
        bridge.driverlab_io_initialize.restype = ctypes.c_uint32
        state = state_dir if state_dir is not None else Path(directory) / "state"
        initialize = bridge.driverlab_io_initialize(os.fsencode(state))
        if initialize:
            raise PEError(f"Private I/O namespace initialization failed: 0x{initialize:08x}")
        status = image.execute(bridge)
        bridge.driverlab_export_count.restype = ctypes.c_size_t
        exports = bridge.driverlab_export_count()
    print(json.dumps({"driver_entry_called": True, "ntstatus": f"0x{status:08x}",
                      "nt_success": status < 0x80000000, "windows_kernel_implemented": False,
                      "kernel_compatibility": "user-mode-subset", "kernel_exports_available": exports,
                      "resolved_import_count": sum(len(m["symbols"]) for m in image.imports)}))
    return 0 if status < 0x80000000 else 1


def main():
    parser = argparse.ArgumentParser(description="Experimental native PE executor with a limited user-mode NT runtime. Not a sandbox or Vanguard runtime.")
    parser.add_argument("driver", type=Path)
    parser.add_argument("--execute", action="store_true", help="Execute trusted native code with your current user permissions")
    parser.add_argument("--timeout", type=float, default=5.0, help="Worker time limit in seconds (default: 5)")
    parser.add_argument("--state-dir", type=Path, help="Retain private I/O files here; registry remains per-worker and volatile")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.worker:
            return worker(args.driver, args.state_dir)
        if not args.execute:
            raise PEError("Execution requires --execute; this runs native code and is not a sandbox")
        if not 0 < args.timeout <= 60:
            raise PEError("Timeout must be greater than 0 and at most 60 seconds")
        command = [sys.executable, "-m", "driverlab.run", str(args.driver.resolve()), "--worker"]
        if args.state_dir is not None:
            command.extend(["--state-dir", str(args.state_dir.resolve())])
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              start_new_session=True, cwd=Path(__file__).resolve().parents[1]) as process:
            try:
                stdout, stderr = process.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise
            result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if result.returncode < 0:
            raise PEError(f"Driver worker terminated by signal {-result.returncode}; execution failed")
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("driverlab: Execution timed out; worker stopped", file=sys.stderr)
        return 2
    except (PEError, OSError) as exc:
        print(f"driverlab: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
