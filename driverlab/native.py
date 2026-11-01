"""Shared compiler configuration for the runtime and its native tests."""
from pathlib import Path

NATIVE = Path(__file__).resolve().parents[1] / "native"
SOURCES = tuple(NATIVE / name for name in ("bridge.c", "ntcompat.c", "ntio.c", "ntcrypto.c", "ntmemory.c", "ntextras.c", "chkstk.S"))


def compiler_command(compiler, output, *extra_sources, shared=False):
    flags = ["-shared", "-fPIC"] if shared else []
    return [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", *flags,
            "-I", str(NATIVE), *(str(p) for p in SOURCES), *(str(p) for p in extra_sources),
            "-pthread", "-lcrypto", "-o", str(output)]
