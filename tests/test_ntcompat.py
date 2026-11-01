from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from driverlab.native import compiler_command


@unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64"
                     and (shutil.which("cc") or shutil.which("gcc")), "Requires x64 Linux and a C compiler")
class KernelCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="driverlab-nt-tests-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "nt-tests"
        root = Path(__file__).resolve().parents[1]
        compiler = shutil.which("cc") or shutil.which("gcc")
        result = subprocess.run(compiler_command(compiler, cls.binary, root / "tests/native_nt_test.c"),
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def check_case(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(name + ": PASS", result.stdout)

    def test_tagged_pool_alignment_and_memory(self): self.check_case("pool")
    def test_utf16_copy_ownership_and_limits(self): self.check_case("unicode")
    def test_strchr_read_only_mutable_and_boundary_inputs(self): self.check_case("strings")
    def test_manual_and_auto_reset_event_waiters(self): self.check_case("events")
    def test_recursive_mutex_and_contended_transfer(self): self.check_case("mutex")
    def test_multithreaded_guarded_mutex_and_spinlock(self): self.check_case("locks")
    def test_rundown_closes_then_drains_references(self): self.check_case("rundown")
    def test_clock_delay_dynamic_lookup_and_image_lookup(self): self.check_case("time")

    def test_invalid_pool_free_fails_instead_of_succeeding(self):
        result = subprocess.run([str(self.binary), "bad-free"], capture_output=True, text=True, timeout=10)
        self.assertLess(result.returncode, 0)
        self.assertIn("unknown or already freed", result.stderr)

    def test_const_preserving_host_header_compiles_with_warnings_as_errors(self):
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run([shutil.which("cc") or shutil.which("gcc"), "-std=c11", "-O2",
                                 "-Wall", "-Wextra", "-Werror", "-fPIC", "-include",
                                 str(root / "tests/const_strchr.h"), "-c", str(root / "native/ntcompat.c"),
                                 "-o", str(Path(self.directory.name) / "const-strchr.o")],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
