from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from driverlab.native import compiler_command


@unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64"
                     and (shutil.which("cc") or shutil.which("gcc")), "Requires x64 Linux and a C compiler")
class KernelExtensionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="driverlab-extras-tests-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "extras"
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(compiler_command(shutil.which("cc") or shutil.which("gcc"), cls.binary,
                                                 root / "tests/native_extras_test.c", root / "tests/chkstk_test.S"),
                                capture_output=True, text=True, timeout=30)
        if result.returncode: raise RuntimeError(result.stderr)

    def check_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(case + ": PASS", result.stdout)

    def check_failure(self, case, message):
        result = subprocess.run([str(self.binary), case], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, -signal.SIGABRT, result.stdout + result.stderr)
        self.assertIn(message, result.stderr)

    def test_secure_crt_copy_concat_truncate_and_errors(self): self.check_case("strings")
    def test_unicode_prefix_case_and_cp1252_conversion(self): self.check_case("unicode")
    def test_calendar_leap_day_negative_ticks_and_local_timezone(self): self.check_case("time")
    def test_pushlock_readers_writers_and_mutex_apc_state(self): self.check_case("push")
    def test_cache_aware_counted_rundown_drain(self): self.check_case("cached")
    def test_cpu_groups_data_export_and_current_processor(self): self.check_case("cpu")
    def test_stack_probe_preserves_registers_at_page_boundaries(self): self.check_case("stack")
    def test_read_and_write_probes_accept_accessible_memory(self): self.check_case("probe")
    def test_write_probe_rejects_read_only_memory(self): self.check_failure("bad-probe", "STATUS_ACCESS_VIOLATION")
    def test_probe_rejects_misalignment(self): self.check_failure("bad-align", "STATUS_DATATYPE_MISALIGNMENT")
    def test_pushlock_rejects_missing_apc_disable(self): self.check_failure("bad-push", "normal APCs disabled")
    def test_cache_rundown_rejects_free_with_live_references(self): self.check_failure("bad-cached", "active cache-aware rundown")

    def test_stack_probe_reaches_real_guard_page(self):
        result = subprocess.run([str(self.binary), "stack-guard"], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, -signal.SIGSEGV, result.stdout + result.stderr)
