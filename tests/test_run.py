import json
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from driverlab.pe import PEError
from driverlab.run import Image
from examples.make_driver import make_image
from test_pe import image as imported_image


class LoaderValidationTests(unittest.TestCase):
    def test_relocation_target_is_decoded(self):
        image = Image(make_image())
        self.assertEqual(len(image.relocations), 1)
        self.assertGreater(image.relocations[0], 0x1000)

    def test_kernel_imports_rejected_before_execution(self):
        with self.assertRaisesRegex(PEError, "ntoskrnl.exe.*not executed"):
            Image(imported_image())

    def test_image_extent_is_validated(self):
        data = bytearray(make_image())
        struct.pack_into("<I", data, 0x98 + 56, 0x2000)
        with self.assertRaisesRegex(PEError, "exceeds SizeOfImage"):
            Image(data)

    def test_unknown_relocation_rejected(self):
        data = bytearray(make_image())
        struct.pack_into("<H", data, 0x608, 0x3000)
        with self.assertRaisesRegex(PEError, "relocation type 3"):
            Image(data)

    def test_writable_executable_section_rejected(self):
        data = bytearray(make_image())
        struct.pack_into("<I", data, 0x188 + 36, 0xE0000020)
        with self.assertRaisesRegex(PEError, "Writable executable"):
            Image(data)

    def test_non_executable_entry_rejected(self):
        data = bytearray(make_image())
        struct.pack_into("<I", data, 0x98 + 16, 0x2000)
        with self.assertRaisesRegex(PEError, "Entry point"):
            Image(data)


@unittest.skipUnless(sys.platform == "linux" and platform.machine() == "x86_64"
                     and (shutil.which("cc") or shutil.which("gcc")), "Requires x64 Linux and a C compiler")
class NativeExecutionTests(unittest.TestCase):
    def run_driver(self, data, *flags):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.sys"
            path.write_bytes(data)
            return subprocess.run([sys.executable, "-m", "driverlab.run", str(path), *flags],
                                  cwd=Path(__file__).resolve().parents[1], capture_output=True,
                                  text=True, timeout=30)

    def test_real_driver_entry_checks_abi_and_reads_relocated_data(self):
        # The code returns success only after reading both Windows-ABI arguments
        # and dereferencing an absolute pointer fixed up by the loader.
        result = self.run_driver(make_image(), "--execute")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["driver_entry_called"])
        self.assertEqual(report["ntstatus"], "0x00000000")

    def test_failed_ntstatus_is_preserved(self):
        result = self.run_driver(make_image(status=0xC0000001), "--execute")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["ntstatus"], "0xc0000001")

    def test_native_fault_is_reported(self):
        result = self.run_driver(make_image(behavior="crash"), "--execute")
        self.assertEqual(result.returncode, 2)
        self.assertIn("terminated by signal", result.stderr)

    def test_hung_native_code_is_stopped(self):
        result = self.run_driver(make_image(behavior="loop"), "--execute", "--timeout", "1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("timed out", result.stderr)

    def test_explicit_execution_flag_required(self):
        result = self.run_driver(make_image())
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --execute", result.stderr)


if __name__ == "__main__":
    unittest.main()
