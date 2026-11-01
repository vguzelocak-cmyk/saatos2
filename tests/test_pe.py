import contextlib
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

from driverlab.pe import PE, PEError


def image():
    """Synthetic native AMD64 PE with one named and one ordinal import."""
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 240)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1100)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<H", data, optional + 68, 1)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 120, 0x1000, 40)
    section = optional + 240
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x700, 0x1000, 0x600, 0x200)
    struct.pack_into("<IIIII", data, 0x200, 0x10A0, 0, 0, 0x1080, 0x10C0)
    module = b"ntoskrnl.exe\0"
    data[0x280:0x280 + len(module)] = module
    struct.pack_into("<QQQ", data, 0x2A0, 0x10E0, (1 << 63) | 42, 0)
    struct.pack_into("<H", data, 0x2E0, 7)
    symbol = b"IoCreateDevice\0"
    data[0x2E2:0x2E2 + len(symbol)] = symbol
    return data


class PEReaderTests(unittest.TestCase):
    def test_named_and_ordinal_imports(self):
        report = PE(bytes(image())).report()
        self.assertEqual(report["machine"], "AMD64")
        self.assertEqual(report["subsystem"], "Native")
        self.assertEqual(report["import_symbol_count"], 2)
        self.assertEqual(report["imports"], [{"module": "ntoskrnl.exe", "symbols": [
            {"name": "IoCreateDevice", "hint": 7}, {"ordinal": 42}]}])
        self.assertFalse(report["execution_supported"])

    def test_no_imports(self):
        data = image()
        struct.pack_into("<II", data, 0x98 + 120, 0, 0)
        self.assertEqual(PE(data).imports(), [])

    def test_unbound_first_thunk_fallback(self):
        data = image()
        struct.pack_into("<I", data, 0x200, 0)
        data[0x2C0:0x2D8] = data[0x2A0:0x2B8]
        self.assertEqual(len(PE(data).imports()[0]["symbols"]), 2)

    def test_bound_fallback_rejected(self):
        data = image()
        struct.pack_into("<II", data, 0x200, 0, 123)
        with self.assertRaisesRegex(PEError, "Bound imports"):
            PE(data).imports()

    def test_truncated_files(self):
        for length in (0, 1, 32, 64, 128, 160, 400, 511, 1024):
            with self.subTest(length=length), self.assertRaises(PEError):
                PE(image()[:length]).report()

    def test_invalid_signatures(self):
        for off in (0, 0x80):
            data = image()
            data[off] = 0
            with self.subTest(offset=off), self.assertRaises(PEError):
                PE(data)

    def test_pe32_rejected(self):
        data = image()
        struct.pack_into("<H", data, 0x98, 0x10B)
        with self.assertRaisesRegex(PEError, "PE32\\+"):
            PE(data)

    def test_directory_count_exceeds_header(self):
        data = image()
        struct.pack_into("<I", data, 0x98 + 108, 17)
        with self.assertRaisesRegex(PEError, "directories"):
            PE(data)

    def test_unbacked_virtual_memory_not_treated_as_import_data(self):
        data = image()
        struct.pack_into("<I", data, 0x200 + 12, 0x1650)
        with self.assertRaisesRegex(PEError, "file-backed"):
            PE(data).imports()

    def test_unterminated_string(self):
        data = image()
        struct.pack_into("<I", data, 0x200 + 12, 0x15F0)
        data[0x7F0:0x800] = b"A" * 16
        with self.assertRaisesRegex(PEError, "Unterminated"):
            PE(data).imports()

    def test_invalid_ordinal_bits(self):
        data = image()
        struct.pack_into("<Q", data, 0x2A0, (1 << 63) | (1 << 20))
        with self.assertRaisesRegex(PEError, "ordinal"):
            PE(data).imports()

    def test_missing_descriptor_terminator(self):
        data = image()
        struct.pack_into("<II", data, 0x98 + 120, 0x1000, 20)
        with self.assertRaisesRegex(PEError, "import directory"):
            PE(data).imports()

    def test_crossing_raw_boundary_rejected(self):
        with self.assertRaisesRegex(PEError, "crosses"):
            PE(image()).at_rva(0x15FF, 2)

    def test_overlapping_sections_rejected(self):
        data = image()
        struct.pack_into("<H", data, 0x86, 2)
        data[0x1B0:0x1D8] = data[0x188:0x1B0]
        with self.assertRaisesRegex(PEError, "Overlapping"):
            PE(data)

    def test_delay_load_limitation_reported(self):
        data = image()
        struct.pack_into("<II", data, 0x98 + 112 + 13 * 8, 0x1100, 32)
        self.assertTrue(any("Delay-load" in item for item in PE(data).report()["limitations"]))

    def test_cli_json_and_error_exit_status(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            driver = Path(temp) / "sample.sys"
            driver.write_bytes(image())
            args = [sys.executable, "-m", "driverlab", str(driver), "--json"]
            good = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(json.loads(good.stdout)["import_symbol_count"], 2)
            driver.write_bytes(b"not a PE")
            bad = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 2)
            self.assertEqual(bad.stdout, "")
            self.assertIn("driverlab:", bad.stderr)
            self.assertNotIn("Traceback", bad.stderr)
            driver.unlink()
            missing = subprocess.run(args, cwd=root, capture_output=True, text=True)
            self.assertEqual(missing.returncode, 2)


if __name__ == "__main__":
    unittest.main()
