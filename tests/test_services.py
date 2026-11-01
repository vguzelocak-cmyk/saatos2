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
class NativeServicesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="driverlab-service-tests-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "services"
        root = Path(__file__).resolve().parents[1]
        result = subprocess.run(compiler_command(shutil.which("cc") or shutil.which("gcc"), cls.binary,
                                                 root / "tests/native_services_test.c"),
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def check_case(self, name):
        with tempfile.TemporaryDirectory(prefix="driverlab-service-state-") as state:
            result = subprocess.run([str(self.binary), name, state], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(name + ": PASS", result.stdout)

    def test_binary_file_roundtrip_permissions_sharing_and_namespace(self): self.check_case("files")
    def test_registry_values_access_rights_query_buffers_and_deletion(self): self.check_case("registry")
    def test_sha256_known_vector_and_hash_lifecycle(self): self.check_case("sha256")
    def test_hmac_known_vector(self): self.check_case("hmac")
    def test_rsa_public_blob_pkcs1_pss_and_rejected_signatures(self): self.check_case("rsa")
    def test_ecc_public_blob_and_rejected_signatures_and_keys(self): self.check_case("ecdsa")
    def test_mdl_actual_host_page_locking_and_shared_page_lifetime(self): self.check_case("memory")

    def test_mdl_write_probe_rejects_read_only_pages(self):
        with tempfile.TemporaryDirectory(prefix="driverlab-service-state-") as state:
            result = subprocess.run([str(self.binary), "bad-probe", state], capture_output=True, text=True, timeout=10)
        self.assertLess(result.returncode, 0)
        self.assertIn("MDL access probe or host page locking failed", result.stderr)

    def test_mdl_modified_range_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="driverlab-service-state-") as state:
            result = subprocess.run([str(self.binary), "bad-mdl", state], capture_output=True, text=True, timeout=10)
        self.assertLess(result.returncode, 0)
        self.assertIn("MDL range changed after allocation", result.stderr)
