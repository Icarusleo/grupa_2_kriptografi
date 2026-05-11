"""
GOST hash plugins, HashRegistry, coexistence with MD5/SHA-256, and HTTP API.

Run from directory backend/api (PYTHONPATH is implicit when using -m unittest):

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

API_ROOT = Path(__file__).resolve().parent.parent
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))


def _reload_hash_plugins() -> None:
    from hash_registry import HashRegistry

    HashRegistry._plugins.clear()
    HashRegistry.load_plugins(str(API_ROOT / "hash_plugins"))


class TestGostImplementationsSelfTests(unittest.TestCase):
    """Run built-in vectors inside gost.python_impl (RFC / regression)."""

    def test_gost94_module_self_tests(self) -> None:
        from gost.python_impl import gost_r34_11_94 as m

        m._self_test()
        m._test_short_bit_aligned_messages()

    def test_streebog_module_self_tests(self) -> None:
        from gost.python_impl import streebog_r34_11_2012 as m

        m._self_test_streebog()
        m._test_short_bit_aligned_messages()


class TestHashRegistryGostPlugins(unittest.TestCase):
    """Plugins load via HashRegistry and match direct Python implementations."""

    @classmethod
    def setUpClass(cls) -> None:
        _reload_hash_plugins()

    def test_all_expected_plugins_registered(self) -> None:
        from hash_registry import HashRegistry

        ids = set(HashRegistry.get_all().keys())
        for pid in (
            "gost_r34_11_94",
            "streebog_256",
            "streebog_512",
            "md5",
            "sha256",
        ):
            self.assertIn(pid, ids, f"missing plugin {pid}")

    def test_gost_sidebar_metadata(self) -> None:
        from hash_registry import HashRegistry

        g94 = HashRegistry.get("gost_r34_11_94")
        self.assertIsNotNone(g94)
        assert g94 is not None
        self.assertEqual(g94.sidebar_group, "GOST Hash")
        self.assertEqual(g94.sidebar_icon, "94")
        s256 = HashRegistry.get("streebog_256")
        self.assertIsNotNone(s256)
        assert s256 is not None
        self.assertEqual(s256.sidebar_group, "GOST Hash")
        md5p = HashRegistry.get("md5")
        self.assertIsNotNone(md5p)
        assert md5p is not None
        self.assertEqual(md5p.sidebar_group, "Dynamic Hashes")

    def test_gost_r34_11_94_plugin_vs_direct(self) -> None:
        from hash_registry import HashRegistry
        from gost.python_impl import new_gost94

        plugin = HashRegistry.get("gost_r34_11_94")
        self.assertIsNotNone(plugin)
        assert plugin is not None
        for data in (b"", b"a", b"This is message, length=32 bytes", bytes(range(64))):
            self.assertEqual(
                plugin.compute_hash(data),
                new_gost94(data).digest(),
                f"len={len(data)}",
            )

    def test_streebog_plugins_vs_direct(self) -> None:
        from hash_registry import HashRegistry
        from gost.python_impl import streebog_new

        s256 = HashRegistry.get("streebog_256")
        s512 = HashRegistry.get("streebog_512")
        self.assertIsNotNone(s256)
        self.assertIsNotNone(s512)
        assert s256 is not None and s512 is not None
        for data in (b"", b"test", bytes(64)):
            self.assertEqual(
                s256.compute_hash(data),
                streebog_new("streebog256", data=bytearray(data)).digest(),
            )
            self.assertEqual(
                s512.compute_hash(data),
                streebog_new("streebog512", data=bytearray(data)).digest(),
            )

    def test_digest_sizes(self) -> None:
        from hash_registry import HashRegistry

        g94 = HashRegistry.get("gost_r34_11_94")
        s256 = HashRegistry.get("streebog_256")
        s512 = HashRegistry.get("streebog_512")
        self.assertIsNotNone(g94)
        self.assertIsNotNone(s256)
        self.assertIsNotNone(s512)
        assert g94 is not None and s256 is not None and s512 is not None
        self.assertEqual(g94.digest_size, 32)
        self.assertEqual(s256.digest_size, 32)
        self.assertEqual(s512.digest_size, 64)

    def test_md5_sha256_coexistence(self) -> None:
        from hash_registry import HashRegistry

        md5p = HashRegistry.get("md5")
        sha = HashRegistry.get("sha256")
        self.assertIsNotNone(md5p)
        self.assertIsNotNone(sha)
        assert md5p is not None and sha is not None
        msg = b"coexistence-check"
        self.assertEqual(md5p.compute_hash(msg), hashlib.md5(msg).digest())
        self.assertEqual(sha.compute_hash(msg), hashlib.sha256(msg).digest())


class TestHashHTTPAPI(unittest.TestCase):
    """Optional: full server import (DLL loading). Skip if import fails."""

    _client = None
    _skip_reason: str | None = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from starlette.testclient import TestClient

            import server as server_mod  # noqa: PLC0415

            cls._client = TestClient(server_mod.app)
        except Exception as e:  # noqa: BLE001 — surface any import/env failure
            cls._skip_reason = str(e)

    def setUp(self) -> None:
        if self._skip_reason is not None:
            self.skipTest(f"server/TestClient unavailable: {self._skip_reason}")

    def test_get_hash_algorithms_has_gost(self) -> None:
        assert self._client is not None
        r = self._client.get("/api/v1/hash/algorithms")
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertIn("gost_r34_11_94", data)
        self.assertIn("streebog_256", data)
        self.assertIn("streebog_512", data)
        g = data["gost_r34_11_94"]
        self.assertEqual(g.get("group"), "GOST Hash")
        self.assertIn("digest_size", g)
        self.assertIn("md5", data)
        self.assertEqual(data["md5"].get("group"), "Dynamic Hashes")

    def test_post_hash_compute_gost_and_sha256(self) -> None:
        assert self._client is not None
        payload = {
            "algorithm_id": "gost_r34_11_94",
            "data": {"value": "test", "encoding": "utf8"},
            "output_encoding": "hex",
        }
        r = self._client.post("/api/v1/hash/compute", json=payload)
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertEqual(body["digest_size"], 32)
        self.assertEqual(len(body["hash"]["hex"]), 64)

        from hash_registry import HashRegistry

        _reload_hash_plugins()
        direct = HashRegistry.get("gost_r34_11_94").compute_hash(b"test").hex()
        self.assertEqual(body["hash"]["hex"], direct)

        r2 = self._client.post(
            "/api/v1/hash/compute",
            json={
                "algorithm_id": "sha256",
                "data": {"value": "test", "encoding": "utf8"},
                "output_encoding": "hex",
            },
        )
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(
            r2.json()["hash"]["hex"],
            hashlib.sha256(b"test").hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
