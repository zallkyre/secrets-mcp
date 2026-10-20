import json
import os
import tempfile
import unittest
from pathlib import Path

from secrets_mcp import store


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SECRETS_MCP_VAULT"] = str(Path(self.tmp.name) / "vault.json")

    def tearDown(self):
        os.environ.pop("SECRETS_MCP_VAULT", None)
        self.tmp.cleanup()

    def test_put_get_roundtrip(self):
        store.put("stripe", "sk_live_abcdef123456")
        self.assertEqual(store.get("stripe"), "sk_live_abcdef123456")

    def test_value_never_stored_in_plaintext(self):
        store.put("openai", "sk-proj-supersecretvalue123456")
        raw = Path(os.environ["SECRETS_MCP_VAULT"]).read_text(encoding="utf-8")
        self.assertNotIn("supersecretvalue", raw)

    def test_listing_hides_values(self):
        store.put("github", "ghp_aaaaaaaaaaaaaaaaaaaa")
        item = store.listing()[0]
        self.assertEqual(item["name"], "github")
        self.assertNotIn("ghp_", json.dumps(item))
        self.assertTrue(item["hint"].endswith("aaaa"))

    def test_delete(self):
        store.put("slack", "xoxb-1234567890")
        self.assertTrue(store.delete("slack"))
        self.assertFalse(store.delete("slack"))
        self.assertEqual(store.listing(), [])

    def test_bad_name_rejected(self):
        with self.assertRaises(store.VaultError):
            store.put("../etc/passwd", "x")

    def test_missing_secret(self):
        with self.assertRaises(store.VaultError):
            store.get("nope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
