import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from secrets_mcp import server, store

HINT_FIELDS = (
    "read_only_hint",
    "destructive_hint",
    "idempotent_hint",
    "open_world_hint",
)


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["SECRETS_MCP_VAULT"] = str(Path(self.tmp.name) / "vault.json")

    def tearDown(self):
        os.environ.pop("SECRETS_MCP_VAULT", None)
        self.tmp.cleanup()

    # -- stage_secret ------------------------------------------------------

    def test_stage_secret_replaces_key_with_handle(self):
        out = json.loads(server.stage_secret("my key is sk_live_abcdef1234567890"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["found"], 1)
        self.assertIn("{{stripe}}", out["text"])
        self.assertNotIn("sk_live_abcdef1234567890", out["text"])

    def test_stage_secret_never_returns_the_value(self):
        key = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        out = server.stage_secret(key)
        self.assertNotIn(key, out)

    def test_stage_secret_with_no_secret(self):
        out = json.loads(server.stage_secret("nothing to see here"))
        self.assertEqual(out["found"], 0)
        self.assertEqual(out["text"], "nothing to see here")

    # -- list_secrets ------------------------------------------------------

    def test_list_secrets_shows_handle_not_value(self):
        store.put("github", "ghp_bbbbbbbbbbbbbbbbbbbb")
        out = json.loads(server.list_secrets())
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["secrets"][0]["name"], "github")
        self.assertNotIn("ghp_", json.dumps(out))

    # -- request_with_secret ----------------------------------------------

    def test_request_with_secret_delegates_to_proxy(self):
        store.put("stripe", "sk_live_abcdef1234567890")
        fake = {"ok": True, "status": 200, "body": "{}"}
        with mock.patch.object(server.proxy, "request", return_value=fake) as call:
            out = json.loads(
                server.request_with_secret(
                    "GET",
                    "https://api.stripe.com/v1/balance",
                    {"Authorization": "Bearer {{stripe}}"},
                )
            )
        self.assertEqual(out["status"], 200)
        call.assert_called_once_with(
            "GET",
            "https://api.stripe.com/v1/balance",
            {"Authorization": "Bearer {{stripe}}"},
            None,
        )

    def test_request_with_secret_reports_proxy_errors(self):
        with mock.patch.object(
            server.proxy, "request", side_effect=RuntimeError("no such handle")
        ):
            out = json.loads(server.request_with_secret("GET", "https://example.com"))
        self.assertFalse(out["ok"])
        self.assertIn("no such handle", out["error"])

    # -- revoke_secret -----------------------------------------------------

    def test_revoke_secret_deletes_handle(self):
        store.put("slack", "xoxb-1234567890")
        out = json.loads(server.revoke_secret("slack"))
        self.assertTrue(out["ok"])
        self.assertEqual(store.listing(), [])

    def test_revoke_secret_unknown_handle(self):
        out = json.loads(server.revoke_secret("nope"))
        self.assertFalse(out["ok"])
        self.assertEqual(out["note"], "no such handle")

    # -- vault_info --------------------------------------------------------

    def test_vault_info_reports_backend_and_count(self):
        store.put("openai", "sk-proj-abcdefghijklmnopqrstuvwx")
        out = json.loads(server.vault_info())
        self.assertTrue(out["ok"])
        self.assertEqual(out["count"], 1)
        self.assertEqual(
            out["backend"], "windows-dpapi" if sys.platform == "win32" else "aes-gcm"
        )
        self.assertTrue(out["vault"].endswith("vault.json"))

    # -- annotations -------------------------------------------------------

    def test_every_tool_declares_all_four_hints(self):
        tools = asyncio.run(server.mcp.list_tools())
        self.assertEqual(
            {t.name for t in tools},
            {
                "stage_secret",
                "list_secrets",
                "request_with_secret",
                "revoke_secret",
                "vault_info",
            },
        )
        for tool in tools:
            with self.subTest(tool=tool.name):
                self.assertIsNotNone(tool.annotations)
                for field in HINT_FIELDS:
                    value = getattr(tool.annotations, field)
                    self.assertIsInstance(value, bool)


if __name__ == "__main__":
    unittest.main(verbosity=2)
