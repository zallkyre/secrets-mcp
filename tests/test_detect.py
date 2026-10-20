import os
import tempfile
import unittest

from secrets_mcp import detect


class DetectTests(unittest.TestCase):
    def test_openai_key(self):
        text = "here you go sk-proj-abc123DEF456ghi789JKL012mno"
        clean, found = detect.redact(text)
        self.assertIn("{{openai}}", clean)
        self.assertNotIn("sk-proj", clean)
        self.assertEqual(list(found), ["openai"])

    def test_anthropic_key(self):
        text = "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        clean, found = detect.redact(text)
        self.assertIn("{{anthropic}}", clean)
        self.assertIn("anthropic", found)

    def test_github_pat(self):
        text = "token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        clean, found = detect.redact(text)
        self.assertIn("{{github}}", clean)
        self.assertIn("github", found)

    def test_aws_and_slack(self):
        text = "AKIAIOSFODNN7EXAMPLE and xoxb-123456789012-abcdefghijkl"
        clean, found = detect.redact(text)
        self.assertIn("{{aws}}", clean)
        self.assertIn("{{slack}}", clean)

    def test_no_false_positive_on_normal_text(self):
        text = "let's refactor the parser and ship it on friday"
        clean, found = detect.redact(text)
        self.assertEqual(clean, text)
        self.assertEqual(found, {})

    def test_repeated_provider_collapses_to_one_handle(self):
        text = "sk-ant-aaaaaaaaaaaaaaaaaaaaaaaa and sk-ant-bbbbbbbbbbbbbbbbbbbbbbbb"
        clean, found = detect.redact(text)
        self.assertEqual(clean.count("{{anthropic}}"), 2)
        self.assertEqual(len(found), 1)

    def test_generic_needs_context(self):
        blob = "a" * 40
        self.assertEqual(detect.redact(blob)[1], {})
        ctx = "api_key = " + blob
        self.assertTrue(detect.redact(ctx)[1])

    def test_pem_block(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890abcdef\n-----END RSA PRIVATE KEY-----"
        clean, found = detect.redact(pem)
        self.assertIn("{{privatekey}}", clean)
        self.assertIn("privatekey", found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
