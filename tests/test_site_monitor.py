import socket
import tempfile
import unittest
from pathlib import Path

import site_monitor


class SiteMonitorTests(unittest.TestCase):
    def test_url_policy(self):
        self.assertEqual(
            site_monitor.safe_https_url("https://example.com/status#now"),
            "https://example.com/status",
        )
        for value in ("http://example.com", "https://user:@example.com", "https://example.com:8443"):
            with self.assertRaises(ValueError):
                site_monitor.safe_https_url(value)

    def test_private_address_is_blocked(self):
        def resolver(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

        with self.assertRaises(ValueError):
            site_monitor.ensure_public_host("internal.example", resolver)

    def test_html_normalization_and_ignored_lines(self):
        content = b"<html><style>.x{}</style><body><h1>Status</h1><p>Build 123</p><script>x()</script></body></html>"
        text = site_monitor.normalize_content(content, "text/html; charset=utf-8", [r"^Build \d+$"])
        self.assertEqual(text, "Status")

    def test_first_seen_unchanged_and_changed(self):
        target = site_monitor.Target.from_dict({"name": "Example", "url": "https://example.com/"})
        with tempfile.TemporaryDirectory() as temporary:
            store = site_monitor.MonitorStore(Path(temporary) / "monitor.db")
            self.assertEqual(store.observe(target, "Version 1")["status"], "first_seen")
            self.assertEqual(store.observe(target, "Version 1")["status"], "unchanged")
            changed = store.observe(target, "Version 2")
            self.assertEqual(changed["status"], "changed")
            self.assertIn("-Version 1", changed["diff_preview"])
            self.assertIn("+Version 2", changed["diff_preview"])


if __name__ == "__main__":
    unittest.main()
