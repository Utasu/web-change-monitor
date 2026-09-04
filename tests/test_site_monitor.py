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


    def test_failed_delivery_is_retried_and_not_lost(self):
        target = site_monitor.Target.from_dict({"name": "Example", "url": "https://example.com/"})
        with tempfile.TemporaryDirectory() as temporary:
            store = site_monitor.MonitorStore(Path(temporary) / "monitor.db")
            store.observe(target, "Version 1")
            store.observe(target, "Version 2")

            def failing(message):
                raise RuntimeError("telegram unreachable")

            self.assertEqual(
                site_monitor.deliver_pending(store, sender=failing), {"notified": 0, "failed": 1}
            )
            # The page already reads as unchanged, so the queue is the only thing
            # keeping this change alive.
            self.assertEqual(store.observe(target, "Version 2")["status"], "unchanged")
            self.assertEqual(len(store.pending_changes()), 1)

            sent = []
            self.assertEqual(
                site_monitor.deliver_pending(store, sender=sent.append), {"notified": 1, "failed": 0}
            )
            self.assertEqual(store.pending_changes(), [])
            self.assertIn("Example", sent[0])
            self.assertIn("+Version 2", sent[0])

    def test_unknown_charset_does_not_abort_the_run(self):
        text = site_monitor.normalize_content(
            b"<html><body>Status</body></html>", "text/html; charset=not-a-real-charset", []
        )
        self.assertEqual(text, "Status")

    def test_redirect_hops_are_revalidated(self):
        # A redirect target that resolves to a private address must be rejected, even
        # though the first hop was public.
        def resolver(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))]

        with self.assertRaises(ValueError):
            site_monitor.ensure_public_host("redirect-target.example", resolver)
        self.assertIsNone(
            site_monitor.NoRedirectHandler().redirect_request(None, None, 302, "", {}, "https://x.example/")
        )


if __name__ == "__main__":
    unittest.main()
