# Web Change Monitor

[![tests](https://github.com/Utasu/web-change-monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/Utasu/web-change-monitor/actions/workflows/tests.yml)

A cautious Python monitor for authorized public HTTPS pages. It stores normalized text snapshots in SQLite and reports only meaningful changes.

## Safety choices

- HTTPS on port 443 only; credentials in URLs are rejected
- DNS resolution blocks private, loopback, link-local, reserved, and non-global targets
- The connection is pinned to the address that passed validation, closing the DNS-rebinding window between the check and the socket
- Redirects are not followed automatically; each hop is re-validated and re-pinned, up to five hops
- 20-second request timeout and 1 MB response limit
- Conditional requests with ETag and Last-Modified when available
- Scripts, styles, SVG, and configured volatile lines are excluded
- Telegram tokens come from environment variables and are never stored in SQLite
- No browser automation, login, CAPTCHA bypass, or access-control evasion

Use this only for pages you own, are authorized to monitor, or whose terms permit automated checks. Respect rate limits and site-specific rules.

## Quickstart

```bash
git clone https://github.com/Utasu/web-change-monitor && cd web-change-monitor
cp config.example.json config.json      # list the pages you are authorized to watch
python3 site_monitor.py --config config.json --db /tmp/monitor.db
```

## Demo

Actual output of the first two runs:

```console
$ python3 site_monitor.py --config config.json --db /tmp/monitor.db
{
  "results": [
    {
      "name": "Example Domain",
      "url": "https://example.com/",
      "status": "first_seen",
      "old_hash": "",
      "new_hash": "e639c656ee40993c86c194936ccd14fb20b5c9d483d5b49d90e3246a8a2b87d3",
      "diff_preview": ""
    }
  ],
  "delivery": { "notified": 0, "failed": 0 }
}

$ python3 site_monitor.py --config config.json --db /tmp/monitor.db
{
  "results": [
    { "name": "Example Domain", "url": "https://example.com/", "status": "unchanged" }
  ],
  "delivery": { "notified": 0, "failed": 0 }
}
```

The first run records a baseline. Later runs return `unchanged` or a bounded unified diff. Add `--send` only after setting `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` securely.

## A detected change is never lost

The new snapshot is committed before anything is sent, so the next run would see an
unchanged page. Changes are therefore queued and only marked delivered once the send
succeeds; a Telegram outage delays notifications and the next run retries them, and
`delivery.failed` plus exit code `1` make that visible to cron or systemd.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Production deployment

Example hardened systemd units are under `deploy/`. Review paths, create a dedicated system user, keep the configuration non-secret, and inject Telegram credentials through a secret manager or systemd credentials.
