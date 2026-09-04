# Web Change Monitor

A cautious Python monitor for authorized public HTTPS pages. It stores normalized text snapshots in SQLite and reports only meaningful changes.

## Safety choices

- HTTPS on port 443 only; credentials in URLs are rejected
- DNS resolution blocks private, loopback, link-local, reserved, and non-global targets
- Redirect destinations are checked again
- 20-second request timeout and 1 MB response limit
- Conditional requests with ETag and Last-Modified when available
- Scripts, styles, SVG, and configured volatile lines are excluded
- Telegram tokens come from environment variables and are never stored in SQLite
- No browser automation, login, CAPTCHA bypass, or access-control evasion

Use this only for pages you own, are authorized to monitor, or whose terms permit automated checks. Respect rate limits and site-specific rules.

## Demo

```bash
cp config.example.json config.json
python3 site_monitor.py --config config.json --db /tmp/monitor.db
python3 site_monitor.py --config config.json --db /tmp/monitor.db
```

The first run records a baseline. Later runs return `unchanged` or a bounded unified diff. Add `--send` only after setting `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` securely.

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Production deployment

Example hardened systemd units are under `deploy/`. Review paths, create a dedicated system user, keep the configuration non-secret, and inject Telegram credentials through a secret manager or systemd credentials.
