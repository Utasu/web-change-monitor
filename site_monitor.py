#!/usr/bin/env python3
"""Monitor authorized HTTPS pages and report meaningful text changes."""

from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable


UTC = dt.timezone.utc
MAX_RESPONSE_BYTES = 1_000_000


def now_iso() -> str:
    return dt.datetime.now(UTC).replace(microsecond=0).isoformat()


def safe_https_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("target URL must use HTTPS")
    if parsed.username or parsed.password:
        raise ValueError("credentials are not allowed in target URLs")
    if parsed.port not in (None, 443):
        raise ValueError("only the standard HTTPS port is allowed")
    return urllib.parse.urlunparse(parsed._replace(fragment=""))


def ensure_public_host(
    hostname: str,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> list[str]:
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("local targets are blocked")
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = [literal]
    except ValueError:
        records = resolver(hostname, 443, type=socket.SOCK_STREAM)
        addresses = [ipaddress.ip_address(record[4][0]) for record in records]
    if not addresses:
        raise ValueError("target hostname did not resolve")
    for address in addresses:
        if not address.is_global:
            raise ValueError(f"non-public target address is blocked: {address}")
    return sorted({str(address) for address in addresses})


class VisibleTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript", "svg"} and self.hidden_depth:
            self.hidden_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden_depth:
            self.parts.append(data)


def normalize_content(content: bytes, content_type: str, ignore_patterns: list[str]) -> str:
    charset_match = re.search(r"charset=([\w-]+)", content_type, re.I)
    charset = charset_match.group(1) if charset_match else "utf-8"
    text = content.decode(charset, errors="replace")
    if "html" in content_type.lower() or "<html" in text[:1000].lower():
        parser = VisibleTextParser()
        parser.feed(text)
        text = "\n".join(parser.parts)
    lines: list[str] = []
    compiled = [re.compile(pattern) for pattern in ignore_patterns]
    for raw_line in text.splitlines():
        line = " ".join(raw_line.split())
        if not line or any(pattern.search(line) for pattern in compiled):
            continue
        lines.append(line)
    return "\n".join(lines)[:250_000]


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    ignore_patterns: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Target":
        name = " ".join(str(value.get("name") or "").split())[:120]
        if not name:
            raise ValueError("target name is required")
        patterns = value.get("ignore_patterns") or []
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise ValueError("ignore_patterns must be a list of regular expressions")
        for pattern in patterns:
            re.compile(pattern)
        return cls(name=name, url=safe_https_url(str(value.get("url") or "")), ignore_patterns=patterns)


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        checked = safe_https_url(newurl)
        ensure_public_host(urllib.parse.urlparse(checked).hostname or "")
        return super().redirect_request(req, fp, code, msg, headers, checked)


@dataclass(frozen=True)
class FetchResult:
    status: int
    content: bytes
    content_type: str
    etag: str
    last_modified: str


def fetch_target(target: Target, etag: str = "", last_modified: str = "") -> FetchResult:
    hostname = urllib.parse.urlparse(target.url).hostname or ""
    ensure_public_host(hostname)
    headers = {
        "Accept": "text/html,text/plain,application/json;q=0.8",
        "User-Agent": "authorized-web-change-monitor/1.0 (+contact-site-owner)",
    }
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    request = urllib.request.Request(target.url, headers=headers)
    opener = urllib.request.build_opener(SafeRedirectHandler())
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        if error.code == 304:
            return FetchResult(304, b"", "", etag, last_modified)
        raise
    with response:
        content = response.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("response exceeds the 1 MB safety limit")
        return FetchResult(
            status=response.status,
            content=content,
            content_type=response.headers.get("Content-Type", "application/octet-stream"),
            etag=response.headers.get("ETag", ""),
            last_modified=response.headers.get("Last-Modified", ""),
        )


class MonitorStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS targets (
              url TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              content_hash TEXT NOT NULL,
              normalized_text TEXT NOT NULL,
              etag TEXT NOT NULL,
              last_modified TEXT NOT NULL,
              checked_at TEXT NOT NULL,
              changed_at TEXT NOT NULL,
              last_error TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS changes (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              url TEXT NOT NULL,
              old_hash TEXT NOT NULL,
              new_hash TEXT NOT NULL,
              diff_preview TEXT NOT NULL,
              detected_at TEXT NOT NULL
            );
            """
        )
        self.connection.commit()

    def get(self, url: str) -> sqlite3.Row | None:
        return self.connection.execute("SELECT * FROM targets WHERE url=?", (url,)).fetchone()

    def unchanged(self, target: Target) -> dict[str, Any]:
        self.connection.execute(
            "UPDATE targets SET checked_at=?,last_error='' WHERE url=?", (now_iso(), target.url)
        )
        self.connection.commit()
        return {"name": target.name, "url": target.url, "status": "unchanged"}

    def observe(self, target: Target, text: str, etag: str = "", last_modified: str = "") -> dict[str, Any]:
        current = self.get(target.url)
        new_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        stamp = now_iso()
        if current and current["content_hash"] == new_hash:
            self.connection.execute(
                """UPDATE targets SET name=?,etag=?,last_modified=?,checked_at=?,last_error=''
                   WHERE url=?""",
                (target.name, etag, last_modified, stamp, target.url),
            )
            self.connection.commit()
            return {"name": target.name, "url": target.url, "status": "unchanged"}

        if current:
            old_text = current["normalized_text"]
            preview = "\n".join(
                difflib.unified_diff(
                    old_text.splitlines(), text.splitlines(), fromfile="previous", tofile="current", lineterm=""
                )
            )[:5000]
            status = "changed"
            old_hash = current["content_hash"]
            self.connection.execute(
                "INSERT INTO changes(url,old_hash,new_hash,diff_preview,detected_at) VALUES(?,?,?,?,?)",
                (target.url, old_hash, new_hash, preview, stamp),
            )
        else:
            preview, status, old_hash = "", "first_seen", ""

        self.connection.execute(
            """INSERT INTO targets
               (url,name,content_hash,normalized_text,etag,last_modified,checked_at,changed_at,last_error)
               VALUES(?,?,?,?,?,?,?,?, '')
               ON CONFLICT(url) DO UPDATE SET name=excluded.name,content_hash=excluded.content_hash,
               normalized_text=excluded.normalized_text,etag=excluded.etag,
               last_modified=excluded.last_modified,checked_at=excluded.checked_at,
               changed_at=excluded.changed_at,last_error=''""",
            (target.url, target.name, new_hash, text, etag, last_modified, stamp, stamp),
        )
        self.connection.commit()
        return {
            "name": target.name,
            "url": target.url,
            "status": status,
            "old_hash": old_hash,
            "new_hash": new_hash,
            "diff_preview": preview,
        }

    def record_error(self, target: Target, error: Exception) -> None:
        current = self.get(target.url)
        if current:
            self.connection.execute(
                "UPDATE targets SET checked_at=?,last_error=? WHERE url=?",
                (now_iso(), type(error).__name__, target.url),
            )
            self.connection.commit()


def telegram_send(message: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        raise ValueError("Telegram environment variables are missing")
    payload = json.dumps(
        {"chat_id": chat_id, "text": message, "disable_web_page_preview": True}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "web-change-monitor/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise RuntimeError("Telegram rejected the message")


def load_targets(path: Path) -> list[Target]:
    config = json.loads(path.read_text(encoding="utf-8"))
    values = config.get("targets") if isinstance(config, dict) else None
    if not isinstance(values, list):
        raise ValueError("configuration requires a targets array")
    return [Target.from_dict(value) for value in values]


def check_target(store: MonitorStore, target: Target) -> dict[str, Any]:
    current = store.get(target.url)
    fetched = fetch_target(
        target,
        current["etag"] if current else "",
        current["last_modified"] if current else "",
    )
    if fetched.status == 304:
        return store.unchanged(target)
    normalized = normalize_content(fetched.content, fetched.content_type, target.ignore_patterns)
    return store.observe(target, normalized, fetched.etag, fetched.last_modified)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("config.json"))
    parser.add_argument("--db", type=Path, default=Path(".state/monitor.sqlite3"))
    parser.add_argument("--send", action="store_true", help="notify Telegram on changes")
    args = parser.parse_args(argv)
    store = MonitorStore(args.db)
    results: list[dict[str, Any]] = []
    for target in load_targets(args.config):
        try:
            result = check_target(store, target)
            results.append(result)
            if result["status"] == "changed" and args.send:
                telegram_send(
                    f"🔎 Page changed: {target.name}\n{target.url}\n\n"
                    + (result.get("diff_preview") or "Content hash changed")[:3000]
                )
        except (OSError, ValueError, RuntimeError, urllib.error.URLError) as error:
            store.record_error(target, error)
            results.append(
                {"name": target.name, "url": target.url, "status": "error", "error": type(error).__name__}
            )
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 1 if any(result["status"] == "error" for result in results) else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
