#!/usr/bin/env python3
"""Build and verify the AdGuard filter for Nanj-related sites."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "data" / "nanj_filter_sources.json"
DEFAULT_OUTPUT = ROOT / "docs" / "nanj-filter.txt"
USER_AGENT = "Mozilla/5.0 (compatible; nanj-filter-check/1.0)"


def load_sources(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def today_jst() -> str:
    return dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).strftime("%Y-%m-%d")


def adguard_rule(domain_or_path: str) -> str:
    value = domain_or_path.strip().removeprefix("http://").removeprefix("https://")
    if "/" in value:
        return f"||{value.rstrip('/')}/*$document"
    return f"||{value}^$document"


def build_filter(config: dict[str, Any], generated_date: str) -> str:
    lines = [
        f"! Title: {config['title']}",
        "! Description: AdGuard用のなんJ系サイトブロックフィルター",
        f"! Homepage: {config.get('homepage', '')}",
        f"! Source: {config.get('source_repository', '')}",
        "! Expires: 1 day",
        f"! Updated: {generated_date}",
        "!",
        "! このファイルは data/nanj_filter_sources.json から生成されています。",
        "! 直接編集せず scripts/build_nanj_filter.py を実行してください。",
        "",
        f"! {config['antenna']['name']}",
    ]

    for domain in config["antenna"]["domains"]:
        lines.append(adguard_rule(domain))

    for source in config["sources"]:
        if not source.get("enabled", True):
            continue

        note = source.get("last_verification_note")
        lines.append("")
        lines.append(f"! {source['name']}")
        if note:
            lines.append(f"! verify: {source.get('last_verified_at', 'unknown')} - {note}")
        for domain in source["domains"]:
            lines.append(adguard_rule(domain))

    return "\n".join(lines).rstrip() + "\n"


def fetch(url: str, insecure_tls: bool) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl._create_unverified_context() if insecure_tls else None
    with urllib.request.urlopen(request, timeout=20, context=context) as response:
        body = response.read()
    return body.decode("utf-8", errors="replace")


def save_sources(path: Path, config: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def antenna_page_urls(config: dict[str, Any]) -> list[str]:
    homepage = config["antenna"]["homepage"].rstrip("/")
    count = int(config["antenna"].get("verify_pages", 1))
    return [homepage] + [f"{homepage}/page/{page}" for page in range(2, count + 1)]


def verify(config: dict[str, Any], insecure_tls: bool, update_metadata: bool) -> int:
    html_pages: list[str] = []
    errors: list[str] = []
    verified_at = today_jst()
    page_count = int(config["antenna"].get("verify_pages", 1))

    for url in antenna_page_urls(config):
        try:
            html_pages.append(fetch(url, insecure_tls=insecure_tls))
        except (urllib.error.URLError, TimeoutError) as exc:
            errors.append(f"{url}: {exc}")

    combined_html = "\n".join(html_pages)
    exit_code = 0

    if errors:
        print("Antenna fetch errors:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        exit_code = 1

    for source in config["sources"]:
        if not source.get("enabled", True):
            continue

        homepage_ok = True
        try:
            fetch(source["homepage"], insecure_tls=insecure_tls)
        except (urllib.error.URLError, TimeoutError) as exc:
            homepage_ok = False
            print(f"WARN: {source['name']} homepage fetch failed: {exc}")

        if source.get("source_type") != "antenna":
            if update_metadata:
                source["last_verified_at"] = verified_at
                if homepage_ok:
                    source["last_verification_note"] = "手動追加対象。サイト実体を確認"
                else:
                    source["last_verification_note"] = "手動追加対象。サイト実体の取得に失敗"
            continue

        label = source.get("antenna_label")
        domains = source.get("domains", [])
        found = bool(label and label in combined_html) or any(domain in combined_html for domain in domains)
        status = "OK" if found else "WARN"
        print(f"{status}: {source['name']}")
        if update_metadata:
            source["last_verified_at"] = verified_at
            if found:
                source["last_verification_note"] = f"なんJアンテナ1-{page_count}ページで掲載を確認"
            elif homepage_ok:
                source["last_verification_note"] = (
                    f"サイト実体は確認。なんJアンテナ1-{page_count}ページでは今回未検出のため、"
                    "前回掲載確認済みサイトとして継続"
                )
            else:
                source["last_verification_note"] = (
                    f"サイト実体の取得に失敗。なんJアンテナ1-{page_count}ページでも未検出のため要確認"
                )
        if not found:
            exit_code = max(exit_code, 2)

    return exit_code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--update-verification-metadata", action="store_true")
    parser.add_argument("--insecure-tls", action="store_true")
    args = parser.parse_args()

    config = load_sources(args.data)

    if args.verify:
        verify_code = verify(
            config,
            insecure_tls=args.insecure_tls,
            update_metadata=args.update_verification_metadata,
        )
        if verify_code == 1:
            return verify_code
        if args.update_verification_metadata:
            save_sources(args.data, config)

    content = build_filter(config, today_jst())

    if args.check:
        if not args.output.exists() or args.output.read_text(encoding="utf-8") != content:
            print(f"{args.output} is not up to date", file=sys.stderr)
            return 1
        return 0

    if args.write:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        return 0

    print(content, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
