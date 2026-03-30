#!/usr/bin/env python3
"""
Trend Radar for NIC (Nordic Information Control).

Fetches trending cybersecurity topics from Reddit and ENISA RSS,
filters for compliance/security relevance, prints terminal tables,
and prepares a context string for later LLM use.
"""

from __future__ import annotations

import argparse
import json
import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests


REDDIT_URL = "https://www.reddit.com/r/cybersecurity/top.json?t=week"
USER_AGENT = "NIC-Trend-Radar/1.0 (+https://www.nord-ic.com)"
DEFAULT_LIMIT = 15
DEFAULT_KEYWORDS = [
    "nis2",
    "dora",
    "ai act",
    "compliance",
    "framework",
    "audit",
    "security control",
    "gdpr",
    "regulation",
    "förordning",
    "forordning",
    "governance",
    "risk",
    "resilience",
    "resiliens",
    "cybersäkerhet",
    "cybersikkerhet",
    "information security",
    "informationssäkerhet",
    "klassificering",
    "classification",
]
DEFAULT_RSS_SOURCES = [
    ("CERT-SE", "https://www.cert.se/feed.rss"),
    ("UK NCSC News", "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml"),
    ("UK NCSC Blog", "https://www.ncsc.gov.uk/api/1/services/v1/blog-post-rss-feed.xml"),
    ("UK NCSC Threat Reports", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
    ("NIST Cybersecurity", "https://www.nist.gov/news-events/cybersecurity/rss.xml"),
    (
        "NIST Cybersecurity Insights",
        "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml",
    ),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
]
DEFAULT_HTML_SOURCES = [
    ("ENISA News", "https://www.enisa.europa.eu/news"),
    ("NCSC Netherlands News", "https://english.ncsc.nl/"),
    ("NSM Alerts", "https://nsm.no/fagomrader/digital-sikkerhet/nasjonalt-cybersikkerhetssenter/varsler-fra-nsm/"),
]
DEFAULT_JSON_SOURCES = [
    (
        "CISA KEV",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    (
        "Microsoft MSRC",
        "https://api.msrc.microsoft.com/update-guide/rss",
    ),
]
SOURCE_BONUS = {
    "ENISA News": 20,
    "CERT-SE": 25,
    "NCSC Netherlands News": 20,
    "UK NCSC News": 18,
    "UK NCSC Blog": 14,
    "UK NCSC Threat Reports": 14,
    "NSM Alerts": 20,
}


@dataclass
class TrendItem:
    source: str
    title: str
    url: str
    score: int
    matched_keywords: list[str]


@dataclass
class FetchResult:
    items: list[dict]
    error: str | None = None


@dataclass
class FeedSource:
    name: str
    url: str
    kind: str


class LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text_parts = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            text = unescape(" ".join(part.strip() for part in self._text_parts)).strip()
            if text:
                self.links.append((self._href, " ".join(text.split())))
            self._href = None
            self._text_parts = []


def fetch_reddit_posts(
    url: str = REDDIT_URL,
    limit: int = 25,
    timeout: int = 15,
) -> list[dict]:
    headers = {"User-Agent": USER_AGENT}
    params = {"limit": limit, "raw_json": 1}
    response = requests.get(url, headers=headers, params=params, timeout=timeout)
    response.raise_for_status()
    payload = response.json()
    children = payload.get("data", {}).get("children", [])

    posts = []
    for child in children:
        data = child.get("data", {})
        posts.append(
            {
                "title": data.get("title", "").strip(),
                "ups": int(data.get("ups", 0) or 0),
                "url": data.get("url", "").strip(),
            }
        )
    return posts


def fetch_rss_headlines(url: str, timeout: int = 15) -> list[dict]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    root = ET.fromstring(response.content)

    items = []
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        if title and link:
            items.append({"title": title, "url": link, "ups": 0})
    return items


def fetch_html_headlines(url: str, timeout: int = 15) -> list[dict]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()

    parser = LinkExtractor()
    parser.feed(response.text)
    domain = urlparse(url).netloc

    items = []
    seen: set[tuple[str, str]] = set()
    for href, title in parser.links:
        link = urljoin(url, href)
        if not title or len(title) < 24:
            continue
        if urlparse(link).netloc and urlparse(link).netloc != domain:
            continue
        lowered = title.lower()
        if any(
            noise in lowered
            for noise in (
                "kontakt",
                "cookies",
                "privacy",
                "linkedin",
                "facebook",
                "instagram",
                "rss",
                "sitemap",
                "report vulnerability",
                "go to content",
            )
        ):
            continue
        key = (title, link)
        if key in seen:
            continue
        seen.add(key)
        items.append({"title": title, "url": link, "ups": 0})
    return items[:50]


def fetch_json_headlines(url: str, timeout: int = 15) -> list[dict]:
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, timeout=timeout)
    response.raise_for_status()
    payload = response.json()

    if isinstance(payload, dict) and "vulnerabilities" in payload:
        items = []
        for record in payload.get("vulnerabilities", []):
            cve = (record.get("cveID") or "").strip()
            vendor = (record.get("vendorProject") or "").strip()
            product = (record.get("product") or "").strip()
            title = " ".join(
                part for part in [cve, vendor, product, "Known Exploited Vulnerability"] if part
            )
            if title:
                items.append({"title": title, "url": url, "ups": 0})
        return items

    if isinstance(payload, dict) and "value" in payload:
        items = []
        for record in payload.get("value", []):
            title = (
                record.get("cveNumber")
                or record.get("title")
                or record.get("id")
                or ""
            ).strip()
            link = (record.get("url") or url).strip()
            if title:
                items.append({"title": title, "url": link, "ups": 0})
        return items

    raise ValueError(f"Unsupported JSON feed format from {url}")


def find_matching_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    normalized = text.lower()
    return [keyword for keyword in keywords if keyword.lower() in normalized]


def score_item(base_score: int, matched_keywords: list[str]) -> int:
    return base_score + len(matched_keywords) * 10


def build_trend_items(
    source: str,
    records: Iterable[dict],
    keywords: Iterable[str],
) -> list[TrendItem]:
    items: list[TrendItem] = []
    for record in records:
        title = record.get("title", "").strip()
        url = record.get("url", "").strip()
        base_score = int(record.get("ups", 0) or 0)
        matched_keywords = find_matching_keywords(title, keywords)
        if not matched_keywords:
            continue

        items.append(
            TrendItem(
                source=source,
                title=title,
                url=url,
                score=score_item(base_score, matched_keywords) + SOURCE_BONUS.get(source, 0),
                matched_keywords=matched_keywords,
            )
        )
    return items


def sort_items(items: Iterable[TrendItem]) -> list[TrendItem]:
    return sorted(
        items,
        key=lambda item: (item.score, len(item.matched_keywords), item.title.lower()),
        reverse=True,
    )


def truncate(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    return value[: max(width - 1, 0)] + "…"


def print_plain_table(title: str, items: list[TrendItem]) -> None:
    print(f"\n{title}")
    print("-" * len(title))

    if not items:
        print("No matching items found.")
        return

    headers = ("Source", "Score", "Keywords", "Title", "URL")
    rows = [
        (
            item.source,
            str(item.score),
            ", ".join(item.matched_keywords),
            truncate(item.title, 72),
            truncate(item.url, 64),
        )
        for item in items
    ]

    widths = [len(header) for header in headers]
    for row in rows:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]

    def format_row(row: tuple[str, str, str, str, str]) -> str:
        return " | ".join(value.ljust(width) for value, width in zip(row, widths))

    print(format_row(headers))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(format_row(row))


def print_rich_table(title: str, items: list[TrendItem]) -> bool:
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return False

    table = Table(title=title)
    table.add_column("Source", style="cyan", no_wrap=True)
    table.add_column("Score", justify="right", style="green")
    table.add_column("Keywords", style="yellow")
    table.add_column("Title", style="white")
    table.add_column("URL", style="blue")

    if not items:
        table.add_row("-", "-", "-", "No matching items found.", "-")
    else:
        for item in items:
            table.add_row(
                item.source,
                str(item.score),
                ", ".join(item.matched_keywords),
                item.title,
                item.url,
            )

    Console().print(table)
    return True


def print_table(title: str, items: list[TrendItem]) -> None:
    if not print_rich_table(title, items):
        print_plain_table(title, items)


def build_context_string(items: list[TrendItem], top_n: int = 5) -> str:
    selected = items[:top_n]
    if not selected:
        return "No relevant headlines were found."

    lines = [
        "Trend Radar context for NIC (Nordic Information Control).",
        "Focus: GDPR, NIS2, DORA, AI Act, compliance, audit, governance, and security controls.",
        "Top relevant headlines:",
    ]

    for index, item in enumerate(selected, start=1):
        keyword_text = ", ".join(item.matched_keywords)
        lines.append(
            f"{index}. [{item.source}] {item.title} | score={item.score} | keywords={keyword_text} | url={item.url}"
        )

    return "\n".join(lines)


def safe_fetch(fetcher, *args, **kwargs) -> FetchResult:
    try:
        return FetchResult(items=fetcher(*args, **kwargs))
    except (requests.RequestException, ET.ParseError, ValueError, json.JSONDecodeError) as exc:
        return FetchResult(items=[], error=str(exc))


def default_sources() -> list[FeedSource]:
    sources = [FeedSource("Reddit", REDDIT_URL, "reddit")]
    sources.extend(FeedSource(name, url, "rss") for name, url in DEFAULT_RSS_SOURCES)
    sources.extend(FeedSource(name, url, "html") for name, url in DEFAULT_HTML_SOURCES)
    sources.extend(FeedSource(name, url, "json") for name, url in DEFAULT_JSON_SOURCES)
    return sources


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trend Radar for compliance and cybersecurity topics."
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="How many top combined results to display.",
    )
    parser.add_argument(
        "--reddit-limit",
        type=int,
        default=25,
        help="How many Reddit posts to fetch before filtering.",
    )
    parser.add_argument(
        "--keywords",
        nargs="*",
        default=DEFAULT_KEYWORDS,
        help="Override keyword list used for filtering.",
    )
    parser.add_argument(
        "--context-only",
        action="store_true",
        help="Print only the generated context string.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    all_items: list[TrendItem] = []
    errors = []

    for source in default_sources():
        if source.kind == "reddit":
            result = safe_fetch(fetch_reddit_posts, url=source.url, limit=args.reddit_limit)
        elif source.kind == "rss":
            result = safe_fetch(fetch_rss_headlines, source.url)
        elif source.kind == "html":
            result = safe_fetch(fetch_html_headlines, source.url)
        else:
            result = safe_fetch(fetch_json_headlines, source.url)

        all_items.extend(build_trend_items(source.name, result.items, args.keywords))
        if result.error:
            errors.append(f"{source.name} fetch failed: {result.error}")

    combined = sort_items(all_items)
    top_items = combined[: args.limit]

    if args.context_only:
        print(build_context_string(top_items))
        return

    print_table("NIC Trend Radar", top_items)

    context_string = build_context_string(top_items)
    print("\nContext String")
    print("--------------")
    print(textwrap.dedent(context_string))

    if errors:
        print("\nWarnings")
        print("--------")
        for error in errors:
            print(f"- {error}")


if __name__ == "__main__":
    main()
