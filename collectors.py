import asyncio
import ipaddress
import json
import os
import re
import socket
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
UA = {"User-Agent": "telco-watch-bot/1.0"}
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_KEY = os.environ.get("NVD_API_KEY")
# The vendor's own rating, read from the advisory text when the source gives no score:
# "CVSS v3.1 Base Score: 9.8", "(Severity: HIGH)", "Security Impact Rating: Critical".
# A vector string ("CVSS:3.1/AV:N/...") is not a score.
CVSS_RE = re.compile(
    r"CVSS(?:\s?v?[234](?:\.\d)?)?[\s\"':=_]*(?:base\s*)?(?:score)?[\s\"':=]*"
    r"(10(?:\.0)?|\d\.\d)(?![\d/.])",
    re.IGNORECASE,
)
LEVEL_WORDS = r"(critical|high|important|medium|moderate|low)"
RATING_RE = re.compile(
    rf"(?:severity|impact rating|\bSIR)[\s\"':=(]*{LEVEL_WORDS}\b"
    rf"|\b{LEVEL_WORDS}[\s-]+severity\b",  # "High severity" or "high-severity"
    re.IGNORECASE,
)
RATINGS = {"important": "high", "moderate": "medium"}  # other words are already levels


def rating_of(value):
    """A vendor rating word as one of the severity levels, or None."""
    word = str(value or "").strip().lower()
    word = RATINGS.get(word, word)
    return word if word in ("critical", "high", "medium", "low") else None


def vendor_score(text):
    """A CVSS score, else a vendor rating, written in an advisory's text: (cvss, rating)."""
    if m := CVSS_RE.search(text):
        return float(m.group(1)), None
    m = RATING_RE.search(text)
    return None, rating_of(m and (m.group(1) or m.group(2)))


def item(
    vendor,
    ident,
    title,
    url,
    text="",
    cvss=None,
    kev=False,
    published="",
    updated="",
    rating=None,
):
    title = (title or "").strip()
    if cvss is None:
        cvss, found = vendor_score(f"{title} {text}")
        rating = rating if rating_of(rating) else found  # a source's own field wins
    return {
        "vendor": vendor,
        "id": str(ident),
        "title": title,
        "url": url,
        "cves": sorted(set(CVE_RE.findall(f"{title} {text}"))),
        "cvss": cvss,
        "kev": kev,
        "published": str(published or ""),
        "updated": str(updated or ""),  # the source's last change, when it gives one
        "rating": None if cvss is not None else rating_of(rating),
    }


def parse_date(raw):
    """A source's date (ISO 8601 or RFC 2822) as an aware datetime, or None if unreadable."""
    raw = str(raw or "").strip()
    for parse in (datetime.fromisoformat, parsedate_to_datetime):
        try:
            dt = parse(raw)
        except (TypeError, ValueError, IndexError):
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None


def short_title(text, limit=200):
    """Text that fits is kept; else its first sentence, cut at a word when still too long."""
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    first = re.split(r"(?<=[.!?])\s", text, maxsplit=1)[0]
    if 40 <= len(first) <= limit:  # a very short "sentence" is likely an abbreviation
        return first
    cut = text[: limit - 1]
    if " " in cut:
        cut = cut.rsplit(" ", 1)[0]
    return cut.rstrip(" ,;:-") + "…"


def safe_url(url):
    """Only public https URLs: blocks Railway-internal hosts and private addresses."""
    p = urlparse(url or "")
    if p.scheme != "https" or not p.hostname:
        return False
    if p.hostname.endswith((".internal", ".local", "localhost")):
        return False
    try:
        infos = socket.getaddrinfo(p.hostname, 443)
    except socket.gaierror:
        return False
    return all(ipaddress.ip_address(i[4][0]).is_global for i in infos)


async def _guard(request):
    if not safe_url(str(request.url)):  # also checks every redirect
        raise httpx.RequestError(f"blocked URL: {request.url}", request=request)


def client():
    return httpx.AsyncClient(
        timeout=30, follow_redirects=True, headers=UA, event_hooks={"request": [_guard]}
    )


# ---------- vendor-specific sources (rows of the sources table) ----------
async def fetch_rss(client, src):
    r = await client.get(src["url"])
    r.raise_for_status()
    return [
        item(
            src["vendor"],
            e.get("id") or e.get("link"),
            e.get("title", ""),
            e.get("link", ""),
            e.get("summary", ""),
            published=e.get("published"),
            # e.get("updated") would warn, then fall back to the published date
            updated=dict.get(e, "updated"),
        )
        for e in feedparser.parse(r.text).entries
    ]


async def fetch_json(client, src):
    # config: {"list": "a.b", "id", "title", "url", "date", "updated", "severity"}
    cfg = src["config"]
    r = await client.get(src["url"])
    r.raise_for_status()
    data = r.json()
    for key in filter(None, cfg.get("list", "").split(".")):
        data = data[key]
    return [
        item(
            src["vendor"],
            d.get(cfg["id"]),
            str(d.get(cfg["title"], "")),
            str(d.get(cfg.get("url", ""), src["url"])),
            json.dumps(d)[:2000],
            published=d.get(cfg.get("date", "")),
            updated=d.get(cfg.get("updated", "")),
            rating=d.get(cfg.get("severity", "")),
        )
        for d in data[:100]
    ]


async def fetch_html(client, src):
    cfg = src["config"]  # {"item": css, "title": css (optional), "link": css}
    r = await client.get(src["url"])
    r.raise_for_status()
    out = []
    for node in BeautifulSoup(r.text, "html.parser").select(cfg["item"])[:50]:
        title = node.select_one(cfg["title"]) if cfg.get("title") else node
        link = node.select_one(cfg.get("link") or "a[href]")
        if not title or not link or not link.get("href"):
            continue
        href = urljoin(src["url"], link["href"])
        out.append(
            item(
                src["vendor"],
                href,
                title.get_text(" ", strip=True),
                href,
                node.get_text(" ", strip=True),
            )
        )
    return out


FETCHERS = {"rss": fetch_rss, "json": fetch_json, "html": fetch_html}


# ---------- global sources, filtered by the vendors table ----------
def kev_matches(keyword, name):
    """Whole-word match on the KEV vendor and product, so "PHP" does not match phpMyAdmin."""
    return (
        re.search(rf"(?<!\w){re.escape(keyword)}(?!\w)", name, re.IGNORECASE)
        is not None
    )


async def fetch_kev(client, vendors):
    r = await client.get(KEV_URL)
    r.raise_for_status()
    out = []
    for v in r.json()["vulnerabilities"]:
        name = f"{v['vendorProject']} {v['product']}"
        match = next((x for x in vendors if kev_matches(x["nvd_keyword"], name)), None)
        if match:
            out.append(
                item(
                    match["name"],
                    "KEV-" + v["cveID"],
                    v["vulnerabilityName"],
                    f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                    v["cveID"],
                    kev=True,
                    published=v["dateAdded"],
                )
            )
    return out


async def fetch_nvd(client, vendors, since):
    now = datetime.now(UTC)
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    out = []
    for v in vendors:
        # A CPE (product) match is exact; a keyword also hits CVEs that merely mention it.
        query = (
            {"virtualMatchString": v["nvd_cpe"]}
            if v.get("nvd_cpe")
            else {"keywordSearch": v["nvd_keyword"]}
        )
        params = {
            **query,
            "lastModStartDate": since.isoformat(timespec="milliseconds"),
            "lastModEndDate": now.isoformat(timespec="milliseconds"),
        }
        r = await client.get(NVD_URL, params=params, headers=headers, timeout=60)
        r.raise_for_status()
        for entry in r.json().get("vulnerabilities", []):
            c, score = entry["cve"], None
            for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                if c.get("metrics", {}).get(k):
                    score = c["metrics"][k][0]["cvssData"]["baseScore"]
                    break
            desc = next(
                (d["value"] for d in c["descriptions"] if d["lang"] == "en"), ""
            )
            out.append(
                item(
                    v["name"],
                    c["id"],
                    short_title(desc),
                    f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                    c["id"],
                    cvss=score,
                    published=c["published"],
                    updated=c.get("lastModified"),
                )
            )
        await asyncio.sleep(0.7 if NVD_KEY else 6.5)  # NVD rate limit
    return out
