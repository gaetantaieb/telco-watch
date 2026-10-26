import asyncio
import ipaddress
import json
import os
import re
import socket
from datetime import UTC, datetime
from urllib.parse import urljoin, urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
UA = {"User-Agent": "telco-watch-bot/1.0"}
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_KEY = os.environ.get("NVD_API_KEY")


def item(vendor, ident, title, url, text="", cvss=None, kev=False, published=""):
    title = (title or "").strip()
    return {
        "vendor": vendor,
        "id": str(ident),
        "title": title,
        "url": url,
        "cves": sorted(set(CVE_RE.findall(f"{title} {text}"))),
        "cvss": cvss,
        "kev": kev,
        "published": str(published or ""),
    }


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
        )
        for e in feedparser.parse(r.text).entries
    ]


async def fetch_json(client, src):
    cfg = src["config"]  # {"list": "a.b", "id": .., "title": .., "url": .., "date": ..}
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
async def fetch_kev(client, vendors):
    r = await client.get(KEV_URL)
    r.raise_for_status()
    out = []
    for v in r.json()["vulnerabilities"]:
        project = v["vendorProject"].lower()
        match = next((x for x in vendors if x["nvd_keyword"].lower() in project), None)
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
        params = {
            "keywordSearch": v["nvd_keyword"],
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
                    desc[:200],
                    f"https://nvd.nist.gov/vuln/detail/{c['id']}",
                    c["id"],
                    cvss=score,
                    published=c["published"],
                )
            )
        await asyncio.sleep(0.7 if NVD_KEY else 6.5)  # NVD rate limit
    return out
