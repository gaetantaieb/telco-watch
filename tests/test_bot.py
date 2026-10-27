import asyncio
import json
import logging
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("TELEGRAM_BOT_TOKEN", "test")
os.environ.setdefault("ANTHROPIC_API_KEY", "test")

import bot
import collectors
import llm
import onboard


def item(**kw):
    base = {
        "vendor": "Cisco",
        "id": "x",
        "title": "t",
        "url": "u",
        "cves": [],
        "cvss": None,
        "kev": False,
        "published": "",
    }
    base.update(kw)
    return base


def mock_client(handler):
    """An httpx client that never touches the network."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def run(coro):
    return asyncio.run(coro)


# ---------- starter tests (spec 3.6) ----------
def test_kev_is_always_critical():
    assert bot.severity(item(kev=True)).startswith("🔴")


def user(**kw):
    base = {
        "chat_id": 1,
        "name": "Ana",
        "status": "active",
        "min_cvss": 7.0,
        "muted": [],
    }
    base.update(kw)
    return base


def test_cvss_threshold():
    assert not bot.wants(user(), item(cvss=5.0))
    assert bot.wants(user(), item(cvss=9.8))
    assert bot.wants(user(min_cvss=4.0), item(cvss=5.0))  # /severity medium


def test_titles_are_html_escaped():
    assert "<script>" not in bot.fmt(item(title="<script>"))


def test_cves_are_extracted():
    it = collectors.item(
        "Cisco", "a", "Fix for CVE-2026-12345", "u", "see CVE-2026-12345 again"
    )
    assert it["cves"] == ["CVE-2026-12345"]


LONG = (
    "A vulnerability in the web-based management interface of Cisco IOS XR Software "
    "could allow an unauthenticated, remote attacker to execute arbitrary commands. "
    "This vulnerability is due to insufficient validation of user-supplied input."
)


def test_short_title_keeps_what_fits_and_summarises_the_rest():
    assert collectors.short_title("IOS XR flaw.  Fixed.") == "IOS XR flaw. Fixed."
    assert collectors.short_title(LONG) == LONG.split(". ")[0] + "."
    cut = collectors.short_title(LONG, 60)
    assert len(cut) <= 60 and cut.endswith("…") and LONG.startswith(cut[:-1])
    assert not cut[:-1].endswith(" ")
    assert collectors.short_title("x" * 300, 50) == "x" * 49 + "…"  # no space at all
    assert collectors.short_title(None) == ""


@pytest.mark.parametrize(
    "text, cvss, rating",
    [
        ("CVSS v3.1 Base Score: 9.8", 9.8, None),
        ("CVSSv3 Score: 7.5", 7.5, None),
        ("CVSS: 8.1 (High)", 8.1, None),
        ('{"cvss_score": 10.0}', 10.0, None),
        ("CVSS:3.1/AV:N/AC:L/PR:N", None, None),  # a vector, not a score
        ("PAN-OS: DoS in DNS proxy (Severity: HIGH)", None, "high"),  # Palo Alto
        ("Security Impact Rating: Critical", None, "critical"),  # Cisco
        ('{"severity": "moderate"}', None, "medium"),  # JSON text
        ("Important severity update", None, "high"),
        ("A low-severity issue", None, "low"),
        ("Highly available routers", None, None),
        ("FortiOS heap overflow", None, None),
    ],
)
def test_vendor_scores_and_ratings_are_read_from_the_text(text, cvss, rating):
    it = collectors.item("X", "1", "t", "u", text)
    assert (it["cvss"], it["rating"]) == (cvss, rating)


def test_a_given_score_wins_over_the_text():
    it = collectors.item("X", "1", "Severity: Low", "u", cvss=9.1)
    assert (it["cvss"], it["rating"]) == (9.1, None)
    assert collectors.item("X", "1", "Severity: Low", "u", rating="HIGH")["rating"] == (
        "high"
    )
    assert collectors.item("X", "1", "t", "u", rating="n/a")["rating"] is None


def test_unsafe_urls_are_refused():
    assert not collectors.safe_url("http://example.com/feed")  # not https
    assert not collectors.safe_url("https://postgres.railway.internal")  # internal host
    assert not collectors.safe_url("https://localhost/feed")


# ---------- scoring and formatting ----------
@pytest.mark.parametrize(
    "cvss, label",
    [
        (9.0, "🔴 CRITICAL"),
        (8.9, "🟠 HIGH"),
        (7.0, "🟠 HIGH"),
        (6.9, "🟡 MEDIUM"),
        (3.9, "⚪ LOW"),
    ],
)
def test_severity_bands(cvss, label):
    assert bot.severity(item(cvss=cvss)) == label


def test_unscored_advisories_are_sent():
    assert bot.severity(item()) == "🔵 ADVISORY"
    assert bot.wants(user(), item())
    assert bot.wants(user(), item(kev=True, cvss=2.0))


@pytest.mark.parametrize(
    "rating, label, sent_at_high",
    [
        ("critical", "🔴 CRITICAL", True),
        ("high", "🟠 HIGH", True),
        ("medium", "🟡 MEDIUM", False),
        ("low", "⚪ LOW", False),
    ],
)
def test_vendor_ratings_use_the_severity_matrix(rating, label, sent_at_high):
    it = item(rating=rating)
    assert bot.severity(it) == label
    assert bot.wants(user(), it) is sent_at_high  # /severity high
    assert bot.wants(user(min_cvss=0.0), it)
    assert f"<b>{label} · vendor rating</b>" in bot.fmt(it)
    assert bot.wants(user(), item(rating="low", kev=True))  # KEV is always sent


def test_muted_vendors_are_not_sent():
    assert not bot.wants(user(muted=["Cisco"]), item(kev=True))
    assert bot.wants(user(muted=["Nokia"]), item(kev=True))


def test_level_names():
    assert [bot.level_name(x) for x in (9.8, 7.0, 4.0, 0.0)] == [
        "critical",
        "high",
        "medium",
        "low",
    ]


def test_fmt_contains_fields():
    text = bot.fmt(
        item(cvss=9.8, cves=["CVE-2026-1", "CVE-2026-2"], url="https://x/a&b")
    )
    assert "CVSS 9.8" in text
    assert "CVE-2026-1, CVE-2026-2" in text
    assert "https://x/a&amp;b" in text
    assert "<b>CVE:</b> —" in bot.fmt(item())


# ---------- logging ----------
def test_request_urls_with_the_bot_token_are_not_logged():
    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)


def test_info_goes_to_stdout_and_warnings_to_stderr(capsys):
    handlers = bot.log_handlers()  # bound to the captured streams
    for level, msg in ((logging.INFO, "cycle ok"), (logging.WARNING, "source down")):
        record = logging.LogRecord("telco-watch", level, __file__, 1, msg, None, None)
        for h in handlers:
            if record.levelno >= h.level and h.filter(record):
                h.handle(record)
    out, err = capsys.readouterr()
    assert "cycle ok" in out and "source down" not in out
    assert "source down" in err and "cycle ok" not in err


# ---------- URL safety ----------
def test_private_addresses_are_refused(monkeypatch):
    def fake_getaddrinfo(host, port):
        ip = {"public.example": "93.184.216.34", "private.example": "10.0.0.5"}[host]
        return [(None, None, None, "", (ip, port))]

    monkeypatch.setattr(collectors.socket, "getaddrinfo", fake_getaddrinfo)
    assert collectors.safe_url("https://public.example/feed")
    assert not collectors.safe_url("https://private.example/feed")
    assert not collectors.safe_url("ftp://public.example/feed")
    assert not collectors.safe_url("")


def test_guard_blocks_requests_and_redirects():
    request = httpx.Request("GET", "https://postgres.railway.internal/x")
    with pytest.raises(httpx.RequestError):
        run(collectors._guard(request))


# ---------- vendor-specific collectors ----------
RSS = """<?xml version="1.0"?><rss version="2.0"><channel><title>PSIRT</title>
<item><title>FortiOS RCE CVE-2026-11111</title><link>https://vendor.example/a1</link>
<guid>FG-IR-26-001</guid><description>Fixes CVE-2026-22222</description>
<pubDate>Thu, 22 Oct 2026 09:14:00 GMT</pubDate></item>
</channel></rss>"""


def test_fetch_rss():
    client = mock_client(lambda r: httpx.Response(200, text=RSS))
    src = {
        "vendor": "Fortinet",
        "type": "rss",
        "url": "https://vendor.example/rss",
        "config": {},
    }
    [it] = run(collectors.fetch_rss(client, src))
    assert it["vendor"] == "Fortinet"
    assert it["id"] == "FG-IR-26-001"
    assert it["url"] == "https://vendor.example/a1"
    assert it["cves"] == ["CVE-2026-11111", "CVE-2026-22222"]
    assert "2026" in it["published"]
    assert it["updated"] == ""  # an RSS item without an update date gets none


def test_fetch_atom_reads_the_update_date():
    atom = (
        '<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>a</id><title>t</title>'
        "<published>2026-10-01T09:00:00Z</published>"
        "<updated>2026-10-23T09:00:00Z</updated></entry></feed>"
    )
    client = mock_client(lambda r: httpx.Response(200, text=atom))
    src = {"vendor": "X", "type": "rss", "url": "https://x.example/", "config": {}}
    [it] = run(collectors.fetch_rss(client, src))
    assert it["published"].startswith("2026-10-01")
    assert it["updated"].startswith("2026-10-23")


def test_fetch_json():
    payload = {
        "data": {
            "advisories": [{"key": "PAN-1", "name": "GlobalProtect CVE-2026-3333"}]
        }
    }
    client = mock_client(lambda r: httpx.Response(200, json=payload))
    src = {
        "vendor": "Palo Alto Networks",
        "type": "json",
        "url": "https://vendor.example/api",
        "config": {"list": "data.advisories", "id": "key", "title": "name"},
    }
    [it] = run(collectors.fetch_json(client, src))
    assert it["id"] == "PAN-1"
    assert (
        it["url"] == "https://vendor.example/api"
    )  # no url field: falls back to the source
    assert it["cves"] == ["CVE-2026-3333"]


def test_fetch_json_reads_the_severity_field():
    payload = [{"ghsa_id": "GHSA-1", "summary": "Heap overflow", "level": "Moderate"}]
    client = mock_client(lambda r: httpx.Response(200, json=payload))
    cfg = {"id": "ghsa_id", "title": "summary", "severity": "level"}
    src = {"vendor": "PHP", "type": "json", "url": "https://x.example/", "config": cfg}
    [it] = run(collectors.fetch_json(client, src))
    assert (it["cvss"], it["rating"]) == (None, "medium")


HTML = """<table>
<tr class="adv"><td><a href="/sa/1">Zyxel firewall advisory</a></td><td>CVE-2026-4444</td></tr>
<tr class="adv"><td>row without a link</td></tr>
</table>"""


def test_fetch_html_resolves_links_and_skips_rows_without_link():
    client = mock_client(lambda r: httpx.Response(200, text=HTML))
    src = {
        "vendor": "Zyxel",
        "type": "html",
        "url": "https://vendor.example/advisories",
        "config": {"item": "tr.adv", "link": "a[href]"},
    }
    [it] = run(collectors.fetch_html(client, src))
    assert it["url"] == "https://vendor.example/sa/1"
    assert it["cves"] == ["CVE-2026-4444"]


def test_fetch_errors_raise():
    client = mock_client(lambda r: httpx.Response(500))
    src = {
        "vendor": "X",
        "type": "rss",
        "url": "https://vendor.example/rss",
        "config": {},
    }
    with pytest.raises(httpx.HTTPStatusError):
        run(collectors.fetch_rss(client, src))


# ---------- global collectors ----------
VENDORS = [
    {"name": "Cisco", "nvd_keyword": "Cisco"},
    {"name": "Palo Alto Networks", "nvd_keyword": "Palo Alto"},
]


def test_fetch_kev_keeps_only_in_scope_vendors():
    kev = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Palo Alto Networks",
                "product": "PAN-OS",
                "vulnerabilityName": "PAN-OS command injection",
                "dateAdded": "2026-10-20",
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "SomeoneElse",
                "product": "Thing",
                "vulnerabilityName": "Unrelated",
                "dateAdded": "2026-10-20",
            },
        ]
    }
    client = mock_client(lambda r: httpx.Response(200, json=kev))
    [it] = run(collectors.fetch_kev(client, VENDORS))
    assert it["vendor"] == "Palo Alto Networks"
    assert it["id"] == "KEV-CVE-2026-0001"
    assert it["kev"] and it["cves"] == ["CVE-2026-0001"]


def test_kev_keywords_match_whole_words_in_vendor_or_product():
    assert collectors.kev_matches("PHP", "PHP PHP")
    assert collectors.kev_matches("php", "The PHP Group PHP-FPM")
    assert not collectors.kev_matches("PHP", "phpMyAdmin phpMyAdmin")
    assert collectors.kev_matches("Palo Alto", "Palo Alto Networks PAN-OS")
    assert collectors.kev_matches("Kubernetes", "Kubernetes Ingress-nginx")
    assert not collectors.kev_matches("ZTE", "Aztec Router")


def test_fetch_nvd_uses_the_cpe_when_there_is_one(monkeypatch):
    async def no_sleep(s):
        return None

    monkeypatch.setattr(collectors.asyncio, "sleep", no_sleep)
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"vulnerabilities": []})

    vendors = [
        {"name": "PHP", "nvd_keyword": "PHP", "nvd_cpe": "cpe:2.3:a:php:php"},
        {"name": "Cisco", "nvd_keyword": "Cisco", "nvd_cpe": None},
    ]
    since = datetime(2026, 10, 22, tzinfo=UTC)
    run(collectors.fetch_nvd(mock_client(handler), vendors, since))
    assert seen[0]["virtualMatchString"] == "cpe:2.3:a:php:php"
    assert "keywordSearch" not in seen[0]
    assert seen[1]["keywordSearch"] == "Cisco" and "virtualMatchString" not in seen[1]


def test_fetch_nvd_reads_best_cvss_and_queries_since(monkeypatch):
    async def no_sleep(s):
        return None

    monkeypatch.setattr(collectors.asyncio, "sleep", no_sleep)
    seen = []
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-5555",
                    "published": "2026-10-22T09:14:00.000",
                    "lastModified": "2026-10-23T07:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Cisco IOS XR flaw"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                }
            }
        ]
    }

    def handler(request):
        seen.append(request.url.params)
        return httpx.Response(200, json=nvd)

    since = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
    out = run(collectors.fetch_nvd(mock_client(handler), VENDORS[:1], since))
    assert [it["cvss"] for it in out] == [9.8]
    assert out[0]["title"] == "Cisco IOS XR flaw"
    assert out[0]["updated"] == "2026-10-23T07:00:00.000"
    assert seen[0]["keywordSearch"] == "Cisco"
    assert seen[0]["lastModStartDate"].startswith("2026-10-22T08:00:00.000")


# ---------- storage and the hourly cycle ----------
class FakeDB:
    """In-memory stand-in for db.py, enough for store() and cycle()."""

    def __init__(self, state=None):
        self.state = dict(state or {})
        self.keys = set()

    def q(self, sql, params=(), one=False):
        if sql.startswith("INSERT INTO items"):
            if params[0] in self.keys:
                return None
            self.keys.add(params[0])
            return {"key": params[0]}
        if "FROM vendors" in sql and "JOIN" not in sql:
            return VENDORS
        return []

    def get_state(self, k):
        return self.state.get(k)

    def set_state(self, k, v):
        self.state[k] = v


def test_store_deduplicates(monkeypatch):
    monkeypatch.setattr(bot, "db", FakeDB())
    assert bot.store(item(id="a"))
    assert not bot.store(item(id="a"))
    assert bot.store(item(id="a", vendor="Nokia"))


class FakeBot:
    def __init__(self):
        self.sent = []
        self.menus = {}  # chat id -> command names, None once deleted

    async def send_message(self, chat, text, **kw):
        self.sent.append((chat, text))

    async def set_my_commands(self, commands, scope=None):
        self.menus[scope and scope.chat_id] = [c.command for c in commands]

    async def delete_my_commands(self, scope=None):
        self.menus[scope.chat_id] = None


def run_cycle(monkeypatch, fake_db, kev_items, nvd_error=None, users=None):
    async def kev(client, vendors):
        return kev_items

    async def nvd(client, vendors, since):
        if nvd_error:
            raise nvd_error
        return []

    async def no_sleep(s):
        return None

    monkeypatch.setattr(bot, "db", fake_db)
    monkeypatch.setattr(bot, "active_users", lambda: users or [])
    monkeypatch.setattr(bot.col, "fetch_kev", kev)
    monkeypatch.setattr(bot.col, "fetch_nvd", nvd)
    monkeypatch.setattr(bot.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(bot, "http", lambda: mock_client(lambda r: httpx.Response(200)))
    fake_bot = FakeBot()
    run(bot.cycle(SimpleNamespace(bot=fake_bot)))
    return fake_bot.sent


def test_first_run_stores_backlog_and_sends_nothing(monkeypatch):
    fake_db = FakeDB()
    sent = run_cycle(monkeypatch, fake_db, [item(kev=True)])
    assert sent == []
    assert len(fake_db.keys) == 1
    assert "last_run" in fake_db.state


def test_new_items_are_sent_once_and_failures_reported(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {1})
    users = [
        user(chat_id=1),
        user(chat_id=2, min_cvss=0.0),
        user(chat_id=3, muted=["Cisco"]),
    ]
    fake_db = FakeDB({"last_run": "2026-10-22T08:00:00+00:00"})
    items = [item(id="k", kev=True), item(id="low", cvss=2.0)]
    sent = run_cycle(
        monkeypatch, fake_db, items, nvd_error=RuntimeError("down"), users=users
    )
    alerts = [
        (chat, "KEV" in text) for chat, text in sent if "Sources failed" not in text
    ]
    # KEV goes to 1 and 2 (3 muted Cisco); the low one only to 2 (/severity low).
    assert alerts == [(1, True), (2, True), (2, False)]
    # Only admins hear about failing sources.
    assert [chat for chat, text in sent if "Sources failed" in text] == [1]
    assert "failed: NVD" in fake_db.state["last_status"]
    # The same advisory is never sent twice.
    assert run_cycle(monkeypatch, fake_db, items, users=users) == []


def test_old_advisories_changed_by_their_source_are_one_line_updates(monkeypatch):
    fake_db = FakeDB({"last_run": (datetime.now(UTC) - timedelta(hours=1)).isoformat()})
    items = [
        item(id="new", cvss=9.8, title="Fresh flaw", published=ago(0.1)),
        item(
            id="old",
            cvss=9.8,
            cves=["CVE-2019-1"],
            title=LONG,
            published="2019-03-12T10:00:00.000",
            updated="2026-01-15T09:14:00.000",
        ),
    ]
    sent = [text for _, text in run_cycle(monkeypatch, fake_db, items, users=[user()])]
    assert sent[0].startswith("<b>🔴 CRITICAL") and "Fresh flaw" in sent[0]
    line, url = sent[1].split("\n")
    assert line.startswith(
        "🔄 <b>Update</b> · 🔴 CRITICAL · CVSS 9.8 · Cisco · CVE-2019-1"
    )
    assert "published 12-03-2019 11:00 CET" in line
    assert line.endswith("· last updated 15-01-2026 10:14 CET") and url == "u"


def test_update_lines_still_follow_the_user_settings(monkeypatch):
    fake_db = FakeDB({"last_run": (datetime.now(UTC) - timedelta(hours=1)).isoformat()})
    old = [item(id="o", cvss=5.0, published="2019-03-12")]
    assert run_cycle(monkeypatch, fake_db, old, users=[user()]) == []  # below /severity


def test_store_keeps_the_parsed_dates(monkeypatch):
    calls = []

    def q(sql, params=(), one=False):
        calls.append(params)
        return {"key": params[0]}

    monkeypatch.setattr(bot, "db", SimpleNamespace(q=q))
    it = item(published="Thu, 22 Oct 2026 09:14:00 GMT", updated="2026-10-23")
    bot.store(it)
    assert calls[0][-2:] == (
        datetime(2026, 10, 22, 9, 14, tzinfo=UTC),
        datetime(2026, 10, 23, tzinfo=UTC),
    )
    bot.store(item(published="soon"))  # no date: collection time, no update date
    assert calls[1][-1] is None and calls[1][-2] > datetime.now(UTC) - timedelta(1)


def test_backfill_parses_the_dates_of_older_rows(monkeypatch):
    seen = datetime(2026, 10, 1, tzinfo=UTC)
    rows = [{"key": "a", "published": "2026-09-30", "seen_at": seen}]
    rows.append({"key": "b", "published": "", "seen_at": seen})
    updates = []

    def q(sql, params=(), one=False):
        if sql.startswith("SELECT"):
            assert "published_at IS NULL" in sql
            return rows
        updates.append(params)

    monkeypatch.setattr(bot, "db", SimpleNamespace(q=q))
    bot.backfill_dates()
    assert updates == [(datetime(2026, 9, 30, tzinfo=UTC), "a"), (seen, "b")]


def test_a_user_who_blocked_the_bot_does_not_stop_the_others():
    class Bot(FakeBot):
        async def send_message(self, chat, text, **kw):
            if chat == 1:
                raise bot.TelegramError("Forbidden: bot was blocked by the user")
            await super().send_message(chat, text, **kw)

    fake_bot = Bot()
    assert not run(bot.send(fake_bot, 1, "x"))
    assert run(bot.send(fake_bot, 2, "x"))
    assert fake_bot.sent == [(2, "x")]


# ---------- commands ----------
class FakeMessage:
    def __init__(self):
        self.replies = []

    async def reply_text(self, text, **kw):
        self.replies.append(text)


def update(user_id, name="Ana"):
    msg = FakeMessage()
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id, full_name=name),
        effective_message=msg,
        message=msg,
    )


class FakeUsers:
    """In-memory users table behind bot's user functions."""

    def __init__(self, monkeypatch, *rows):
        self.rows = {r["chat_id"]: dict(r) for r in rows}
        for name in (
            "get_user",
            "save_user",
            "decide_user",
            "set_user_status",
            "set_role",
            "promoted_admins",
            "set_min_cvss",
            "set_muted",
            "find_vendor",
        ):
            monkeypatch.setattr(bot, name, getattr(self, name))

    def get_user(self, uid):
        return self.rows.get(uid)

    def save_user(self, uid, name, status):
        row = self.rows.setdefault(uid, user(chat_id=uid))
        row.update(name=name, status=status)

    def decide_user(self, uid, status, admin_id):
        row = self.rows.get(uid)
        if not row or row["status"] != "pending":
            return None
        row["status"] = status
        return row

    def set_user_status(self, uid, status, admin_id):
        row = self.rows.get(uid)
        if row:
            row["status"] = status
            if status != "active":
                row["role"] = "user"
        return row

    def set_role(self, uid, role):
        row = self.rows.get(uid)
        if not row or row["status"] != "active":
            return None
        row["role"] = role
        return row

    def promoted_admins(self):
        return [
            r
            for r in self.rows.values()
            if r.get("role") == "admin" and r["status"] == "active"
        ]

    def set_min_cvss(self, uid, score):
        self.rows[uid]["min_cvss"] = score

    def set_muted(self, uid, vendor, muted):
        rest = [v for v in self.rows[uid]["muted"] if v != vendor]
        self.rows[uid]["muted"] = rest + [vendor] if muted else rest

    def find_vendor(self, name):
        return {"name": "Cisco"} if name.lower() == "cisco" else None


def ctx(args=(), fake_bot=None):
    return SimpleNamespace(args=list(args), bot=fake_bot or FakeBot())


def test_new_user_request_goes_to_the_admins(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch)
    c = ctx()
    u = update(7, "Bob")
    run(bot.start(u, c))
    assert users.rows[7]["status"] == "pending"
    assert c.bot.sent == [(42, "Access request from Bob (id 7).")]
    assert "sent to the admins" in u.message.replies[0]
    # Asking again does not notify the admins a second time.
    run(bot.start(update(7, "Bob"), c))
    assert len(c.bot.sent) == 1


def test_admins_are_active_without_approval(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch)
    u = update(42)
    run(bot.start(u, ctx()))
    assert users.rows[42]["status"] == "active"
    assert "/adduser" in u.message.replies[0]  # admins see the admin commands


def test_members_see_help_and_removed_users_get_no_answer(monkeypatch):
    FakeUsers(monkeypatch, user(chat_id=1), user(chat_id=2, status="blocked"))
    member, removed = update(1), update(2)
    run(bot.start(member, ctx()))
    run(bot.start(removed, ctx()))
    assert member.message.replies == [bot.HELP]
    assert removed.message.replies == []


def test_commands_need_access(monkeypatch):
    FakeUsers(monkeypatch, user(chat_id=7, status="pending"))
    for cmd in (
        bot.status,
        bot.latest,
        bot.vendors_cmd,
        bot.ask_cmd,
        bot.severity_cmd,
        bot.mute,
    ):
        u = update(7)
        run(cmd(u, ctx()))
        assert u.message.replies == [
            "You don't have access yet: send /start to request it."
        ]


def test_approve_button_activates_and_tells_the_user(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch, user(chat_id=7, status="pending"))
    edits = []

    async def answer(*a, **kw):
        return None

    async def edit(text):
        edits.append(text)

    qy = SimpleNamespace(
        from_user=SimpleNamespace(id=42, first_name="Admin"),
        answer=answer,
        edit_message_text=edit,
        message=SimpleNamespace(text="Access request from Bob (id 7)."),
        data="uok:7",
    )
    c = ctx()
    run(bot.on_button(SimpleNamespace(callback_query=qy), c))
    assert users.rows[7]["status"] == "active"
    assert edits[-1].endswith("Approved by Admin.")
    assert c.bot.sent[0][0] == 7 and "approved" in c.bot.sent[0][1]
    # A second tap (or another admin) cannot decide again.
    run(bot.on_button(SimpleNamespace(callback_query=qy), c))
    assert edits[-1].endswith("Already decided.")


def test_severity_and_mute_are_personal(monkeypatch):
    users = FakeUsers(monkeypatch, user(chat_id=1), user(chat_id=2))
    run(bot.severity_cmd(update(1), ctx(["medium"])))
    run(bot.mute(update(1), ctx(["cisco"])))
    assert users.rows[1]["min_cvss"] == 4.0 and users.rows[1]["muted"] == ["Cisco"]
    assert users.rows[2]["min_cvss"] == 7.0 and users.rows[2]["muted"] == []
    run(bot.unmute(update(1), ctx(["Cisco"])))
    assert users.rows[1]["muted"] == []
    u = update(1)
    run(bot.mute(u, ctx(["Unknown"])))
    assert u.message.replies == ["Unknown vendor, see /vendors."]


def test_admins_add_and_remove_users(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch, user(chat_id=7, name="Bob"))
    run(bot.removeuser(update(42), ctx(["7"])))
    assert users.rows[7]["status"] == "blocked"
    c = ctx(["8"])
    run(bot.adduser(update(42), c))
    assert users.rows[8]["status"] == "active" and c.bot.sent[0][0] == 8
    u = update(7)
    run(bot.adduser(u, ctx(["9"])))
    assert u.message.replies == ["Admins only."]


def test_admin_commands_refuse_non_admins(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    FakeUsers(monkeypatch, user(chat_id=7))
    for cmd in (bot.checknow, bot.addvendor, bot.removevendor):
        u = update(7)
        run(cmd(u, SimpleNamespace(args=["Zyxel"])))
        assert u.message.replies == ["Admins only."]


def test_approve_button_refuses_non_admins(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    FakeUsers(monkeypatch)
    answers = []

    async def answer(text=None, show_alert=False):
        answers.append(text)

    qy = SimpleNamespace(from_user=SimpleNamespace(id=7), answer=answer, data="add:x")
    run(bot.on_button(SimpleNamespace(callback_query=qy), None))
    assert answers == ["Admins only."]


def test_ask_requires_a_question(monkeypatch):
    FakeUsers(monkeypatch, user(chat_id=1))
    u = update(1)
    run(bot.ask_cmd(u, SimpleNamespace(args=[])))
    assert u.message.replies[0].startswith("Usage: /ask")


def test_help_and_health_are_commands():
    assert bot.COMMANDS["help"] is bot.start
    assert bot.COMMANDS["health"] is bot.status


def test_commands_only_work_in_private_chats():
    assert bot.PRIVATE is bot.filters.ChatType.PRIVATE


def test_failed_command_replies_to_the_user(monkeypatch):
    monkeypatch.setattr(bot, "Update", SimpleNamespace)  # what update() builds
    u = update(1)
    run(bot.on_error(u, SimpleNamespace(error=RuntimeError("db down"))))
    assert u.message.replies == ["Something went wrong; try again in a moment."]


def test_pools_check_connections_before_use():
    assert bot.db.pool._check is bot.db.CHECK
    assert bot.db.ro_pool._check is bot.db.CHECK


@pytest.mark.parametrize(
    "published, expected",
    [
        ("2026-10-22T09:14:00.000", datetime(2026, 10, 22, 9, 14, tzinfo=UTC)),  # NVD
        ("2026-10-20", datetime(2026, 10, 20, tzinfo=UTC)),  # KEV
        (
            "Thu, 22 Oct 2026 09:14:00 GMT",
            datetime(2026, 10, 22, 9, 14, tzinfo=UTC),
        ),  # RSS
        ("", datetime(2026, 10, 1, tzinfo=UTC)),  # HTML page: no date, use seen_at
        ("next week", datetime(2026, 10, 1, tzinfo=UTC)),
    ],
)
def test_published_at_reads_every_source_format(published, expected):
    it = item(published=published, seen_at=datetime(2026, 10, 1, tzinfo=UTC))
    assert bot.published_at(it) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-01-15T09:14:00.000", "15-01-2026 10:14 CET"),  # NVD, UTC, winter
        ("Thu, 22 Oct 2026 09:14:00 GMT", "22-10-2026 11:14 CEST"),  # RSS, summer
        ("2026-10-22T09:14:00-07:00", "22-10-2026 18:14 CEST"),  # any offset
        (datetime(2026, 10, 27, 8, 5, tzinfo=UTC), "27-10-2026 09:05 CET"),
        ("2026-10-20", "20-10-2026"),  # KEV: a date without a time stays a date
        ("next week", "next week"),  # unreadable: shown as given
        ("", ""),
    ],
)
def test_dates_are_shown_in_paris_time(value, expected):
    assert bot.when(value) == expected


def test_alerts_and_status_use_paris_time(monkeypatch):
    assert "<b>Published:</b> 20-10-2026\n" in bot.fmt(item(published="2026-10-20"))
    fake_db = FakeDB({"last_run": "2026-10-22T08:00:00+00:00"})
    run_cycle(monkeypatch, fake_db, [])
    assert fake_db.state["last_status"].split(" · ")[0].endswith(("CET", "CEST"))


def ago(days):
    return (datetime.now(UTC) - timedelta(days=days)).isoformat()


def stored(**kw):
    """An item as read back from the database, with its parsed publication date."""
    it = item(**kw)
    it["published_at"] = bot.published_at(it)
    return it


def run_latest_all(monkeypatch, rows, args):
    calls = []

    def q(sql, params=(), one=False):
        calls.append((sql, params))
        return rows

    FakeUsers(monkeypatch, user(chat_id=1))
    monkeypatch.setattr(bot.db, "q", q)
    u = update(1)
    run(bot.latest(u, ctx(args)))
    return u.message.replies, calls


def test_latest_all_lists_high_and_above_by_publication_date(monkeypatch):
    now = datetime.now(UTC)
    rows = [
        stored(id="a", vendor="Nokia", cvss=7.5, published=ago(2), seen_at=now),
        stored(id="b", vendor="Cisco", cvss=9.8, published=ago(1), seen_at=now),
        stored(
            id="c",
            vendor="ZTE",
            kev=True,
            cvss=None,
            cves=["CVE-2026-9"],
            published=ago(3),
            seen_at=now,
        ),
        stored(
            id="pan",
            vendor="Palo Alto Networks",
            rating="critical",
            published=ago(1),
            seen_at=now,
        ),
        stored(
            id="adv",
            vendor="Fortinet",
            title="FortiOS advisory",
            published=ago(1),
            seen_at=now,
        ),
    ]
    replies, calls = run_latest_all(monkeypatch, rows, ["all", "5"])
    sql, params = calls[0]
    assert "kev OR cvss >= %s" in sql and params == (7.0, 5)
    assert "published_at >= now()" in sql  # an old item stored today is left out
    text = "\n\n".join(replies)
    assert text.startswith("High and above, all vendors, last 5 days: 4")
    assert "rating IN ('critical', 'high')" in sql
    # KEV first, then by score; a vendor's critical rating counts as 9.0.
    assert text.index("ZTE") < text.index("Cisco") < text.index("Palo Alto")
    assert text.index("Palo Alto") < text.index("Nokia")
    assert "🔴 CRITICAL · vendor rating · Palo Alto Networks" in text
    assert "without a score or rating: 1" in text and "FortiOS advisory" in text


def test_latest_all_defaults_to_7_days_and_caps_at_90(monkeypatch):
    _, calls = run_latest_all(monkeypatch, [], ["all"])
    assert calls[0][1] == (7.0, 7)
    replies, calls = run_latest_all(monkeypatch, [], ["ALL", "365"])
    assert calls[0][1] == (7.0, 90)
    assert replies == ["No high or critical alert in the last 90 days."]


def test_latest_all_splits_long_lists_and_caps_them(monkeypatch):
    now = datetime.now(UTC)
    rows = [
        stored(
            id=str(i),
            cvss=9.0,
            title="x" * 100,
            url="https://e.example/" + "y" * 60,
            published=ago(1),
            seen_at=now,
        )
        for i in range(60)
    ]
    replies, _ = run_latest_all(monkeypatch, rows, ["all", "3"])
    assert len(replies) > 1 and all(len(r) <= 4000 for r in replies)
    assert replies[-1].endswith("…and 20 more: try a shorter period or /ask.")


def test_brief_names_the_cves_or_nothing():
    assert bot.brief(item(cvss=9.8, cves=["CVE-2026-1"])).startswith(
        "🔴 CRITICAL · CVSS 9.8 · Cisco · CVE-2026-1\n"
    )
    assert bot.brief(item()).startswith("🔵 ADVISORY · Cisco\n")


def test_brief_shortens_long_titles_at_a_word():
    title = bot.brief(item(title=LONG)).split("\n")[1]
    assert len(title) <= 120 and title.endswith("…")
    assert LONG.startswith(title[:-1]) and LONG[len(title) - 1] == " "  # whole words


def test_latest_with_a_vendor_still_works(monkeypatch):
    _, calls = run_latest_all(monkeypatch, [], ["Cisco", "3"])
    assert "vendor ILIKE" in calls[0][0] and calls[0][1] == ["%Cisco%", 3]
    assert "ORDER BY published_at DESC" in calls[0][0]  # not by collection time


def test_menu_lists_real_commands_and_admin_ones_only_for_admins():
    names = [n for n, _ in bot.OWNER_MENU]
    assert set(names) <= set(bot.COMMANDS) and len(names) == len(set(names))
    assert set(bot.COMMANDS) - set(names) == {"health"}  # alias, kept out of the menu
    user_menu = {n for n, _ in bot.MENU}
    assert {"checknow", "addvendor", "users"}.isdisjoint(user_menu)
    admin_menu = {n for n, _ in bot.ADMIN_MENU}
    assert "users" in admin_menu and {"promote", "demote"}.isdisjoint(admin_menu)


def test_set_menu_sets_the_admin_menu_per_admin_chat(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42, 43})
    FakeUsers(monkeypatch, user(chat_id=44, role="admin"), user(chat_id=45))
    calls = []

    async def set_my_commands(commands, scope=None):
        if scope is not None and scope.chat_id == 43:
            raise bot.TelegramError("Bad Request: chat not found")
        calls.append(([c.command for c in commands], scope and scope.chat_id))

    app = SimpleNamespace(bot=SimpleNamespace(set_my_commands=set_my_commands))
    run(bot.set_menu(app))  # one admin failing does not stop the others
    assert calls[0] == ([n for n, _ in bot.MENU], None)
    assert calls[1] == ([n for n, _ in bot.OWNER_MENU], 42)  # permanent admin
    assert calls[2] == ([n for n, _ in bot.ADMIN_MENU], 44)  # promoted admin
    assert len(calls) == 3


def test_backfill_rates_stored_items_from_their_title(monkeypatch):
    rows = [
        {"key": "a", "title": "PAN-OS: DoS in DNS proxy (Severity: CRITICAL)"},
        {"key": "b", "title": "Router flaw, CVSS v3.1 Base Score: 8.6"},
        {"key": "c", "title": "FortiOS heap overflow"},  # nothing to read: untouched
        {"key": "d", "title": None},
    ]
    updates = []

    def q(sql, params=(), one=False):
        if sql.startswith("SELECT"):
            assert "cvss IS NULL AND rating IS NULL" in sql
            return rows
        updates.append(params)

    monkeypatch.setattr(bot, "db", SimpleNamespace(q=q))
    bot.backfill_ratings()
    assert updates == [(None, "critical", "a"), (8.6, None, "b")]


def test_permanent_admins_promote_and_demote(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(
        monkeypatch, user(chat_id=7, name="Bob"), user(chat_id=8, status="pending")
    )
    c = ctx(["7"])
    run(bot.promote(update(42), c))
    assert users.rows[7]["role"] == "admin"
    assert c.bot.menus[7] == [n for n, _ in bot.ADMIN_MENU]
    assert c.bot.sent[0][0] == 7 and c.bot.sent[0][1].startswith("You are now an admin")
    assert "/checknow" in c.bot.sent[0][1] and "/promote" not in c.bot.sent[0][1]
    # A promoted admin has the admin commands and buttons...
    assert bot.is_admin(7) and 7 in bot.admin_ids()
    assert "/promote" in bot.help_text(42) and "/promote" not in bot.help_text(7)
    # ...but cannot promote or demote.
    for cmd in (bot.promote, bot.demote):
        u = update(7)
        run(cmd(u, ctx(["8"])))
        assert u.message.replies == [
            "Only the permanent admins (ADMIN_USER_IDS) can do this."
        ]
    c = ctx(["7"])
    run(bot.demote(update(42), c))
    assert users.rows[7]["role"] == "user" and not bot.is_admin(7)
    assert c.bot.menus[7] is None and c.bot.sent[0] == (
        7,
        "You are no longer an admin.",
    )


def test_promote_refuses_unknown_inactive_and_permanent_admins(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch, user(chat_id=8, status="pending"))
    for arg, reply in (
        ("8", "Unknown or inactive user, see /users."),
        ("9", "Unknown or inactive user, see /users."),
        (
            "42",
            "42 is a permanent admin (ADMIN_USER_IDS); change that variable instead.",
        ),
        ("bob", "Usage: give the user id shown by /users."),
    ):
        u = update(42)
        run(bot.demote(u, ctx([arg])) if arg == "42" else bot.promote(u, ctx([arg])))
        assert u.message.replies == [reply]
    assert "role" not in users.rows[8]


def test_promoted_admins_get_requests_and_failure_notices(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    FakeUsers(monkeypatch, user(chat_id=7, role="admin"))
    c = ctx()
    run(bot.start(update(9, "Eve"), c))
    assert sorted(chat for chat, _ in c.bot.sent) == [7, 42]
    fake_db = FakeDB({"last_run": "2026-10-22T08:00:00+00:00"})
    users = [user(chat_id=7, role="admin"), user(chat_id=8)]
    sent = run_cycle(monkeypatch, fake_db, [], nvd_error=RuntimeError("x"), users=users)
    assert [chat for chat, text in sent if "Sources failed" in text] == [7]


def test_removing_a_promoted_admin_takes_the_role_and_menu(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    users = FakeUsers(monkeypatch, user(chat_id=7, role="admin"), user(chat_id=8))
    c = ctx(["7"])
    run(bot.removeuser(update(42), c))
    assert users.rows[7]["role"] == "user" and c.bot.menus == {7: None}
    c = ctx(["8"])
    run(bot.removeuser(update(42), c))
    assert c.bot.menus == {}  # not an admin: the menu is left alone


def test_users_marks_admins(monkeypatch):
    monkeypatch.setattr(bot, "ADMINS", {42})
    FakeUsers(monkeypatch)
    rows = [
        {"chat_id": 42, "name": "Ann", "status": "active", "role": "user"},
        {"chat_id": 7, "name": "Bob", "status": "active", "role": "admin"},
        {"chat_id": 8, "name": "Cy", "status": "active", "role": "user"},
    ]
    monkeypatch.setattr(bot.db, "q", lambda sql, params=(), one=False: rows)
    u = update(42)
    run(bot.users_cmd(u, ctx()))
    assert u.message.replies == [
        "active: Ann (id 42) · admin\nactive: Bob (id 7) · admin\nactive: Cy (id 8)"
    ]


class FakePoolConn:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, stmt, params=()):
        self.log.append(stmt.as_string(None))


def run_ensure_ro(monkeypatch, rw, ro, exists=False):
    log = []
    monkeypatch.setattr(
        bot.db,
        "pool",
        SimpleNamespace(conninfo=rw, connection=lambda: FakePoolConn(log)),
    )
    monkeypatch.setattr(bot.db, "ro_pool", SimpleNamespace(conninfo=ro))
    monkeypatch.setattr(
        bot.db, "q", lambda *a, **k: {"?column?": 1} if exists else None
    )
    bot.db.ensure_ro_role()
    return log


RW = "postgresql://postgres:secret@db.internal:5432/railway"


def test_read_only_role_is_created_with_select_on_alerts_only(monkeypatch):
    log = run_ensure_ro(
        monkeypatch, RW, "postgresql://ask_ro:p%27w@db.internal:5432/railway"
    )
    assert log == [
        "CREATE ROLE \"ask_ro\" LOGIN PASSWORD 'p''w'",  # quoted, not interpolated
        'GRANT CONNECT ON DATABASE "railway" TO "ask_ro"',
        'GRANT USAGE ON SCHEMA public TO "ask_ro"',
        'GRANT SELECT ON items, vendors TO "ask_ro"',
    ]


def test_read_only_role_password_follows_the_variable(monkeypatch):
    log = run_ensure_ro(
        monkeypatch, RW, "postgresql://ask_ro:new@db.internal/railway", exists=True
    )
    assert log[0] == "ALTER ROLE \"ask_ro\" LOGIN PASSWORD 'new'"


def test_no_role_when_both_urls_use_the_same_account(monkeypatch):
    assert run_ensure_ro(monkeypatch, RW, RW) == []
    assert (
        run_ensure_ro(monkeypatch, RW, "postgresql://ask_ro@db.internal/railway") == []
    )


# ---------- /ask tools (section 5) ----------
def test_search_alerts_is_parameterised(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.db, "q_ro", lambda sql, p=(): calls.append((sql, p)) or [])
    llm.search_alerts(
        vendor="Cisco'; DROP TABLE items;--", since_hours=48, min_cvss=7, limit=99
    )
    sql, params = calls[0]
    assert "DROP" not in sql
    assert params == [
        "%Cisco'; DROP TABLE items;--%",
        48,
        7.0,
        25,
    ]  # limit capped at 25


def test_search_alerts_filters(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.db, "q_ro", lambda sql, p=(): calls.append((sql, p)) or [])
    llm.search_alerts(kev_only=True, cve="cve-2026-12345", text="IOS XR")
    sql, params = calls[0]
    assert " kev " in sql and "ANY(cves)" in sql and "title ILIKE" in sql
    assert params == ["CVE-2026-12345", "%IOS XR%", 10]


def test_alert_stats_groups(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.db, "q_ro", lambda sql, p=(): calls.append((sql, p)) or [])
    llm.alert_stats("vendor", since_hours=168)
    llm.alert_stats("severity")
    assert calls[0][0].startswith("SELECT vendor AS grp") and calls[0][1] == [168]
    assert "CASE WHEN" in calls[1][0] and calls[1][1] == []


def test_ask_counts_vendor_ratings_in_their_level(monkeypatch):
    calls = []
    monkeypatch.setattr(llm.db, "q_ro", lambda sql, p=(): calls.append((sql, p)) or [])
    llm.search_alerts(min_cvss=7)
    assert "COALESCE(cvss, CASE rating WHEN 'critical' THEN 9" in calls[0][0]
    assert "rating" in llm.COLS and "rating" in llm.SEV


def test_tools_match_functions():
    assert {t["name"] for t in llm.TOOLS} == set(llm.FUNCS)


def block(type, **kw):
    return SimpleNamespace(type=type, **kw)


class FakeMessages:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def create(self, **kw):
        self.calls.append(kw)
        return self.responses.pop(0)


def test_ask_runs_tool_then_answers(monkeypatch):
    monkeypatch.setattr(
        llm.db, "q_ro", lambda sql, p=(): [{"vendor": "Cisco", "cvss": 9.8}]
    )
    fake = FakeMessages(
        [
            SimpleNamespace(
                stop_reason="tool_use",
                content=[
                    block(
                        "tool_use",
                        id="t1",
                        name="search_alerts",
                        input={"vendor": "Cisco"},
                    )
                ],
            ),
            SimpleNamespace(
                stop_reason="end_turn", content=[block("text", text="🔴 Cisco 9.8")]
            ),
        ]
    )
    monkeypatch.setattr(llm, "client", SimpleNamespace(messages=fake))
    assert run(llm.ask("Which alerts concern Cisco?")) == "🔴 Cisco 9.8"
    result = fake.calls[1]["messages"][-1]["content"][0]
    assert result["tool_use_id"] == "t1"
    assert json.loads(result["content"]) == [{"vendor": "Cisco", "cvss": 9.8}]


def ask_with(monkeypatch, rows, answer, tool=True):
    monkeypatch.setattr(llm.db, "q_ro", lambda sql, p=(): rows)
    final = SimpleNamespace(
        stop_reason="end_turn", content=[block("text", text=answer)]
    )
    use = block("tool_use", id="t1", name="search_alerts", input={"cve": "CVE-2026-1"})
    first = SimpleNamespace(stop_reason="tool_use", content=[use])
    fake = FakeMessages([first, final] if tool else [final])
    monkeypatch.setattr(llm, "client", SimpleNamespace(messages=fake))
    return run(llm.ask("CVE-2026-1")), fake


def test_ask_without_data_gives_the_english_default(monkeypatch):
    answer, fake = ask_with(monkeypatch, [], "Ничего не найдено.")
    assert answer == llm.NO_DATA and answer.startswith("No stored alert matches")
    assert "unclear" in fake.calls[0]["system"] and "English" in fake.calls[0]["system"]


def test_ask_with_data_keeps_the_model_answer(monkeypatch):
    answer, _ = ask_with(monkeypatch, [{"vendor": "Cisco"}], "🔴 Cisco CVE-2026-1")
    assert answer == "🔴 Cisco CVE-2026-1"


def test_ask_never_returns_an_empty_answer(monkeypatch):
    assert ask_with(monkeypatch, [{"vendor": "Cisco"}], "  ")[0] == llm.NO_DATA
    assert ask_with(monkeypatch, [], "Hello", tool=False)[0] == "Hello"  # no tool


# ---------- /addvendor (section 6) ----------
def test_discover_validates_llm_output(monkeypatch):
    answer = json.dumps(
        {
            "vendor": "Zyxel <b>Networks</b>",
            "nvd_keyword": "Zyxel",
            "sources": [
                {
                    "type": "html",
                    "url": "https://zyxel.example/sa",
                    "config": {"item": "tr"},
                },
                {"type": "exec", "url": "https://zyxel.example/x"},  # unknown type
                {"type": "rss", "url": "https://zyxel.example/feed", "config": "bad"},
                {"type": "rss", "url": 123},  # not a string
                {
                    "type": "rss",
                    "url": "https://zyxel.example/4th",
                },  # beyond the cap of 3
            ],
        }
    )
    fake = FakeMessages(
        [
            SimpleNamespace(
                stop_reason="end_turn",
                content=[
                    block("server_tool_use"),
                    block("text", text="Here: " + answer),
                ],
            )
        ]
    )
    monkeypatch.setattr(onboard, "client", SimpleNamespace(messages=fake))
    found = run(onboard.discover("zyxel"))
    assert found["vendor"] == "Zyxel bNetworksb"
    assert found["nvd_keyword"] == "Zyxel"
    assert [s["type"] for s in found["sources"]] == ["html", "rss"]
    assert found["sources"][1]["config"] == {}


@pytest.mark.parametrize(
    "cpe, expected",
    [
        ("cpe:2.3:a:php:php", "cpe:2.3:a:php:php"),
        ("CPE:2.3:O:Cisco:IOS_XR", "cpe:2.3:o:cisco:ios_xr"),
        ("cpe:2.3:a:openssl", "cpe:2.3:a:openssl"),
        ("", None),
        ("cpe:2.3:a:php:php;DROP", None),
        ("php", None),
    ],
)
def test_discover_keeps_only_valid_cpes(monkeypatch, cpe, expected):
    answer = json.dumps(
        {"vendor": "PHP", "nvd_keyword": "PHP", "nvd_cpe": cpe, "sources": []}
    )
    fake = FakeMessages(
        [SimpleNamespace(stop_reason="end_turn", content=[block("text", text=answer)])]
    )
    monkeypatch.setattr(onboard, "client", SimpleNamespace(messages=fake))
    found = run(onboard.discover("php"))
    assert found["nvd_cpe"] == expected
    assert "telecom equipment vendor" not in fake.calls[0]["messages"][0]["content"]


def test_count_cves_uses_the_proposed_match(monkeypatch):
    seen = []

    async def fake_nvd(client, vendors, since):
        seen.append(vendors[0])
        return [{}, {}, {}]

    monkeypatch.setattr(onboard.col, "fetch_nvd", fake_nvd)
    found = {"vendor": "PHP", "nvd_keyword": "PHP", "nvd_cpe": "cpe:2.3:a:php:php"}
    assert run(onboard.count_cves(found)) == 3
    assert seen[0]["nvd_cpe"] == "cpe:2.3:a:php:php"


def test_discover_without_json_fails(monkeypatch):
    fake = FakeMessages(
        [SimpleNamespace(stop_reason="end_turn", content=[block("text", text="no")])]
    )
    monkeypatch.setattr(onboard, "client", SimpleNamespace(messages=fake))
    with pytest.raises(ValueError):
        run(onboard.discover("Nobody"))


def test_test_source_refuses_internal_urls():
    src = {
        "vendor": "X",
        "type": "rss",
        "url": "https://postgres.railway.internal/",
        "config": {},
    }
    ok, msg, sample = run(onboard.test_source(src))
    assert not ok and msg.startswith("refused") and sample == []


# ---------- release notes ----------
def test_release_notes_are_short_and_versions_unique():
    entries = yaml.safe_load((ROOT / "release_notes.yaml").read_text())
    versions = [str(e["version"]) for e in entries]
    assert versions and len(versions) == len(set(versions))
    for e in entries:
        lines = e["notes"].strip().splitlines()
        assert 1 <= len(lines) <= 4, e["version"]


def test_release_notes_go_once_to_active_users(monkeypatch):
    fake_db = FakeDB()
    monkeypatch.setattr(bot, "db", fake_db)
    monkeypatch.setattr(bot, "active_users", lambda: [user(chat_id=1), user(chat_id=2)])
    monkeypatch.setattr(bot, "release_notes", lambda: ("v2", "🆕 New\n• a"))
    fake_bot = FakeBot()
    run(bot.announce_release(fake_bot))
    assert fake_bot.sent == [(1, "🆕 New\n• a"), (2, "🆕 New\n• a")]
    assert fake_db.state["announced_version"] == "v2"
    run(bot.announce_release(fake_bot))  # a redeploy without new notes sends nothing
    assert len(fake_bot.sent) == 2
    monkeypatch.setattr(bot, "release_notes", lambda: ("v3", "🆕 Newer"))
    run(bot.announce_release(fake_bot))
    assert fake_bot.sent[-2:] == [(1, "🆕 Newer"), (2, "🆕 Newer")]


def test_release_notes_are_cut_to_4_lines(monkeypatch, tmp_path):
    (tmp_path / "release_notes.yaml").write_text(
        '- version: "2"\n  notes: |\n    1\n    2\n    3\n    4\n    5\n'
        '- version: "1"\n  notes: old\n'
    )
    monkeypatch.chdir(tmp_path)
    assert bot.release_notes() == ("2", "1\n2\n3\n4")


def test_start_up_sets_the_menu_then_announces(monkeypatch):
    calls = []

    async def set_menu(app):
        calls.append("menu")

    async def announce(b):
        calls.append(("announce", b))

    monkeypatch.setattr(bot, "set_menu", set_menu)
    monkeypatch.setattr(bot, "announce_release", announce)
    app = SimpleNamespace(bot="the bot")
    run(bot.on_start(app))
    assert calls == ["menu", ("announce", "the bot")]


# ---------- seed.yaml ----------
def test_seed_lists_all_vendors_of_section_2_2():
    seed = yaml.safe_load((ROOT / "seed.yaml").read_text())
    names = [v["name"] for v in seed["vendors"]]
    assert len(names) == 29 and len(set(names)) == 29
    for s in seed["sources"]:
        assert s["vendor"] in names
        assert s["type"] in collectors.FETCHERS
        assert s["url"].startswith("https://")
