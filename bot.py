import asyncio
import hashlib
import html
import logging
import os
import re
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import yaml
from psycopg.types.json import Jsonb
from telegram import (
    BotCommand,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Update,
)
from telegram.constants import ParseMode
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    filters,
)

import collectors as col
import db
import onboard
from llm import ask as llm_ask


def log_handlers():
    """INFO to stdout, warnings and errors to stderr: Railway marks every stderr line as an error."""
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    out = logging.StreamHandler(sys.stdout)
    out.addFilter(lambda r: r.levelno < logging.WARNING)
    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    for h in (out, err):
        h.setFormatter(fmt)
    return [out, err]


logging.basicConfig(level=logging.INFO, handlers=log_handlers())
# httpx logs every request URL at INFO, and Telegram API URLs contain the bot token.
logging.getLogger("httpx").setLevel(logging.WARNING)
log = logging.getLogger("telco-watch")

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
# Permanent admins; others can be made admin with /promote (users.role).
ADMINS = {int(x) for x in os.environ.get("ADMIN_USER_IDS", "").split(",") if x}
MIN_CVSS = float(os.environ.get("MIN_CVSS", "7.0"))  # default /severity of a new user
LEVELS = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.0}
PARIS = ZoneInfo("Europe/Paris")  # dates are shown in CET, or CEST in summer
DATE_ONLY = re.compile(r"\d{4}-\d{2}-\d{2}")
PRIVATE = filters.ChatType.PRIVATE  # the bot only works in one-to-one chats
PENDING = {}  # /addvendor proposals waiting for an admin's approval
LAST_ASK = {}  # user id -> time of last /ask


def http():
    return col.client()  # public https only, redirects included


# ---------- scoring, formatting, storage ----------
def level(it):
    """The score the severity matrix uses: CVSS, else the vendor rating's lowest score."""
    if it["cvss"] is not None:
        return it["cvss"]
    return LEVELS.get(it.get("rating"))


def score_text(it):
    if it["cvss"] is not None:
        return f" · CVSS {it['cvss']}"
    return " · vendor rating" if it.get("rating") else ""


def severity(it):
    if it["kev"]:
        return "🔴 CRITICAL · ⚠️ KEV"
    s = level(it)
    if s is None:
        return "🔵 ADVISORY"
    return (
        "🔴 CRITICAL"
        if s >= 9
        else "🟠 HIGH"
        if s >= 7
        else "🟡 MEDIUM"
        if s >= 4
        else "⚪ LOW"
    )


def wants(user, it):
    """Does this user want this alert, given their /severity and /mute settings?"""
    if it["vendor"] in user["muted"]:
        return False
    s = level(it)
    return it["kev"] or s is None or s >= user["min_cvss"]


def level_name(min_cvss):
    return next(name for name, score in LEVELS.items() if min_cvss >= score)


def when(value):
    """dd-mm-yyyy HH:MM in Paris time (CET or CEST); a date given without a time stays a date."""
    if isinstance(value, str):
        raw = value.strip()
        if DATE_ONLY.fullmatch(raw):  # e.g. CISA KEV: no time, so none is made up
            return datetime.fromisoformat(raw).strftime("%d-%m-%Y")
        value = col.parse_date(raw)
        if value is None:
            return raw  # unreadable: shown as the source gave it
    local = value.astimezone(PARIS)
    return f"{local:%d-%m-%Y %H:%M} {local:%Z}"


def fmt(it):
    e = html.escape
    score = score_text(it)
    return (
        f"<b>{severity(it)}{score}</b>\n"
        f"<b>Vendor:</b> {e(it['vendor'])}\n"
        f"<b>Title:</b> {e(it['title'] or '')}\n"
        f"<b>CVE:</b> {e(', '.join(it['cves']) or '—')}\n"
        f"<b>Published:</b> {e(when(it['published'] or ''))}\n"
        f"{e(it['url'] or '')}"
    )


def update_line(it):
    """An old advisory collected only now because its source changed it: one line, not an alert."""
    e = html.escape
    score = score_text(it)
    cves = f" · {', '.join(it['cves'])}" if it["cves"] else ""
    published = f" · published {when(it['published'])}" if it["published"] else ""
    changed = when(it["updated_at"] or datetime.now(UTC))
    return (
        f"🔄 <b>Update</b> · {severity(it)}{score} · {e(it['vendor'] + cves)} · "
        f"{e(col.short_title(it['title'], 120))}{e(published)} · last updated {changed}\n"
        f"{e(it['url'] or '')}"
    )


def store(it):
    """Insert an item, with its parsed dates; True only if it was not already in the database."""
    key = hashlib.sha256(f"{it['vendor']}|{it['id']}".encode()).hexdigest()
    it["published_at"] = col.parse_date(it["published"]) or datetime.now(UTC)
    it["updated_at"] = col.parse_date(it.get("updated"))
    row = db.q(
        "INSERT INTO items (key, vendor, title, url, cves, cvss, kev, published, rating, "
        "published_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (key) DO NOTHING RETURNING key",
        (
            key,
            it["vendor"],
            it["title"],
            it["url"],
            it["cves"],
            it["cvss"],
            it["kev"],
            it["published"],
            it.get("rating"),
            it["published_at"],
            it["updated_at"],
        ),
        one=True,
    )
    return row is not None


def backfill_dates():
    """Items stored before published_at existed get it from their published text."""
    for r in db.q(
        "SELECT key, published, seen_at FROM items WHERE published_at IS NULL"
    ):
        db.q(
            "UPDATE items SET published_at = %s WHERE key = %s",
            (published_at(r), r["key"]),
        )


def backfill_ratings():
    """Items stored before vendor ratings were read get one from their stored title.

    Runs at every start, so stored items also benefit when the patterns improve; items
    with neither a score nor a rating in their title are only read, never rewritten.
    """
    for r in db.q("SELECT key, title FROM items WHERE cvss IS NULL AND rating IS NULL"):
        cvss, rating = col.vendor_score(r["title"] or "")
        if cvss is not None or rating:
            db.q(
                "UPDATE items SET cvss = %s, rating = %s WHERE key = %s",
                (cvss, rating, r["key"]),
            )


# ---------- users ----------
def get_user(uid):
    return db.q("SELECT * FROM users WHERE chat_id = %s", (uid,), one=True)


def active_users():
    return db.q("SELECT * FROM users WHERE status = 'active' ORDER BY chat_id")


def save_user(uid, name, status):
    db.q(
        "INSERT INTO users (chat_id, name, status, min_cvss) VALUES (%s, %s, %s, %s) "
        "ON CONFLICT (chat_id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status",
        (uid, name, status, MIN_CVSS),
    )


def decide_user(uid, status, admin_id):
    """Approve or reject a pending request; None if it was already decided."""
    return db.q(
        "UPDATE users SET status = %s, approved_by = %s "
        "WHERE chat_id = %s AND status = 'pending' RETURNING chat_id, name",
        (status, admin_id, uid),
        one=True,
    )


def set_user_status(uid, status, admin_id):
    """A removed user also loses the admin role."""
    return db.q(
        "UPDATE users SET status = %s, approved_by = %s, "
        "role = CASE WHEN %s = 'active' THEN role ELSE 'user' END "
        "WHERE chat_id = %s RETURNING name",
        (status, admin_id, status, uid),
        one=True,
    )


def set_role(uid, role):
    """/promote and /demote; None unless the user is active."""
    return db.q(
        "UPDATE users SET role = %s WHERE chat_id = %s AND status = 'active' RETURNING name",
        (role, uid),
        one=True,
    )


def promoted_admins():
    return db.q("SELECT chat_id FROM users WHERE role = 'admin' AND status = 'active'")


def is_admin(uid, user=None):
    """Permanent admins (ADMIN_USER_IDS) and active users promoted with /promote."""
    if uid in ADMINS:
        return True
    user = user or get_user(uid)
    return bool(user) and user["status"] == "active" and user.get("role") == "admin"


def admin_ids():
    return ADMINS | {r["chat_id"] for r in promoted_admins()}


def set_min_cvss(uid, score):
    db.q("UPDATE users SET min_cvss = %s WHERE chat_id = %s", (score, uid))


def set_muted(uid, vendor, muted):
    db.q(
        "UPDATE users SET muted = array_remove(muted, %s::text) "
        + ("|| ARRAY[%s::text] " if muted else "")
        + "WHERE chat_id = %s",
        (vendor, vendor, uid) if muted else (vendor, uid),
    )


def find_vendor(name):
    return db.q("SELECT name FROM vendors WHERE name ILIKE %s", (name,), one=True)


async def send(bot, chat_id, text, **kw):
    """Send to one user; a user who blocked the bot must not stop the others."""
    try:
        await bot.send_message(chat_id, text, **kw)
        return True
    except TelegramError as ex:
        log.warning("could not send to %s: %s", chat_id, ex)
        return False


# ---------- the hourly cycle ----------
async def cycle(context: ContextTypes.DEFAULT_TYPE):
    started = datetime.now(UTC)
    last = db.get_state("last_run")
    first_run = last is None  # store the backlog, send nothing
    since = datetime.fromisoformat(last) if last else started - timedelta(hours=24)
    vendors = db.q("SELECT name, nvd_keyword, nvd_cpe FROM vendors WHERE enabled")
    sources = db.q(
        "SELECT s.* FROM sources s JOIN vendors v ON v.name = s.vendor WHERE s.enabled AND v.enabled"
    )
    new, failed = [], []
    async with http() as client:
        jobs = [
            ("CISA KEV", lambda: col.fetch_kev(client, vendors)),
            ("NVD", lambda: col.fetch_nvd(client, vendors, since)),
        ]
        jobs += [
            (
                f"{s['vendor']} ({s['type']})",
                lambda s=s: col.FETCHERS[s["type"]](client, s),
            )
            for s in sources
        ]
        for name, job in jobs:
            try:
                items = await job()
            except Exception as ex:  # noqa: BLE001 - one failing source never blocks the others
                log.warning("source %s failed: %s", name, ex)
                failed.append(name)
                continue
            new += [it for it in items if store(it)]
    db.set_state("last_run", started.isoformat())
    db.set_state(
        "last_status",
        f"{when(started)} · {len(new)} new · failed: {', '.join(failed) or 'none'}",
    )
    if first_run:
        log.info("first run: backlog stored, nothing sent")
        return
    users = active_users()
    # Published well before the previous cycle: not a new advisory, an old one the
    # source has just changed (NVD re-analysis), so it gets a one-line update.
    old = since - timedelta(days=1)
    for it in new:
        text = fmt(it) if it["published_at"] >= old else update_line(it)
        sent = False
        for user in users:
            if wants(user, it):
                sent |= await send(
                    context.bot,
                    user["chat_id"],
                    text,
                    parse_mode=ParseMode.HTML,
                    disable_web_page_preview=True,
                )
        if sent:
            await asyncio.sleep(1.1)  # Telegram: about 1 message/s per chat
    if failed:
        for user in users:
            if is_admin(user["chat_id"], user):
                await send(
                    context.bot,
                    user["chat_id"],
                    "⚠️ Sources failed: " + ", ".join(failed),
                )


# ---------- commands ----------
def admin_only(fn):
    async def wrapper(u: Update, c: ContextTypes.DEFAULT_TYPE):
        if not is_admin(u.effective_user.id):
            return await u.effective_message.reply_text("Admins only.")
        return await fn(u, c)

    return wrapper


def permanent_admin_only(fn):
    async def wrapper(u: Update, c: ContextTypes.DEFAULT_TYPE):
        if u.effective_user.id not in ADMINS:
            return await u.effective_message.reply_text(
                "Only the permanent admins (ADMIN_USER_IDS) can do this."
            )
        return await fn(u, c)

    return wrapper


def members_only(fn):
    async def wrapper(u: Update, c: ContextTypes.DEFAULT_TYPE):
        user = get_user(u.effective_user.id)
        if not user or user["status"] != "active":
            return await u.effective_message.reply_text(
                "You don't have access yet: send /start to request it."
            )
        return await fn(u, c)

    return wrapper


HELP = (
    "Telco Vendor Watch sends you vendor security advisories as they are published.\n\n"
    "/status: last collection cycle\n"
    "/latest [vendor] [n]: last advisories\n"
    "/latest all [days]: high and above from all vendors, published in the last days (default 7)\n"
    "/vendors: monitored vendors\n"
    "/ask <question>: ask about the stored alerts\n"
    "/severity <critical|high|medium|low>: minimum severity of your alerts\n"
    "/mute <vendor> · /unmute <vendor>: stop or resume a vendor's alerts"
)
ADMIN_HELP = (
    "\n\nAdmin: /checknow /addvendor /removevendor\n"
    "/users · /adduser <id> · /removeuser <id>: manage who can use the bot"
)
OWNER_HELP = "\n/promote <id> · /demote <id>: give or take back the admin role"


def help_text(uid):
    if uid in ADMINS:
        return HELP + ADMIN_HELP + OWNER_HELP
    return HELP + (ADMIN_HELP if is_admin(uid) else "")


async def start(u: Update, c: ContextTypes.DEFAULT_TYPE):
    """Shows help to members; registers anyone else and asks the admins to approve them."""
    uid, name = u.effective_user.id, u.effective_user.full_name
    user = get_user(uid)
    if uid in ADMINS and (not user or user["status"] != "active"):
        save_user(uid, name, "active")  # admins never need approval
        user = {"status": "active"}
    if user and user["status"] == "active":
        return await u.message.reply_text(help_text(uid))
    if user and user["status"] == "blocked":
        return None  # no answer to removed users
    if user:
        return await u.message.reply_text(
            "Your access request is waiting for an admin."
        )
    save_user(uid, name, "pending")
    kb = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Approve", callback_data=f"uok:{uid}"),
                InlineKeyboardButton("Reject", callback_data=f"uno:{uid}"),
            ]
        ]
    )
    for admin in admin_ids():
        await send(
            c.bot, admin, f"Access request from {name} (id {uid}).", reply_markup=kb
        )
    await u.message.reply_text(
        "Your access request was sent to the admins; you'll get a message once it's approved."
    )


async def on_error(update: object, c: ContextTypes.DEFAULT_TYPE):
    """Log a failed command and tell the user, instead of leaving them without a reply."""
    log.error("update failed", exc_info=c.error)
    if isinstance(update, Update) and update.effective_message:
        await update.effective_message.reply_text(
            "Something went wrong; try again in a moment."
        )


@members_only
async def status(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await u.message.reply_text(db.get_state("last_status") or "No cycle yet.")


@members_only
async def latest(u: Update, c: ContextTypes.DEFAULT_TYPE):
    args = c.args or []
    if args and args[0].lower() == "all":
        days = int(args[1]) if len(args) > 1 and args[1].isdigit() else 7
        return await latest_all(u, max(1, min(days, 90)))
    n = int(args[-1]) if args and args[-1].isdigit() else 5
    vendor = args[0] if args and not args[0].isdigit() else None
    sql = "SELECT * FROM items" + (" WHERE vendor ILIKE %s" if vendor else "")
    params = ([f"%{vendor}%"] if vendor else []) + [min(n, 20)]
    rows = db.q(sql + " ORDER BY published_at DESC NULLS LAST LIMIT %s", params)
    if not rows:
        return await u.message.reply_text("Nothing stored yet.")
    for it in rows:
        await u.message.reply_text(
            fmt(it), parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )


def published_at(it):
    """The vendor's publication time; falls back to collection time when the source has none."""
    return col.parse_date(it["published"]) or it["seen_at"]


def brief(it):
    score = score_text(it)
    cves = f" · {', '.join(it['cves'])}" if it["cves"] else ""
    title = col.short_title(it["title"], 120)
    return f"{severity(it)}{score} · {it['vendor']}{cves}\n{title}\n{it['url'] or ''}"


def chunks(blocks, limit=4000):
    """Join blocks into as few messages as possible under Telegram's size limit."""
    out, cur = [], ""
    for b in blocks:
        if cur and len(cur) + len(b) + 2 > limit:
            out.append(cur)
            cur = ""
        cur = f"{cur}\n\n{b}" if cur else b
    return out + [cur] if cur else out


async def latest_all(u: Update, days, cap=40):
    """/latest all [days]: high and above from every vendor, by publication date."""
    rows = db.q(
        "SELECT * FROM items WHERE (kev OR cvss >= %s "
        "OR (cvss IS NULL AND (rating IS NULL OR rating IN ('critical', 'high')))) "
        "AND published_at >= now() - %s * interval '1 day'",
        (LEVELS["high"], days),
    )
    scored = [r for r in rows if r["kev"] or level(r) is not None]
    unscored = [r for r in rows if not r["kev"] and level(r) is None]
    scored.sort(
        key=lambda r: (not r["kev"], -(level(r) or 0), -r["published_at"].timestamp())
    )
    unscored.sort(key=lambda r: -r["published_at"].timestamp())
    if not scored and not unscored:
        return await u.message.reply_text(
            f"No high or critical alert in the last {days} days."
        )
    blocks = [f"High and above, all vendors, last {days} days: {len(scored)}"]
    blocks += [brief(r) for r in scored[:cap]]
    if len(scored) > cap:
        blocks.append(f"…and {len(scored) - cap} more: try a shorter period or /ask.")
    if unscored:
        blocks.append(f"Vendor advisories without a score or rating: {len(unscored)}")
        blocks += [brief(r) for r in unscored[: cap // 2]]
        if len(unscored) > cap // 2:
            blocks.append(f"…and {len(unscored) - cap // 2} more.")
    for text in chunks(blocks):
        await u.message.reply_text(text, disable_web_page_preview=True)


@members_only
async def vendors_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    rows = db.q(
        "SELECT v.name, v.enabled, count(s.id) AS n FROM vendors v "
        "LEFT JOIN sources s ON s.vendor = v.name AND s.enabled "
        "GROUP BY v.name, v.enabled ORDER BY v.name"
    )
    lines = [
        f"{'✅' if r['enabled'] else '⏸'} {r['name']}: {r['n']} own source(s) + KEV/NVD"
        for r in rows
    ]
    await u.message.reply_text("\n".join(lines) or "No vendors.")


@admin_only
async def checknow(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await u.message.reply_text("Running a cycle…")
    await cycle(c)
    await u.message.reply_text(db.get_state("last_status"))


@admin_only
async def addvendor(u: Update, c: ContextTypes.DEFAULT_TYPE):
    name = " ".join(c.args or []).strip()
    if not name or len(name) > 60:
        return await u.message.reply_text(
            "Usage: /addvendor <vendor, product or technology>, e.g. /addvendor PHP"
        )
    await u.message.reply_text(
        f"Searching the advisory sources of {name}… (about a minute)"
    )
    try:
        found = await onboard.discover(name)
    except Exception as ex:  # noqa: BLE001 - reported to the admin
        log.warning("discovery failed: %s", ex)
        return await u.message.reply_text(
            "Discovery failed; try again or check the logs."
        )
    match = (
        f"CPE {found['nvd_cpe']}"
        if found["nvd_cpe"]
        else f"keyword {found['nvd_keyword']}"
    )
    lines = [
        f"Vendor: {found['vendor']} (NVD {match}, KEV keyword {found['nvd_keyword']})"
    ]
    try:
        lines.append(f"NVD: {await onboard.count_cves(found)} CVEs in the last 30 days")
    except Exception as ex:  # noqa: BLE001 - the count is only informative
        log.warning("NVD count failed: %s", ex)
    working = []
    for src in found["sources"]:
        ok, msg, sample = await onboard.test_source(src)
        lines.append(f"{'✅' if ok else '❌'} {src['type']} {src['url']}: {msg}")
        lines += [f"    • {s['title'][:80]}" for s in sample]
        if ok:
            working.append(src)
    pid = secrets.token_hex(4)
    PENDING[pid] = {**found, "sources": working}
    lines.append(
        "\nApprove to add it with the ✅ sources."
        if working
        else "\nNo working source found. Approve to add it with KEV/NVD monitoring only."
    )
    kb = InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("Approve", callback_data=f"add:{pid}"),
                InlineKeyboardButton("Cancel", callback_data=f"cancel:{pid}"),
            ]
        ]
    )
    await u.message.reply_text(
        "\n".join(lines), reply_markup=kb, disable_web_page_preview=True
    )


async def on_button(u: Update, c: ContextTypes.DEFAULT_TYPE):
    qy = u.callback_query
    if not is_admin(qy.from_user.id):
        return await qy.answer("Admins only.", show_alert=True)
    await qy.answer()
    action, pid = qy.data.split(":", 1)
    if action in ("uok", "uno"):
        return await decide(c, qy, int(pid), approve=action == "uok")
    p = PENDING.pop(pid, None)
    if p is None:
        return await qy.edit_message_text(
            qy.message.text + "\n\nExpired: run /addvendor again."
        )
    if action == "cancel":
        return await qy.edit_message_text(qy.message.text + "\n\nCancelled.")
    db.q(
        "INSERT INTO vendors (name, nvd_keyword, nvd_cpe) VALUES (%s, %s, %s) "
        "ON CONFLICT (name) DO UPDATE SET enabled = TRUE, "
        "nvd_keyword = EXCLUDED.nvd_keyword, nvd_cpe = EXCLUDED.nvd_cpe",
        (p["vendor"], p["nvd_keyword"], p["nvd_cpe"]),
    )
    for s in p["sources"]:
        db.q(
            "INSERT INTO sources (vendor, type, url, config, added_by) VALUES (%s, %s, %s, %s, %s)",
            (p["vendor"], s["type"], s["url"], Jsonb(s["config"]), qy.from_user.id),
        )
    # Store the existing advisories silently, so the next cycle does not flood the chat.
    seeded = 0
    vendor_row = {"name": p["vendor"], "nvd_keyword": p["nvd_keyword"]}
    async with http() as client:
        jobs = [lambda: col.fetch_kev(client, [vendor_row])]
        jobs += [lambda s=s: col.FETCHERS[s["type"]](client, s) for s in p["sources"]]
        for job in jobs:
            try:
                seeded += sum(store(it) for it in await job())
            except Exception as ex:  # noqa: BLE001 - seeding is best-effort
                log.warning("seeding failed: %s", ex)
    await qy.edit_message_text(
        qy.message.text + f"\n\nAdded by {qy.from_user.first_name}: "
        f"{seeded} existing advisories stored silently; new ones "
        "are alerted from the next cycle."
    )


async def decide(c, qy, uid, approve):
    """Approve or Reject button on an access request."""
    row = decide_user(uid, "active" if approve else "blocked", qy.from_user.id)
    if row is None:
        return await qy.edit_message_text(qy.message.text + "\n\nAlready decided.")
    verdict = "Approved" if approve else "Rejected"
    await qy.edit_message_text(
        qy.message.text + f"\n\n{verdict} by {qy.from_user.first_name}."
    )
    if approve:
        await send(c.bot, uid, "Your access was approved.\n\n" + help_text(uid))
    return None


@admin_only
async def removevendor(u: Update, c: ContextTypes.DEFAULT_TYPE):
    name = " ".join(c.args or []).strip()
    row = db.q(
        "UPDATE vendors SET enabled = FALSE WHERE name ILIKE %s RETURNING name",
        (name,),
        one=True,
    )
    if row:
        db.q("UPDATE sources SET enabled = FALSE WHERE vendor = %s", (row["name"],))
    await u.message.reply_text(
        f"{row['name']} and its sources disabled; history kept. Re-add with /addvendor."
        if row
        else "Unknown vendor, see /vendors."
    )


@members_only
async def ask_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    q = " ".join(c.args or [])
    if not q:
        return await u.message.reply_text(
            "Usage: /ask most critical alerts in the past 2 days?"
        )
    uid = u.effective_user.id
    if time.time() - LAST_ASK.get(uid, 0) < 10:
        return await u.message.reply_text("One question every 10 s, please.")
    LAST_ASK[uid] = time.time()
    await u.message.chat.send_action("typing")
    try:
        answer = await llm_ask(q[:500])
    except Exception as ex:  # noqa: BLE001 - reported to the user
        log.warning("llm failed: %s", ex)
        answer = "The assistant is unavailable right now; try /latest."
    await u.message.reply_text(answer[:4000], disable_web_page_preview=True)


@members_only
async def severity_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    uid = u.effective_user.id
    level = (c.args or [""])[0].lower()
    if level not in LEVELS:
        current = level_name(get_user(uid)["min_cvss"])
        return await u.message.reply_text(
            f"Your alerts start at {current}. Usage: /severity <critical|high|medium|low>. "
            "Actively exploited (KEV) and unscored advisories are always sent."
        )
    set_min_cvss(uid, LEVELS[level])
    await u.message.reply_text(f"You'll now get {level} alerts and above.")


async def mute_toggle(u: Update, c: ContextTypes.DEFAULT_TYPE, muted):
    uid = u.effective_user.id
    name = " ".join(c.args or []).strip()
    if not name:
        current = ", ".join(get_user(uid)["muted"]) or "none"
        return await u.message.reply_text(
            f"Muted vendors: {current}. Usage: /mute <vendor> or /unmute <vendor>."
        )
    row = find_vendor(name)
    if not row:
        return await u.message.reply_text("Unknown vendor, see /vendors.")
    set_muted(uid, row["name"], muted)
    await u.message.reply_text(
        f"{row['name']} {'muted' if muted else 'unmuted'}: you'll "
        f"{'no longer' if muted else 'again'} get its alerts."
    )


@members_only
async def mute(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await mute_toggle(u, c, True)


@members_only
async def unmute(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await mute_toggle(u, c, False)


@admin_only
async def users_cmd(u: Update, c: ContextTypes.DEFAULT_TYPE):
    rows = db.q("SELECT chat_id, name, status, role FROM users ORDER BY status, name")
    lines = [
        f"{r['status']}: {r['name']} (id {r['chat_id']})"
        + (" · admin" if is_admin(r["chat_id"], r) else "")
        for r in rows
    ]
    await u.message.reply_text("\n".join(lines) or "No users yet.")


async def change_user(u: Update, c: ContextTypes.DEFAULT_TYPE, status):
    arg = (c.args or [""])[0]
    if not arg.isdigit():
        return await u.message.reply_text("Usage: give the user id shown by /users.")
    uid = int(arg)
    promoted = uid not in ADMINS and is_admin(uid)
    if status == "active" and not get_user(uid):
        save_user(uid, None, "active")  # added before they ever wrote to the bot
        row = {"name": f"id {uid}"}
    else:
        row = set_user_status(uid, status, u.effective_user.id)
    if not row:
        return await u.message.reply_text("Unknown user, see /users.")
    if status == "active":
        await send(c.bot, uid, "Your access was approved.\n\n" + help_text(uid))
    elif promoted:
        await set_chat_menu(c.bot, uid, None)  # removed: the admin role goes too
    await u.message.reply_text(
        f"{row['name'] or uid} {'can now use' if status == 'active' else 'can no longer use'} the bot."
    )


@admin_only
async def adduser(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await change_user(u, c, "active")


@admin_only
async def removeuser(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await change_user(u, c, "blocked")


async def change_role(u: Update, c: ContextTypes.DEFAULT_TYPE, admin):
    arg = (c.args or [""])[0]
    if not arg.isdigit():
        return await u.message.reply_text("Usage: give the user id shown by /users.")
    uid = int(arg)
    if uid in ADMINS:
        return await u.message.reply_text(
            f"{uid} is a permanent admin (ADMIN_USER_IDS); change that variable instead."
        )
    row = set_role(uid, "admin" if admin else "user")
    if not row:
        return await u.message.reply_text("Unknown or inactive user, see /users.")
    await set_chat_menu(c.bot, uid, ADMIN_MENU if admin else None)
    await send(
        c.bot,
        uid,
        "You are now an admin.\n\n" + help_text(uid)
        if admin
        else "You are no longer an admin.",
    )
    await u.message.reply_text(
        f"{row['name'] or uid} {'is now' if admin else 'is no longer'} an admin."
    )


@permanent_admin_only
async def promote(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await change_role(u, c, True)


@permanent_admin_only
async def demote(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await change_role(u, c, False)


COMMANDS = {
    "start": start,
    "help": start,
    "status": status,
    "health": status,
    "latest": latest,
    "vendors": vendors_cmd,
    "checknow": checknow,
    "ask": ask_cmd,
    "addvendor": addvendor,
    "removevendor": removevendor,
    "severity": severity_cmd,
    "mute": mute,
    "unmute": unmute,
    "users": users_cmd,
    "adduser": adduser,
    "removeuser": removeuser,
    "promote": promote,
    "demote": demote,
}

# The Telegram command menu, set by the bot itself at start-up (no BotFather step).
# /health is an alias of /status and stays out of the menu.
MENU = [
    ("start", "Register and show help"),
    ("help", "Show the commands"),
    ("status", "Last cycle and source health"),
    ("latest", "Last advisories: /latest [vendor] [n] or /latest all [days]"),
    ("vendors", "List monitored vendors"),
    ("ask", "Ask a question about the alerts"),
    ("severity", "Minimum severity of your alerts"),
    ("mute", "Stop alerts for a vendor"),
    ("unmute", "Resume alerts for a vendor"),
]
ADMIN_MENU = MENU + [
    ("checknow", "Run a collection cycle now"),
    ("addvendor", "Add a vendor, product or technology"),
    ("removevendor", "Stop monitoring a vendor"),
    ("users", "List users"),
    ("adduser", "Give a user access"),
    ("removeuser", "Remove a user's access"),
]
OWNER_MENU = ADMIN_MENU + [  # permanent admins only
    ("promote", "Make a user an admin"),
    ("demote", "Take back a user's admin role"),
]


async def set_chat_menu(bot, chat_id, menu):
    """One chat's own menu; None goes back to the user menu."""
    scope = BotCommandScopeChat(chat_id)
    try:
        if menu is None:
            await bot.delete_my_commands(scope=scope)
        else:
            await bot.set_my_commands([BotCommand(n, d) for n, d in menu], scope=scope)
    except TelegramError as ex:  # e.g. this admin never wrote to the bot
        log.warning("menu for %s not set: %s", chat_id, ex)


async def set_menu(app):
    """Everyone sees the user commands; each admin's chat also lists the admin ones."""
    await app.bot.set_my_commands([BotCommand(n, d) for n, d in MENU])
    for admin in sorted(admin_ids()):
        await set_chat_menu(
            app.bot, admin, OWNER_MENU if admin in ADMINS else ADMIN_MENU
        )


def release_notes():
    """The newest entry of release_notes.yaml: its version and notes (4 lines at most)."""
    with open("release_notes.yaml") as f:
        newest = yaml.safe_load(f)[0]
    lines = newest["notes"].strip().splitlines()[:4]
    return str(newest["version"]), "\n".join(lines)


async def announce_release(bot):
    """Sends the newest release notes once to every active user."""
    version, notes = release_notes()
    if db.get_state("announced_version") == version:
        return
    db.set_state("announced_version", version)  # first, so a restart never repeats it
    users = active_users()
    for user in users:
        await send(bot, user["chat_id"], notes)
    log.info("release %s announced to %d users", version, len(users))


async def on_start(app):
    await set_menu(app)
    await announce_release(app.bot)


def main():
    db.init()
    backfill_dates()
    backfill_ratings()
    app = Application.builder().token(TOKEN).post_init(on_start).build()
    for name, fn in COMMANDS.items():
        app.add_handler(CommandHandler(name, fn, filters=PRIVATE))
    app.add_handler(CallbackQueryHandler(on_button, pattern=r"^(add|cancel|uok|uno):"))
    app.add_error_handler(on_error)
    app.job_queue.run_repeating(cycle, interval=3600, first=10)  # hourly
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
