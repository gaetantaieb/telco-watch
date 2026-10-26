import asyncio
import hashlib
import html
import logging
import os
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta

from psycopg.types.json import Jsonb
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
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
CHAT_IDS = [int(x) for x in os.environ.get("ALLOWED_CHAT_IDS", "0").split(",") if x]
ADMINS = {int(x) for x in os.environ.get("ADMIN_USER_IDS", "").split(",") if x}
MIN_CVSS = float(os.environ.get("MIN_CVSS", "7.0"))
ALLOWED = filters.Chat(chat_id=CHAT_IDS)
PENDING = {}  # /addvendor proposals waiting for an admin's approval
LAST_ASK = {}  # user id -> time of last /ask


def http():
    return col.client()  # public https only, redirects included


# ---------- scoring, formatting, storage ----------
def severity(it):
    if it["kev"]:
        return "🔴 CRITICAL · ⚠️ KEV"
    s = it["cvss"]
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


def worth_sending(it):
    return it["kev"] or it["cvss"] is None or it["cvss"] >= MIN_CVSS


def fmt(it):
    e = html.escape
    score = f" · CVSS {it['cvss']}" if it["cvss"] is not None else ""
    return (
        f"<b>{severity(it)}{score}</b>\n"
        f"<b>Vendor:</b> {e(it['vendor'])}\n"
        f"<b>Title:</b> {e(it['title'] or '')}\n"
        f"<b>CVE:</b> {e(', '.join(it['cves']) or '—')}\n"
        f"<b>Published:</b> {e(it['published'] or '')}\n"
        f"{e(it['url'] or '')}"
    )


def store(it):
    """Insert an item; True only if it was not already in the database."""
    key = hashlib.sha256(f"{it['vendor']}|{it['id']}".encode()).hexdigest()
    row = db.q(
        "INSERT INTO items (key, vendor, title, url, cves, cvss, kev, published) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
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
        ),
        one=True,
    )
    return row is not None


# ---------- the hourly cycle ----------
async def cycle(context: ContextTypes.DEFAULT_TYPE):
    started = datetime.now(UTC)
    last = db.get_state("last_run")
    first_run = last is None  # store the backlog, send nothing
    since = datetime.fromisoformat(last) if last else started - timedelta(hours=24)
    vendors = db.q("SELECT name, nvd_keyword FROM vendors WHERE enabled")
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
            new += [it for it in items if store(it) and worth_sending(it)]
    db.set_state("last_run", started.isoformat())
    db.set_state(
        "last_status",
        f"{started:%Y-%m-%d %H:%M} UTC · {len(new)} new · failed: {', '.join(failed) or 'none'}",
    )
    if first_run:
        log.info("first run: backlog stored, nothing sent")
        return
    for it in new:
        for chat in CHAT_IDS:
            await context.bot.send_message(
                chat, fmt(it), parse_mode=ParseMode.HTML, disable_web_page_preview=True
            )
            await asyncio.sleep(1.1)  # Telegram rate limit
    if failed:
        for chat in CHAT_IDS:
            await context.bot.send_message(
                chat, "⚠️ Sources failed: " + ", ".join(failed)
            )


# ---------- commands ----------
def admin_only(fn):
    async def wrapper(u: Update, c: ContextTypes.DEFAULT_TYPE):
        if u.effective_user.id not in ADMINS:
            return await u.effective_message.reply_text("Admins only.")
        return await fn(u, c)

    return wrapper


async def start(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await u.message.reply_text(
        "Telco Vendor Watch is running. Commands: /status /latest "
        "/vendors /ask /checknow /addvendor /removevendor"
    )


async def status(u: Update, c: ContextTypes.DEFAULT_TYPE):
    await u.message.reply_text(db.get_state("last_status") or "No cycle yet.")


async def latest(u: Update, c: ContextTypes.DEFAULT_TYPE):
    args = c.args or []
    n = int(args[-1]) if args and args[-1].isdigit() else 5
    vendor = args[0] if args and not args[0].isdigit() else None
    sql = "SELECT * FROM items" + (" WHERE vendor ILIKE %s" if vendor else "")
    params = ([f"%{vendor}%"] if vendor else []) + [min(n, 20)]
    rows = db.q(sql + " ORDER BY seen_at DESC LIMIT %s", params)
    if not rows:
        return await u.message.reply_text("Nothing stored yet.")
    for it in rows:
        await u.message.reply_text(
            fmt(it), parse_mode=ParseMode.HTML, disable_web_page_preview=True
        )


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
        return await u.message.reply_text("Usage: /addvendor <vendor name>")
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
    lines = [f"Vendor: {found['vendor']} (NVD keyword: {found['nvd_keyword']})"]
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
    if qy.from_user.id not in ADMINS:
        return await qy.answer("Admins only.", show_alert=True)
    await qy.answer()
    action, pid = qy.data.split(":", 1)
    p = PENDING.pop(pid, None)
    if p is None:
        return await qy.edit_message_text(
            qy.message.text + "\n\nExpired: run /addvendor again."
        )
    if action == "cancel":
        return await qy.edit_message_text(qy.message.text + "\n\nCancelled.")
    db.q(
        "INSERT INTO vendors (name, nvd_keyword) VALUES (%s, %s) ON CONFLICT (name) "
        "DO UPDATE SET enabled = TRUE, nvd_keyword = EXCLUDED.nvd_keyword",
        (p["vendor"], p["nvd_keyword"]),
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


def main():
    db.init()
    app = Application.builder().token(TOKEN).build()
    for name, fn in [
        ("start", start),
        ("status", status),
        ("latest", latest),
        ("vendors", vendors_cmd),
        ("checknow", checknow),
        ("ask", ask_cmd),
        ("addvendor", addvendor),
        ("removevendor", removevendor),
    ]:
        app.add_handler(CommandHandler(name, fn, filters=ALLOWED))
    app.add_handler(CallbackQueryHandler(on_button, pattern=r"^(add|cancel):"))
    app.job_queue.run_repeating(cycle, interval=3600, first=10)  # hourly
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
