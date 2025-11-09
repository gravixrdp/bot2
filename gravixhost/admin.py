from aiogram import Router, F
from aiogram.types import Message, CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

from .config import ADMIN_TELEGRAM_ID, ADMIN_TELEGRAM_IDS
from .keyboards import admin_fixed_bar, main_menu, admin_menu, admin_menu_apps
from .storage import (
    _read_db,
    get_user,
    set_premium,
    remove_premium,
    get_user_bots,
    update_user,
    add_admin_reply,
    get_settings,
    update_settings,
)
from .utils import bold, code, human_dt, pre, escape
import asyncio


router = Router(name="admin")


async def _enrich_user_profile(bot, u: dict) -> dict:
    """
    Try to fill missing name/username for a user by querying Telegram.
    Only updates if fields are empty; silent on failures.
    """
    uid = int(u.get("id"))
    name = (u.get("name") or "").strip()
    uname = (u.get("username") or "").strip()
    if name and uname:
        return u
    try:
        chat = await bot.get_chat(uid)
        new_name = name or (chat.full_name or "").strip()
        new_uname = uname or (chat.username or "").strip()
        if new_name or new_uname:
            update_user(uid, name=new_name or u.get("name"), username=new_uname or u.get("username"))
            # Refresh local copy
            u = get_user(uid)
    except Exception:
        # Ignore if bot cannot access chat info
        pass
    return u


class AdminReplyStates(StatesGroup):
    waiting_reply = State()


class BroadcastStates(StatesGroup):
    choosing_audience = State()
    waiting_text = State()


def is_admin(user_id: int) -> bool:
    return bool(ADMIN_TELEGRAM_IDS) and user_id in ADMIN_TELEGRAM_IDS


@router.message(Command("admin"))
async def admin_entry(message: Message):
    if not is_admin(message.from_user.id):
        return
    await message.answer(
        bold("🛡️ Admin Panel"),
        reply_markup=admin_menu(),
        parse_mode=ParseMode.HTML,
    )


# Reply-keyboard based admin navigation
@router.message(F.text == "👥 Users")
async def admin_users_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    db = _read_db()
    users = list(db["users"].values())
    text = [bold("👥 Users")]
    from datetime import datetime
    now = datetime.utcnow()
    
    # Enrich user profiles with fresh data from Telegram
    enriched_users = []
    for u in users:
        try:
            enriched = await _enrich_user_profile(message.bot, u)
            enriched_users.append(enriched)
        except Exception:
            # If enrichment fails, use original data
            enriched_users.append(u)
    
    for u in enriched_users:
        apps_count = len(get_user_bots(u["id"]))
        display_name = _format_user_display(u)
        referrals = int((u.get("referral_count") or 0))
        exp_dt = _safe_parse(u.get("premium_expiry"))
        is_prem = bool(u.get("is_premium"))
        if is_prem and exp_dt and now < exp_dt:
            expiry_text = f"Active until {human_dt(exp_dt)}"
        elif is_prem and exp_dt:
            expiry_text = f"Expired on {human_dt(exp_dt)}"
        else:
            # For non-premium users, do not show any stored expiry
            expiry_text = "Not Applicable"
        text.append(
            f"• {bold(display_name)} — ID {code(str(u['id']))} — "
            f"Status: {'Premium' if is_prem else 'Free'} — "
            f"Apps: {bold(str(apps_count))} — "
            f"Referrals: {bold(str(referrals))} — "
            f"Expiry: {expiry_text}"
        )
    await message.answer("\n".join(text), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


def _safe_parse(s):
    if not s:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _format_user_display(u: dict) -> str:
    """
    Combine username and name for display:
    - If username exists, include as @username
    - If name exists, include after username
    - Format: @username Name or Name (if no username) or Unknown
    """
    uname = (u.get("username") or "").strip()
    name = (u.get("name") or "").strip()
    parts = []
    if uname:
        parts.append(f"@{uname}")
    if name:
        parts.append(f"({name})")
    result = " ".join(parts).strip()
    if not result:
        # Fallback: try to get from first_name/last_name if available
        first_name = u.get("first_name") or ""
        last_name = u.get("last_name") or ""
        full_name = (first_name + " " + last_name).strip()
        if full_name:
            return full_name
    return result or f"User {u.get('id', 'Unknown')}"


@router.message(F.text == "💎 Premium")
async def admin_premium_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    await message.answer(
        bold("💎 Premium Controls") + "\nSend: " + code("premium <user_id> <days>") + " or " + code("unpremium <user_id>"),
        reply_markup=admin_menu(),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text == "📢 Broadcast")
async def admin_broadcast_msg(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Free Users", callback_data="admin_broadcast:free"),
                InlineKeyboardButton(text="Premium Users", callback_data="admin_broadcast:premium"),
            ],
            [
                InlineKeyboardButton(text="Both", callback_data="admin_broadcast:both"),
            ],
        ]
    )
    await state.set_state(BroadcastStates.choosing_audience)
    await message.answer(bold("📢 Broadcast") + "\nChoose audience:", reply_markup=kb, parse_mode=ParseMode.HTML)

@router.message(F.text == "💬 Inbox")
async def admin_inbox(message: Message):
    if not is_admin(message.from_user.id):
        return
    from .storage import get_messages
    msgs = get_messages(limit=50)
    if not msgs:
        await message.answer(bold("💬 Inbox") + "\nNo messages yet.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
        return
    # Build readable list
    lines = [bold("💬 Inbox (last 50)") + "\n" + code("Use: reply <user_id> <your message>")]
    for m in msgs:
        u = get_user(int(m["user_id"]))
        display_name = _format_user_display(u)
        prefix = "Admin →" if m.get("from_admin") else "User →"
        lines.append(f"• {m['time']} — {bold(display_name)} ({code(str(m['user_id']))}) — {prefix}")
        lines.append(f"  {escape(m['text'])}")
    await message.answer("\n".join(lines), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^reply\s+\d+\s+.+$"))
async def admin_reply(message: Message):
    """
    Admin can reply to a user from the inbox using:
    reply <user_id> <your message>
    """
    if not is_admin(message.from_user.id):
        return
    parts = message.text.split(maxsplit=2)
    if len(parts) < 3:
        await message.answer("Usage: " + code("reply <user_id> <message>"), parse_mode=ParseMode.HTML, reply_markup=admin_menu())
        return
    try:
        target_id = int(parts[1])
    except Exception:
        await message.answer("Invalid user_id.", parse_mode=ParseMode.HTML, reply_markup=admin_menu())
        return
    text = parts[2].strip()
    if not text:
        await message.answer("Message cannot be empty.", parse_mode=ParseMode.HTML, reply_markup=admin_menu())
        return
    # Send message to user and log it
    try:
        await message.bot.send_message(chat_id=target_id, text=text, parse_mode=ParseMode.HTML)
        add_admin_reply(target_user_id=target_id, admin_id=message.from_user.id, text=text)
        await message.answer("✅ Reply sent.", parse_mode=ParseMode.HTML, reply_markup=admin_menu())
    except Exception:
        await message.answer("❌ Failed to deliver reply (user may not have started the bot).", parse_mode=ParseMode.HTML, reply_markup=admin_menu())


@router.message(F.text == "📦 Apps")
async def admin_apps_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    db = _read_db()
    bots = list(db["bots"].values())
    
    # Show app count
    total_apps = len(bots)
    text = [bold(f"📦 Apps — Total: {total_apps}")]
    
    if not bots:
        await message.answer(bold("No bots yet."), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        return

    # Group bots by owner for display
    owners = {}
    for b in bots:
        owners.setdefault(b["owner_id"], []).append(b)

    for owner_id, owner_bots in owners.items():
        u = get_user(int(owner_id))
        # Try to enrich profile if missing name/username
        try:
            u = await _enrich_user_profile(message.bot, u)
        except Exception:
            pass
        owner_display = _format_user_display(u)
        text.append(f"\n{bold(owner_display)} ({code(str(owner_id))})")
        for b in owner_bots:
            text.append(
                f"• {bold(b.get('name') or 'Unknown')} — ID {code(b['id'])} — Status: {bold(b['status'])}"
            )

    await message.answer("\n".join(text), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)

    # Show combined inline keyboard with all actions for all bots
    from .keyboards import bots_combined_actions
    if bots:
        await message.answer(
            bold("⚡ Quick Actions") + "\nSelect an action for any bot:",
            reply_markup=bots_combined_actions(bots),
            parse_mode=ParseMode.HTML
        )

    


@router.message(F.text == "🧾 Logs")
async def admin_logs_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    db = _read_db()
    logs = db["logs"][-30:]
    header = bold("🧾 Logs (last 30)")
    body = pre("\n".join(["• {0} — {1}".format(l['time'], l['event']) for l in logs]))
    await message.answer(header + "\n" + body, reply_markup=admin_menu(), parse_mode=ParseMode.HTML)

@router.message(F.text == "🗑️ Clear Admin Logs")
async def admin_clear_logs(message: Message):
    if not is_admin(message.from_user.id):
        return
    from .storage import clear_admin_logs, log_event_admin
    clear_admin_logs()
    log_event_admin(f"Admin {message.from_user.id} cleared admin logs")
    await message.answer("✅ Admin logs cleared.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


# Settings commands
@router.message(F.text.regexp(r"^setfree\s+\d+$"))
async def admin_set_free_time(message: Message):
    if not is_admin(message.from_user.id):
        return
    parts = message.text.strip().split()
    minutes = int(parts[1])
    from .storage import update_settings
    update_settings(free_duration_minutes=minutes)
    await message.answer(f"✅ Free hosting time set to {bold(str(minutes))} minutes.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setrestart\s+(on|off)$"))
async def admin_set_restart(message: Message):
    if not is_admin(message.from_user.id):
        return
    mode = message.text.strip().split()[1].lower()
    if mode not in {"on", "off"}:
        await message.answer("Usage: " + code("setrestart <on|off>"), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
        return
    from .storage import update_settings
    update_settings(restart_policy=mode)
    await message.answer(f"✅ Restart policy {bold('Enabled' if mode=='on' else 'Disabled')}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setcpu\s+[0-9]+(\.[0-9]+)?$"))
async def admin_set_cpu(message: Message):
    if not is_admin(message.from_user.id):
        return
    value = message.text.strip().split()[1]
    try:
        _ = float(value)
    except Exception:
        await message.answer("Usage: " + code("setcpu <fraction>"), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
        return
    from .storage import update_settings
    update_settings(cpu_limit=value)
    await message.answer(f"✅ CPU limit set to {bold(value)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setmem\s+\S+$"))
async def admin_set_mem(message: Message):
    if not is_admin(message.from_user.id):
        return
    value = message.text.strip().split()[1]
    from .storage import update_settings
    update_settings(mem_limit=value)
    await message.answer(f"✅ Memory limit set to {bold(value)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setnetwork\s+\S+$"))
async def admin_set_network(message: Message):
    if not is_admin(message.from_user.id):
        return
    value = message.text.strip().split()[1]
    from .storage import update_settings
    # 'off' clears network
    update_settings(network=None if value.lower() == "off" else value)
    await message.answer(f"✅ Network set to {bold('default' if value.lower()=='off' else value)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text == "⚙️ Settings")
async def admin_settings_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    from .storage import get_settings
    s = get_settings()
    free_minutes = s.get("free_duration_minutes")
    restart_on = s.get("restart_policy") == "on"
    cpu = s.get("cpu_limit")
    mem = s.get("mem_limit")
    net = s.get("network") or "default"
    run_mode = s.get("run_mode", "runner")
    text = (
        bold("⚙️ Settings") + "\n"
        + f"• Free hosting time: {bold(str(free_minutes))} minutes\n"
        + f"• Restart policy: {bold('Enabled' if restart_on else 'Disabled')}\n"
        + f"• CPU limit: {bold(str(cpu))}\n"
        + f"• Memory limit: {bold(str(mem))}\n"
        + f"• Network: {bold(str(net))}\n"
        + f"• Run mode: {bold(run_mode)}\n\n"
        + "Use commands to adjust:\n"
        + code("setfree <minutes>") + " — e.g., setfree 60\n"
        + code("setrestart <on|off>") + " — e.g., setrestart on\n"
        + code("setcpu <fraction>") + " — e.g., setcpu 0.5\n"
        + code("setmem <limit>") + " — e.g., setmem 256m\n"
        + code("setnetwork <name|off>") + " — e.g., setnetwork mynet or setnetwork off\n"
        + code("setrun <runner|direct>") + " — e.g., setrun direct\n"
    )
    await message.answer(text, reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(BroadcastStates.waiting_text, F.text)
async def admin_broadcast_send(message: Message, state: FSMContext):
    if not is_admin(message.from_user.id):
        return
    data = await state.get_data()
    audience = (data.get("broadcast_audience") or "").lower()
    if audience not in {"free", "premium", "both"}:
        await message.answer("Invalid broadcast audience. Start again: tap 📢 Broadcast.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
        await state.clear()
        return

    db = _read_db()
    users = list(db.get("users", {}).values())
    targets = []
    for u in users:
        is_premium = bool(u.get("is_premium"))
        if audience == "both":
            targets.append(int(u["id"]))
        elif audience == "premium" and is_premium:
            targets.append(int(u["id"]))
        elif audience == "free" and not is_premium:
            targets.append(int(u["id"]))

    sent = 0
    failed = 0
    for uid in targets:
        try:
            await message.bot.send_message(chat_id=uid, text=message.text, parse_mode=ParseMode.HTML)
            sent += 1
        except Exception:
            failed += 1

    from .storage import log_event_admin
    log_event_admin(f"Broadcast by {message.from_user.id} audience={audience} sent={sent} failed={failed}")

    await message.answer(f"✅ Broadcast completed.\nAudience: {bold(audience.capitalize())}\nDelivered: {bold(str(sent))}\nFailed: {bold(str(failed))}", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
    await state.clear()


@router.message(F.text == "🏠 Main Menu")
async def admin_main_menu_msg(message: Message):
    if not is_admin(message.from_user.id):
        return
    await admin_entry(message)


@router.message(F.text == "🛡️ Admin Panel")
async def admin_panel_button(message: Message):
    if not is_admin(message.from_user.id):
        return
    await admin_entry(message)


# Quick-action helper buttons (send usage if no id provided)
@router.message(F.text.in_(["stopbot", "restartbot", "removebot", "logsbot"]))
async def admin_action_help(message: Message):
    if not is_admin(message.from_user.id):
        return
    action = message.text.strip()
    usage_map = {
        "stopbot": "stopbot <id>",
        "restartbot": "restartbot <id>",
        "removebot": "removebot <id>",
        "logsbot": "logsbot <id>",
    }
    usage = usage_map[action]
    # Also list bots with IDs for convenience
    db = _read_db()
    lines = [bold("📦 Bots List")]
    for b in db["bots"].values():
        lines.append(f"• {bold(b.get('name') or 'Unknown')} — ID {code(b['id'])} — Owner {code(str(b['owner_id']))}")
    lines.append("\nSend: " + code(usage))
    await message.answer("\n".join(lines), parse_mode=ParseMode.HTML, reply_markup=admin_menu_apps())


# Existing command regex handlers (with IDs)
@router.message(F.text.regexp(r"^premium\s+\d+\s+\d+$"))
async def premium_set(message: Message):
    if not is_admin(message.from_user.id):
        return
    parts = message.text.strip().split()
    user_id = int(parts[1])
    days = int(parts[2])

    # Capture previous state
    prev = get_user(user_id)
    was_premium = bool(prev.get("is_premium"))

    set_premium(user_id, days)

    # Notify admin
    await message.answer(
        f"✅ Premium set for {code(str(user_id))} for {days} days.",
        parse_mode=ParseMode.HTML,
        reply_markup=admin_menu(),
    )

    # Notify the target user with a premium-styled welcome
    try:
        from datetime import datetime
        from .keyboards import channel_join_kb
        updated = get_user(user_id)
        expiry_str = updated.get("premium_expiry")
        expiry_text = human_dt(datetime.fromisoformat(expiry_str)) if expiry_str else "Not set"

        premium_msg = (
            "╔═══════════════════════╗\n"
            "    🌟 WELCOME TO GRAVIXVPSBOT 🌟\n"
            "╚═══════════════════════╝\n\n"
            f"👋 Welcome {updated.get('name') or 'User'}!\n"
            f"🆔 Your ID: {code(str(user_id))}\n"
            "💎 Plan: Premium — Active\n"
            f"📅 Expires on: {bold(expiry_text)}\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "🔥 PREMIUM FEATURES:\n\n"
            "⏱️ Unlimited Uptime — your bots stay online\n"
            "🤖 Multiple Bots — host more than one bot\n"
            "💬 Priority Support — access Contact Admin\n"
            "⚙️ Manage My Bots — view, stop, restart, remove\n"
            "📜 Bot & System Logs — inspect recent activity\n"
            "👤 My Info — account and usage overview\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "✨ Welcome aboard — enjoy premium capabilities! ✨\n"
        )

        # Send the premium welcome with a channel join button
        await message.bot.send_message(
            chat_id=user_id,
            text=premium_msg,
            reply_markup=channel_join_kb(),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        # Silent fail if bot can't message the user (e.g., user never started the bot)
        pass


@router.message(F.text.regexp(r"^unpremium\s+\d+$"))
async def premium_remove(message: Message):
    if not is_admin(message.from_user.id):
        return
    parts = message.text.strip().split()
    user_id = int(parts[1])
    remove_premium(user_id)
    await message.answer(f"✅ Premium removed for {code(str(user_id))}.", parse_mode=ParseMode.HTML, reply_markup=admin_menu())

    # Notify the target user about deactivation
    try:
        from .keyboards import support_url_kb
        u = get_user(user_id)
        display_name = u.get("name") or "User"
        deact_msg = (
            "╔═══════════════════════╗\n"
            "    🌟 WELCOME TO GRAVIXVPSBOT 🌟\n"
            "╚═══════════════════════╝\n\n"
            f"👋 Hello {display_name}!\n"
            f"🆔 Your ID: {code(str(user_id))}\n"
            "💎 Plan: Premium — Deactivated\n"
            "📅 Expiry: Expired\n\n"
            "━━━━━━━━━━━━━━━━━━━━\n"
            "Your premium has been deactivated. You can continue using the Free plan.\n\n"
            "To restore Premium (unlimited uptime, multi-bot hosting, priority support), contact us below.\n"
        )
        await message.bot.send_message(
            chat_id=user_id,
            text=deact_msg,
            reply_markup=support_url_kb(),
            parse_mode=ParseMode.HTML,
        )
    except Exception:
        # Silent if user cannot be messaged
        pass


@router.message(F.text.regexp(r"^stopbot\s+\S+$"))
async def admin_stopbot(message: Message):
    if not is_admin(message.from_user.id):
        return
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot, mark_stopped, log_event_admin
    from .services.hoster import stop_runtime
    b = get_bot(bot_id)
    if not b:
        await message.answer("Bot not found.", reply_markup=admin_menu_apps())
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    mark_stopped(bot_id)
    log_event_admin(f"Admin {message.from_user.id} stopped bot {bot_id}")
    await message.answer(f"🛑 Stopped {code(bot_id)}", parse_mode=ParseMode.HTML, reply_markup=admin_menu_apps())


@router.message(F.text.regexp(r"^restartbot\s+\S+$"))
async def admin_restartbot(message: Message):
    if not is_admin(message.from_user.id):
        return
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot
    from .services.hoster import restart_runtime
    b = get_bot(bot_id)
    if not b:
        await message.answer("Bot not found.", reply_markup=admin_menu_apps())
        return
    rid = b.get("runtime_id")
    if rid and restart_runtime(rid):
        await message.answer(f"♻️ Restarted {code(bot_id)}", parse_mode=ParseMode.HTML, reply_markup=admin_menu_apps())
    else:
        await message.answer("Failed to restart.", reply_markup=admin_menu_apps())


@router.message(F.text.regexp(r"^removebot\s+\S+$"))
async def admin_removebot(message: Message):
    if not is_admin(message.from_user.id):
        return
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot, delete_bot
    from .services.hoster import stop_runtime, remove_workspace, remove_image
    b = get_bot(bot_id)
    if not b:
        await message.answer("Bot not found.", reply_markup=admin_menu_apps())
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    # remove workspace and image
    image_tag = f"gravixhost_{b['owner_id']}_{bot_id}".lower()
    remove_image(image_tag)
    if b.get("path"):
        remove_workspace(b["path"])
    delete_bot(bot_id)
    await message.answer(f"🗑️ Removed {code(bot_id)}", parse_mode=ParseMode.HTML, reply_markup=admin_menu_apps())


@router.message(F.text.regexp(r"^logsbot\s+\S+$"))
async def admin_logsbot(message: Message):
    if not is_admin(message.from_user.id):
        return
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot
    from .services.hoster import get_runtime_logs

    db = _read_db()
    logs = []
    for entry in reversed(db.get("logs", [])):
        ev = entry.get("event", "")
        if bot_id in ev:
            logs.append(f"• {entry.get('time','')} — {ev}")
        if len(logs) >= 100:
            break

    # Try to fetch container logs too
    b = get_bot(bot_id)
    runtime_text = ""
    if b and b.get("runtime_id"):
        rid = b["runtime_id"]
        docker_logs = await asyncio.to_thread(get_runtime_logs, rid, 200)
        if docker_logs:
            runtime_text = docker_logs.strip()

    if not logs and not runtime_text:
        await message.answer(bold("No logs for this bot."), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        return

    # Chunked send of system logs
    if logs:
        header = bold("🧾 Bot Logs (system)")
        chunk = []
        current_len = 0
        for line in logs:
            if current_len + len(line) + 1 > 3500:
                await message.answer(header + "\n" + pre("\n".join(chunk)), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
                chunk = []
                current_len = 0
            chunk.append(line)
            current_len += len(line) + 1
        if chunk:
            await message.answer(header + " (cont.)\n" + pre("\n".join(chunk)), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)

    # Send docker logs
    if runtime_text:
        await message.answer(bold("🧾 Bot Logs (container)") + "\n" + pre(runtime_text[-3500:]), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)


# Keep callback-based handlers for backward compatibility (not used by the new UI)
@router.callback_query(F.data == "admin_users")
async def admin_users(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    db = _read_db()
    users = list(db["users"].values())
    text = [bold("👥 Users")]
    enriched = []
    for u in users:
        u2 = await _enrich_user_profile(cb.message.bot, u)
        enriched.append(u2)
    from datetime import datetime
    now = datetime.utcnow()
    for u in enriched:
        display_name = _format_user_display(u)
        apps_count = len(get_user_bots(u["id"]))
        referrals = int((u.get("referral_count") or 0))
        exp_dt = _safe_parse(u.get("premium_expiry"))
        is_prem = bool(u.get("is_premium"))
        if is_prem and exp_dt and now < exp_dt:
            expiry_text = f"Active until {human_dt(exp_dt)}"
        elif exp_dt:
            expiry_text = f"Expired on {human_dt(exp_dt)}"
        else:
            expiry_text = "Not Applicable"
        text.append(
            f"• {bold(display_name)} — ID {code(str(u['id']))} — "
            f"Status: {'Premium' if is_prem else 'Free'} — "
            f"Apps: {bold(str(apps_count))} — "
            f"Referrals: {bold(str(referrals))} — "
            f"Expiry: {expiry_text}"
        )
    await cb.message.answer("\n".join(text), reply_markup=admin_fixed_bar(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data == "admin_premium")
async def admin_premium(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    await cb.message.answer(
        bold("💎 Premium Controls") + "\nSend: " + code("premium <user_id> <days>") + " or " + code("unpremium <user_id>"),
        reply_markup=admin_fixed_bar(),
        parse_mode=ParseMode.HTML,
    )
    await cb.answer()


@router.callback_query(F.data == "admin_broadcast")
async def admin_broadcast_cb(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id):
        return
    from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
    kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="Free Users", callback_data="admin_broadcast:free"),
                InlineKeyboardButton(text="Premium Users", callback_data="admin_broadcast:premium"),
            ],
            [
                InlineKeyboardButton(text="Both", callback_data="admin_broadcast:both"),
            ],
        ]
    )
    await state.set_state(BroadcastStates.choosing_audience)
    await cb.message.answer(bold("📢 Broadcast") + "\nChoose audience:", reply_markup=kb, parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("admin_broadcast:"))
async def admin_broadcast_choose(cb: CallbackQuery, state: FSMContext):
    if not is_admin(cb.from_user.id):
        return
    audience = cb.data.split(":", 1)[1]
    if audience not in {"free", "premium", "both"}:
        await cb.message.answer("Invalid audience selection.", reply_markup=admin_fixed_bar(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    await state.update_data(broadcast_audience=audience)
    await state.set_state(BroadcastStates.waiting_text)
    await cb.message.answer(bold("📢 Broadcast") + f"\nAudience: {bold(audience.capitalize())}\nSend the message text to broadcast.", parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data == "admin_apps")
async def admin_apps(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    db = _read_db()
    bots = list(db["bots"].values())
    
    # Show app count
    total_apps = len(bots)
    text = [bold(f"📦 Apps — Total: {total_apps}")]

    if not bots:
        await cb.message.answer(bold("No bots yet."), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return

    # Group bots by owner
    owners = {}
    for b in bots:
        owners.setdefault(b["owner_id"], []).append(b)

    for owner_id, owner_bots in owners.items():
        u = get_user(int(owner_id))
        owner_display = _format_user_display(u)
        text.append(f"\n{bold(owner_display)} ({code(str(owner_id))})")
        for b in owner_bots:
            text.append(
                f"• {bold(b.get('name') or 'Unknown')} — ID {code(b['id'])} — Status: {bold(b['status'])}"
            )

    await cb.message.answer("\n".join(text), reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)

    # Show combined inline keyboard with all actions for all bots
    from .keyboards import bots_combined_actions
    if bots:
        await cb.message.answer(
            bold("⚡ Quick Actions") + "\nSelect an action for any bot:",
            reply_markup=bots_combined_actions(bots),
            parse_mode=ParseMode.HTML
        )
    await cb.answer()


@router.callback_query(F.data.startswith("admin_stop:"))
async def admin_cb_stop(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot, mark_stopped
    from .services.hoster import stop_runtime
    b = get_bot(bot_id)
    if not b:
        await cb.message.answer("Bot not found.", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    mark_stopped(bot_id)
    await cb.message.answer(f"🛑 Stopped {code(bot_id)}", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("admin_restart:"))
async def admin_cb_restart(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot
    from .services.hoster import restart_runtime
    b = get_bot(bot_id)
    if not b:
        await cb.message.answer("Bot not found.", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    rid = b.get("runtime_id")
    if rid and restart_runtime(rid):
        await cb.message.answer(f"♻️ Restarted {code(bot_id)}", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
    else:
        await cb.message.answer("Failed to restart.", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("admin_remove:"))
async def admin_cb_remove(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot, delete_bot
    from .services.hoster import stop_runtime, remove_workspace, remove_image
    b = get_bot(bot_id)
    if not b:
        await cb.message.answer("Bot not found.", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    image_tag = f"gravixhost_{b['owner_id']}_{bot_id}".lower()
    remove_image(image_tag)
    if b.get("path"):
        remove_workspace(b["path"])
    delete_bot(bot_id)
    await cb.message.answer(f"🗑️ Removed {code(bot_id)}", reply_markup=admin_menu_apps(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("admin_logs:"))
async def admin_cb_logs(cb: CallbackQuery):
    """
    Show logs for a bot - just display logs, no more buttons.
    """
    if not is_admin(cb.from_user.id):
        return
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot
    from .services.hoster import get_runtime_logs

    db = _read_db()
    logs = []
    for entry in reversed(db.get("logs", [])):
        ev = entry.get("event", "")
        if bot_id in ev:
            logs.append(f"• {entry.get('time','')} — {ev}")
        if len(logs) >= 100:
            break

    # Try to fetch container logs too
    b = get_bot(bot_id)
    runtime_text = ""
    if b and b.get("runtime_id"):
        rid = b["runtime_id"]
        docker_logs = await asyncio.to_thread(get_runtime_logs, rid, 200)
        if docker_logs:
            runtime_text = docker_logs.strip()

    if not logs and not runtime_text:
        await cb.message.answer(bold("No logs for this bot."), parse_mode=ParseMode.HTML)
        await cb.answer()
        return

    # Chunked send of system logs
    if logs:
        header = bold("🧾 Bot Logs (system)")
        chunk = []
        current_len = 0
        for line in logs:
            if current_len + len(line) + 1 > 3500:
                await cb.message.answer(header + "\n" + pre("\n".join(chunk)), parse_mode=ParseMode.HTML)
                chunk = []
                current_len = 0
            chunk.append(line)
            current_len += len(line) + 1
        if chunk:
            await cb.message.answer(header + " (cont.)\n" + pre("\n".join(chunk)), parse_mode=ParseMode.HTML)

    # Send docker logs
    if runtime_text:
        await cb.message.answer(bold("🧾 Bot Logs (container)") + "\n" + pre(runtime_text[-3500:]), parse_mode=ParseMode.HTML)
    
    await cb.answer()


@router.callback_query(F.data.startswith("admin_bot_info:"))
async def admin_cb_bot_info(cb: CallbackQuery):
    # Placeholder for bot info - just answer the callback (no action needed, it's just a label)
    await cb.answer()


@router.callback_query(F.data == "admin_logs")
async def admin_logs(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    db = _read_db()
    logs = db["logs"][-30:]
    header = bold("🧾 Logs (last 30)")
    body = pre("\n".join(["• {0} — {1}".format(l['time'], l['event']) for l in logs]))
    await cb.message.answer(header + "\n" + body, reply_markup=admin_fixed_bar(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data == "admin_settings")
async def admin_settings(cb: CallbackQuery):
    if not is_admin(cb.from_user.id):
        return
    s = get_settings()
    free_mins = s.get("free_duration_minutes", 60)
    restart = "Enabled" if str(s.get("restart_policy", "on")).lower() == "on" else "Disabled"
    cpu = s.get("cpu_limit", "0.5")
    mem = s.get("mem_limit", "256m")
    net = s.get("network") or "default"
    text = (
        bold("⚙️ Settings") + "\n"
        + f"• Free hosting time: {bold(str(free_mins))} min\n"
        + f"• Restart policy: {bold(restart)}\n"
        + f"• CPU limit: {bold(str(cpu))}\n"
        + f"• Memory limit: {bold(str(mem))}\n"
        + f"• Network: {bold(str(net))}\n\n"
        + code("setfree <minutes>") + " — e.g., setfree 120\n"
        + code("setrestart <on|off>") + " — e.g., setrestart off\n"
        + code("setcpu <fraction>") + " — e.g., setcpu 0.75\n"
        + code("setmem <limit>") + " — e.g., setmem 512m\n"
        + code("setnetwork <name|off>") + " — e.g., setnetwork mynet or setnetwork off\n"
    )
    await cb.message.answer(text, reply_markup=admin_fixed_bar(), parse_mode=ParseMode.HTML)
    await cb.answer()


# Settings update handlers
@router.message(F.text.regexp(r"^setfree\s+\d+$"))
async def set_free_time(message: Message):
    if not is_admin(message.from_user.id):
        return
    try:
        minutes = int(message.text.strip().split()[1])
        update_settings(free_duration_minutes=max(1, minutes))
        await message.answer(f"✅ Free hosting time set to {code(str(minutes))} minutes.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
    except Exception:
        await message.answer("❌ Invalid value. Usage: " + code("setfree <minutes>"), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setrestart\s+\S+$"))
async def set_restart_policy(message: Message):
    if not is_admin(message.from_user.id):
        return
    val = message.text.strip().split()[1].lower()
    if val in {"on", "off"}:
        update_settings(restart_policy=val)
        await message.answer(f"✅ Restart policy set to {bold('Enabled' if val=='on' else 'Disabled')}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
    else:
        await message.answer("❌ Invalid value. Use: " + code("setrestart <on|off>"), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setcpu\s+[0-9]*\.?[0-9]+$"))
async def set_cpu_limit(message: Message):
    if not is_admin(message.from_user.id):
        return
    try:
        val = float(message.text.strip().split()[1])
        update_settings(cpu_limit=str(val))
        await message.answer(f"✅ CPU limit set to {code(str(val))}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
    except Exception:
        await message.answer("❌ Invalid value. Usage: " + code("setcpu <fraction>"), reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setmem\s+\S+$"))
async def set_mem_limit(message: Message):
    if not is_admin(message.from_user.id):
        return
    val = message.text.strip().split()[1]
    update_settings(mem_limit=val)
    await message.answer(f"✅ Memory limit set to {code(val)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^setnetwork\s+\S+$"))
async def set_network(message: Message):
    if not is_admin(message.from_user.id):
        return
    val = message.text.strip().split()[1]
    if val.lower() in {"off", "none", "default"}:
        update_settings(network=None)
        await message.answer("✅ Network set to default.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)
    else:
        update_settings(network=val)
        await message.answer(f"✅ Network set to {code(val)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)

@router.message(F.text.regexp(r"^setrun\s+(runner|direct)$"))
async def set_run_mode(message: Message):
    if not is_admin(message.from_user.id):
        return
    mode = message.text.strip().split()[1].lower()
    update_settings(run_mode=mode)
    await message.answer(f"✅ Run mode set to {bold(mode)}.", reply_markup=admin_menu(), parse_mode=ParseMode.HTML)