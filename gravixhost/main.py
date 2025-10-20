import asyncio
import os
from dataclasses import dataclass
from typing import Optional, Dict, List

from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message, CallbackQuery, Document
from aiogram.filters import Command
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.context import FSMContext

from .config import MASTER_BOT_TOKEN, APP_NAME, ADMIN_TELEGRAM_ID
from .keyboards import main_menu, support_url_kb, user_manage_menu, bots_action_list
from .utils import bold, code, human_dt, is_valid_token, italic, underline, strike, pre
from .storage import (
    get_user,
    update_user,
    add_bot,
    update_bot,
    can_host_more,
    mark_started,
    mark_stopped,
    get_active_bots,
    get_user_bots,
)
from .services.hoster import save_upload, build_and_run, remove_workspace
from .services.scheduler import Scheduler
from .admin import router as admin_router, is_admin
from .services.ai_assistant import suggest_fix


@dataclass
class PendingHost:
    workspace: Optional[str] = None
    entry_name: Optional[str] = None
    token: Optional[str] = None
    bot_record_id: Optional[str] = None
    bot_name: Optional[str] = None


class HostStates(StatesGroup):
    waiting_file = State()
    waiting_name = State()
    waiting_token = State()


class ContactStates(StatesGroup):
    chat = State()


router = Router(name="user")


@router.message(Command("start"))
async def cmd_start(message: Message):
    user = get_user(message.from_user.id)
    update_user(
        message.from_user.id,
        name=message.from_user.full_name,
        username=message.from_user.username
    )
    welcome = (
        f"✨ Welcome to {bold(APP_NAME)}\n"
        f"Host your Telegram bot in a secure, isolated environment.\n\n"
        f"Choose an option below:"
    )
    await message.answer(welcome, reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(message.from_user.id)), parse_mode=ParseMode.HTML)


@router.message(Command("help"))
async def cmd_help(message: Message):
    text = (
        f"{bold('🆘 Help')}\n"
        "• Use '📦 Host My Bot' to upload your bot code.\n"
        "• Upload a .py file or a .zip containing your bot code.\n"
        "• After upload, send your bot token from " + bold("@BotFather") + ".\n"
        "• Free plan: 1 hour; Premium: unlimited uptime 💎.\n"
    )
    await message.answer(text, reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")), parse_mode=ParseMode.HTML)

# Explicit commands to go back to main menu from anywhere
@router.message(Command("back"))
@router.message(Command("menu"))
async def cmd_back_to_menu(message: Message, state: FSMContext):
    await state.clear()
    user = get_user(message.from_user.id)
    await message.answer(bold("🏠 Main Menu"), reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(message.from_user.id)), parse_mode=ParseMode.HTML)

# Robust global Back handler that matches most variants, anywhere
@router.message(F.text.regexp(r"(?i)^\s*(?:/)?\s*(?:⬅️\s*)?back\s*$"))
async def any_back(message: Message, state: FSMContext):
    await state.clear()
    user = get_user(message.from_user.id)
    await message.answer(bold("🏠 Main Menu"), reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(message.from_user.id)), parse_mode=ParseMode.HTML)


@router.message(Command("myinfo"))
async def cmd_myinfo(message: Message):
    user = get_user(message.from_user.id)
    text = (
        f"{bold('👤 User Info')}\n"
        f"• Name: {bold(message.from_user.full_name)}\n"
        f"• ID: {code(str(message.from_user.id))}\n"
        f"• Status: {'Premium User' if user.get('is_premium') else 'Free User'}\n"
        f"• Hosted Bots: {len(get_user_bots(message.from_user.id))}\n"
        f"• Plan Expiry: {bold(human_dt(_safe_parse(user.get('premium_expiry'))))}\n"
    )
    await message.answer(text, reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(message.from_user.id)), parse_mode=ParseMode.HTML)


def _safe_parse(s):
    if not s:
        return None
    from datetime import datetime
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _detect_entry(workspace: str, uploaded_filename: str) -> str:
    # Prefer typical names if present
    candidates = ["bot.py", "app.py", "main.py", "bold.py"]
    for c in candidates:
        p = os.path.join(workspace, c)
        if os.path.exists(p):
            return c
    # If user uploaded a single .py, run that
    if uploaded_filename.lower().endswith(".py"):
        return uploaded_filename
    # Otherwise, pick a top-level .py if available, else first .py anywhere
    tops = []
    any_py = None
    for root, _, files in os.walk(workspace):
        for f in files:
            if f.endswith(".py"):
                if any_py is None:
                    any_py = os.path.relpath(os.path.join(root, f), workspace)
                if os.path.abspath(root) == os.path.abspath(workspace):
                    tops.append(f)
    if tops:
        return tops[0]
    return any_py or "bot.py"


@router.message(Command("upgrade"))
async def cmd_upgrade(message: Message):
    """
    Show upgrade info and provide a direct contact button to @Dravonnbot (admin)
    for all users, including free users.
    """
    text = (
        f"{bold('💎 Upgrade to Premium')}\\n"
        "• Unlimited uptime\\n"
        "• Host multiple bots\\n"
        "• Priority support\\n\\n"
        "To upgrade, contact our admin directly at " + bold("@Dravonnbot") + ".\\n"
        "Use the button below to open the chat."
    )
    # Provide direct link to @Dravonnbot
    await message.answer(text, reply_markup=support_url_kb(), parse_mode=ParseMode.HTML)


@router.message(Command("host"))
async def cmd_host(message: Message, state: FSMContext):
    await _start_host_flow(message, state)


@router.message(Command("bold"))
async def cmd_bold(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/bold Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(bold(parts[1]), parse_mode=ParseMode.HTML)


@router.message(Command("italic"))
async def cmd_italic(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/italic Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(italic(parts[1]), parse_mode=ParseMode.HTML)


@router.message(Command("underline"))
async def cmd_underline(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/underline Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(underline(parts[1]), parse_mode=ParseMode.HTML)


@router.message(Command("strike"))
async def cmd_strike(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/strike Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(strike(parts[1]), parse_mode=ParseMode.HTML)


@router.message(Command("mono"))
async def cmd_mono(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/mono Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(code(parts[1]), parse_mode=ParseMode.HTML)


@router.message(Command("pre"))
async def cmd_pre(message: Message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer("Usage: " + code("/pre Your text here"), parse_mode=ParseMode.HTML)
        return
    await message.answer(pre(parts[1]), parse_mode=ParseMode.HTML)


# Map reply keyboard button texts to actions
@router.message(F.text == "📦 Host My Bot")
async def on_host_btn(message: Message, state: FSMContext):
    await _start_host_flow(message, state)


@router.message(F.text.in_(["📘 How it Works", "ℹ️ How it Works"]))
async def on_how_it_works(message: Message):
    text = (
        f"{bold('📘 How it Works')}\n"
        "• Upload your bot code (.py or a .zip). We auto-detect your entry file.\n"
        "• Send your bot token.\n"
        "• We prepare a secure runtime and get your bot online.\n"
        "• Free plan: 1 hour uptime; Premium: unlimited.\n"
    )
    await message.answer(text, reply_markup=main_menu(get_user(message.from_user.id).get("is_premium"), show_admin=is_admin(message.from_user.id)), parse_mode=ParseMode.HTML)


@router.message(F.text == "💰 Upgrade to Premium")
async def on_upgrade_btn(message: Message):
    await cmd_upgrade(message)


@router.message(F.text == "👤 My Info")
async def on_my_info_btn(message: Message):
    await cmd_myinfo(message)

@router.message(F.text == "⏳ Premium Time Left")
async def on_premium_time_left(message: Message):
    user = get_user(message.from_user.id)
    if not user.get("is_premium"):
        await message.answer(
            bold("⏳ Premium Time Left") + "\nYou are currently on the Free plan.\nUse the upgrade button to get unlimited uptime 💎.",
            reply_markup=main_menu(False),
            parse_mode=ParseMode.HTML,
        )
        return
    expiry_str = user.get("premium_expiry")
    if not expiry_str:
        await message.answer(
            bold("⏳ Premium Time Left") + "\nPremium status is active, but expiry is not set.",
            reply_markup=main_menu(True),
            parse_mode=ParseMode.HTML,
        )
        return
    from datetime import datetime
    try:
        exp_dt = datetime.fromisoformat(expiry_str)
        now = datetime.utcnow()
        if now >= exp_dt:
            await message.answer(
                bold("⏳ Premium Time Left") + "\nYour premium has expired.",
                reply_markup=main_menu(False),
                parse_mode=ParseMode.HTML,
            )
            return
        remaining = exp_dt - now
        days = remaining.days
        hours = remaining.seconds // 3600
        minutes = (remaining.seconds % 3600) // 60
        text = (
            bold("⏳ Premium Time Left") + "\n"
            + f"• Expires on: {bold(human_dt(exp_dt))}\n"
            + f"• Remaining: {bold(f'{days}d {hours}h {minutes}m')}"
        )
        await message.answer(text, reply_markup=main_menu(True), parse_mode=ParseMode.HTML)
    except Exception:
        await message.answer(
            bold("⏳ Premium Time Left") + "\nCould not determine expiry.",
            reply_markup=main_menu(True),
            parse_mode=ParseMode.HTML,
        )


@router.message(F.text == "🆘 Support")
async def on_support(message: Message):
    await message.answer(
        bold("🆘 Support") + "\nUse the button below to contact support:",
        reply_markup=support_url_kb(),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text == "⚙️ Manage My Bots")
async def on_manage_bots(message: Message):
    user = get_user(message.from_user.id)
    bots = get_user_bots(message.from_user.id)
    lines = [bold("⚙️ Manage My Bots")]
    if not bots:
        lines.append("• You have no bots yet. Use '📦 Host My Bot' to upload.")
    else:
        for b in bots:
            lines.append(f"• {bold(b.get('name') or 'MyBot')} — ID {code(b['id'])} — Status: {bold(b['status'])}")
    await message.answer("\n".join(lines), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text == "🔍 My Running Bots")
async def my_running_bots(message: Message):
    bots = [b for b in get_user_bots(message.from_user.id) if b["status"] == "running"]
    if not bots:
        await message.answer(bold("ℹ️ No running bots."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    lines = [bold("🟢 Running Bots")]
    for b in bots:
        lines.append(f"• {bold(b.get('name') or 'MyBot')} — ID {code(b['id'])}")
    await message.answer("\n".join(lines), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text == "🧾 My Logs")
async def my_logs(message: Message):
    # Show last logs related to user's bots
    from .storage import _read_db
    db = _read_db()
    my_ids: List[str] = [b["id"] for b in get_user_bots(message.from_user.id)]
    logs = []
    for entry in reversed(db.get("logs", [])):
        ev = entry.get("event", "")
        if any(bid in ev for bid in my_ids) or str(message.from_user.id) in ev:
            logs.append(f"• {entry.get('time','')} — {ev}")
        if len(logs) >= 50:
            break
    if not logs:
        await message.answer(bold("No logs yet."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    # Split into safe chunks to avoid Telegram message length limit (~4096 chars)
    header = bold("🧾 Your Logs")
    chunk = []
    current_len = 0
    for line in logs:
        if current_len + len(line) + 1 > 3500:
            await message.answer(header + "\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
            chunk = []
            current_len = 0
        chunk.append(line)
        current_len += len(line) + 1
    if chunk:
        await message.answer(header + " (cont.)\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text == "🗑️ Remove My Bot")
async def help_remove_my_bot(message: Message):
    bots = get_user_bots(message.from_user.id)
    if not bots:
        await message.answer(bold("You have no bots."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    await message.answer(
        bold("🗑️ Remove My Bot") + "\nTap a button to delete directly:",
        reply_markup=bots_action_list(bots, "Delete", "user_remove"),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text == "📜 Bot Logs")
async def help_logs_my_bot(message: Message):
    bots = get_user_bots(message.from_user.id)
    if not bots:
        await message.answer(bold("You have no bots."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    await message.answer(
        bold("📜 Bot Logs") + "\nTap a bot to view logs:",
        reply_markup=bots_action_list(bots, "Logs", "user_logs"),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text == "🛑 Stop My Bot")
async def help_stop_my_bot(message: Message):
    bots = get_user_bots(message.from_user.id)
    if not bots:
        await message.answer(bold("You have no bots."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    await message.answer(
        bold("🛑 Stop My Bot") + "\nTap a bot to stop it:",
        reply_markup=bots_action_list(bots, "Stop", "user_stop"),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text == "♻️ Restart My Bot")
async def help_restart_my_bot(message: Message):
    bots = get_user_bots(message.from_user.id)
    if not bots:
        await message.answer(bold("You have no bots."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    await message.answer(
        bold("♻️ Restart My Bot") + "\nTap a bot to restart it:",
        reply_markup=bots_action_list(bots, "Restart", "user_restart"),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.text.regexp(r"^stop\s+\S+$"))
async def user_stop_bot(message: Message):
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot
    from .services.hoster import stop_runtime
    b = get_bot(bot_id)
    if not b or b["owner_id"] != message.from_user.id:
        await message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    mark_stopped(bot_id)
    await message.answer(f"🛑 Stopped {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^restart\s+\S+$"))
async def user_restart_bot(message: Message):
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot
    from .services.hoster import restart_runtime
    b = get_bot(bot_id)
    if not b or b["owner_id"] != message.from_user.id:
        await message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    rid = b.get("runtime_id")
    if rid and restart_runtime(rid):
        await message.answer(f"♻️ Restarted {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    else:
        await message.answer("Failed to restart.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^remove\s+\S+$"))
async def user_remove_bot(message: Message):
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot, delete_bot
    from .services.hoster import stop_runtime, remove_workspace, remove_image
    b = get_bot(bot_id)
    if not b or b["owner_id"] != message.from_user.id:
        await message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    image_tag = f"gravixhost_{b['owner_id']}_{bot_id}".lower()
    remove_image(image_tag)
    if b.get("path"):
        remove_workspace(b["path"])
    delete_bot(bot_id)
    await message.answer(f"🗑️ Removed {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text.regexp(r"^logs\s+\S+$"))
async def user_logs_bot(message: Message):
    bot_id = message.text.strip().split()[1]
    from .storage import get_bot, _read_db
    from .services.hoster import get_runtime_logs
    b = get_bot(bot_id)
    if not b or b["owner_id"] != message.from_user.id:
        await message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return

    # Combine system logs and container logs
    db = _read_db()
    sys_logs = []
    for entry in reversed(db.get("logs", [])):
        ev = entry.get("event", "")
        if bot_id in ev:
            sys_logs.append(f"• {entry.get('time','')} — {ev}")
        if len(sys_logs) >= 50:
            break

    runtime_text = ""
    rid = b.get("runtime_id")
    if rid:
        docker_logs = await asyncio.to_thread(get_runtime_logs, rid, 200)
        if docker_logs:
            runtime_text = docker_logs.strip()

    if not sys_logs and not runtime_text:
        await message.answer(bold("No logs for this bot."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        return

    # Send system logs (chunked)
    if sys_logs:
        header = bold("🧾 Bot Logs (system)")
        chunk = []
        current_len = 0
        for line in sys_logs:
            if current_len + len(line) + 1 > 3500:
                await message.answer(header + "\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
                chunk = []
                current_len = 0
            chunk.append(line)
            current_len += len(line) + 1
        if chunk:
            await message.answer(header + " (cont.)\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)

    # Send recent Docker logs
    if runtime_text:
        await message.answer(bold("🧾 Bot Logs (container)") + "\n" + pre(runtime_text[-3500:]), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)


@router.message(F.text == "🏠 Main Menu")
async def on_main_menu(message: Message):
    user = get_user(message.from_user.id)
    await message.answer(
        bold("🏠 Main Menu"),
        reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(message.from_user.id)),
        parse_mode=ParseMode.HTML,
    )



@router.message(F.text == "💬 Contact Admin")
async def on_contact_admin(message: Message, state: FSMContext):
    user = get_user(message.from_user.id)
    if not user.get("is_premium"):
        await message.answer("This feature is available for premium users only.", parse_mode=ParseMode.HTML)
        return
    from .keyboards import contact_chat_menu
    await state.set_state(ContactStates.chat)
    await message.answer(
        bold("💬 Contact Admin") + "\nType your message below. We'll forward it to the admin.",
        reply_markup=contact_chat_menu(),
        parse_mode=ParseMode.HTML,
    )





async def _start_host_flow(message: Message, state: FSMContext):
    await state.set_state(HostStates.waiting_file)
    await state.update_data(pending=PendingHost().__dict__)
    await message.answer(
        f"{bold('🚀 Let’s get your bot online!')}\nPlease upload a file (like " + code("bot.py") + " or a .zip containing your bot code).",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
        parse_mode=ParseMode.HTML,
    )


@router.message(HostStates.waiting_file, F.document)
async def handle_upload(message: Message, state: FSMContext):
    doc: Document = message.document
    filename = doc.file_name or "upload"
    # Validate extension
    if not (filename.endswith(".py") or filename.endswith(".zip")):
        await message.answer(
            "⚠️ File type not supported.\nPlease upload a .py file or .zip archive.",
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )
        return
    user_id = message.from_user.id
    # Create a bot record (temporary)
    bot_rec = add_bot(user_id, name=os.path.splitext(filename)[0], token="", path="")
    # Download file
    file = await message.bot.get_file(doc.file_id)
    content = await message.bot.download_file(file.file_path)
    data_bytes = content.read()
    workspace = save_upload(user_id, bot_rec["id"], filename, data_bytes)
    update_bot(bot_rec["id"], path=workspace)

    # Detect entry file
    entry_name = _detect_entry(workspace, filename)
    await state.update_data(pending=PendingHost(workspace=workspace, entry_name=entry_name, bot_record_id=bot_rec["id"], bot_name=bot_rec["name"]).__dict__)

    # Ask for app name first
    await message.answer(
        "📝 Please send a name for your app (e.g., MyShopBot).",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
        parse_mode=ParseMode.HTML,
    )
    await state.set_state(HostStates.waiting_name)


@router.message(HostStates.waiting_file)
async def upload_error(message: Message):
    await message.answer(
        f"{bold('⚠️ File type not supported.')}\nPlease upload a .py file or .zip archive.",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
        parse_mode=ParseMode.HTML,
    )


@router.message(HostStates.waiting_name, F.text)
async def handle_app_name(message: Message, state: FSMContext):
    name = (message.text or "").strip()
    if not name:
        await message.answer(
            "⚠️ Please send a non-empty name for your app.",
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )
        return

    # Persist name into bot record and pending state
    data = await state.get_data()
    pending = PendingHost(**data.get("pending"))
    pending.bot_name = name
    update_bot(pending.bot_record_id, name=name)
    await state.update_data(pending=pending.__dict__)

    # Continue to token
    await message.answer(
        "🔐 Please send your bot token (e.g. " + code("123456:ABC-DEF...") + ")",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
        parse_mode=ParseMode.HTML,
    )
    await state.set_state(HostStates.waiting_token)


@router.message(HostStates.waiting_name)
async def handle_app_name_nontext(message: Message):
    await message.answer(
        "⚠️ Please send the app name as a text message.",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
        parse_mode=ParseMode.HTML,
    )


@router.message(HostStates.waiting_token)
async def handle_token(message: Message, state: FSMContext):
    raw = message.text
    from .utils import normalize_token
    token = normalize_token(raw)
    if not token or not await is_valid_token(token):
        await message.answer(
            "❌ That doesn't look like a valid bot token.\nPlease check again from @BotFather.",
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )
        return

    user = get_user(message.from_user.id)
    data = await state.get_data()
    pending = PendingHost(**data.get("pending"))
    # Enforce plan constraints
    if not can_host_more(message.from_user.id):
        await message.answer(
            f"{bold('⚠️ Limit reached')}\nFree users can only host 1 bot for 1 hour.\nStop or wait for it to expire, or upgrade to premium 💎.",
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )
        # Cleanup workspace
        if pending.workspace:
            remove_workspace(pending.workspace)
        await state.clear()
        return

    # Build and deploy
    await message.answer("🔧 Setting up your hosting environment...", reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")), parse_mode=ParseMode.HTML)
    ok, runtime_id, err = build_and_run(message.from_user.id, pending.bot_record_id, token, pending.workspace, entry=pending.entry_name)
    if not ok:
        # Build user-friendly guidance, without exposing infrastructure details.
        base_msg = ""
        if err == "docker_unavailable":
            base_msg = (
                bold("⚠️ Hosting service not available") + "\n"
                + "System thoda busy ya unavailable hai. Please try again after some time."
            )
        elif err == "build_error":
            base_msg = (
                bold("⚠️ Build failed") + "\n"
                + "Kuch dependencies or imports resolve nahi ho rahe.\n"
                + "• Check your requirements.txt (spelling and versions)\n"
                + "• Ensure entry file runs locally: " + code(f"python {pending.entry_name or 'your_file.py'}")
            )
        elif err == "no_entry_py":
            base_msg = (
                bold("⚠️ Entry file not found") + "\n"
                + "Please upload a .py file (e.g., bot.py/app.py/main.py) or a zip with your code."
            )
        else:
            base_msg = (
                bold("⚠️ Setup failed") + "\n"
                + "Please double-check code, imports, and token. Try running locally: "
                + code(f"python {pending.entry_name or 'your_file.py'}")
            )

        # Ask the AI assistant for a concise fix suggestion
        ctx_lines = [
            f"user_id={message.from_user.id}",
            f"bot_id={pending.bot_record_id}",
            f"entry={pending.entry_name}",
            f"error={err}",
            "Goal: get Telegram bot running.",
        ]
        ai_tip = await asyncio.to_thread(suggest_fix, "\n".join([l for l in ctx_lines if l]))
        tip_text = ("\n\n" + bold("Suggested fix") + ":\n" + ai_tip) if ai_tip else ""

        await message.answer(
            base_msg + tip_text,
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )
        await state.clear()
        return

    # Success
    plan = "premium" if user.get("is_premium") else "free"
    mark_started(pending.bot_record_id, plan, runtime_id or "")
    await message.answer(
        f"{bold('✅ Your bot is live!')}\n"
        f"• Name: {bold(pending.bot_name or 'MyBot')}\n"
        f"• ID: {code(pending.bot_record_id)}\n"
        f"• Host Time: {'Unlimited (Premium Plan)' if plan == 'premium' else '1 Hour (Free Plan)'}\n"
        "Use /stop to end early.",
        reply_markup=main_menu(get_user(message.from_user.id).get("is_premium"), show_admin=is_admin(message.from_user.id)),
        parse_mode=ParseMode.HTML,
    )
    # Ask for feedback and screenshots
    feedback_text = (
        bold("📸 Share Feedback") + "\n"
        "Please send:\n"
        "• A screenshot of your hosted bot running\n"
        "• A screenshot of your current chat in GRAVIXVPS\n"
        "• Your feedback about the platform (what did you like, what can be improved)\n\n"
        "Submit your feedback and screenshots to our support bot: " + bold("@Dravonnbot") + ".\n"
        "Tap the button below to open the support chat."
    )
    await message.answer(feedback_text, reply_markup=support_url_kb(), parse_mode=ParseMode.HTML)
    await state.clear()


@router.message(Command("stop"))
async def cmd_stop(message: Message):
    # Stop user's active bot(s)
    active = get_active_bots(message.from_user.id)
    if not active:
        await message.answer(bold("ℹ️ No active hosted bots."), reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")), parse_mode=ParseMode.HTML)
        return

    from .services.hoster import stop_runtime
    stopped_any = False
    for b in active:
        rid = b.get("runtime_id")
        if rid:
            stop_runtime(rid)
        mark_stopped(b["id"])
        stopped_any = True
    if stopped_any:
        await message.answer(bold("🛑 Your hosted bot has been stopped."), reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")), parse_mode=ParseMode.HTML)
    else:
        await message.answer(
            bold("⚙️ Internal error") + "\nThere was a problem handling your request. Don't worry — our system automatically handles this.\nPlease retry in a few minutes.",
            reply_markup=main_menu(get_user(message.from_user.id).get("is_premium")),
            parse_mode=ParseMode.HTML,
        )


# Keep callback-based handlers for backward compatibility with any existing inline keyboards
@router.callback_query(F.data == "my_info")
async def cb_myinfo(cb: CallbackQuery):
    await cmd_myinfo(cb.message)
    await cb.answer()


@router.callback_query(F.data == "upgrade")
async def cb_upgrade(cb: CallbackQuery):
    await cmd_upgrade(cb.message)
    await cb.answer()


@router.callback_query(F.data == "contact_admin")
async def cb_contact_admin(cb: CallbackQuery):
    user = get_user(cb.from_user.id)
    if not user.get("is_premium"):
        await cb.message.answer("This feature is available for premium users only.", parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    await cb.message.answer(
        "💬 Contact Admin\nSend a message starting with " + code("admin:") + " and we'll forward it to the admin.",
        reply_markup=main_menu(True),
        parse_mode=ParseMode.HTML,
    )
    await cb.answer()


@router.message(ContactStates.chat, F.text.in_(["⬅️ Back", "Back", "🔙 Back"]))
async def contact_admin_back(message: Message, state: FSMContext):
    # Exit chat state without sending a message
    await state.clear()
    user = get_user(message.from_user.id)
    await message.answer(bold("🏠 Main Menu"), reply_markup=main_menu(user.get("is_premium")), parse_mode=ParseMode.HTML)


@router.message(ContactStates.chat, F.text)
async def contact_admin_forward(message: Message, state: FSMContext):
    user = get_user(message.from_user.id)
    if not user.get("is_premium"):
        await message.answer("This feature is available for premium users only.", parse_mode=ParseMode.HTML)
        await state.clear()
        return
    if not ADMIN_TELEGRAM_ID:
        await message.answer("Admin is not configured.", parse_mode=ParseMode.HTML)
        await state.clear()
        return
    # If user presses Back while in chat, handle above; otherwise treat as a message
    if message.text.strip().lower() in {"⬅️ back", "back", "🔙 back"}:
        await contact_admin_back(message, state)
        return
    # Persist to admin inbox
    try:
        from .storage import add_message
        add_message(message.from_user.id, message.text)
    except Exception:
        # Non-fatal if inbox storage fails
        pass
    try:
        await message.bot.send_message(
            chat_id=ADMIN_TELEGRAM_ID,
            text=f"📨 Message from {bold(message.from_user.full_name)} ({code(str(message.from_user.id))}):\n{message.text}",
            parse_mode=ParseMode.HTML,
        )
        await message.answer("✅ Sent to admin.", parse_mode=ParseMode.HTML)
    finally:
        await state.clear()


@router.callback_query(F.data == "how_it_works")
async def cb_how(cb: CallbackQuery):
    text = (
        "📘 How it Works\n"
        "• Upload your bot code (.py or a .zip). We auto-detect your entry file.\n"
        "• Send your bot token.\n"
        "• We prepare a secure runtime and get your bot online.\n"
        "• Free plan: 1 hour uptime; Premium: unlimited.\n"
    )
    await cb.message.answer(text, reply_markup=main_menu(get_user(cb.from_user.id).get("is_premium")), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data == "manage_bots")
async def cb_manage(cb: CallbackQuery):
    user = get_user(cb.from_user.id)
    bots = get_user_bots(cb.from_user.id)
    lines = ["⚙️ Manage My Bots"]
    if not bots:
        lines.append("• You have no bots yet. Use '📦 Host My Bot' to upload.")
    else:
        for b in bots:
            lines.append(f"• {bold(b.get('name') or 'MyBot')} — ID {code(b['id'])} — Status: {bold(b['status'])}")
    lines.append("\nUse the buttons below. For stop/restart, send: " + code("stop <bot_id>") + " / " + code("restart <bot_id>"))
    await cb.message.answer("\n".join(lines), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data == "main_menu")
async def cb_main_menu(cb: CallbackQuery):
    user = get_user(cb.from_user.id)
    await cb.message.answer(
        bold("🏠 Main Menu"),
        reply_markup=main_menu(user.get("is_premium"), show_admin=is_admin(cb.from_user.id)),
        parse_mode=ParseMode.HTML,
    )
    await cb.answer()


# User inline actions: stop, restart, remove, logs
@router.callback_query(F.data.startswith("user_stop:"))
async def cb_user_stop(cb: CallbackQuery):
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot
    from .services.hoster import stop_runtime
    b = get_bot(bot_id)
    if not b or b["owner_id"] != cb.from_user.id:
        await cb.message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    rid = b.get("runtime_id")
    if rid:
        stop_runtime(rid)
    mark_stopped(bot_id)
    await cb.message.answer(f"🛑 Stopped {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("user_restart:"))
async def cb_user_restart(cb: CallbackQuery):
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot
    from .services.hoster import restart_runtime
    b = get_bot(bot_id)
    if not b or b["owner_id"] != cb.from_user.id:
        await cb.message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    rid = b.get("runtime_id")
    if rid and restart_runtime(rid):
        await cb.message.answer(f"♻️ Restarted {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    else:
        await cb.message.answer("Failed to restart.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("user_remove:"))
async def cb_user_remove(cb: CallbackQuery):
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot, delete_bot
    from .services.hoster import stop_runtime, remove_workspace, remove_image
    b = get_bot(bot_id)
    if not b or b["owner_id"] != cb.from_user.id:
        await cb.message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
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
    await cb.message.answer(f"🗑️ Removed {code(bot_id)}", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    await cb.answer()


@router.callback_query(F.data.startswith("user_logs:"))
async def cb_user_logs(cb: CallbackQuery):
    bot_id = cb.data.split(":", 1)[1]
    from .storage import get_bot, _read_db
    b = get_bot(bot_id)
    if not b or b["owner_id"] != cb.from_user.id:
        await cb.message.answer("Bot not found or not yours.", reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    db = _read_db()
    logs = []
    for entry in reversed(db.get("logs", [])):
        ev = entry.get("event", "")
        if bot_id in ev:
            logs.append(f"• {entry.get('time','')} — {ev}")
        if len(logs) >= 50:
            break
    if not logs:
        await cb.message.answer(bold("No logs for this bot."), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
        await cb.answer()
        return
    header = bold("🧾 Bot Logs")
    chunk = []
    current_len = 0
    for line in logs:
        if current_len + len(line) + 1 > 3500:
            await cb.message.answer(header + "\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
            chunk = []
            current_len = 0
        chunk.append(line)
        current_len += len(line) + 1
    if chunk:
        await cb.message.answer(header + " (cont.)\n" + pre("\n".join(chunk)), reply_markup=user_manage_menu(), parse_mode=ParseMode.HTML)
    await cb.answer()


async def on_timeout_notify(bot: Bot, user_id: int, bot_id: str):
    await bot.send_message(
        chat_id=user_id,
        text="⏱️ Hosting time expired!\nYour hosted bot has been stopped automatically.\nUpgrade to premium for unlimited uptime 💎.",
        parse_mode=ParseMode.HTML,
    )


# Feedback handlers
@router.message(F.text.regexp(r"(?i)^feedback:\s*(.+)$"))
async def on_feedback_text(message: Message):
    # Acknowledge and direct user to support bot for screenshots/feedback collection
    try:
        from .storage import add_message
        add_message(message.from_user.id, message.text)
    except Exception:
        pass
    await message.answer(
        "✅ Thank you! Please submit your feedback and screenshots to our support bot.",
        reply_markup=support_url_kb(),
        parse_mode=ParseMode.HTML,
    )


@router.message(F.photo, F.caption.regexp(r"(?i)^feedback:"))
async def on_feedback_photo(message: Message):
    try:
        photo = message.photo[-1]  # largest size
        await message.bot.send_photo(
            chat_id=ADMIN_TELEGRAM_ID,
            photo=photo.file_id,
            caption=f"🖼️ Feedback screenshot from {bold(message.from_user.full_name)} ({code(str(message.from_user.id))}):\n{message.caption}",
            parse_mode=ParseMode.HTML,
        )
        await message.answer("✅ Screenshot forwarded. Thank you!", parse_mode=ParseMode.HTML)
    except Exception:
        await message.answer("⚠️ Could not forward the screenshot. Please try again.", parse_mode=ParseMode.HTML)


@router.message(F.document, F.caption.regexp(r"(?i)^feedback:"))
async def on_feedback_document(message: Message):
    try:
        await message.bot.send_document(
            chat_id=ADMIN_TELEGRAM_ID,
            document=message.document.file_id,
            caption=f"📄 Feedback attachment from {bold(message.from_user.full_name)} ({code(str(message.from_user.id))}):\n{message.caption}",
            parse_mode=ParseMode.HTML,
        )
        await message.answer("✅ Attachment forwarded. Thank you!", parse_mode=ParseMode.HTML)
    except Exception:
        await message.answer("⚠️ Could not forward the attachment. Please try again.", parse_mode=ParseMode.HTML)


def create_app():
    if not MASTER_BOT_TOKEN:
        raise RuntimeError("MASTER_BOT_TOKEN not set")
    bot = Bot(MASTER_BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher(storage=MemoryStorage())
    dp.include_router(router)
    dp.include_router(admin_router)

    scheduler = Scheduler(on_timeout_notify=lambda uid, bid: asyncio.create_task(on_timeout_notify(bot, uid, bid)))

    async def run():
        await scheduler.start()
        await dp.start_polling(bot)

    return run


if __name__ == "__main__":
    asyncio.run(create_app()())