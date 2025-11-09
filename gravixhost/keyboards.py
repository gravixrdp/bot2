from aiogram.types import (
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    ReplyKeyboardMarkup,
)


def _chunk_buttons(buttons, per_row: int = 2):
    """
    Arrange a flat list of KeyboardButton into rows with `per_row` items each.
    Default is 2 per row as requested. This keeps the keyboard compact and readable.
    """
    rows = []
    row = []
    for b in buttons:
        row.append(b)
        if len(row) >= per_row:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return rows


# Reply keyboard that stays above the input field and sends button text as a message
def main_menu(is_premium: bool, show_admin: bool = False) -> ReplyKeyboardMarkup:
    if is_premium:
        buttons = [
            KeyboardButton(text="📦 Host My Bot"),
            KeyboardButton(text="⚙️ Manage My Bots"),
            KeyboardButton(text="📘 How it Works"),
            KeyboardButton(text="💬 Contact Admin"),
            KeyboardButton(text="🆘 Support"),
            KeyboardButton(text="👤 My Info"),
            KeyboardButton(text="⏳ Premium Time Left"),
            KeyboardButton(text="🏠 Main Menu"),
            KeyboardButton(text="🎁 Referral"),
        ]
    else:
        buttons = [
            KeyboardButton(text="📦 Host My Bot"),
            KeyboardButton(text="⚙️ Manage My Bots"),
            KeyboardButton(text="ℹ️ How it Works"),
            KeyboardButton(text="💰 Upgrade to Premium"),
            KeyboardButton(text="🆘 Support"),
            KeyboardButton(text="👤 My Info"),
            KeyboardButton(text="⏳ Premium Time Left"),
            KeyboardButton(text="🏠 Main Menu"),
            KeyboardButton(text="🎁 Referral"),
        ]
    if show_admin:
        # Place Admin Panel button at the end (last row)
        buttons.append(KeyboardButton(text="🛡️ Admin Panel"))
    rows = _chunk_buttons(buttons, per_row=2)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)


# User "Manage My Bots" persistent menu
def user_manage_menu() -> ReplyKeyboardMarkup:
    buttons = [
        KeyboardButton(text="🔍 My Running Bots"),
        KeyboardButton(text="🛑 Stop My Bot"),
        KeyboardButton(text="♻️ Restart My Bot"),
        KeyboardButton(text="🗑️ Remove My Bot"),
        KeyboardButton(text="📜 Bot Logs"),
        KeyboardButton(text="🧾 My Logs"),
        KeyboardButton(text="🏠 Main Menu"),
    ]
    rows = _chunk_buttons(buttons, per_row=2)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)


# Admin menus as persistent reply keyboards
def admin_menu() -> ReplyKeyboardMarkup:
    buttons = [
        KeyboardButton(text="👥 Users"),
        KeyboardButton(text="💎 Premium"),
        KeyboardButton(text="📦 Apps"),
        KeyboardButton(text="💬 Inbox"),
        KeyboardButton(text="🧾 Logs"),
        KeyboardButton(text="🗑️ Clear Admin Logs"),
        KeyboardButton(text="⚙️ Settings"),
        # Place Broadcast as the last actionable button just before Main Menu
        KeyboardButton(text="📢 Broadcast"),
        KeyboardButton(text="🏠 Main Menu"),
    ]
    rows = _chunk_buttons(buttons, per_row=2)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)


def contact_chat_menu() -> ReplyKeyboardMarkup:
    # Minimal chat UI for contacting admin
    rows = _chunk_buttons([KeyboardButton(text="⬅️ Back")], per_row=2)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)


def admin_menu_apps() -> ReplyKeyboardMarkup:
    # Include quick actions; arranged in rows of 2
    buttons = [
        KeyboardButton(text="👥 Users"),
        KeyboardButton(text="💎 Premium"),
        KeyboardButton(text="📦 Apps"),
        KeyboardButton(text="🧾 Logs"),
        KeyboardButton(text="⚙️ Settings"),
        KeyboardButton(text="🏠 Main Menu"),
        KeyboardButton(text="stopbot"),
        KeyboardButton(text="restartbot"),
        KeyboardButton(text="removebot"),
    ]
    rows = _chunk_buttons(buttons, per_row=2)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)


def admin_fixed_bar() -> InlineKeyboardMarkup:
    # Kept for backward compatibility (unused now)
    buttons = [
        [
            InlineKeyboardButton(text="👥 Users", callback_data="admin_users"),
        ],
        [
            InlineKeyboardButton(text="💎 Premium", callback_data="admin_premium"),
        ],
        [
            InlineKeyboardButton(text="📦 Apps", callback_data="admin_apps"),
        ],
        [
            InlineKeyboardButton(text="🧾 Logs", callback_data="admin_logs"),
        ],
        [
            InlineKeyboardButton(text="📢 Broadcast", callback_data="admin_broadcast"),
        ],
        [
            InlineKeyboardButton(text="⚙️ Settings", callback_data="admin_settings"),
        ],
        [
            InlineKeyboardButton(text="🏠 Main Menu", callback_data="main_menu"),
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def support_url_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Open Support Chat", url="https://t.me/dravonnbot")]
        ]
    )

def channel_join_kb() -> InlineKeyboardMarkup:
    # Inline button to join the official channel
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Join Channel", url="https://t.me/GravixRDP")]
        ]
    )


def bots_action_list(bots, action_text: str, prefix: str) -> InlineKeyboardMarkup:
    """
    Build an inline keyboard with one button per bot.
    action_text: label prefix e.g., "Delete", "Stop", "Restart", "Logs"
    prefix: callback prefix e.g., "user_remove", "user_stop"
    """
    rows = []
    for b in bots:
        name = b.get("name") or "MyBot"
        bid = b.get("id")
        rows.append([InlineKeyboardButton(text=f"{action_text}: {name} — {bid}", callback_data=f"{prefix}:{bid}")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def bots_combined_actions(bots) -> InlineKeyboardMarkup:
    """
    Build a combined inline keyboard with all actions (Stop, Remove, Logs, Restart) for each bot.
    Each bot gets 2 rows: first row shows bot name/ID as label, second row has 4 action buttons.
    """
    rows = []
    for b in bots:
        name = b.get("name") or "MyBot"
        bid = b.get("id")
        # Shorten name if too long for display
        display_name = name[:20] if len(name) > 20 else name
        # First row: Bot name/ID as label
        rows.append([InlineKeyboardButton(text=f"📦 {display_name} ({bid})", callback_data=f"admin_bot_info:{bid}")])
        # Second row: Action buttons
        rows.append([
            InlineKeyboardButton(text="🛑 Stop", callback_data=f"admin_stop:{bid}"),
            InlineKeyboardButton(text="🗑️ Remove", callback_data=f"admin_remove:{bid}"),
            InlineKeyboardButton(text="📜 Logs", callback_data=f"admin_logs:{bid}"),
            InlineKeyboardButton(text="♻️ Restart", callback_data=f"admin_restart:{bid}"),
        ])
    return InlineKeyboardMarkup(inline_keyboard=rows)

def referral_share_kb(ref_url: str, share_text: str = "") -> InlineKeyboardMarkup:
    """
    Inline keyboard for referral:
    - Join/Open Link: opens the referral link (start payload)
    - Share Referral: opens Telegram share dialog with prefilled link and text
    """
    import urllib.parse as _u
    share = f"https://t.me/share/url?url={_u.quote(ref_url)}"
    if share_text:
        share += f"&text={_u.quote(share_text)}"
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Open Referral Link", url=ref_url)],
            [InlineKeyboardButton(text="Share Referral", url=share)],
        ]
    )