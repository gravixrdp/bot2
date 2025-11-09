# ====== Gravix + VPS Safe Import ======
try:
    import sys
except Exception:
    sys = None

# Telegram Video Compressor Bot (Optimized for VPS up to 3 GB)
# Made by - @ApkaChotaBhaiJex

import os, json, asyncio, subprocess
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, MessageHandler, CallbackQueryHandler,
    CallbackContext, filters
)

# --------------- CONFIG ----------------
BOT_TOKEN = "8041992730:AAGB-GXBSCNOoRLRlB1mi3P8SxI1pMX1inc"       # ← Replace with your bot token
ADMIN_ID = 8186973947                    # ← Replace with your Telegram ID
WATERMARK_TEXT = "@Compressor26Bot"

# --------------- SETUP ----------------
os.makedirs("downloads", exist_ok=True)
os.makedirs("data", exist_ok=True)

USERS_FILE = "data/users.json"
STATS_FILE = "data/stats.json"

def load_json(path, default):
    if not os.path.exists(path):
        with open(path, "w") as f:
            json.dump(default, f)
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

users = load_json(USERS_FILE, {})
stats = load_json(STATS_FILE, {"videos": 0, "users": 0})

# --------------- VIDEO PROCESS ----------------
async def compress_with_watermark(input_path, output_path, quality):
    scale_map = {"480p": "854:480", "720p": "1280:720", "1080p": "1920:1080"}
    scale = scale_map.get(quality, "1280:720")

    # ⚙️ Optimized ffmpeg (for big files, smooth compression)
    cmd = (
        f'ffmpeg -y -i "{input_path}" '
        f'-vf "scale={scale},drawtext=text=\'{WATERMARK_TEXT}\':fontcolor=white:fontsize=24:'
        f'box=1:boxcolor=black@0.5:boxborderw=5:x=w-tw-10:y=h-th-10" '
        f'-preset veryslow -crf 32 -b:v 1000k -b:a 96k -c:a aac "{output_path}" '
        f'-hide_banner -loglevel error'
    )
    subprocess.run(cmd, shell=True)

# --------------- START ----------------
async def start(update: Update, context: CallbackContext):
    user = update.message.from_user
    if str(user.id) not in users:
        users[str(user.id)] = {"name": user.first_name, "count": 0}
        stats["users"] = len(users)
        save_json(USERS_FILE, users)
        save_json(STATS_FILE, stats)

    welcome = (
        f"👋 *Welcome {user.first_name}!* to *Compressor26Bot* 💾\n\n"
        "🎥 Send me any video and I’ll compress it with a watermark.\n"
        "Choose your quality — 480p, 720p, or 1080p.\n\n"
        "Made by - @ApkaChotaBhaiJex ❤️"
    )

    keyboard = [
        [InlineKeyboardButton("ℹ️ How to Use", callback_data="how_to_use")],
        [InlineKeyboardButton("📢 Feedback", url="https://t.me/YourFeedbackGroup")],
        [InlineKeyboardButton("📩 Contact Admin", url="https://t.me/ApkaChotaBhaiJex")],
    ]
    await update.message.reply_text(welcome, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))

# --------------- HOW TO USE ----------------
async def how_to_use(update: Update, context: CallbackContext):
    text = (
        "📚 *How to Use:*\n\n"
        "1️⃣ Send any video (even forwarded).\n"
        "2️⃣ Select quality (480p / 720p / 1080p).\n"
        "3️⃣ Wait for compression (progress will show ⚙️).\n"
        "4️⃣ Receive your smaller video with watermark ✅"
    )
    await update.callback_query.message.reply_text(text, parse_mode="Markdown")
    await update.callback_query.answer()

# --------------- VIDEO HANDLER ----------------
async def handle_video(update: Update, context: CallbackContext):
    user = update.message.from_user
    message = update.message

    video = message.video or getattr(message, "forward_from_message_id", None) and message.video
    if not video:
        await message.reply_text("⚠️ Couldn't find video file.")
        return

    # ✅ Supports up to 3GB (for VPS)
    if video.file_size > 3_000_000_000:
        await message.reply_text("🚫 File too large! Max supported: 3GB.")
        return

    file = await video.get_file()
    msg = await message.reply_text("✅ Got your video! Choose compression quality 👇")

    context.user_data["file"] = file
    context.user_data["uid"] = user.id

    keyboard = [
        [InlineKeyboardButton("480p (Smallest)", callback_data="q_480p")],
        [InlineKeyboardButton("720p (Recommended)", callback_data="q_720p")],
        [InlineKeyboardButton("1080p (HD Quality)", callback_data="q_1080p")]
    ]
    await msg.reply_text("Select compression quality:", reply_markup=InlineKeyboardMarkup(keyboard))

# --------------- COMPRESSION PROCESS ----------------
async def process_compression(update: Update, context: CallbackContext, quality):
    query = update.callback_query
    user_id = context.user_data["uid"]
    file = context.user_data["file"]

    input_path = f"downloads/{user_id}_input.mp4"
    output_path = f"downloads/{user_id}_compressed.mp4"

    await query.message.reply_text("📥 Downloading video... (ETA 10%)")
    await file.download_to_drive(input_path)

    users[str(user_id)]["count"] += 1
    stats["videos"] += 1
    save_json(USERS_FILE, users)
    save_json(STATS_FILE, stats)

    msg = await query.message.reply_text(f"⚙️ Compressing ({quality})... ETA 40%")
    await compress_with_watermark(input_path, output_path, quality)
    await msg.edit_text("🚀 Finishing... ETA 90%")

    await query.message.reply_video(
        video=open(output_path, "rb"),
        caption=f"✅ Done! Compressed ({quality})\nWatermark: {WATERMARK_TEXT}",
        parse_mode="Markdown"
    )
    await msg.edit_text("✅ Upload complete!")

    for path in [input_path, output_path]:
        if os.path.exists(path):
            os.remove(path)

# --------------- ADMIN ----------------
async def stats_cmd(update: Update, context: CallbackContext):
    msg = (
        f"📊 *Bot Stats*\n\n"
        f"👥 Users: {stats['users']}\n"
        f"🎬 Videos Compressed: {stats['videos']}"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

async def leaderboard(update: Update, context: CallbackContext):
    sorted_users = sorted(users.items(), key=lambda x: x[1]["count"], reverse=True)[:10]
    msg = "🏆 *Top Users*\n\n"
    for i, (uid, data) in enumerate(sorted_users, start=1):
        msg += f"{i}. {data['name']} — {data['count']} videos\n"
    await update.message.reply_text(msg, parse_mode="Markdown")

# --------------- CALLBACK HANDLER ----------------
async def button_callback(update: Update, context: CallbackContext):
    query = update.callback_query
    data = query.data
    await query.answer("⏳ Working on it...", show_alert=False)

    if data == "how_to_use":
        await how_to_use(update, context)
    elif data.startswith("q_"):
        quality = data.split("_")[1]
        await query.message.reply_text(f"🎞 Compression started at {quality.upper()} — please wait...")
        asyncio.create_task(process_compression(update, context, quality))

# --------------- MAIN ----------------
def main():
    app = Application.builder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("stats", stats_cmd))
    app.add_handler(CommandHandler("leaderboard", leaderboard))
    app.add_handler(MessageHandler(filters.VIDEO | filters.FORWARDED, handle_video))
    app.add_handler(CallbackQueryHandler(button_callback))

    print("✅ Bot is running... Press Ctrl+C to stop.")
    app.run_polling()

if __name__ == "__main__":
    asyncio.run(main())