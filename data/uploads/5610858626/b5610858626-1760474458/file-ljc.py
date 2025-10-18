# test_bot.py
import asyncio
from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import Message, ReplyKeyboardMarkup, KeyboardButton
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode

TOKEN = "8286550650:AAHbOQEjRsQ9LBIDFhgu08pGeFblqLcF_XU"  # replace with your token

router = Router()

def main_menu() -> ReplyKeyboardMarkup:
    buttons = [
        KeyboardButton(text="📦 Host My Bot"),
        KeyboardButton(text="⚙️ Manage My Bots"),
        KeyboardButton(text="📘 How it Works"),
        KeyboardButton(text="💬 Contact Admin"),
        KeyboardButton(text="🆘 Support"),
        KeyboardButton(text="👤 My Info"),
        KeyboardButton(text="⏳ Premium Time Left"),
        KeyboardButton(text="🏠 Main Menu"),
        KeyboardButton(text="⬅️ Back"),
    ]
    rows = []
    row = []
    for b in buttons:
        row.append(b)
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True, one_time_keyboard=False, is_persistent=True)

@router.message(F.text.regexp(r"(?i)^\s*(?:/)?\s*(?:⬅️\s*)?back\s*$"))
async def back_handler(message: Message):
    await message.answer("🏠 Main Menu", reply_markup=main_menu(), parse_mode=ParseMode.HTML)

@router.message(F.text == "📘 How it Works")
async def how_handler(message: Message):
    await message.answer("📘 How it Works\nUpload code, send token, we host.", reply_markup=main_menu(), parse_mode=ParseMode.HTML)

@router.message(F.text == "🏠 Main Menu")
async def main_menu_handler(message: Message):
    await message.answer("🏠 Main Menu", reply_markup=main_menu(), parse_mode=ParseMode.HTML)

@router.message()
async def echo(message: Message):
    await message.answer(f"🔁 You said: {message.text}", reply_markup=main_menu(), parse_mode=ParseMode.HTML)

async def run():
    bot = Bot(TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(router)
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(run())