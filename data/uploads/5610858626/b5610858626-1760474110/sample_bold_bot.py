#!/usr/bin/env python3
"""
Simple Text Bold Bot - Sample for Testing
This bot converts any text message to bold format
"""

import os
import telebot

# Bot token - will be set by environment variable
TOKEN = os.getenv('TOKEN') or os.getenv('BOT_TOKEN')

# Initialize bot
bot = telebot.TeleBot(TOKEN)

@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    """Send welcome message"""
    welcome_text = """👋 **Welcome to Bold Text Bot!**

Send me any text and I'll make it bold!

**Commands:**
/start - Start the bot
/help - Show this help message

Just send any text to make it bold!"""

    bot.reply_to(message, welcome_text, parse_mode='Markdown')

@bot.message_handler(func=lambda message: True)
def make_bold(message):
    """Make text bold"""
    text = message.text
    bold_text = f"**{text}**"
    bot.reply_to(message, bold_text, parse_mode='Markdown')

# Start polling
if __name__ == '__main__':
    print("✅ Bold Text Bot is running...")
    bot.infinity_polling()
