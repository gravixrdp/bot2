import os
from pyrogram import Client, filters
from pyrogram.types import Message, ChatPermissions
from pyrogram.enums import ChatMemberStatus
from collections import defaultdict

# --- ⚠️ APNI DETAILS YAHA DAALEIN ---
# Aapke API ID aur HASH (my.telegram.org se mil jayega)
API_ID = 28103139  # Apna API_ID yahaan daalein
API_HASH = "5a690e3f95c47aeafa44e721558470f1"  # Apna API_HASH yahaan daalein

# Aapke Bot ka Token (BotFather se mil jayega)
BOT_TOKEN = "7702141884:AAH5JJIMcDWm08zbAMfMAijbJMLi8T5hz-Q"  # Apna BOT_TOKEN yahaan daalein
# --- ⚠️ ---

# --- Custom Settings ---
# Aap apne group ke rules yahaan likh sakte hain
GROUP_RULES = """
**📜 Group Rules 📜**

1.  Koi spamming ya promotion nahi.
2.  Sabse respect se baat karein.
3.  Off-topic discussion na karein.
4.  Links share karna allowed nahi hai (sirf admins kar sakte hain).
"""

# Jin shabdo ko block karna hai, unhe yahaan daalein (lowercase mein)
BLACKLISTED_WORDS = ["badword1", "examplegaali", "spamword"]

# Kitni warnings ke baad ban karna hai
MAX_WARNINGS = 3
# --- ---

# Bot Client ko initialize karna
app = Client(
    "group_manager_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN
)

# User warnings ko store karne ke liye (bot restart hone par reset ho jayega)
# Structure: {chat_id: {user_id: warning_count}}
user_warnings = defaultdict(lambda: defaultdict(int))


# --- Custom Filter: Check karne ke liye ki user Admin hai ya nahi ---
async def admin_check(_, __, message: Message):
    if not message.from_user:
        return False
    # Check if the user who sent the message is an admin or owner
    member = await message.chat.get_member(message.from_user.id)
    return member.status in [ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER]

is_admin = filters.create(admin_check)


# --- 1. Basic Commands ---

@app.on_message(filters.command("start") & filters.private)
async def start_command(client: Client, message: Message):
    # (FIXED: f-string ko .format() se replace kiya gaya)
    start_text = "Hello {}!\nMain ek advanced group management bot hoon. Mujhe kisi group mein add karein aur admin banayein taki main kaam kar sakoon.".format(
        message.from_user.first_name
    )
    await message.reply_text(start_text)

@app.on_message(filters.command("help"))
async def help_command(client: Client, message: Message):
    await message.reply_text(
        "**💡 Available Commands 💡**\n\n"
        "**/start**: Bot ko start karein (private chat mein).\n"
        "**/help**: Ye help message dekhein.\n"
        "**/info**: User ki jaankari dekhein (reply karke ya seedha).\n"
        "**/rules**: Group ke rules dekhein.\n\n"
        "**👑 Admin Commands 👑**\n"
        "*(Sirf admins use kar sakte hain)*\n"
        "**/kick [reply]**: User ko group se kick karein.\n"
        "**/ban [reply]**: User ko group se ban karein.\n"
        "**/mute [reply]**: User ko mute karein.\n"
        "**/unmute [reply]**: User ko unmute karein.\n"
        "**/unban [username/id]**: User ko unban karein.\n"
        "**/warn [reply]**: User ko warning dein (3 par ban).\n"
        "**/warnings [reply]**: User ki warnings check karein."
    )

@app.on_message(filters.command("rules") & filters.group)
async def rules_command(client: Client, message: Message):
    await message.reply_text(GROUP_RULES, disable_web_page_preview=True)


# --- 2. Welcome Message ---

@app.on_message(filters.new_chat_members & filters.group)
async def welcome_new_member(client: Client, message: Message):
    # Bot ke paas "Can delete messages" permission honi chahiye Telegram service message ko delete karne ke liye
    try:
        await message.delete() 
    except Exception:
        pass # Agar bot admin nahi hai toh fail ho sakta hai

    for user in message.new_chat_members:
        if user.is_bot:
            continue # Bots ko welcome nahi karna
        # (FIXED: f-string ko .format() se replace kiya gaya)
        welcome_text = "👋 Welcome, {}!\n\n{} mein aapka swagat hai.\nPlease `/rules` command se rules padh lein.".format(
            user.mention, message.chat.title
        )
        await message.chat.send_message(welcome_text)


# --- 3. User Info Command ---

@app.on_message(filters.command("info") & filters.group)
async def user_info(client: Client, message: Message):
    # Check karein ki user ne reply kiya hai ya nahi
    if message.reply_to_message:
        target_user = message.reply_to_message.from_user
    else:
        target_user = message.from_user

    try:
        member = await message.chat.get_member(target_user.id)
        
        # (FIXED: f-string ko .format() se replace kiya gaya)
        info_text = (
            "**👤 User Info 👤**\n\n"
            "**First Name:** {}\n"
            "**Last Name:** {}\n"
            "**Username:** @{}\n"
            "**User ID:** `{}`\n"
            "**Group Status:** {}"
        ).format(
            target_user.first_name,
            target_user.last_name or 'N/A',
            target_user.username or 'N/A',
            target_user.id,
            member.status.name.capitalize()
        )
        await message.reply_text(info_text)
        
    except Exception as e:
        await message.reply_text("User ki details nahi mil paayi: {}".format(e))


# --- 4. Admin Moderation Commands (Kick, Ban, Mute, etc.) ---

@app.on_message(filters.command("kick") & filters.group & is_admin)
async def kick_user(client: Client, message: Message):
    if not message.reply_to_message:
        await message.reply_text("Kick karne ke liye user ke message ko reply karein.")
        return
    
    user_to_kick = message.reply_to_message.from_user
    admin_user = message.from_user
    
    if user_to_kick.id == admin_user.id:
        await message.reply_text("Aap khud ko kick nahi kar sakte.")
        return

    try:
        await message.chat.kick_member(user_to_kick.id)
        await message.reply_text("✅ {} ko group se kick kar diya gaya hai.".format(user_to_kick.mention))
    except Exception as e:
        await message.reply_text("❌ Error: {}".format(e))

@app.on_message(filters.command("ban") & filters.group & is_admin)
async def ban_user(client: Client, message: Message):
    if not message.reply_to_message:
        await message.reply_text("Ban karne ke liye user ke message ko reply karein.")
        return

    user_to_ban = message.reply_to_message.from_user
    admin_user = message.from_user

    if user_to_ban.id == admin_user.id:
        await message.reply_text("Aap khud ko ban nahi kar sakte.")
        return
        
    try:
        await message.chat.ban_member(user_to_ban.id)
        await message.reply_text("🚫 {} ko group se ban kar diya gaya hai.".format(user_to_ban.mention))
    except Exception as e:
        await message.reply_text("❌ Error: {}".format(e))

@app.on_message(filters.command("mute") & filters.group & is_admin)
async def mute_user(client: Client, message: Message):
    if not message.reply_to_message:
        await message.reply_text("Mute karne ke liye user ke message ko reply karein.")
        return

    user_to_mute = message.reply_to_message.from_user
    try:
        # User ko mute karne ke liye empty permissions set karein
        await message.chat.restrict_member(user_to_mute.id, ChatPermissions())
        await message.reply_text("🔇 {} ko mute kar diya gaya hai.".format(user_to_mute.mention))
    except Exception as e:
        await message.reply_text("❌ Error: {}".format(e))

@app.on_message(filters.command("unmute") & filters.group & is_admin)
async def unmute_user(client: Client, message: Message):
    if not message.reply_to_message:
        await message.reply_text("Unmute karne ke liye user ke message ko reply karein.")
        return

    user_to_unmute = message.reply_to_message.from_user
    try:
        # unrestrict_member user ko wapas default permissions de deta hai
        await message.chat.unrestrict_member(user_to_unmute.id)
        await message.reply_text("🔊 {} ko unmute kar diya gaya hai.".format(user_to_unmute.mention))
    except Exception as e:
        await message.reply_text("❌ Error: {}".format(e))

@app.on_message(filters.command("unban") & filters.group & is_admin)
async def unban_user(client: Client, message: Message):
    if len(message.command) < 2:
        await message.reply_text("Usage: `/unban <username ya user_id>`")
        return
    
    user_to_unban = message.command[1]
    try:
        await message.chat.unban_member(user_to_unban)
        await message.reply_text("✅ {} ko unban kar diya gaya hai.".format(user_to_unban))
    except Exception as e:
        await message.reply_text("❌ Error: {}".format(e))


# --- 5. Automatic Filters (Links & Blacklist) ---

@app.on_message(
    filters.group &
    (filters.text & (filters.regex(r"https?://") | filters.entity("url"))) &
    ~is_admin  # Ye filter tabhi kaam karega jab user admin NAHI hai
)
async def anti_link_filter(client: Client, message: Message):
    try:
        await message.delete()
        # (FIXED: f-string ko .format() se replace kiya gaya)
        link_warning_text = "Hey {}, admins ke alawa kisi aur ko links share karna allowed nahi hai. 😠".format(
            message.from_user.mention
        )
        await message.reply_text(link_warning_text)
    except Exception as e:
        print("Anti-link filter mein error: {}".format(e))

# (NEW) --- 6. Word Blacklist Filter ---
@app.on_message(filters.text & filters.group & ~is_admin)
async def word_blacklist_filter(client: Client, message: Message):
    if not message.text:
        return
        
    message_text_lower = message.text.lower()
    for word in BLACKLISTED_WORDS:
        if word in message_text_lower:
            try:
                await message.delete()
                # (FIXED: f-string ko .format() se replace kiya gaya)
                blacklist_warning_text = "Hey {}, aapne ek blacklisted shabd ka istemaal kiya hai. Message delete kar diya gaya hai.".format(
                    message.from_user.mention
                )
                await message.reply_text(blacklist_warning_text)
                return # Ek baar delete karne ke baad function rok dein
            except Exception as e:
                print("Blacklist filter mein error: {}".format(e))
                return

# (NEW) --- 7. Warning System ---

@app.on_message(filters.command("warn") & filters.group & is_admin)
async def warn_user(client: Client, message: Message):
    if not message.reply_to_message:
        await message.reply_text("Warning dene ke liye user ke message ko reply karein.")
        return

    user_to_warn = message.reply_to_message.from_user
    chat_id = message.chat.id
    admin_user = message.from_user

    if user_to_warn.id == admin_user.id:
        await message.reply_text("Aap khud ko warn nahi kar sakte.")
        return
    
    # Check if admin is trying to warn another admin
    try:
        member = await message.chat.get_member(user_to_warn.id)
        if member.status in [ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER]:
            await message.reply_text("Aap kisi doosre admin ko warn nahi kar sakte.")
            return
    except Exception:
        pass # User not in chat?

    # Warning badhayein
    user_warnings[chat_id][user_to_warn.id] += 1
    current_warnings = user_warnings[chat_id][user_to_warn.id]
    
    # (FIXED: f-string ko .format() se replace kiya gaya)
    warn_text = "⚠️ Warning! {} ko ek warning di gayi hai.\nTotal warnings: **{}/{}**.".format(
        user_to_warn.mention, current_warnings, MAX_WARNINGS
    )
    await message.reply_text(warn_text)

    # Max warnings par ban karein
    if current_warnings >= MAX_WARNINGS:
        try:
            await message.chat.ban_member(user_to_warn.id)
            # (FIXED: f-string ko .format() se replace kiya gaya)
            ban_text = "🚫 **BANNED!** {} ko {} warnings milne ke kaaran group se ban kar diya gaya hai.".format(
                user_to_warn.mention, MAX_WARNINGS
            )
            await message.chat.send_message(ban_text)
            # Ban ke baad warnings reset karein
            user_warnings[chat_id][user_to_warn.id] = 0
        except Exception as e:
            await message.reply_text("❌ User ko ban karne mein error: {}".format(e))

@app.on_message(filters.command("warnings") & filters.group)
async def check_warnings(client: Client, message: Message):
    if message.reply_to_message:
        target_user = message.reply_to_message.from_user
    else:
        target_user = message.from_user
        
    chat_id = message.chat.id
    current_warnings = user_warnings[chat_id][target_user.id]
    
    # (FIXED: f-string ko .format() se replace kiya gaya)
    warnings_text = "ℹ️ {} ke paas **{}/{}** warnings hain.".format(
        target_user.mention, current_warnings, MAX_WARNINGS
    )
    await message.reply_text(warnings_text)


# --- Bot ko run karna ---
if __name__ == "__main__":
    print("Bot starting with syntax fix (.format method)...")
    app.run()