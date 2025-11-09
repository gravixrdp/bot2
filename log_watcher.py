#!/usr/bin/env python3
"""
Real-time log watcher for bot2 folder
Monitors all log files and sends updates to Telegram bot
Auto-deletes messages after 15 minutes
"""
import os
import sys
import time
import json
import asyncio
import subprocess
from pathlib import Path
from typing import Set, Optional, Dict, List
from datetime import datetime, timedelta

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    from aiogram import Bot
    from aiogram.types import Message
except ImportError as e:
    print(f"❌ Missing dependencies: {e}")
    print("Install with: pip install watchdog aiogram")
    sys.exit(1)

# Configuration
BOT_TOKEN = "8517626041:AAGIvKkM9013dqlR4_9qu1w5-oVECzlVd6s"
BOT2_FOLDER = "/home/ubuntu/bot2"
LOG_FILES = {
    "data/logs.txt": "📊 System Logs",
    "/tmp/bot.log": "🤖 Bot Runtime",
    "data/deployment.log": "🚀 Deployment",
}
MESSAGE_DELETE_AFTER_MINUTES = 15  # Auto-delete messages after 15 minutes

# Track file positions to only send new lines
file_positions = {}
watched_files = set()
bot_instance = None
admin_chat_ids = []

# Track sent messages for auto-deletion
sent_messages = []  # List of (message_id, chat_id, timestamp)

# Track user bot containers
user_bot_containers = {}  # bot_id -> container_name

def get_admin_chat_ids() -> list:
    """Get admin chat IDs from database (premium users)"""
    admin_ids = []
    try:
        db_path = os.path.join(BOT2_FOLDER, "data", "db.json")
        if os.path.exists(db_path):
            with open(db_path, "r") as f:
                db = json.load(f)
                # Get all premium users as admins
                users = db.get("users", {})
                for user_id, user_data in users.items():
                    if user_data.get("is_premium"):
                        try:
                            admin_ids.append(int(user_id))
                        except:
                            pass
    except Exception:
        pass
    return admin_ids

async def send_log_message(message: str, file_tag: str = ""):
    """Send log message to Telegram admins and schedule auto-deletion"""
    global bot_instance, admin_chat_ids, sent_messages
    
    if not bot_instance:
        bot_instance = Bot(token=BOT_TOKEN)
        admin_chat_ids = get_admin_chat_ids()
        if not admin_chat_ids:
            # Try to get updates to find chat ID
            try:
                updates = await bot_instance.get_updates(limit=5)
                for update in updates:
                    if update.message:
                        chat_id = update.message.from_user.id
                        if chat_id not in admin_chat_ids:
                            admin_chat_ids.append(chat_id)
                if admin_chat_ids:
                    print(f"✅ Detected admin chat IDs: {admin_chat_ids}")
            except Exception as e:
                print(f"⚠️ Could not detect admin chat ID: {e}")
                print("Please send a message to the bot first")
                return
    
    if not admin_chat_ids:
        print("⚠️ No admin chat IDs found. Skipping message.")
        return
    
    try:
        # Format message with file tag
        if file_tag:
            formatted_msg = f"{file_tag}\n\n{message}"
        else:
            formatted_msg = message
        
        # Truncate if too long (Telegram limit is 4096 chars)
        if len(formatted_msg) > 4000:
            formatted_msg = formatted_msg[:4000] + "\n\n... (truncated)"
        
        # Send to all admin chat IDs
        for chat_id in admin_chat_ids:
            try:
                sent_msg = await bot_instance.send_message(chat_id=chat_id, text=formatted_msg)
                # Track message for auto-deletion
                sent_messages.append({
                    'message_id': sent_msg.message_id,
                    'chat_id': chat_id,
                    'timestamp': datetime.now(),
                    'file_tag': file_tag
                })
                print(f"✅ Sent log to {chat_id}: {file_tag} - {message[:50]}...")
            except Exception as e:
                print(f"⚠️ Failed to send to {chat_id}: {e}")
    except Exception as e:
        print(f"❌ Failed to send message: {e}")

async def delete_old_messages():
    """Delete messages older than 15 minutes"""
    global bot_instance, sent_messages
    
    if not bot_instance or not sent_messages:
        return
    
    now = datetime.now()
    cutoff_time = now - timedelta(minutes=MESSAGE_DELETE_AFTER_MINUTES)
    
    messages_to_delete = []
    remaining_messages = []
    
    for msg in sent_messages:
        if msg['timestamp'] < cutoff_time:
            messages_to_delete.append(msg)
        else:
            remaining_messages.append(msg)
    
    sent_messages = remaining_messages
    
    # Delete old messages
    for msg in messages_to_delete:
        try:
            await bot_instance.delete_message(chat_id=msg['chat_id'], message_id=msg['message_id'])
            print(f"🗑️ Deleted old message {msg['message_id']} ({msg['file_tag']})")
        except Exception as e:
            # Message might already be deleted or not found
            pass

def get_user_bot_containers() -> Dict[str, str]:
    """Get all user bot containers from database"""
    containers = {}
    try:
        db_path = os.path.join(BOT2_FOLDER, "data", "db.json")
        if os.path.exists(db_path):
            with open(db_path, "r") as f:
                db = json.load(f)
                bots = db.get("bots", {})
                for bot_id, bot_data in bots.items():
                    runtime_id = bot_data.get("runtime_id")
                    if runtime_id:
                        containers[bot_id] = runtime_id
    except Exception:
        pass
    return containers

def get_container_logs(container_name: str, tail: int = 10) -> List[str]:
    """Get recent logs from Docker container"""
    try:
        result = subprocess.run(
            ['sudo', 'docker', 'logs', '--tail', str(tail), container_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[-tail:]
    except Exception:
        pass
    return []

def read_new_lines(file_path: str, file_tag: str) -> list:
    """Read new lines from file since last position"""
    global file_positions
    
    try:
        if not os.path.exists(file_path):
            return []
        
        current_pos = file_positions.get(file_path, 0)
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(current_pos)
            new_lines = f.readlines()
            file_positions[file_path] = f.tell()
        
        return [line.strip() for line in new_lines if line.strip()]
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {e}")
        return []

class LogHandler(FileSystemEventHandler):
    """Handle file system events for log files"""
    
    def __init__(self, message_queue):
        super().__init__()
        self.last_modified = {}
        self.last_container_check = 0
        self.message_queue = message_queue
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = event.src_path
        rel_path = os.path.relpath(file_path, BOT2_FOLDER)
        
        # Check if it's a log file
        is_log_file = False
        file_tag = ""
        
        # Check predefined log files
        for log_file, tag in LOG_FILES.items():
            if rel_path == log_file or file_path == log_file:
                is_log_file = True
                file_tag = tag
                break
        
        # Check if it's any .log file in bot2 folder (INCLUDING uploads - user bot logs)
        if not is_log_file and file_path.endswith((".log", ".txt")):
            is_log_file = True
            # Check if it's a user bot log
            if "uploads" in file_path:
                # Extract bot name from path
                parts = file_path.split("/")
                try:
                    upload_idx = parts.index("uploads")
                    if upload_idx + 1 < len(parts):
                        user_id = parts[upload_idx + 1]
                        bot_folder = parts[upload_idx + 2] if upload_idx + 2 < len(parts) else ""
                        file_tag = f"🤖 User Bot [{user_id}]"
                        if bot_folder:
                            file_tag = f"🤖 User Bot [{bot_folder}]"
                except:
                    file_tag = f"🤖 User Bot Log"
            else:
                file_tag = f"📝 {os.path.basename(file_path)}"
        
        if is_log_file:
            # Read new lines
            new_lines = read_new_lines(file_path, file_tag)
            if new_lines:
                # Send each significant line
                for line in new_lines:
                    # Filter out noise (heartbeat, empty lines)
                    if line and not line.startswith("gravix_runner: heartbeat"):
                        # Check if it's an error or important event
                        is_important = any(keyword in line.lower() for keyword in [
                            "error", "failed", "exception", "timeout", "deploy", 
                            "build", "started", "stopped", "docker", "warning", "bot",
                            "token", "running", "crash", "exit"
                        ])
                        
                        if is_important or len(new_lines) <= 5:  # Send all if few lines, or important ones
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            message = f"[{timestamp}] {line}"
                            # Queue message for async processing
                            self.message_queue.put((message, file_tag))
    
    
    def on_created(self, event):
        """Handle new log file creation"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        if file_path.endswith((".log", ".txt")):
            rel_path = os.path.relpath(file_path, BOT2_FOLDER)
            if "uploads" not in file_path:
                print(f"📄 New log file detected: {rel_path}")
                # Initialize position
                file_positions[file_path] = 0

async def process_message_queue(message_queue):
    """Process messages from queue"""
    while True:
        try:
            if not message_queue.empty():
                message, file_tag = message_queue.get_nowait()
                await send_log_message(message, file_tag)
            await asyncio.sleep(0.1)
        except asyncio.QueueEmpty:
            await asyncio.sleep(0.1)
        except Exception as e:
            print(f"⚠️ Error processing message queue: {e}")
            await asyncio.sleep(1)

async def run_periodic_tasks(message_queue):
    """Run periodic tasks (delete old messages, check containers)"""
    # Start message queue processor
    asyncio.create_task(process_message_queue(message_queue))
    
    while True:
        try:
            await delete_old_messages()
            # Check user bot containers
            containers = get_user_bot_containers()
            global user_bot_containers
            
            # Check for new/stopped containers
            for bot_id, container_name in containers.items():
                if bot_id not in user_bot_containers:
                    # New container detected
                    await send_log_message(
                        f"🆕 New user bot container started: {container_name}",
                        "🤖 User Bot"
                    )
                    user_bot_containers[bot_id] = container_name
            
            # Check stopped containers
            for bot_id in list(user_bot_containers.keys()):
                if bot_id not in containers:
                    container_name = user_bot_containers.pop(bot_id)
                    await send_log_message(
                        f"🛑 User bot container stopped: {container_name}",
                        "🤖 User Bot"
                    )
            
            # Check container logs for errors
            for bot_id, container_name in user_bot_containers.items():
                try:
                    logs = get_container_logs(container_name, tail=5)
                    if logs:
                        for log_line in logs:
                            if any(keyword in log_line.lower() for keyword in [
                                "error", "exception", "failed", "crash", "warning"
                            ]):
                                timestamp = datetime.now().strftime("%H:%M:%S")
                                message = f"[{timestamp}] {log_line}"
                                await send_log_message(
                                    message,
                                    f"🐳 Docker [{container_name[:20]}]"
                                )
                except Exception:
                    pass
            
            await asyncio.sleep(60)  # Check every minute
        except Exception as e:
            print(f"⚠️ Error in periodic tasks: {e}")
            await asyncio.sleep(60)

def monitor_log_files():
    """Monitor all log files in bot2 folder"""
    global file_positions
    
    # Create message queue for thread-safe async communication
    import queue
    message_queue = queue.Queue()
    
    # Initialize positions for existing files
    for log_file, tag in LOG_FILES.items():
        full_path = os.path.join(BOT2_FOLDER, log_file) if not log_file.startswith("/") else log_file
        if os.path.exists(full_path):
            file_positions[full_path] = os.path.getsize(full_path)
            print(f"📊 Monitoring: {log_file}")
    
    # Find all .log and .txt files in bot2 folder (INCLUDING uploads)
    for root, dirs, files in os.walk(BOT2_FOLDER):
        for file in files:
            if file.endswith((".log", ".txt")):
                file_path = os.path.join(root, file)
                if file_path not in file_positions:
                    file_positions[file_path] = os.path.getsize(file_path) if os.path.exists(file_path) else 0
                    rel_path = os.path.relpath(file_path, BOT2_FOLDER)
                    if "uploads" in rel_path:
                        print(f"🤖 Found user bot log: {rel_path}")
                    else:
                        print(f"📄 Found log file: {rel_path}")
    
    # Setup watchdog
    event_handler = LogHandler(message_queue)
    observer = Observer()
    observer.schedule(event_handler, BOT2_FOLDER, recursive=True)
    observer.start()
    
    print(f"✅ Log watcher started. Monitoring: {BOT2_FOLDER}")
    print(f"🗑️ Auto-delete messages after {MESSAGE_DELETE_AFTER_MINUTES} minutes")
    print("📱 Waiting for admin chat ID... (send a message to the bot)")
    
    # Start periodic tasks in background thread
    import threading
    def run_async_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(run_periodic_tasks(message_queue))
    
    async_thread = threading.Thread(target=run_async_loop, daemon=True)
    async_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Stopping log watcher...")
        observer.stop()
    observer.join()

async def send_startup_message():
    """Send startup notification"""
    await send_log_message(
        f"🚀 Log Watcher Started\n"
        f"📁 Monitoring: {BOT2_FOLDER}\n"
        f"🗑️ Auto-delete: {MESSAGE_DELETE_AFTER_MINUTES} minutes\n"
        f"🤖 User bot logs: Enabled\n"
        f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "📊 System"
    )

def main():
    """Main entry point"""
    print("=" * 50)
    print("📊 Bot2 Log Watcher")
    print("=" * 50)
    print(f"Bot Token: {BOT_TOKEN[:20]}...")
    print(f"Monitoring: {BOT2_FOLDER}")
    print("=" * 50)
    
    # Initialize bot and send startup message
    asyncio.run(send_startup_message())
    
    # Start monitoring
    monitor_log_files()

if __name__ == "__main__":
    main()

