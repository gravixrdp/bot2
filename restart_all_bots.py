#!/usr/bin/env python3
"""
Script to restart all stopped bots
"""
import os
import sys
import json

# Add the bot2 directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gravixhost.storage import _read_db, _write_db
from gravixhost.services.hoster import build_and_run, extract_token_from_code

def find_entry_file(workspace):
    """Find the entry Python file in workspace"""
    if not os.path.exists(workspace):
        return None
    
    # Check for bot.py first
    candidate = os.path.join(workspace, "bot.py")
    if os.path.exists(candidate):
        return "bot.py"
    
    # Check for any .py file
    for f in os.listdir(workspace):
        if f.endswith(".py") and not f.startswith("_"):
            return f
    
    return None

def restart_stopped_bots():
    """Restart all stopped bots and rebuild containers with old runner code"""
    db = _read_db()
    bots = db.get("bots", {})
    
    # Get all bots that are stopped OR need to be rebuilt (running but with old code)
    stopped_bots = [b for b in bots.values() if b.get("status") == "stopped"]
    
    # Rebuild ALL running bots to use updated autostart logic
    running_bots_needing_rebuild = [b for b in bots.values() if b.get("status") == "running"]
    
    all_bots_to_restart = stopped_bots + running_bots_needing_rebuild
    
    if not all_bots_to_restart:
        print("No bots found.")
        return
    
    print(f"Found {len(all_bots_to_restart)} bot(s) to restart/rebuild.")
    if stopped_bots:
        print(f"  - {len(stopped_bots)} stopped bot(s)")
    if running_bots_needing_rebuild:
        print(f"  - {len(running_bots_needing_rebuild)} running bot(s) that need rebuild with updated code")
    
    for bot in all_bots_to_restart:
        bot_id = bot["id"]
        owner_id = bot["owner_id"]
        name = bot.get("name", "Unknown")
        workspace = bot.get("path")
        
        print(f"\n{'='*60}")
        print(f"Restarting bot: {name} (ID: {bot_id})")
        print(f"Owner: {owner_id}")
        print(f"Workspace: {workspace}")
        
        if not workspace or not os.path.exists(workspace):
            print(f"❌ ERROR: Workspace path does not exist: {workspace}")
            continue
        
        # Find entry file
        entry_file = find_entry_file(workspace)
        if not entry_file:
            print(f"❌ ERROR: No Python file found in workspace")
            continue
        
        entry_path = os.path.join(workspace, entry_file)
        
        # Extract token from code
        try:
            with open(entry_path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            token = extract_token_from_code(code)
            
            if not token:
                print(f"⚠️  WARNING: Could not extract token from code. Trying to use existing token...")
                token = bot.get("token", "")
                if not token:
                    print(f"❌ ERROR: No token found. Skipping...")
                    continue
        except Exception as e:
            print(f"❌ ERROR: Could not read code file: {e}")
            continue
        
        print(f"✓ Token extracted: {token[:10]}...{token[-5:]}")
        print(f"✓ Entry file: {entry_file}")
        
        # Stop and remove old container if exists
        from docker import from_env as docker_from_env
        client = docker_from_env()
        old_container_name = f"hostbot_{owner_id}_{bot_id}"
        try:
            containers = client.containers.list(all=True, filters={"name": old_container_name})
            for container in containers:
                if old_container_name in container.name:
                    print(f"🛑 Stopping old container: {container.name}")
                    container.stop()
                    print(f"🗑️  Removing old container: {container.name}")
                    container.remove()
        except Exception as e:
            print(f"⚠️  Could not remove old container: {e}")
        
        # Restart the bot
        try:
            print(f"🚀 Rebuilding and starting bot with updated code...")
            success, runtime_id, error = build_and_run(
                user_id=owner_id,
                bot_id=bot_id,
                token=token,
                workspace=workspace,
                entry=entry_file
            )
            
            if success:
                # Update database
                bot["status"] = "running"
                bot["runtime_id"] = runtime_id
                from datetime import datetime
                bot["started_at"] = datetime.now().isoformat()
                bots[bot_id] = bot
                db["bots"] = bots
                _write_db(db)
                print(f"✅ SUCCESS: Bot started! Runtime ID: {runtime_id}")
            else:
                print(f"❌ FAILED: {error}")
        except Exception as e:
            print(f"❌ EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print("Done!")

if __name__ == "__main__":
    restart_stopped_bots()

