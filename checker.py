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
COOKIE_FILE = "cookie.json"

app = Client("my_bot", api_id=API_ID, api_hash=API_HASH, bot_token=BOT_TOKEN)

# --- rest of your code remains unchanged ---

user_pending_files = {}
pending_cookie_users = set()
cookie_retry_counts = defaultdict(int)
cookie_cooldowns = {}

# Helper function to validate VIP access
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

# Function to check if user can use VIP command
def can_use_vip(user_id):
    if user_id == ADMIN_ID:
        return True, None
    if not has_vip_access(user_id):
        return False, "\ud83d\udeab You need to avail a lifetime key to use this command!"
    return True, None

# Save file to download location
async def save_file(message):
    file_message = message.reply_to_message if message.reply_to_message and message.reply_to_message.document else message if message.document else None
    if not file_message:
        return None, "\ud83d\udeab Please send or reply to a file."
    os.makedirs("downloads", exist_ok=True)
    file_path = f"downloads/{file_message.document.file_name}"
    await file_message.download(file_path)
    return file_path, None

@app.on_message(filters.command("checkfile"))
async def check_file(client, message):
    user_id = message.from_user.id

    if user_id in cookie_cooldowns and (remaining := int(cookie_cooldowns[user_id] - time.time())) > 0:
        await message.reply(f"\u23f3 You're on cooldown due to too many failed cookie retries. Please wait {remaining // 60}m {remaining % 60}s.")
        return
    elif user_id in cookie_cooldowns:
        del cookie_cooldowns[user_id]
        cookie_retry_counts[user_id] = 0

    can_use, error_message = can_use_vip(user_id)
    if not can_use:
        await message.reply(error_message)
        return

    if not os.path.exists(COOKIE_FILE):
        file_path, error = await save_file(message)
        if error:
            await message.reply(error)
            return
        user_pending_files[user_id] = file_path
        pending_cookie_users.add(user_id)
        await message.reply("\ud83c\udf5a Please send your cookies using `/sendcookies key=value; key2=value2`")
        return

    file_path, error = await save_file(message)
    if error:
        await message.reply(error)
        return

    await message.reply("\ud83d\udd0d Running bulk check...")
    cookies = main.get_cookies()
    await bulk_check(file_path, cookies, message)

@app.on_message(filters.command("sendcookies"))
async def receive_cookies(client, message):
    user_id = message.from_user.id

    if user_id not in pending_cookie_users:
        await message.reply("\u2139\ufe0f No cookie request pending. Use /checkfile first.")
        return

    parts = message.text.split(" ", 1)
    if len(parts) < 2 or '=' not in parts[1]:
        await message.reply("\u274c Please include cookies in the format: `key=value; key2=value2`")
        return

    cookie_str = parts[1].strip()
    cookies = {k.strip(): v.strip() for k, v in (i.split('=', 1) for i in cookie_str.split('; ') if '=' in i)}

    if not main.validate_cookies(cookies):
        await message.reply("\u274c Invalid cookies. Please enter a valid cookie.")
        user_pending_files.pop(user_id, None)
        pending_cookie_users.discard(user_id)
        return

    main.save_cookies(cookies)
    pending_cookie_users.discard(user_id)
    await message.reply("\u2705 Cookies saved successfully!")

    if user_id in user_pending_files:
        file_path = user_pending_files.pop(user_id)
        await message.reply("\ud83d\udd0d Running bulk check now...")
        await bulk_check(file_path, cookies, message)

# Function for bulk checking accounts
async def bulk_check(file_path, cookies, message):
    import time  # ensure this is imported at the top

    user_id = message.from_user.id
    date = main.get_datenow()
    successful_count = failed_count = 0

    if not file_path.endswith('.txt'):
        await message.reply("\u274c Error: Provided file is not a .txt file.")
        return

    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    failed_file = os.path.join(output_dir, f"failed_{date}.txt")
    success_file = os.path.join(output_dir, f"valid_accounts_{date}.txt")

    with open(file_path, 'r', encoding='utf-8') as infile, \
         open(failed_file, 'a', encoding='utf-8') as fail_out, \
         open(success_file, 'a', encoding='utf-8') as success_out:

        accounts = infile.readlines()
        await message.reply(f"\ud83d\udccc Loaded {len(accounts)} accounts for checking.")

        # Get the start index from the pending files (if retrying)
        start_index = user_pending_files.get(user_id, 0)

        for i in range(start_index, len(accounts)):
            acc = accounts[i].strip()
            if ':' not in acc:
                failed_count += 1
                fail_out.write(f"{acc} - Invalid format\n")
                await message.reply(f"\u274c {acc} - Invalid format")
                continue

            username, password = acc.rsplit(':', 1)
            sys.stdin = io.StringIO("\n")
            result = await asyncio.to_thread(main.check_account, username, password, date)
            clean = main.strip_ansi_codes_jarell(result)
            print(f"[DEBUG] Result: {clean}")  # Helpful debug log

            if "CAPTCHA" in clean.upper() or "COOKIE" in clean.upper():
                cookie_retry_counts[user_id] += 1

                if cookie_retry_counts[user_id] > 3:
                    cooldown = 15 * 60
                    cookie_cooldowns[user_id] = time.time() + cooldown
                    msg = await message.reply("\u274c Maximum retries reached. Try again in 15-20 minutes.")
                    for i in range(15):
                        await asyncio.sleep(1)
                        bar = "#" * (29 - i) + "-" * (i + 1)
                        await msg.edit(f"\u23f3 Stopping check in... [{bar}] {15 - i - 1}s")
                    break

                user_pending_files[user_id] = i  # Store the current index
                pending_cookie_users.add(user_id)

                msg = await message.reply("Too much... Please resend a new cookie using `/sendcookies` within 30 seconds...\n\nProgress: [------------------------------] 30s")
                for i in range(30):
                    await asyncio.sleep(1)
                    if user_id not in pending_cookie_users:
                        cookies = main.get_cookies()
                        break
                    bar = "-" * (29 - i) + "#" * (i + 1)
                    await msg.edit(f"Too much... Please resend a new cookie using `/sendcookies` within 30 seconds...\n\nProgress: [{bar}] {30 - i - 1}s")
                else:
                    await msg.edit("\u23f3 Cookie not received in time. Stopping check.")
                break

            elif "[+]" in clean:
                successful_count += 1
                success_out.write(f"{username}:{password} - valid\n")
                await message.reply(clean)
            else:
                failed_count += 1
                fail_out.write(f"{username}:{password} - {clean}\n")
                await message.reply(f"\u274c {username}:{password} - {clean}")

    await message.reply(
        f"\ud83d\udcca **Bulk Check Summary:**\n"
        f"\ud83d\udccc Total: {len(accounts)}\n"
        f"\u2705 Success: {successful_count}\n"
        f"\u274c Failed: {failed_count}"
    )

app.run()
