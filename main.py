import time
import json
import base64
import hmac
import hashlib
import requests
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

API_KEY = os.getenv("API_KEY")
SECRET_KEY = 'WqL37vOWMy3GUUfDkCsEofpBreCwgHS8'
ACTIONS = ['slot_spin', 'box_spin', 'fortune_spin', 'instantbonus', 'mega_bonus', 'dailybonus', 'scratch_card']

def jwt_encode(payload, key, header={'alg': 'HS256', 'typ': 'JWT'}):
    def base64url_encode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    header_encoded = base64url_encode(json.dumps(header).encode())
    payload_encoded = base64url_encode(json.dumps(payload).encode())
    signature = hmac.new(key.encode(), f'{header_encoded}.{payload_encoded}'.encode(), hashlib.sha256).digest()
    signature_encoded = base64url_encode(signature)
    return f'{header_encoded}.{payload_encoded}.{signature_encoded}'

def decode_jwt(jwt):
    try:
        parts = jwt.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
        return payload.get('sourceId'), payload.get('uuid')
    except Exception:
        return None, None

async def handle_token(update: Update, context: ContextTypes.DEFAULT_TYPE):
    jwt = update.message.text.strip()
    sourceId, uuid = decode_jwt(jwt)
    
    if not sourceId or not uuid:
        await update.message.reply_text("❌ Invalid JWT token.")
        return

    coins_map = {
        'slot_spin': 100, 'box_spin': 100, 'fortune_spin': 100,
        'instantbonus': 500, 'mega_bonus': 300, 'dailybonus': 1000,
        'scratch_card': 100
    }

    limit_flags = {action: False for action in ACTIONS}

    await update.message.reply_text("🤖 Bot started. Processing all actions repeatedly until limit reached...")

    while not all(limit_flags.values()):
        for action in ACTIONS:
            if limit_flags[action]:
                continue  # Skip if limit already reached for this action

            coin = coins_map.get(action, 12)
            payload = {
                'sourceId': sourceId,
                'requestId': 'req_' + str(int(time.time())),
                'uuid': uuid,
                'coins': str(coin),
                'exp': int(time.time()) + 3600
            }

            jwt_token = jwt_encode(payload, SECRET_KEY)
            url = f"https://app.royalspin.fun/v0/bonus/claim/{action}"
            headers = {
                "authorization": f"Bearer {jwt_token}",
                "content-type": "application/json; charset=utf-8",
                "accept-encoding": "gzip",
                "user-agent": "okhttp/4.12.0"
            }

            try:
                response = requests.put(url, headers=headers, json={'sid': sourceId}, timeout=10)
                json_data = response.json()
            except Exception as e:
                await update.message.reply_text(f"⚠️ Error during `{action}`: {str(e)}")
                time.sleep(1)
                continue

            if json_data.get("error") == "You have exceeded todays limit! Come again tomorrow.":
                await update.message.reply_text(f"🚫 `{action}` limit reached. Skipping now.")
                limit_flags[action] = True
            elif json_data.get("error") == "Failed to process! Please try again":
                await update.message.reply_text(f"⚠️ `{action}` failed, will retry later.")
            else:
                await update.message.reply_text(f"✅ `{action}` completed.\n🔽 Response:\n{json.dumps(json_data, indent=2)}")

            time.sleep(1)

    await update.message.reply_text("🎉 All tasks completed for this token.")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Send your JWT token to start the auto-claim process.")

def main():
    app = ApplicationBuilder().token(API_KEY).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_token))
    app.run_polling()

if __name__ == '__main__':
    main()
