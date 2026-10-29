import os
import asyncio
from dotenv import load_dotenv
from telethon import TelegramClient

load_dotenv()

api_id = int(os.environ["TELEGRAM_API_ID"])
api_hash = os.environ["TELEGRAM_API_HASH"]

async def main():
    async with TelegramClient(
        "telegram_threat_intel",
        api_id,
        api_hash,
    ) as client:
        me = await client.get_me()
        print(f"Connected successfully as: {me.first_name}")
        print("Telegram API authentication is working.")

if __name__ == "__main__":
    asyncio.run(main())