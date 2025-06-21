import os
import asyncio, json, websockets

PORT = int(os.environ.get("PORT", 8765))

clients = set()
async def handler(ws, path):
    clients.add(ws)
    try: await ws.wait_closed()
    finally: clients.remove(ws)

async def main():
    async with websockets.serve(handler, "0.0.0.0", PORT):
        await asyncio.Future()

if __name__=="__main__":
    asyncio.run(main())
