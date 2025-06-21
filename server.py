import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

clients: list[WebSocket] = []

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    clients.append(ws)
    try:
        while True:
            await ws.receive_text()   # just keep alive
    except WebSocketDisconnect:
        clients.remove(ws)

@app.post("/push")
async def push_line(payload: dict):
    line = payload.get("line")
    if not line:
        return {"error": "no line provided"}
    msg = json.dumps({"line": line})
    for ws in clients[:]:
        try:
            await ws.send_text(msg)
        except:
            clients.remove(ws)
    return {"status": "ok"}
