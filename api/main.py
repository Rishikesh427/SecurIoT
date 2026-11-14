"""Hour 1–4 platform foundation. Business routes are defined in /contract."""
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SecurIoT API", version="0.1.0", root_path=os.getenv("ROOT_PATH", ""))
origins = [value.strip() for value in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if value.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "PUT"], allow_headers=["Authorization", "Content-Type", "X-API-Key"])


@app.get("/healthz", tags=["platform"])
def health():
    """Process health only; does not claim database or agent connectivity."""
    return {"status": "ok", "service": "securiot-api", "stage": "platform-h1-4"}
