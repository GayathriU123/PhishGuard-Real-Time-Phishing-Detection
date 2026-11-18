from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from threading import Lock
from time import monotonic

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api.routes import router
from backend.app.database import init_db

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_ROOT = PROJECT_ROOT / "frontend"
_scan_requests: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = Lock()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="PhishGuard API",
    version="1.0.0",
    description="Explainable URL and email investigation API.",
    lifespan=lifespan,
)
app.include_router(router, prefix="/api/v1")
app.mount("/assets", StaticFiles(directory=FRONTEND_ROOT / "assets"), name="assets")


@app.middleware("http")
async def scan_rate_limit(request: Request, call_next):
    if request.method == "POST" and request.url.path.startswith("/api/v1/scan/"):
        address = request.client.host if request.client else "unknown"
        now = monotonic()
        with _rate_lock:
            requests = _scan_requests[address]
            while requests and now - requests[0] >= 60:
                requests.popleft()
            if len(requests) >= 30:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Scan limit reached. Try again in a minute."},
                )
            requests.append(now)
    return await call_next(request)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def home() -> FileResponse:
    return FileResponse(FRONTEND_ROOT / "index.html")


@app.get("/{full_path:path}")
def frontend_route(full_path: str) -> FileResponse:
    if full_path.startswith("api/") or full_path.startswith("assets/"):
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Not found.")
    return FileResponse(FRONTEND_ROOT / "index.html")
