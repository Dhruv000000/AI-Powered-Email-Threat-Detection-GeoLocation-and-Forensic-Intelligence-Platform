import sys
from pathlib import Path

# Ensure backend and root directories are in sys.path
_current_file = Path(__file__).resolve()
_app_dir = _current_file.parent
_backend_dir = _app_dir.parent
_root_dir = _backend_dir.parent

for _p in [str(_backend_dir), str(_root_dir)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.config import settings
from app.core.logging import logger
from app.db.base import Base
from app.db.session import engine, _verify_sqlite_schema
from app.db.models import *  # Ensure all models are loaded
from app.api.v1.router import api_v1_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure database tables are created
    logger.info(f"Initializing AEGIS database schema (Engine: {settings.ANALYSIS_ENGINE_VERSION})...")
    Base.metadata.create_all(bind=engine)
    _verify_sqlite_schema(engine)
    logger.info("Database schema initialized successfully.")
    yield
    # Shutdown
    logger.info("AEGIS backend shutting down.")

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "### AEGIS — AI-Powered Email Threat Intelligence & Forensic Investigation Platform\n\n"
        "Forensic static analysis engine designed for incident responders and DFIR analysts.\n\n"
        "**Core Capabilities:**\n"
        "- RFC 822 / MIME Multi-part Email Parsing\n"
        "- Hop-by-Hop SMTP Received Relay Chain Reconstruction\n"
        "- SPF / DKIM / DMARC Header Verification\n"
        "- Static Hyperlink & Lookalike Domain Analysis (Zero Network Egress)\n"
        "- Non-Executing Attachment Extraction & SHA-256 Hashing\n"
        "- Hybrid Scikit-learn Threat Classification & 0-100 Composite Risk Scoring\n"
        "- Evidence-Referenced Reason Codes & Provenance Tracking"
    ),
    version=settings.ANALYSIS_ENGINE_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware
origins = [
    settings.FRONTEND_URL,
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include v1 API Router
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


# Clean Error Handlers (Never expose stack traces)
@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    if isinstance(detail, dict) and "code" in detail:
        error_payload = detail
    else:
        error_payload = {
            "code": f"HTTP_{exc.status_code}",
            "message": str(detail)
        }
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": error_payload}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = []
    for err in exc.errors():
        field = ".".join(str(loc) for loc in err["loc"])
        errors.append(f"{field}: {err['msg']}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "Invalid request parameters or payload structure.",
                "details": errors
            }
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled server exception on {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred while processing the forensic request."
            }
        }
    )


@app.get("/health", tags=["Health"])
def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "aegis-email-analysis-engine",
        "version": settings.ANALYSIS_ENGINE_VERSION,
        "feature_schema_version": settings.FEATURE_SCHEMA_VERSION,
        "model_name": settings.ML_MODEL_NAME,
        "model_version": settings.ML_MODEL_VERSION,
    }

@app.get("/", tags=["Root"])
def root():
    return {
        "title": settings.PROJECT_NAME,
        "docs": "/docs",
        "api_v1": settings.API_V1_PREFIX,
        "status": "online",
    }
