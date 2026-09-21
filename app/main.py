from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.errors import setup_exception_handlers

app = FastAPI(
    title=settings.APP_NAME,
    description="MailTrace-AI pre-delivery email threat detection, geolocation, and forensic intelligence platform backend.",
    version="0.1.0",
    debug=settings.DEBUG,
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup Exception Handlers
setup_exception_handlers(app)


from app.api.v1.router import api_v1_router

# Include API v1 router (and /api alias for contract compatibility)
app.include_router(api_v1_router, prefix="/api/v1")
app.include_router(api_v1_router, prefix="/api")


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify backend service status."""
    return {"status": "ok"}

