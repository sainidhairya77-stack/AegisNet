"""
AegisNet Main Application

FastAPI application entry point with all routes, middleware, and configuration
"""

from contextlib import asynccontextmanager
import logging
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.database import init_db
from app.api import auth, health, pcaps


# ============================================================
# Logging Configuration
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)

logger = logging.getLogger(__name__)


# ============================================================
# Application Settings
# ============================================================

settings = get_settings()


# ============================================================
# Application Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup and shutdown lifecycle.
    """

    logger.info("🚀 Starting AegisNet API...")

    try:
        # Initialize database
        init_db()

        logger.info(
            "✅ Database initialized successfully"
        )

    except Exception as e:

        logger.error(
            f"❌ Failed to initialize database: {str(e)}",
            exc_info=True
        )

        raise

    yield

    logger.info(
        "🛑 Shutting down AegisNet API..."
    )


# ============================================================
# FastAPI Application
# ============================================================

app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=(
        "AI-Assisted Network Defense, Attack Path Analysis "
        "& Controlled Automated Response Platform"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# ============================================================
# CORS Middleware
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Health Check
# ============================================================

@app.get(
    "/health",
    tags=["Health"]
)
async def health_check():
    """
    Check API health status.
    """

    return {
        "status": "ok",
        "service": "AegisNet API",
        "environment": settings.environment
    }


# ============================================================
# API Routers
# ============================================================

app.include_router(auth.router)

app.include_router(pcaps.router)


# ============================================================
# Global Exception Handler
# ============================================================

@app.exception_handler(Exception)
async def general_exception_handler(
    request,
    exc
):
    """
    Handle unexpected application errors.
    """

    logger.error(
        f"Unhandled exception: {str(exc)}",
        exc_info=True
    )

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "code": "INTERNAL_ERROR"
        }
    )


# ============================================================
# Root Endpoint
# ============================================================

@app.get(
    "/",
    tags=["Root"]
)
async def root():
    """
    AegisNet API root endpoint.
    """

    return {
        "message": "Welcome to AegisNet API",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health"
    }


# ============================================================
# Local Development Entry Point
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.is_development,
        log_level=settings.log_level.lower()
    )