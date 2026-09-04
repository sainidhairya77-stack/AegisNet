"""
AegisNet Main Application

FastAPI application entry point with all routes, middleware, and configuration
"""

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import sys

from app.config import get_settings
from app.database import init_db
from app.api import auth, health, pcaps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifecycle management
    - Startup: Initialize database
    - Shutdown: Cleanup
    """
    # Startup
    logger.info("🚀 Starting AegisNet API...")
    try:
        init_db()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ Failed to initialize database: {str(e)}")
        raise
    
    yield
    
    # Shutdown
    logger.info("🛑 Shutting down AegisNet API...")


# Create FastAPI application
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description="AI-Assisted Network Defense, Attack Path Analysis & Controlled Automated Response Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check route (no auth required)
@app.get("/health", tags=["Health"])
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "ok",
        "service": "AegisNet API",
        "environment": settings.environment
    }


# Include routers
app.include_router(auth.router)
app.include_router(pcaps.router)


# Error handlers
@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """Handle uncaught exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
            "code": "INTERNAL_ERROR"
        }
    )


@app.get("/", tags=["Root"])
async def root():
    """API root endpoint"""
    return {
        "message": "Welcome to AegisNet API",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.is_development,
        log_level=settings.log_level.lower()
    )
