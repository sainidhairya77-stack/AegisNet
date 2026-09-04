"""
Health check routes
"""

from fastapi import APIRouter

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "ok",
        "service": "AegisNet API"
    }
