"""
Security module for authentication and authorization
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Header
from sqlalchemy.orm import Session
from app.config import get_settings
from app.models import User
import logging

logger = logging.getLogger(__name__)

settings = get_settings()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordHasher:
    """Password hashing utilities"""

    @staticmethod
    def hash(password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)

    @staticmethod
    def verify(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)


class JWTHandler:
    """JWT token creation and validation"""

    @staticmethod
    def create_access_token(user_id: str, username: str, role: str) -> tuple:
        """
        Create a JWT access token
        
        Returns:
            Tuple of (token, expiration_time)
        """
        expires = datetime.utcnow() + timedelta(hours=settings.jwt_expiration_hours)
        payload = {
            "sub": user_id,
            "username": username,
            "role": role,
            "exp": expires,
            "iat": datetime.utcnow()
        }
        token = jwt.encode(
            payload,
            settings.jwt_secret,
            algorithm=settings.jwt_algorithm
        )
        return token, expires

    @staticmethod
    def verify_token(token: str) -> dict:
        """
        Verify a JWT token and return payload
        
        Raises:
            HTTPException if token is invalid or expired
        """
        try:
            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[settings.jwt_algorithm]
            )
            return payload
        except JWTError as e:
            logger.warning(f"Invalid token: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={"WWW-Authenticate": "Bearer"},
            )


async def get_current_user(
    authorization: Optional[str] = Header(None)
) -> str:
    """
    Dependency injection for getting current authenticated user ID
    Returns user ID from JWT token. Actual User object requires DB lookup.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization[7:]  # Remove "Bearer " prefix
    payload = JWTHandler.verify_token(token)
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )

    return user_id


async def get_current_admin(
    authorization: Optional[str] = Header(None)
) -> str:
    """
    Dependency for admin-only routes
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization[7:]  # Remove "Bearer " prefix
    payload = JWTHandler.verify_token(token)
    
    if payload.get("role") != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return payload.get("sub")


async def get_current_analyst(
    authorization: Optional[str] = Header(None)
) -> str:
    """
    Dependency for analyst/admin routes
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization[7:]  # Remove "Bearer " prefix
    payload = JWTHandler.verify_token(token)
    
    if payload.get("role") not in ("ADMIN", "ANALYST"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required"
        )
    
    return payload.get("sub")


class AuthorizationError(HTTPException):
    """Custom authorization error"""
    def __init__(self, detail: str = "Not authorized"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )
