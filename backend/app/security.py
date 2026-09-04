"""
Security module for authentication and authorization
"""

from datetime import datetime, timedelta
from typing import Optional

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from app.config import get_settings

import logging


logger = logging.getLogger(__name__)

settings = get_settings()


# ============================================================
# Password Hashing
# ============================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


# ============================================================
# Swagger / Bearer Authentication
# ============================================================

bearer_scheme = HTTPBearer(
    scheme_name="BearerAuth",
    auto_error=False
)


# ============================================================
# Password Hasher
# ============================================================

class PasswordHasher:
    """Password hashing utilities"""

    @staticmethod
    def hash(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify(
        plain_password: str,
        hashed_password: str
    ) -> bool:

        return pwd_context.verify(
            plain_password,
            hashed_password
        )


# ============================================================
# JWT Handler
# ============================================================

class JWTHandler:
    """JWT token creation and validation"""

    @staticmethod
    def create_access_token(
        user_id: str,
        username: str,
        role: str
    ) -> tuple:

        expires = datetime.utcnow() + timedelta(
            hours=settings.jwt_expiration_hours
        )

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
    def verify_token(
        token: str
    ) -> dict:

        try:

            payload = jwt.decode(
                token,
                settings.jwt_secret,
                algorithms=[
                    settings.jwt_algorithm
                ]
            )

            return payload

        except JWTError as e:

            logger.warning(
                f"Invalid token: {str(e)}"
            )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication token",
                headers={
                    "WWW-Authenticate": "Bearer"
                }
            )


# ============================================================
# Current User
# ============================================================

async def get_current_user(
    credentials: Optional[
        HTTPAuthorizationCredentials
    ] = Depends(bearer_scheme)
) -> str:

    # No token
    if credentials is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    # Get token
    token = credentials.credentials

    # Verify JWT
    payload = JWTHandler.verify_token(token)

    # Get user ID
    user_id = payload.get("sub")

    if not user_id:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    return user_id


# ============================================================
# Current Admin
# ============================================================

async def get_current_admin(
    credentials: Optional[
        HTTPAuthorizationCredentials
    ] = Depends(bearer_scheme)
) -> str:

    if credentials is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    token = credentials.credentials

    payload = JWTHandler.verify_token(token)

    if payload.get("role") != "ADMIN":

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    return payload.get("sub")


# ============================================================
# Current Analyst
# ============================================================

async def get_current_analyst(
    credentials: Optional[
        HTTPAuthorizationCredentials
    ] = Depends(bearer_scheme)
) -> str:

    if credentials is None:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={
                "WWW-Authenticate": "Bearer"
            }
        )

    token = credentials.credentials

    payload = JWTHandler.verify_token(token)

    if payload.get("role") not in (
        "ADMIN",
        "ANALYST"
    ):

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Analyst or admin access required"
        )

    return payload.get("sub")


# ============================================================
# Authorization Error
# ============================================================

class AuthorizationError(HTTPException):
    """Custom authorization error"""

    def __init__(
        self,
        detail: str = "Not authorized"
    ):

        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail
        )
        