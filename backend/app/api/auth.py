"""
Authentication API routes
"""

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import UserRegister, UserLogin, TokenResponse, UserResponse
from app.security import PasswordHasher, JWTHandler, get_current_user

import logging

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    """
    Register a new user.

    Default role is VIEWER.
    """

    # Check username
    existing_user = (
        db.query(User)
        .filter(User.username == user_data.username)
        .first()
    )

    if existing_user:
        logger.warning(
            f"Registration attempt with existing username: "
            f"{user_data.username}"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check email
    existing_email = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )

    if existing_email:
        logger.warning(
            f"Registration attempt with existing email: "
            f"{user_data.email}"
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Generate user ID
    user_id = str(uuid4())

    # Hash password
    hashed_password = PasswordHasher.hash(
        user_data.password
    )

    # Create user
    new_user = User(
        id=user_id,
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        role="VIEWER",
        is_active=True,
        created_at=datetime.utcnow()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(
        f"New user registered: "
        f"{new_user.username} ({new_user.id})"
    )

    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    """
    Login with username and password.

    Returns a JWT access token.
    """

    # Find user
    user = (
        db.query(User)
        .filter(User.username == credentials.username)
        .first()
    )

    if not user:
        logger.warning(
            f"Login attempt with non-existent username: "
            f"{credentials.username}"
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Verify password
    if not PasswordHasher.verify(
        credentials.password,
        user.hashed_password
    ):
        logger.warning(
            f"Wrong password for user: {user.username}"
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check active account
    if not user.is_active:
        logger.warning(
            f"Inactive user attempted login: "
            f"{user.username}"
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Create JWT
    token, expires = JWTHandler.create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role
    )

    logger.info(
        f"User logged in: {user.username}"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int(
            (expires - datetime.utcnow()).total_seconds()
        )
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    db: Session = Depends(get_db),
    user_id: str = Depends(get_current_user)
):
    """
    Get information about the currently authenticated user.
    """

    user = (
        db.query(User)
        .filter(User.id == user_id)
        .first()
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return user


@router.get("/health")
async def health_check():
    """
    Authentication service health check.
    """

    return {
        "status": "ok",
        "message": "Authentication service is running"
    }
