"""
Authentication API routes
"""

from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from uuid import uuid4

from app.database import get_db
from app.schemas import UserRegister, UserLogin, TokenResponse, UserResponse
from app.models import User
from app.security import PasswordHasher, JWTHandler
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    """
    Register a new user
    
    - username: unique username (alphanumeric)
    - email: unique email address
    - password: at least 8 characters
    - full_name: optional full name
    
    Default role is VIEWER. Admins can change roles.
    """
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        logger.warning(f"Registration attempt with existing username: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )

    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        logger.warning(f"Registration attempt with existing email: {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Create new user
    user_id = str(uuid4())
    hashed_password = PasswordHasher.hash(user_data.password)

    new_user = User(
        id=user_id,
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        role="VIEWER",  # Default role
        is_active=True,
        created_at=datetime.utcnow()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    logger.info(f"New user registered: {new_user.username} ({new_user.id})")

    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: UserLogin,
    db: Session = Depends(get_db)
):
    """
    Login with username and password
    
    Returns a JWT access token valid for 24 hours
    """
    # Find user by username
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user:
        logger.warning(f"Login attempt with non-existent username: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check password
    if not PasswordHasher.verify(credentials.password, user.hashed_password):
        logger.warning(f"Login attempt with wrong password for user: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if user is active
    if not user.is_active:
        logger.warning(f"Login attempt by inactive user: {user.username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Generate token
    token, expires = JWTHandler.create_access_token(
        user_id=user.id,
        username=user.username,
        role=user.role
    )

    logger.info(f"User logged in: {user.username}")

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": int((expires - datetime.utcnow()).total_seconds())
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    db: Session = Depends(get_db),
    user_id: str = Depends(__import__("app.security", fromlist=["get_current_user"]).get_current_user)
):
    """
    Get current authenticated user information
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@router.get("/health")
async def health_check():
    """
    Health check endpoint (no authentication required)
    """
    return {"status": "ok", "message": "Authentication service is running"}
