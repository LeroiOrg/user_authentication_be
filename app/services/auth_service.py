"""
Authentication service with ACID transaction support
UPDATED: Now uses atomic transactions for data consistency
"""
import jwt
import os
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user_model import User
from app.models.blocked_email import BlockedEmail
from app.models.verification_code import VerificationCode
from app.schemas.user_scheme import UserCreate
from app.db.transactions import atomic_transaction, retry_on_deadlock, TransactionContext
import logging

logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode["exp"] = expire
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def is_email_blocked(db: Session, email: str) -> bool:
    blocked = db.query(BlockedEmail).filter_by(email=email).first()
    if blocked and blocked.blocked_until:
        if blocked.blocked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            return True
    return False


# ==================== ACID TRANSACTION FUNCTIONS ====================

@atomic_transaction
@retry_on_deadlock(max_attempts=3)
def register_user(db: Session, user: UserCreate):
    """
    ACID Transaction: Register new user with automatic rollback on failure
    Ensures user is only created if all operations succeed
    
    Args:
        db: Database session
        user: User registration data
    
    Returns:
        User: Created user object
    
    Raises:
        Exception: If email already exists or registration fails
    """
    # Check if email already exists
    if db.query(User).filter_by(correo=user.email).first():
        raise Exception("El correo ya está registrado")
    
    # Hash password
    hashed_password = get_password_hash(user.password)
    
    # Create user
    db_user = User(
        nombre=user.first_name,
        apellido=user.last_name or '',
        correo=user.email,
        contraseña=hashed_password,
        proveedor=user.provider,
        creditos=1000
    )
    
    db.add(db_user)
    # Note: commit is handled by @atomic_transaction decorator
    db.flush()  # Flush to get ID without committing
    db.refresh(db_user)
    
    logger.info(f"✅ User registered successfully: {user.email}")
    return db_user


def authenticate_user(db: Session, correo: str, contraseña: str):
    """
    Authenticate user - Read-only operation, no transaction needed
    
    Args:
        db: Database session
        correo: User email
        contraseña: User password
    
    Returns:
        User or None: Authenticated user or None if authentication fails
    """
    user = db.query(User).filter_by(correo=correo).first()
    if not user:
        return None
    if not verify_password(contraseña, user.contraseña):
        return None
    return user


@atomic_transaction
def save_verification_code(db: Session, email: str, code: str, minutes_expire: int = 5):
    """
    ACID Transaction: Save verification code with automatic expiration
    
    Args:
        db: Database session
        email: User email
        code: Verification code
        minutes_expire: Minutes until code expires
    
    Returns:
        VerificationCode: Created verification code object
    """
    expiration = datetime.now(timezone.utc) + timedelta(minutes=minutes_expire)
    db_code = VerificationCode(email=email, code=code, expiration=expiration)
    db.add(db_code)
    # Commit handled by decorator
    db.flush()
    
    logger.info(f"✅ Verification code saved for: {email}")
    return db_code


@atomic_transaction
def verify_code(db: Session, email: str, code: str) -> bool:
    """
    ACID Transaction: Verify and delete verification code atomically
    Ensures code is only deleted if verification succeeds
    
    Args:
        db: Database session
        email: User email
        code: Verification code to check
    
    Returns:
        bool: True if code is valid, False otherwise
    """
    db_code = db.query(VerificationCode).filter_by(email=email, code=code).first()
    
    if db_code and db_code.expiration.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
        # Code is valid, delete it atomically
        db.delete(db_code)
        # Commit handled by decorator
        logger.info(f"✅ Verification code validated and deleted for: {email}")
        return True
    
    logger.warning(f"⚠️  Invalid or expired verification code for: {email}")
    return False


@atomic_transaction
@retry_on_deadlock(max_attempts=3)
def login_or_register_google(db: Session, correo: str, nombre: str):
    """
    ACID Transaction: Login or register user via Google OAuth
    Ensures user is only created if all operations succeed
    
    Args:
        db: Database session
        correo: User email from Google
        nombre: User name from Google
    
    Returns:
        User: Existing or newly created user
    """
    user = db.query(User).filter_by(correo=correo).first()
    
    if not user:
        # Create new user
        user = User(
            nombre=nombre,
            apellido='',
            correo=correo,
            contraseña=None,
            proveedor="google",
            creditos=1000,
        )
        db.add(user)
        db.flush()
        db.refresh(user)
        logger.info(f"✅ New Google user registered: {correo}")
    else:
        logger.info(f"✅ Existing Google user logged in: {correo}")
    
    return user


@atomic_transaction
def register_user_with_initial_credits(db: Session, user: UserCreate, initial_credits: int = 1000):
    """
    ACID Transaction: Register user and set initial credits atomically
    Example of complex transaction with multiple related operations
    
    Args:
        db: Database session
        user: User registration data
        initial_credits: Initial credit amount for new user
    
    Returns:
        dict: User data with credit information
    """
    # Check if email already exists
    if db.query(User).filter_by(correo=user.email).first():
        raise Exception("El correo ya está registrado")
    
    # Hash password
    hashed_password = get_password_hash(user.password)
    
    # Create user with initial credits
    db_user = User(
        nombre=user.first_name,
        apellido=user.last_name or '',
        correo=user.email,
        contraseña=hashed_password,
        proveedor=user.provider,
        creditos=initial_credits
    )
    
    db.add(db_user)
    db.flush()
    db.refresh(db_user)
    
    logger.info(f"✅ User registered with {initial_credits} credits: {user.email}")
    
    return {
        'success': True,
        'user': db_user,
        'initial_credits': initial_credits,
        'message': f'User created successfully with {initial_credits} credits'
    }


@atomic_transaction
def update_user_credits_atomic(db: Session, user_id: int, credit_change: int, reason: str):
    """
    ACID Transaction: Update user credits with audit trail
    Example of transactional update with validation
    
    Args:
        db: Database session
        user_id: User ID
        credit_change: Amount to add (positive) or subtract (negative)
        reason: Reason for credit change
    
    Returns:
        dict: Updated user data
    """
    user = db.query(User).filter_by(id_usuario=user_id).first()
    
    if not user:
        raise Exception(f"User with ID {user_id} not found")
    
    # Calculate new credit amount
    new_credits = user.creditos + credit_change
    
    # Validate: credits can't go below zero
    if new_credits < 0:
        raise Exception(f"Insufficient credits. Current: {user.creditos}, Attempted change: {credit_change}")
    
    # Update credits
    old_credits = user.creditos
    user.creditos = new_credits
    
    db.flush()
    
    logger.info(f"✅ Credits updated for user {user_id}: {old_credits} → {new_credits} (Reason: {reason})")
    
    return {
        'success': True,
        'user_id': user_id,
        'old_credits': old_credits,
        'new_credits': new_credits,
        'change': credit_change,
        'reason': reason
    }


def block_email_with_reason_atomic(db: Session, email: str, reason: str, hours: int = 24):
    """
    ACID Transaction: Block email with reason and expiration
    Uses context manager for explicit transaction control
    
    Args:
        db: Database session
        email: Email to block
        reason: Reason for blocking
        hours: Hours until unblock
    
    Returns:
        dict: Block information
    """
    with TransactionContext(db) as tx:
        # Check if already blocked
        existing_block = tx.session.query(BlockedEmail).filter_by(email=email).first()
        
        if existing_block:
            # Update existing block
            existing_block.blocked_until = datetime.now(timezone.utc) + timedelta(hours=hours)
            existing_block.failed_attempts += 1
        else:
            # Create new block
            new_block = BlockedEmail(
                email=email,
                blocked_until=datetime.now(timezone.utc) + timedelta(hours=hours),
                failed_attempts=1
            )
            tx.session.add(new_block)
        
        tx.session.flush()
        
        logger.info(f"✅ Email blocked: {email} for {hours} hours (Reason: {reason})")
        
        return {
            'email': email,
            'blocked_until': datetime.now(timezone.utc) + timedelta(hours=hours),
            'reason': reason,
            'hours': hours
        }
