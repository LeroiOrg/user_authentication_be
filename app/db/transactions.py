"""
ACID Transactions Module for PostgreSQL (SQLAlchemy)
Provides transaction management with proper rollback handling
"""
from sqlalchemy.orm import Session
from typing import Callable, Any
from functools import wraps
import logging

logger = logging.getLogger(__name__)


def atomic_transaction(func: Callable) -> Callable:
    """
    Decorator that ensures ACID properties for database operations
    Automatically commits on success and rolls back on failure
    
    Usage:
        @atomic_transaction
        def my_db_function(db: Session, ...):
            # Your database operations here
            pass
    
    The decorated function must accept 'db: Session' as first parameter
    """
    @wraps(func)
    def wrapper(db: Session, *args, **kwargs):
        try:
            # Execute the function within a transaction
            result = func(db, *args, **kwargs)
            
            # If no exception, commit the transaction
            db.commit()
            logger.info(f"✅ Transaction committed successfully: {func.__name__}")
            return result
            
        except Exception as e:
            # On any exception, rollback all changes
            db.rollback()
            logger.error(f"❌ Transaction rolled back: {func.__name__} - Error: {e}")
            raise  # Re-raise the exception after rollback
            
    return wrapper


def atomic_transaction_async(func: Callable) -> Callable:
    """
    Async version of atomic_transaction decorator
    For async functions that need ACID guarantees
    
    Usage:
        @atomic_transaction_async
        async def my_async_db_function(db: Session, ...):
            # Your database operations here
            pass
    """
    @wraps(func)
    async def wrapper(db: Session, *args, **kwargs):
        try:
            # Execute the async function within a transaction
            result = await func(db, *args, **kwargs)
            
            # If no exception, commit the transaction
            db.commit()
            logger.info(f"✅ Transaction committed successfully: {func.__name__}")
            return result
            
        except Exception as e:
            # On any exception, rollback all changes
            db.rollback()
            logger.error(f"❌ Transaction rolled back: {func.__name__} - Error: {e}")
            raise  # Re-raise the exception after rollback
            
    return wrapper


class TransactionContext:
    """
    Context manager for explicit transaction control
    Provides more fine-grained control over transaction boundaries
    
    Usage:
        with TransactionContext(db) as tx:
            # Your database operations
            user = User(...)
            tx.session.add(user)
            # Transaction commits automatically on context exit
            # Or rolls back if exception occurs
    """
    
    def __init__(self, session: Session):
        self.session = session
        self._committed = False
    
    def __enter__(self):
        """Start transaction context"""
        logger.info("🔄 Starting transaction context")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit transaction context
        Commits if no exception, rolls back otherwise
        """
        if exc_type is not None:
            # Exception occurred, rollback
            self.session.rollback()
            logger.error(f"❌ Transaction rolled back due to: {exc_val}")
            return False  # Re-raise exception
        else:
            # No exception, commit
            if not self._committed:
                self.session.commit()
                self._committed = True
                logger.info("✅ Transaction committed successfully")
            return True
    
    def commit(self):
        """Manually commit within context"""
        if not self._committed:
            self.session.commit()
            self._committed = True
            logger.info("✅ Manual commit successful")
    
    def rollback(self):
        """Manually rollback within context"""
        self.session.rollback()
        logger.warning("⚠️  Manual rollback executed")


def with_savepoint(func: Callable) -> Callable:
    """
    Decorator that creates a savepoint before function execution
    Allows partial rollback to savepoint instead of full transaction rollback
    Useful for nested transactions
    
    Usage:
        @with_savepoint
        def risky_operation(db: Session, ...):
            # This operation can rollback to savepoint
            # without affecting outer transaction
            pass
    """
    @wraps(func)
    def wrapper(db: Session, *args, **kwargs):
        # Create a savepoint
        savepoint = db.begin_nested()
        logger.info(f"🔖 Savepoint created for: {func.__name__}")
        
        try:
            result = func(db, *args, **kwargs)
            savepoint.commit()
            logger.info(f"✅ Savepoint committed: {func.__name__}")
            return result
            
        except Exception as e:
            savepoint.rollback()
            logger.warning(f"⚠️  Savepoint rolled back: {func.__name__} - Error: {e}")
            raise
            
    return wrapper


def retry_on_deadlock(max_attempts: int = 3):
    """
    Decorator for automatic retry on database deadlocks
    Useful for handling concurrent transaction conflicts
    
    Args:
        max_attempts: Maximum number of retry attempts
    
    Usage:
        @retry_on_deadlock(max_attempts=3)
        @atomic_transaction
        def concurrent_operation(db: Session, ...):
            # This will retry up to 3 times on deadlock
            pass
    """
    import time
    from sqlalchemy.exc import OperationalError
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempt = 0
            delay = 0.1  # Initial delay in seconds
            
            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except OperationalError as e:
                    # Check if it's a deadlock error
                    if 'deadlock' in str(e).lower():
                        attempt += 1
                        if attempt >= max_attempts:
                            logger.error(f"❌ Max retry attempts ({max_attempts}) reached for deadlock")
                            raise
                        
                        logger.warning(f"⚠️  Deadlock detected, retrying (attempt {attempt}/{max_attempts})")
                        time.sleep(delay)
                        delay *= 2  # Exponential backoff
                    else:
                        # Not a deadlock, re-raise immediately
                        raise
            
        return wrapper
    return decorator
