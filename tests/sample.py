"""
Python Sample File for Theme Testing
This file demonstrates various Python syntax and features for comprehensive theme testing
"""

import asyncio
import json
import logging
import re
import sqlite3
import typing
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from functools import wraps, lru_cache
from pathlib import Path
from typing import Optional, List, Dict, Union, Callable, Any, TypeVar, Generic
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants and enums
DEFAULT_PAGE_SIZE = 20
MAX_USERS = 10000

class UserRole(Enum):
    """User roles enumeration"""
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

class UserStatus(Enum):
    """User status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"

class Priority(Enum):
    """Priority levels for various operations"""
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

# Type aliases
UserId = int
Email = str
UserDict = Dict[str, Any]

# Generic type variables
T = TypeVar('T')
U = TypeVar('U')

# Custom exceptions
class UserError(Exception):
    """Base exception for user-related errors"""
    
    def __init__(self, message: str, user_id: Optional[UserId] = None, error_code: Optional[str] = None):
        super().__init__(message)
        self.user_id = user_id
        self.error_code = error_code

class UserNotFoundError(UserError):
    """Raised when a user is not found"""
    pass

class DuplicateEmailError(UserError):
    """Raised when attempting to create a user with an existing email"""
    pass

class ValidationError(UserError):
    """Raised when user data validation fails"""
    pass

# Dataclasses and type annotations
@dataclass
class UserPreferences:
    """User preferences data structure"""
    theme: str = "light"
    language: str = "en"
    notifications_enabled: bool = True
    email_frequency: str = "daily"
    timezone: str = "UTC"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert preferences to dictionary"""
        return {
            'theme': self.theme,
            'language': self.language,
            'notifications_enabled': self.notifications_enabled,
            'email_frequency': self.email_frequency,
            'timezone': self.timezone
        }

@dataclass
class User:
    """User data model with validation"""
    id: UserId
    name: str
    email: Email
    role: UserRole = UserRole.USER
    status: UserStatus = UserStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    preferences: UserPreferences = field(default_factory=UserPreferences)
    password_hash: Optional[str] = field(default=None, repr=False)
    
    def __post_init__(self):
        """Validate user data after initialization"""
        self.validate()
    
    def validate(self) -> None:
        """Validate user data"""
        if not self.name or len(self.name.strip()) == 0:
            raise ValidationError("User name cannot be empty")
        
        if len(self.name) > 255:
            raise ValidationError("User name cannot exceed 255 characters")
        
        if not self.is_valid_email(self.email):
            raise ValidationError(f"Invalid email format: {self.email}")
        
        if not isinstance(self.role, UserRole):
            raise ValidationError(f"Invalid role: {self.role}")
        
        if not isinstance(self.status, UserStatus):
            raise ValidationError(f"Invalid status: {self.status}")
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @property
    def display_name(self) -> str:
        """Get user display name"""
        return self.name if self.name else self.email.split('@')[0]
    
    @property
    def is_active(self) -> bool:
        """Check if user is active"""
        return self.status == UserStatus.ACTIVE
    
    @property
    def is_admin(self) -> bool:
        """Check if user is an admin"""
        return self.role == UserRole.ADMIN
    
    @property
    def days_since_creation(self) -> int:
        """Calculate days since user creation"""
        return (datetime.now() - self.created_at).days
    
    def to_dict(self, include_sensitive: bool = False) -> UserDict:
        """Convert user to dictionary"""
        data = {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'display_name': self.display_name,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'days_since_creation': self.days_since_creation,
            'preferences': self.preferences.to_dict()
        }
        
        if include_sensitive and self.password_hash:
            data['password_hash'] = self.password_hash
        
        return data
    
    @classmethod
    def from_dict(cls, data: UserDict) -> 'User':
        """Create user from dictionary"""
        preferences_data = data.get('preferences', {})
        preferences = UserPreferences(**preferences_data) if preferences_data else UserPreferences()
        
        return cls(
            id=data['id'],
            name=data['name'],
            email=data['email'],
            role=UserRole(data.get('role', UserRole.USER.value)),
            status=UserStatus(data.get('status', UserStatus.PENDING.value)),
            created_at=datetime.fromisoformat(data.get('created_at', datetime.now().isoformat())),
            preferences=preferences,
            password_hash=data.get('password_hash')
        )

# Abstract base classes and protocols
class UserRepositoryInterface(ABC):
    """Abstract interface for user repositories"""
    
    @abstractmethod
    async def find_by_id(self, user_id: UserId) -> Optional[User]:
        """Find user by ID"""
        pass
    
    @abstractmethod
    async def find_by_email(self, email: Email) -> Optional[User]:
        """Find user by email"""
        pass
    
    @abstractmethod
    async def find_all(self, 
                      filters: Optional[Dict[str, Any]] = None,
                      limit: Optional[int] = None,
                      offset: Optional[int] = None) -> List[User]:
        """Find all users with optional filters"""
        pass
    
    @abstractmethod
    async def save(self, user: User) -> User:
        """Save user to repository"""
        pass
    
    @abstractmethod
    async def delete(self, user_id: UserId) -> bool:
        """Delete user from repository"""
        pass
    
    @abstractmethod
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count users with optional filters"""
        pass

# Generic repository implementation
class Repository(Generic[T]):
    """Generic repository pattern implementation"""
    
    def __init__(self, model_class: typing.Type[T]):
        self.model_class = model_class
        self._storage: Dict[int, T] = {}
        self._next_id = 1
    
    def create(self, **kwargs) -> T:
        """Create new entity"""
        entity = self.model_class(id=self._next_id, **kwargs)
        self._storage[self._next_id] = entity
        self._next_id += 1
        return entity
    
    def get(self, entity_id: int) -> Optional[T]:
        """Get entity by ID"""
        return self._storage.get(entity_id)
    
    def get_all(self) -> List[T]:
        """Get all entities"""
        return list(self._storage.values())
    
    def update(self, entity_id: int, **kwargs) -> Optional[T]:
        """Update entity"""
        if entity_id in self._storage:
            entity = self._storage[entity_id]
            for key, value in kwargs.items():
                if hasattr(entity, key):
                    setattr(entity, key, value)
            return entity
        return None
    
    def delete(self, entity_id: int) -> bool:
        """Delete entity"""
        if entity_id in self._storage:
            del self._storage[entity_id]
            return True
        return False

# Database implementation
class SQLiteUserRepository(UserRepositoryInterface):
    """SQLite implementation of user repository"""
    
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self) -> None:
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    preferences TEXT,
                    password_hash TEXT
                )
            """)
            conn.commit()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    async def find_by_id(self, user_id: UserId) -> Optional[User]:
        """Find user by ID"""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return self._row_to_user(row) if row else None
    
    async def find_by_email(self, email: Email) -> Optional[User]:
        """Find user by email"""
        with self._get_connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
            return self._row_to_user(row) if row else None
    
    async def find_all(self, 
                      filters: Optional[Dict[str, Any]] = None,
                      limit: Optional[int] = None,
                      offset: Optional[int] = None) -> List[User]:
        """Find all users with optional filters"""
        query = "SELECT * FROM users"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if key in ['role', 'status', 'email']:
                    conditions.append(f"{key} = ?")
                    params.append(value)
                elif key == 'name_search':
                    conditions.append("name LIKE ?")
                    params.append(f"%{value}%")
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY created_at DESC"
        
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        if offset:
            query += " OFFSET ?"
            params.append(offset)
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            return [self._row_to_user(row) for row in rows]
    
    async def save(self, user: User) -> User:
        """Save user to database"""
        user.validate()
        
        with self._get_connection() as conn:
            if user.id and await self.find_by_id(user.id):
                # Update existing user
                conn.execute("""
                    UPDATE users SET name = ?, email = ?, role = ?, status = ?, 
                                   preferences = ?, password_hash = ?
                    WHERE id = ?
                """, (
                    user.name, user.email, user.role.value, user.status.value,
                    json.dumps(user.preferences.to_dict()), user.password_hash, user.id
                ))
            else:
                # Insert new user
                cursor = conn.execute("""
                    INSERT INTO users (name, email, role, status, created_at, preferences, password_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    user.name, user.email, user.role.value, user.status.value,
                    user.created_at.isoformat(), json.dumps(user.preferences.to_dict()),
                    user.password_hash
                ))
                user.id = cursor.lastrowid
            
            conn.commit()
            return user
    
    async def delete(self, user_id: UserId) -> bool:
        """Delete user from database"""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    async def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Count users with optional filters"""
        query = "SELECT COUNT(*) FROM users"
        params = []
        
        if filters:
            conditions = []
            for key, value in filters.items():
                if key in ['role', 'status']:
                    conditions.append(f"{key} = ?")
                    params.append(value)
            
            if conditions:
                query += " WHERE " + " AND ".join(conditions)
        
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()[0]
    
    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert database row to User object"""
        preferences_data = json.loads(row['preferences']) if row['preferences'] else {}
        preferences = UserPreferences(**preferences_data)
        
        return User(
            id=row['id'],
            name=row['name'],
            email=row['email'],
            role=UserRole(row['role']),
            status=UserStatus(row['status']),
            created_at=datetime.fromisoformat(row['created_at']),
            preferences=preferences,
            password_hash=row['password_hash']
        )

# Service layer with dependency injection
class UserService:
    """Service class for user management business logic"""
    
    def __init__(self, repository: UserRepositoryInterface, max_users: int = MAX_USERS):
        self.repository = repository
        self.max_users = max_users
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def create_user(self, user_data: UserDict, password: Optional[str] = None) -> User:
        """Create a new user with validation"""
        self.logger.info(f"Creating user with email: {user_data.get('email')}")
        
        # Check if email already exists
        existing_user = await self.repository.find_by_email(user_data['email'])
        if existing_user:
            raise DuplicateEmailError(f"User with email {user_data['email']} already exists")
        
        # Check user limit
        current_count = await self.repository.count()
        if current_count >= self.max_users:
            raise UserError(f"Maximum number of users ({self.max_users}) reached")
        
        # Create user object
        user = User(
            id=0,  # Will be set by repository
            name=user_data['name'],
            email=user_data['email'],
            role=UserRole(user_data.get('role', UserRole.USER.value)),
            status=UserStatus(user_data.get('status', UserStatus.PENDING.value)),
            preferences=UserPreferences(**user_data.get('preferences', {}))
        )
        
        if password:
            user.password_hash = self._hash_password(password)
        
        saved_user = await self.repository.save(user)
        self.logger.info(f"Created user with ID: {saved_user.id}")
        return saved_user
    
    async def get_user(self, user_id: UserId) -> User:
        """Get user by ID"""
        user = await self.repository.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User with ID {user_id} not found", user_id=user_id)
        return user
    
    async def get_user_by_email(self, email: Email) -> User:
        """Get user by email"""
        user = await self.repository.find_by_email(email)
        if not user:
            raise UserNotFoundError(f"User with email {email} not found")
        return user
    
    async def get_users(self, 
                       filters: Optional[Dict[str, Any]] = None,
                       page: int = 1, 
                       page_size: int = DEFAULT_PAGE_SIZE) -> Dict[str, Any]:
        """Get paginated list of users"""
        offset = (page - 1) * page_size
        users = await self.repository.find_all(filters, page_size, offset)
        total = await self.repository.count(filters)
        
        return {
            'users': users,
            'pagination': {
                'current_page': page,
                'page_size': page_size,
                'total': total,
                'total_pages': (total + page_size - 1) // page_size
            }
        }
    
    async def update_user(self, user_id: UserId, updates: Dict[str, Any]) -> User:
        """Update user information"""
        user = await self.get_user(user_id)
        
        # Check for email uniqueness if email is being updated
        if 'email' in updates and updates['email'] != user.email:
            existing_user = await self.repository.find_by_email(updates['email'])
            if existing_user and existing_user.id != user_id:
                raise DuplicateEmailError(f"Email {updates['email']} already exists")
        
        # Apply updates
        for key, value in updates.items():
            if key == 'role' and isinstance(value, str):
                user.role = UserRole(value)
            elif key == 'status' and isinstance(value, str):
                user.status = UserStatus(value)
            elif key == 'preferences' and isinstance(value, dict):
                user.preferences = UserPreferences(**value)
            elif hasattr(user, key):
                setattr(user, key, value)
        
        updated_user = await self.repository.save(user)
        self.logger.info(f"Updated user with ID: {user_id}")
        return updated_user
    
    async def delete_user(self, user_id: UserId) -> bool:
        """Delete user by ID"""
        user = await self.get_user(user_id)  # Verify user exists
        success = await self.repository.delete(user_id)
        if success:
            self.logger.info(f"Deleted user with ID: {user_id}")
        return success
    
    async def get_user_statistics(self) -> Dict[str, Any]:
        """Get user statistics"""
        total = await self.repository.count()
        active = await self.repository.count({'status': UserStatus.ACTIVE.value})
        inactive = await self.repository.count({'status': UserStatus.INACTIVE.value})
        pending = await self.repository.count({'status': UserStatus.PENDING.value})
        
        admins = await self.repository.count({'role': UserRole.ADMIN.value})
        users = await self.repository.count({'role': UserRole.USER.value})
        guests = await self.repository.count({'role': UserRole.GUEST.value})
        
        return {
            'total_users': total,
            'by_status': {
                'active': active,
                'inactive': inactive,
                'pending': pending
            },
            'by_role': {
                'admin': admins,
                'user': users,
                'guest': guests
            },
            'activity_rate': round((active / total * 100), 2) if total > 0 else 0
        }
    
    def _hash_password(self, password: str) -> str:
        """Hash password (simplified implementation)"""
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()

# Decorators
def retry(max_attempts: int = 3, delay: float = 1.0):
    """Retry decorator for handling transient failures"""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
                        await asyncio.sleep(delay)
                    else:
                        logger.error(f"All {max_attempts} attempts failed")
            raise last_exception
        return wrapper
    return decorator

def cache_result(ttl_seconds: int = 300):
    """Cache decorator with TTL"""
    def decorator(func: Callable) -> Callable:
        cache = {}
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Create cache key from function arguments
            key = f"{func.__name__}:{hash(str(args) + str(sorted(kwargs.items())))}"
            now = datetime.now()
            
            # Check if cached result is still valid
            if key in cache:
                cached_result, timestamp = cache[key]
                if (now - timestamp).total_seconds() < ttl_seconds:
                    return cached_result
            
            # Execute function and cache result
            result = await func(*args, **kwargs)
            cache[key] = (result, now)
            
            # Clean expired entries
            expired_keys = [
                k for k, (_, ts) in cache.items()
                if (now - ts).total_seconds() >= ttl_seconds
            ]
            for k in expired_keys:
                del cache[k]
            
            return result
        return wrapper
    return decorator

def log_execution_time(func: Callable) -> Callable:
    """Decorator to log function execution time"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = datetime.now()
        try:
            result = await func(*args, **kwargs)
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            logger.info(f"{func.__name__} executed in {duration:.3f} seconds")
            return result
        except Exception as e:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            logger.error(f"{func.__name__} failed after {duration:.3f} seconds: {e}")
            raise
    return wrapper

# Utility functions and classes
class UserValidator:
    """Utility class for user validation"""
    
    @staticmethod
    def validate_password_strength(password: str) -> Dict[str, Any]:
        """Validate password strength"""
        errors = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            errors.append("Password must contain at least one special character")
        
        # Calculate strength score
        score = 0
        score += min(len(password) * 2, 50)
        if re.search(r'[a-z]', password): score += 10
        if re.search(r'[A-Z]', password): score += 10
        if re.search(r'\d', password): score += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password): score += 15
        
        # Deduct points for patterns
        if re.search(r'(.)\1{2,}', password): score -= 10  # Repeated characters
        if re.search(r'123|abc|qwe', password.lower()): score -= 15  # Sequential
        
        if score >= 80: strength = "strong"
        elif score >= 60: strength = "medium"
        elif score >= 40: strength = "weak"
        else: strength = "very_weak"
        
        return {
            'is_valid': len(errors) == 0,
            'errors': errors,
            'strength': strength,
            'score': score
        }

class UserExporter:
    """Utility class for exporting user data"""
    
    @staticmethod
    def to_csv(users: List[User]) -> str:
        """Export users to CSV format"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Name', 'Email', 'Role', 'Status', 'Created At'])
        
        # Write user data
        for user in users:
            writer.writerow([
                user.id,
                user.name,
                user.email,
                user.role.value,
                user.status.value,
                user.created_at.isoformat()
            ])
        
        return output.getvalue()
    
    @staticmethod
    def to_json(users: List[User], include_sensitive: bool = False) -> str:
        """Export users to JSON format"""
        user_dicts = [user.to_dict(include_sensitive) for user in users]
        return json.dumps(user_dicts, indent=2, default=str)

# Async context managers and generators
class UserManager:
    """Context manager for user operations"""
    
    def __init__(self, service: UserService):
        self.service = service
        self.operations = []
    
    async def __aenter__(self):
        logger.info("Starting user management session")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            logger.error(f"User management session failed: {exc_val}")
        else:
            logger.info(f"User management session completed. Operations: {len(self.operations)}")
    
    async def create_user(self, user_data: UserDict) -> User:
        """Create user within managed context"""
        user = await self.service.create_user(user_data)
        self.operations.append(f"Created user {user.id}")
        return user

async def generate_user_reports(service: UserService, batch_size: int = 100):
    """Async generator for user report data"""
    page = 1
    
    while True:
        result = await service.get_users(page=page, page_size=batch_size)
        users = result['users']
        
        if not users:
            break
        
        # Yield report data for this batch
        for user in users:
            yield {
                'user_id': user.id,
                'display_name': user.display_name,
                'is_active': user.is_active,
                'days_active': user.days_since_creation,
                'role': user.role.value
            }
        
        page += 1

# List comprehensions and generator expressions
def analyze_user_data(users: List[User]) -> Dict[str, Any]:
    """Analyze user data using comprehensions"""
    
    # List comprehension
    active_users = [user for user in users if user.is_active]
    
    # Dict comprehension
    user_by_role = {
        role.value: len([u for u in users if u.role == role])
        for role in UserRole
    }
    
    # Set comprehension
    unique_domains = {user.email.split('@')[1] for user in users}
    
    # Generator expression for memory efficiency
    total_days = sum(user.days_since_creation for user in users)
    
    return {
        'active_users_count': len(active_users),
        'users_by_role': user_by_role,
        'unique_email_domains': list(unique_domains),
        'average_days_since_creation': total_days / len(users) if users else 0
    }

# Main execution and example usage
async def main():
    """Main function demonstrating the user management system"""
    
    # Initialize repository and service
    repository = SQLiteUserRepository()
    service = UserService(repository)
    
    try:
        # Create sample users
        sample_users = [
            {
                'name': 'John Doe',
                'email': 'john@example.com',
                'role': UserRole.ADMIN.value,
                'status': UserStatus.ACTIVE.value
            },
            {
                'name': 'Jane Smith',
                'email': 'jane@example.com',
                'role': UserRole.USER.value,
                'status': UserStatus.ACTIVE.value
            },
            {
                'name': 'Bob Johnson',
                'email': 'bob@example.com',
                'role': UserRole.USER.value,
                'status': UserStatus.PENDING.value
            }
        ]
        
        # Use context manager for user operations
        async with UserManager(service) as manager:
            created_users = []
            for user_data in sample_users:
                user = await manager.create_user(user_data)
                created_users.append(user)
                logger.info(f"Created user: {user.display_name}")
        
        # Get user statistics
        stats = await service.get_user_statistics()
        logger.info(f"User statistics: {stats}")
        
        # Demonstrate filtering and pagination
        active_users_result = await service.get_users(
            filters={'status': UserStatus.ACTIVE.value},
            page=1,
            page_size=10
        )
        logger.info(f"Found {len(active_users_result['users'])} active users")
        
        # Export data
        all_users_result = await service.get_users()
        all_users = all_users_result['users']
        
        csv_data = UserExporter.to_csv(all_users)
        json_data = UserExporter.to_json(all_users)
        
        logger.info("Data export completed")
        
        # Analyze user data
        analysis = analyze_user_data(all_users)
        logger.info(f"User analysis: {analysis}")
        
        # Generate reports using async generator
        logger.info("Generating user reports...")
        async for report_data in generate_user_reports(service, batch_size=2):
            logger.debug(f"Report data: {report_data}")
        
        # Demonstrate error handling
        try:
            await service.get_user(99999)
        except UserNotFoundError as e:
            logger.warning(f"Expected error: {e}")
        
        # Test password validation
        password_result = UserValidator.validate_password_strength("MySecureP@ssw0rd!")
        logger.info(f"Password validation: {password_result}")
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        raise

# Lambda functions and functional programming
def create_user_filters():
    """Create various user filter functions"""
    
    # Lambda functions
    is_admin = lambda user: user.role == UserRole.ADMIN
    is_recent = lambda user, days=30: user.days_since_creation <= days
    has_email_domain = lambda user, domain: user.email.endswith(f"@{domain}")
    
    # Higher-order functions
    def create_role_filter(role: UserRole) -> Callable[[User], bool]:
        return lambda user: user.role == role
    
    def create_status_filter(status: UserStatus) -> Callable[[User], bool]:
        return lambda user: user.status == status
    
    return {
        'is_admin': is_admin,
        'is_recent': is_recent,
        'has_email_domain': has_email_domain,
        'admin_filter': create_role_filter(UserRole.ADMIN),
        'active_filter': create_status_filter(UserStatus.ACTIVE)
    }

# Testing and assertion examples
def test_user_validation():
    """Test user validation functionality"""
    
    # Test valid user
    try:
        user = User(
            id=1,
            name="Test User",
            email="test@example.com",
            role=UserRole.USER,
            status=UserStatus.ACTIVE
        )
        assert user.is_valid_email("test@example.com")
        assert user.display_name == "Test User"
        logger.info("✓ Valid user test passed")
    except Exception as e:
        logger.error(f"✗ Valid user test failed: {e}")
    
    # Test invalid email
    try:
        User(
            id=2,
            name="Invalid User",
            email="invalid-email",
            role=UserRole.USER
        )
        logger.error("✗ Invalid email test failed - should have raised exception")
    except ValidationError:
        logger.info("✓ Invalid email test passed")
    
    # Test empty name
    try:
        User(
            id=3,
            name="",
            email="empty@example.com",
            role=UserRole.USER
        )
        logger.error("✗ Empty name test failed - should have raised exception")
    except ValidationError:
        logger.info("✓ Empty name test passed")

# Script execution
if __name__ == "__main__":
    # Run tests
    test_user_validation()
    
    # Run main application
    asyncio.run(main())
    
    # Demonstrate filter functions
    filters = create_user_filters()
    logger.info("User filters created successfully")
    
    logger.info("Python sample script completed successfully!")