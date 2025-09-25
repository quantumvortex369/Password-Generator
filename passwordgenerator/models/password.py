"""Password data models."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum

class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    VERY_STRONG = 4
    EXCELLENT = 5

@dataclass
class PasswordEntry:
    """Represents a password entry in the password manager."""
    service: str
    password: str
    username: str = ""
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_in_days: Optional[int] = 90
    strength: Optional[PasswordStrength] = None
    is_compromised: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the entry to a dictionary."""
        return {
            'service': self.service,
            'username': self.username,
            'password': self.password,
            'notes': self.notes,
            'tags': self.tags,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'expires_in_days': self.expires_in_days,
            'strength': self.strength.value if self.strength else None,
            'is_compromised': self.is_compromised,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create an entry from a dictionary."""
        strength = data.get('strength')
        if strength is not None and not isinstance(strength, PasswordStrength):
            strength = PasswordStrength(strength)
        
        return cls(
            service=data['service'],
            username=data.get('username', ''),
            password=data['password'],
            notes=data.get('notes', ''),
            tags=data.get('tags', []),
            created_at=data.get('created_at', datetime.now().isoformat()),
            updated_at=data.get('updated_at', datetime.now().isoformat()),
            expires_in_days=data.get('expires_in_days', 90),
            strength=strength,
            is_compromised=data.get('is_compromised', False),
            metadata=data.get('metadata', {})
        )
    
    def is_expired(self) -> bool:
        """Check if the password has expired."""
        if not self.expires_in_days:
            return False
            
        try:
            created = datetime.fromisoformat(self.created_at)
            expiry_date = created + datetime.timedelta(days=self.expires_in_days)
            return datetime.now() > expiry_date
        except (ValueError, TypeError):
            return False
    
    def days_until_expiry(self) -> Optional[int]:
        """Get the number of days until the password expires."""
        if not self.expires_in_days:
            return None
            
        try:
            created = datetime.fromisoformat(self.created_at)
            expiry_date = created + datetime.timedelta(days=self.expires_in_days)
            delta = expiry_date - datetime.now()
            return max(0, delta.days)
        except (ValueError, TypeError):
            return None
