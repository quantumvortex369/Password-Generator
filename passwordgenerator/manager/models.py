"""
Módulo de modelos para el gestor de contraseñas.
Define las estructuras de datos para almacenar información de contraseñas y categorías.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

class PasswordStrength(Enum):
    """Niveles de fortaleza de contraseña."""
    VERY_WEAK = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    VERY_STRONG = 4

@dataclass
class PasswordEntry:
    """
    Representa una entrada de contraseña en el gestor.
    """
    id: str
    title: str
    username: str
    password: str
    website: Optional[str] = None
    notes: Optional[str] = None
    category_id: Optional[str] = None
    strength: PasswordStrength = PasswordStrength.MODERATE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_used: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convierte la entrada de contraseña a un diccionario."""
        return {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'password': self.password,
            'website': self.website,
            'notes': self.notes,
            'category_id': self.category_id,
            'strength': self.strength.name,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'tags': self.tags,
            'custom_fields': self.custom_fields
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'PasswordEntry':
        """Crea una instancia de PasswordEntry a partir de un diccionario."""
        return cls(
            id=data['id'],
            title=data['title'],
            username=data['username'],
            password=data['password'],
            website=data.get('website'),
            notes=data.get('notes'),
            category_id=data.get('category_id'),
            strength=PasswordStrength[data.get('strength', 'MODERATE')],
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow(),
            last_used=datetime.fromisoformat(data['last_used']) if data.get('last_used') else None,
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            tags=data.get('tags', []),
            custom_fields=data.get('custom_fields', {})
        )

@dataclass
class PasswordCategory:
    """
    Representa una categoría para organizar las contraseñas.
    """
    id: str
    name: str
    description: Optional[str] = None
    parent_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    icon: Optional[str] = None
    color: Optional[str] = None

    def to_dict(self) -> dict:
        """Convierte la categoría a un diccionario."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'parent_id': self.parent_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'icon': self.icon,
            'color': self.color
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'PasswordCategory':
        """Crea una instancia de PasswordCategory a partir de un diccionario."""
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description'),
            parent_id=data.get('parent_id'),
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow(),
            icon=data.get('icon'),
            color=data.get('color')
        )
