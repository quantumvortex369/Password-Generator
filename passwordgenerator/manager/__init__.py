"""
Módulo para el gestor de contraseñas del generador de contraseñas.
Incluye funcionalidades para almacenar, recuperar y gestionar contraseñas de forma segura.
"""

from .password_manager import PasswordManager
from .models import PasswordEntry, PasswordCategory

__all__ = ['PasswordManager', 'PasswordEntry', 'PasswordCategory']
