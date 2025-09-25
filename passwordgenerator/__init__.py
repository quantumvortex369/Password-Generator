"""
Generador de Contraseñas Seguras

Un módulo completo para generar y gestionar contraseñas seguras.
"""

__version__ = "1.0.0"

from .generator import PasswordGenerator
from .strength_checker import PasswordStrengthChecker
from .passphrase_generator import PassphraseGenerator
from .storage import PasswordStorage
from .cli import main as cli_main

__all__ = [
    'PasswordGenerator',
    'PasswordStrengthChecker',
    'PassphraseGenerator',
    'PasswordStorage',
    'cli_main'
]
