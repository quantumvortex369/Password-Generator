"""
Módulo de seguridad para el generador de contraseñas.
"""

"""
Este paquete contiene utilidades relacionadas con la seguridad de las contraseñas,
como evaluación de fortaleza y generación de hashes.
"""

from .strength import (
    calculate_entropy,
    check_common_passwords,
    get_password_strength,
    PasswordStrength
)

__all__ = [
    'calculate_entropy',
    'check_common_passwords',
    'get_password_strength',
    'PasswordStrength'
]
