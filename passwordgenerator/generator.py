import secrets
import string
from typing import List, Dict, Optional

class PasswordGenerator:
    """Clase para generar contraseñas seguras con múltiples opciones."""
    
    def __init__(self):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'special': '¡!¿?@#$%&/()=¿¡',
            'brackets': '[]{}()<>',
            'math': '+−×÷=±√∛∜',
            'greek': 'αβγδεζηθικλμνξπρσςτυφχψω',
            'circled': 'ⓐⓑⓒⓓⓔⓕⓖⓗⓘⓙⓚⓛⓜⓝⓞⓟⓠⓡⓢⓣⓤⓥⓦⓧⓨⓩ',
            'box': '▁▂▃▄▅▆▇█',
        }
        
    def generate_password(
        self,
        length: int = 16,
        use_lower: bool = True,
        use_upper: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_similar: bool = True,
        exclude_ambiguous: bool = True,
        custom_chars: str = '',
        min_lower: int = 1,
        min_upper: int = 1,
        min_digits: int = 1,
        min_symbols: int = 1
    ) -> str:
        """
        Genera una contraseña segura con los parámetros especificados.
        
        Args:
            length: Longitud de la contraseña
            use_lower: Incluir letras minúsculas
            use_upper: Incluir letras mayúsculas
            use_digits: Incluir dígitos
            use_symbols: Incluir símbolos
            exclude_similar: Excluir caracteres similares (1, l, I, 0, O)
            exclude_ambiguous: Excluir caracteres ambiguos ({ } [ ] ( ) / \ ' " ` ~ , ; : . < > )
            custom_chars: Caracteres personalizados a incluir
            min_lower: Mínimo de letras minúsculas
            min_upper: Mínimo de letras mayúsculas
            min_digits: Mínimo de dígitos
            min_symbols: Mínimo de símbolos
            
        Returns:
            str: Contraseña generada
        """
        if length < 8:
            raise ValueError("La longitud mínima de la contraseña debe ser 8")
            
        # Construir el conjunto de caracteres
        chars = ''
        required_chars = []
        
        if use_lower:
            lowercase = self.char_sets['lowercase']
            if exclude_similar:
                lowercase = lowercase.replace('l', '').replace('o', '')
            chars += lowercase
            required_chars.extend(secrets.choice(lowercase) for _ in range(min_lower))
            
        if use_upper:
            uppercase = self.char_sets['uppercase']
            if exclude_similar:
                uppercase = uppercase.replace('I', '').replace('O', '')
            chars += uppercase
            required_chars.extend(secrets.choice(uppercase) for _ in range(min_upper))
            
        if use_digits:
            digits = self.char_sets['digits']
            if exclude_similar:
                digits = digits.replace('0', '').replace('1', '')
            chars += digits
            required_chars.extend(secrets.choice(digits) for _ in range(min_digits))
            
        if use_symbols:
            symbols = self.char_sets['symbols']
            if exclude_ambiguous:
                symbols = ''.join(c for c in symbols if c not in '{}[]()/\\\'"`~,;:.<> ')
            chars += symbols
            required_chars.extend(secrets.choice(symbols) for _ in range(min_symbols))
            
        if custom_chars:
            chars += custom_chars
            required_chars.append(secrets.choice(custom_chars))
            
        if not chars:
            raise ValueError("Debe seleccionar al menos un tipo de caracteres")
            
        # Calcular caracteres restantes
        remaining_length = max(0, length - len(required_chars))
        
        # Generar el resto de la contraseña
        password = required_chars + [secrets.choice(chars) for _ in range(remaining_length)]
        
        # Mezclar los caracteres
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_with_pattern(self, pattern: str) -> str:
        """
        Genera una contraseña siguiendo un patrón específico.
        
        Patrones disponibles:
        - L: Letra mayúscula
        - l: Letra minúscula
        - d: Dígito
        - s: Símbolo
        - *: Cualquier carácter
        
        Ejemplo: "LLL-lll-ddd-sss"
        """
        password = []
        for char in pattern:
            if char == 'L':
                password.append(secrets.choice(self.char_sets['uppercase']))
            elif char == 'l':
                password.append(secrets.choice(self.char_sets['lowercase']))
            elif char == 'd':
                password.append(secrets.choice(self.char_sets['digits']))
            elif char == 's':
                password.append(secrets.choice(self.char_sets['symbols']))
            elif char == '*':
                all_chars = (self.char_sets['lowercase'] + 
                            self.char_sets['uppercase'] + 
                            self.char_sets['digits'] + 
                            self.char_sets['symbols'])
                password.append(secrets.choice(all_chars))
            else:
                password.append(char)
                
        return ''.join(password)
