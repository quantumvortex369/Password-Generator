import re
from typing import Dict, List, Tuple
import math
from datetime import datetime, timedelta

class PasswordStrengthChecker:
    """Clase para evaluar la fortaleza de una contraseña."""
    
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.leak_database = self._load_leak_database()
    
    def _load_common_passwords(self) -> set:
        """Carga una lista de contraseñas comunes."""
        common = [
            '123456', 'password', '123456789', '12345', '12345678',
            'qwerty', '1234567', '111111', '1234567890', '123123',
            'admin', 'welcome', 'password1', '1234', '12345',
            '12345678', '123', 'qwerty123', '1q2w3e4r', '1qaz2wsx'
        ]
        return set(common)
    
    def _load_leak_database(self) -> set:
        """Simula una base de datos de contraseñas comprometidas."""
        # En una implementación real, esto se conectaría a una API como Have I Been Pwned
        return set()
    
    def check_strength(self, password: str) -> Dict[str, any]:
        """
        Evalúa la fortaleza de una contraseña.
        
        Returns:
            Dict con información detallada sobre la fortaleza
        """
        result = {
            'score': 0,
            'length': len(password),
            'has_lower': False,
            'has_upper': False,
            'has_digit': False,
            'has_symbol': False,
            'is_common': False,
            'is_compromised': False,
            'entropy': 0,
            'crack_time': 'instant',
            'feedback': [],
            'suggestions': []
        }
        
        # Verificar longitud
        if len(password) >= 12:
            result['score'] += 2
        elif len(password) >= 8:
            result['score'] += 1
        
        # Verificar tipos de caracteres
        if re.search(r'[a-z]', password):
            result['has_lower'] = True
            result['score'] += 1
            
        if re.search(r'[A-Z]', password):
            result['has_upper'] = True
            result['score'] += 1
            
        if re.search(r'\d', password):
            result['has_digit'] = True
            result['score'] += 1
            
        if re.search(r'[^a-zA-Z0-9]', password):
            result['has_symbol'] = True
            result['score'] += 1
        
        # Verificar contraseñas comunes
        if password.lower() in self.common_passwords:
            result['is_common'] = True
            result['score'] = 0
            result['feedback'].append('Esta contraseña es muy común y fácil de adivinar.')
            result['suggestions'].append('Evita usar contraseñas comunes o patrones simples.')
        
        # Verificar si ha sido comprometida
        if password in self.leak_database:
            result['is_compromised'] = True
            result['score'] = 0
            result['feedback'].append('¡Atención! Esta contraseña ha sido expuesta en filtraciones de datos.')
            result['suggestions'].append('Cambia esta contraseña inmediatamente y no la uses en ningún otro sitio.')
        
        # Calcular entropía
        result['entropy'] = self._calculate_entropy(password)
        
        # Estimar tiempo de descifrado
        result['crack_time'] = self._estimate_crack_time(password)
        
        # Ajustar puntuación basada en entropía
        if result['entropy'] > 100:
            result['score'] = min(5, result['score'] + 2)
        elif result['entropy'] > 80:
            result['score'] = min(5, result['score'] + 1)
        
        # Asegurar que el puntaje esté entre 0 y 5
        result['score'] = max(0, min(5, result['score']))
        
        # Generar retroalimentación adicional
        self._generate_feedback(result)
        
        return result
    
    def _calculate_entropy(self, password: str) -> float:
        """Calcula la entropía de la contraseña en bits."""
        if not password:
            return 0.0
            
        # Calcular el tamaño del conjunto de caracteres
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(not c.isalnum() for c in password):
            charset_size += 32  # Aproximación común para símbolos
            
        if charset_size == 0:
            return 0.0
            
        # Calcular entropía
        entropy = len(password) * (math.log(charset_size) / math.log(2))
        return round(entropy, 2)
    
    def _estimate_crack_time(self, password: str) -> str:
        """Estima el tiempo que tomaría descifrar la contraseña."""
        entropy = self._calculate_entropy(password)
        
        # Suposiciones: 10,000,000,000 intentos por segundo (GPU potente)
        attempts_per_second = 10_000_000_000
        seconds = (2 ** entropy) / attempts_per_second
        
        if seconds < 1:
            return "menos de un segundo"
        elif seconds < 60:
            return f"{int(seconds)} segundos"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutos"
        elif seconds < 86400:
            return f"{int(seconds/3600)} horas"
        elif seconds < 31536000:  # 1 año
            return f"{int(seconds/86400)} días"
        elif seconds < 3153600000:  # 100 años
            return f"{int(seconds/31536000)} años"
        else:
            return "miles de años"
    
    def _generate_feedback(self, result: Dict):
        """Genera retroalimentación y sugerencias basadas en el análisis."""
        if result['length'] < 8:
            result['feedback'].append('La contraseña es demasiado corta.')
            result['suggestions'].append('Usa al menos 12 caracteres para mayor seguridad.')
        
        if not result['has_lower']:
            result['suggestions'].append('Añade letras minúsculas.')
            
        if not result['has_upper']:
            result['suggestions'].append('Añade letras mayúsculas.')
            
        if not result['has_digit']:
            result['suggestions'].append('Añade números.')
            
        if not result['has_symbol']:
            result['suggestions'].append('Añade símbolos especiales.')
        
        # Eliminar sugerencias duplicadas
        result['suggestions'] = list(dict.fromkeys(result['suggestions']))
    
    def get_strength_label(self, score: int) -> str:
        """Devuelve una etiqueta descriptiva para el puntaje de fortaleza."""
        labels = {
            0: 'Muy débil',
            1: 'Débil',
            2: 'Regular',
            3: 'Buena',
            4: 'Fuerte',
            5: 'Muy fuerte'
        }
        return labels.get(score, 'Desconocida')
