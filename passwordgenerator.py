import secrets
import string
import argparse
import pyperclip
import json
import re
import hashlib
import sys
import os
import getpass
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum, auto
from collections import defaultdict

# Local wordlist for passphrase generation
WORDS_ES = [
    'casa', 'perro', 'gato', 'arbol', 'flor', 'sol', 'luna', 'estrella', 'agua', 'fuego',
    'tierra', 'aire', 'libro', 'lapiz', 'mesa', 'silla', 'ventana', 'puerta', 'cielo', 'mar',
    'rio', 'montaña', 'nube', 'lluvia', 'viento', 'naturaleza', 'jardin', 'parque', 'calle', 'ciudad',
    'pueblo', 'pais', 'mundo', 'universo', 'galaxia', 'planeta', 'satelite', 'cometa', 'meteorito', 'estacion',
    'primavera', 'verano', 'otono', 'invierno', 'manzana', 'naranja', 'platano', 'uva', 'fresa', 'cereza'
]

WORDS_EN = [
    'apple', 'banana', 'cherry', 'dog', 'cat', 'house', 'tree', 'flower', 'sun', 'moon',
    'star', 'water', 'fire', 'earth', 'air', 'book', 'pencil', 'table', 'chair', 'window',
    'door', 'sky', 'sea', 'river', 'mountain', 'cloud', 'rain', 'wind', 'nature', 'garden',
    'park', 'street', 'city', 'town', 'country', 'world', 'universe', 'galaxy', 'planet', 'satellite',
    'comet', 'meteor', 'season', 'spring', 'summer', 'autumn', 'winter', 'orange', 'grape', 'strawberry'
]

class PasswordStrength(Enum):
    VERY_WEAK = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    VERY_STRONG = 4
    EXCELLENT = 5

@dataclass
class PasswordEntry:
    service: str
    password: str
    username: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_in_days: Optional[int] = 90
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    strength: Optional[PasswordStrength] = None
    is_compromised: bool = False

class PasswordGenerator:
    def __init__(self, data_dir: Optional[Path] = None):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'brackets': '[]{}()<>',
            'punctuation': '!?.,;:',
            'math': '+=-*/><^',
            'space': ' '
        }
        
        # Set up data directory
        self.data_dir = data_dir or Path.home() / '.password_generator'
        self.data_dir.mkdir(exist_ok=True, parents=True)
        
        # Initialize database paths
        self.passwords_file = self.data_dir / 'passwords.json'
        self.history_file = self.data_dir / 'history.json'
        self.config_file = self.data_dir / 'config.json'
        
        # Load data
        self.passwords: Dict[str, PasswordEntry] = self._load_passwords()
        self.history = self._load_history()
        self.config = self._load_config()
        
        # Check for compromised passwords on startup
        self._check_compromised_passwords()

    def _load_passwords(self) -> Dict[str, PasswordEntry]:
        """Carga las contraseñas guardadas desde el archivo JSON."""
        if self.passwords_file.exists():
            try:
                with open(self.passwords_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {k: PasswordEntry(**v) for k, v in data.items()}
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error al cargar las contraseñas: {e}")
        return {}
    
    def _load_history(self) -> Dict[str, List[Dict]]:
        """Carga el historial de contraseñas."""
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}
    
    def _load_config(self) -> Dict:
        """Carga la configuración."""
        default_config = {
            'default_length': 16,
            'default_use_lower': True,
            'default_use_upper': True,
            'default_use_digits': True,
            'default_use_symbols': True,
            'default_expiry_days': 90,
            'language': 'es',
            'theme': 'system',
            'auto_check_compromised': True,
            'auto_lock_timeout': 300,  # 5 minutes
            'backup_enabled': True,
            'backup_count': 5
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    return {**default_config, **config}
            except (json.JSONDecodeError, IOError):
                pass
        return default_config
    
    def save_config(self):
        """Guarda la configuración actual."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
        except IOError as e:
            print(f"Error al guardar la configuración: {e}")
    
    def save_passwords(self):
        """Guarda las contraseñas en el archivo JSON."""
        try:
            # Create backup if enabled
            if self.config.get('backup_enabled', True):
                self._create_backup()
                
            with open(self.passwords_file, 'w', encoding='utf-8') as f:
                serialized = {k: asdict(v) for k, v in self.passwords.items()}
                json.dump(serialized, f, ensure_ascii=False, indent=2)
        except IOError as e:
            print(f"Error al guardar las contraseñas: {e}")
    
    def _create_backup(self):
        """Crea una copia de seguridad del archivo de contraseñas."""
        if not self.passwords_file.exists():
            return
            
        backup_dir = self.data_dir / 'backups'
        backup_dir.mkdir(exist_ok=True)
        
        # Rotate backups
        backups = sorted(backup_dir.glob('passwords_*.json'))
        max_backups = self.config.get('backup_count', 5)
        
        # Remove old backups if we have too many
        while len(backups) >= max_backups:
            backups[0].unlink()
            backups = backups[1:]
        
        # Create new backup
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = backup_dir / f'passwords_{timestamp}.json'
        
        import shutil
        shutil.copy2(self.passwords_file, backup_file)

    def generate_password(self, length: int = 16, use_lower: bool = True, use_upper: bool = True,
                        use_digits: bool = True, use_symbols: bool = True) -> str:
        """Genera una contraseña segura con los parámetros especificados."""
        if length < 8:
            print("¡Advertencia! Una contraseña segura debe tener al menos 8 caracteres.")
            length = 8

        chars = []
        if use_lower:
            chars.append(self.char_sets['lowercase'])
        if use_upper:
            chars.append(self.char_sets['uppercase'])
        if use_digits:
            chars.append(self.char_sets['digits'])
        if use_symbols:
            chars.append(self.char_sets['symbols'])

        if not chars:
            raise ValueError("Debe seleccionar al menos un tipo de caracteres")

        all_chars = ''.join(chars)
        
        # Asegurar que la contraseña incluya al menos un carácter de cada tipo seleccionado
        password = []
        if use_lower:
            password.append(secrets.choice(self.char_sets['lowercase']))
        if use_upper:
            password.append(secrets.choice(self.char_sets['uppercase']))
        if use_digits:
            password.append(secrets.choice(self.char_sets['digits']))
        if use_symbols:
            password.append(secrets.choice(self.char_sets['symbols']))

        # Completar el resto de la contraseña
        remaining_length = length - len(password)
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))

        # Mezclar los caracteres para mayor aleatoriedad
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

    def generate_passphrase(
        self, 
        words: int = 4, 
        separator: str = '-', 
        capitalize: bool = True,
        add_number: bool = True,
        add_symbol: bool = True,
        language: str = 'es'
    ) -> str:
        """
        Genera una frase de contraseña fácil de recordar.
        
        Args:
            words: Número de palabras en la frase
            separator: Separador entre palabras
            capitalize: Si es True, capitaliza cada palabra
            add_number: Si es True, añade un número aleatorio
            add_symbol: Si es True, añade un símbolo aleatorio
            language: 'es' para español, 'en' para inglés
            
        Returns:
            str: Frase de contraseña generada
        """
        wordlist = WORDS_ES if language.lower() == 'es' else WORDS_EN
        
        # Seleccionar palabras aleatorias
        selected_words = []
        for _ in range(words):
            word = secrets.choice(wordlist)
            if capitalize:
                word = word.capitalize()
            selected_words.append(word)
        
        passphrase = separator.join(selected_words)
        
        # Añadir número si está habilitado
        if add_number:
            number = str(secrets.randbelow(90) + 10)  # Número entre 10 y 99
            if secrets.randbelow(2):  # 50% de probabilidad al principio o al final
                passphrase = number + separator + passphrase
            else:
                passphrase = passphrase + separator + number
        
        # Añadir símbolo si está habilitado
        if add_symbol and self.char_sets['symbols']:
            symbol = secrets.choice(self.char_sets['symbols'])
            if secrets.randbelow(2):  # 50% de probabilidad al principio o al final
                passphrase = symbol + passphrase
            else:
                passphrase = passphrase + symbol
        
        return passphrase

    def check_strength(self, password: str) -> Tuple[PasswordStrength, str, Dict]:
        """
        Evalúa la fortaleza de una contraseña.
        
        Returns:
            Tuple[PasswordStrength, str, Dict]: (strength_enum, strength_name, details)
        """
        if not password:
            return PasswordStrength.VERY_WEAK, "Muy débil", {}
            
        details = {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_symbol': any(c in self.char_sets['symbols'] for c in password),
            'has_repeats': len(set(password)) < len(password) * 0.7,
            'is_common': self._is_common_password(password),
            'entropy': self._calculate_entropy(password)
        }
        
        # Calculate score
        score = 0
        
        # Length score
        if details['length'] >= 20:
            score += 2
        elif details['length'] >= 12:
            score += 1
            
        # Character diversity
        if details['has_lower']:
            score += 1
        if details['has_upper']:
            score += 1
        if details['has_digit']:
            score += 1
        if details['has_symbol']:
            score += 1
            
        # Deductions
        if details['is_common']:
            score = max(0, score - 2)
        if details['has_repeats']:
            score = max(0, score - 1)
            
        # Entropy check
        if details['entropy'] < 30:
            score = min(score, 2)
        elif details['entropy'] < 60:
            score = min(score, 3)
            
        # Cap the score
        score = min(score, 5)
        
        strength_map = {
            0: (PasswordStrength.VERY_WEAK, "Muy débil"),
            1: (PasswordStrength.WEAK, "Débil"),
            2: (PasswordStrength.MODERATE, "Moderada"),
            3: (PasswordStrength.STRONG, "Fuerte"),
            4: (PasswordStrength.VERY_STRONG, "Muy fuerte"),
            5: (PasswordStrength.EXCELLENT, "Excelente")
        }
        
        strength_enum, strength_name = strength_map.get(score, (PasswordStrength.VERY_WEAK, "Desconocida"))
        return strength_enum, strength_name, details
    
    def _calculate_entropy(self, password: str) -> float:
        """Calcula la entropía de una contraseña en bits."""
        if not password:
            return 0.0
            
        # Determine character pool size
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(c in self.char_sets['symbols'] for c in password):
            pool_size += len(self.char_sets['symbols'])
            
        # Calculate entropy
        import math
        entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
        return entropy
    
    def _is_common_password(self, password: str) -> bool:
        """Verifica si la contraseña está en la lista de contraseñas comunes."""
        common_passwords = {
            'password', '123456', '12345678', '1234', 'qwerty', '12345',
            'dragon', 'baseball', 'football', 'letmein', 'monkey',
            'mustang', 'michael', 'shadow', 'master', 'jennifer',
            '111111', '2000', 'jordan', 'superman', 'harley', '1234567'
        }
        return password.lower() in common_passwords

    def save_password(
        self, 
        service: str, 
        password: str, 
        username: str = "",
        notes: str = "",
        tags: List[str] = None,
        expires_in_days: Optional[int] = None
    ) -> bool:
        """
        Guarda una contraseña de forma segura.
        
        Args:
            service: Nombre del servicio o sitio web
            password: Contraseña a guardar
            username: Nombre de usuario (opcional)
            notes: Notas adicionales (opcional)
            tags: Etiquetas para organizar (opcional)
            expires_in_days: Días hasta que expire la contraseña (opcional)
            
        Returns:
            bool: True si se guardó correctamente, False en caso contrario
        """
        if not service or not password:
            return False
            
        # Normalizar el nombre del servicio
        service_lower = service.lower().strip()
        
        # Verificar si ya existe una entrada para este servicio
        if service_lower in self.passwords:
            # Mover la contraseña actual al historial
            if service_lower not in self.history:
                self.history[service_lower] = []
                
            # Guardar la versión anterior en el historial
            self.history[service_lower].append({
                'password': self.passwords[service_lower].password,
                'updated_at': self.passwords[service_lower].updated_at,
                'changed_by': os.getlogin() if 'getlogin' in dir(os) else 'system'
            })
            
            # Limitar el historial a las últimas 5 versiones
            self.history[service_lower] = self.history[service_lower][-5:]
            
            # Actualizar la entrada existente
            entry = self.passwords[service_lower]
            entry.password = password
            entry.username = username or entry.username
            entry.updated_at = datetime.now().isoformat()
            if expires_in_days is not None:
                entry.expires_in_days = expires_in_days
            if notes:
                entry.notes = notes
            if tags:
                entry.tags = list(set(entry.tags + tags))  # Unir y eliminar duplicados
        else:
            # Crear una nueva entrada
            entry = PasswordEntry(
                service=service,
                password=password,
                username=username,
                notes=notes,
                tags=tags or [],
                expires_in_days=expires_in_days or self.config.get('default_expiry_days', 90)
            )
            
        # Calcular la fortaleza de la contraseña
        strength_enum, strength_name, _ = self.check_strength(password)
        entry.strength = strength_enum
        
        # Verificar si la contraseña está comprometida
        entry.is_compromised = self._check_if_compromised(password)
        
        # Guardar la entrada
        self.passwords[service_lower] = entry
        self.save_passwords()
        
        # Guardar el historial
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except IOError as e:
            print(f"Error al guardar el historial: {e}")
        
        return True
    
    def _check_if_compromised(self, password: str) -> bool:
        """
        Verifica si una contraseña ha sido comprometida usando el algoritmo k-anonimity
        con la API de Have I Been Pwned.
        """
        if not password or not self.config.get('auto_check_compromised', True):
            return False
            
        try:
            # Hash SHA-1 de la contraseña
            password_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = password_hash[:5]
            
            # Realizar la solicitud a la API de HIBP
            import requests
            from requests.adapters import HTTPAdapter, Retry
            
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
            session.mount('https://', HTTPAdapter(max_retries=retries))
            
            response = session.get(
                f'https://api.pwnedpasswords.com/range/{prefix}',
                headers={'User-Agent': 'PasswordGenerator/2.0'},
                timeout=5
            )
            
            if response.status_code == 200:
                # Buscar el sufijo del hash en la respuesta
                suffix = password_hash[5:]
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        count = int(line.split(':')[1])
                        return count > 0
            
            return False
            
        except Exception as e:
            print(f"Advertencia: No se pudo verificar si la contraseña está comprometida: {e}")
            return False
    
    def _check_compromised_passwords(self):
        """Verifica todas las contraseñas guardadas para ver si han sido comprometidas."""
        if not self.config.get('auto_check_compromised', True):
            return
            
        updated = False
        for service, entry in self.passwords.items():
            if not entry.is_compromised:  # Solo verificar si no está ya marcada como comprometida
                is_compromised = self._check_if_compromised(entry.password)
                if is_compromised != entry.is_compromised:
                    entry.is_compromised = is_compromised
                    updated = True
                    
                    if is_compromised:
                        print(f"¡Advertencia! La contraseña para '{service}' ha sido comprometida. "
                              f"Se recomienda cambiarla de inmediato.")
        
        if updated:
            self.save_passwords()
    
    def get_expiring_passwords(self, days_threshold: int = 14) -> List[Dict]:
        """
        Obtiene una lista de contraseñas que están por expirar.
        
        Args:
            days_threshold: Días para considerar que una contraseña está por expirar
            
        Returns:
            Lista de diccionarios con información de las contraseñas que están por expirar
        """
        expiring = []
        now = datetime.now()
        
        for service, entry in self.passwords.items():
            if entry.expires_in_days is None:
                continue
                
            created_at = datetime.fromisoformat(entry.created_at)
            expiry_date = created_at + timedelta(days=entry.expires_in_days)
            days_until_expiry = (expiry_date - now).days
            
            if 0 <= days_until_expiry <= days_threshold:
                expiring.append({
                    'service': service,
                    'username': entry.username,
                    'expiry_date': expiry_date.isoformat(),
                    'days_until_expiry': days_until_expiry,
                    'created_at': entry.created_at,
                    'strength': entry.strength.name if entry.strength else 'UNKNOWN'
                })
        
        # Ordenar por días hasta la expiración (más cercano primero)
        return sorted(expiring, key=lambda x: x['days_until_expiry'])
    
    def find_duplicate_passwords(self) -> Dict[str, List[Dict]]:
        """
        Encuentra contraseñas duplicadas entre los servicios.
        
        Returns:
            Un diccionario donde las claves son hashes de contraseñas y los valores son listas
            de servicios que usan esa contraseña.
        """
        password_map = defaultdict(list)
        
        for service, entry in self.passwords.items():
            # Usamos el hash de la contraseña para agrupar
            password_hash = hashlib.sha256(entry.password.encode('utf-8')).hexdigest()
            password_map[password_hash].append({
                'service': service,
                'username': entry.username,
                'strength': entry.strength.name if entry.strength else 'UNKNOWN',
                'created_at': entry.created_at
            })
        
        # Filtrar solo las contraseñas que están duplicadas
        return {k: v for k, v in password_map.items() if len(v) > 1}
    
    def export_passwords(self, output_file: str, format_type: str = 'json', master_password: str = None) -> bool:
        """
        Exporta las contraseñas a un archivo.
        
        Args:
            output_file: Ruta del archivo de salida
            format_type: Formato de exportación ('json', 'csv')
            master_password: Contraseña maestra para cifrar el archivo (opcional)
            
        Returns:
            bool: True si la exportación fue exitosa, False en caso contrario
        """
        try:
            data = {k: asdict(v) for k, v in self.passwords.items()}
            
            if format_type.lower() == 'json':
                output = json.dumps(data, ensure_ascii=False, indent=2)
            elif format_type.lower() == 'csv':
                import csv
                import io
                
                # Preparar los datos para CSV
                rows = []
                for service, entry in data.items():
                    row = {
                        'service': service,
                        'username': entry.get('username', ''),
                        'password': entry.get('password', ''),
                        'created_at': entry.get('created_at', ''),
                        'updated_at': entry.get('updated_at', ''),
                        'strength': entry.get('strength', '')
                    }
                    rows.append(row)
                
                # Escribir a un buffer primero
                output_buffer = io.StringIO()
                if rows:
                    writer = csv.DictWriter(output_buffer, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                output = output_buffer.getvalue()
            else:
                print(f"Formato de exportación no soportado: {format_type}")
                return False
            
            # Cifrar si se proporciona una contraseña maestra
            if master_password:
                try:
                    from cryptography.fernet import Fernet
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    import base64
                    
                    # Generar una clave a partir de la contraseña maestra
                    salt = os.urandom(16)
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
                    f = Fernet(key)
                    
                    # Cifrar los datos
                    encrypted_data = f.encrypt(output.encode())
                    
                    # Guardar los datos cifrados junto con la sal
                    with open(output_file, 'wb') as f:
                        f.write(salt + b'::' + encrypted_data)
                    
                    print(f"Contraseñas exportadas y cifradas correctamente en {output_file}")
                    return True
                    
                except ImportError:
                    print("Advertencia: No se pudo importar la biblioteca de cifrado. "
                          "Instala cryptography con 'pip install cryptography' para habilitar el cifrado.")
                    print("Exportando sin cifrar...")
            
            # Guardar sin cifrar
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output)
            
            print(f"Contraseñas exportadas correctamente a {output_file}")
            return True
            
        except Exception as e:
            print(f"Error al exportar las contraseñas: {e}")
            return False
    
    def import_passwords(self, input_file: str, format_type: str = None, master_password: str = None) -> bool:
        """
        Importa contraseñas desde un archivo.
        
        Args:
            input_file: Ruta del archivo de entrada
            format_type: Formato del archivo ('json', 'csv', None para autodetectar)
            master_password: Contraseña maestra si el archivo está cifrado
            
        Returns:
            bool: True si la importación fue exitosa, False en caso contrario
        """
        if not os.path.exists(input_file):
            print(f"Error: El archivo {input_file} no existe.")
            return False
            
        try:
            # Detectar el formato si no se especificó
            if format_type is None:
                if input_file.lower().endswith('.json'):
                    format_type = 'json'
                elif input_file.lower().endswith('.csv'):
                    format_type = 'csv'
                else:
                    print("No se pudo determinar el formato del archivo. Especifícalo con el parámetro format_type.")
                    return False
            
            # Leer el archivo
            with open(input_file, 'rb') as f:
                file_content = f.read()
            
            # Verificar si el archivo está cifrado (comienza con una sal seguida de '::')
            if file_content.startswith(b'salt::') or (b'::' in file_content[:64]):
                if not master_password:
                    master_password = getpass.getpass("Ingrese la contraseña maestra: ")
                    if not master_password:
                        print("Se requiere una contraseña maestra para importar el archivo cifrado.")
                        return False
                
                try:
                    from cryptography.fernet import Fernet, InvalidToken
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                    import base64
                    
                    # Extraer la sal y los datos cifrados
                    salt, encrypted_data = file_content.split(b'::', 1)
                    
                    # Derivar la clave
                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                    )
                    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
                    f = Fernet(key)
                    
                    # Descifrar los datos
                    try:
                        file_content = f.decrypt(encrypted_data)
                    except InvalidToken:
                        print("Error: Contraseña maestra incorrecta o archivo corrupto.")
                        return False
                    
                except ImportError:
                    print("Error: No se pudo importar la biblioteca de cifrado. "
                          "Instala cryptography con 'pip install cryptography' para importar archivos cifrados.")
                    return False
                except Exception as e:
                    print(f"Error al descifrar el archivo: {e}")
                    return False
            
            # Procesar el contenido según el formato
            if format_type.lower() == 'json':
                try:
                    data = json.loads(file_content)
                    for service, entry_data in data.items():
                        # Crear una nueva entrada de contraseña
                        entry = PasswordEntry(**entry_data)
                        self.passwords[service.lower()] = entry
                    
                    # Guardar los cambios
                    self.save_passwords()
                    print(f"Se importaron {len(data)} contraseñas desde {input_file}")
                    return True
                    
                except json.JSONDecodeError as e:
                    print(f"Error al analizar el archivo JSON: {e}")
                    return False
                    
            elif format_type.lower() == 'csv':
                try:
                    import csv
                    import io
                    
                    # Leer el archivo CSV
                    csv_reader = csv.DictReader(io.StringIO(file_content.decode('utf-8')))
                    imported_count = 0
                    
                    for row in csv_reader:
                        if 'service' not in row or 'password' not in row:
                            print("Error: El archivo CSV debe contener al menos las columnas 'service' y 'password'.")
                            return False
                        
                        # Crear una nueva entrada de contraseña
                        service = row['service'].lower()
                        entry = PasswordEntry(
                            service=row['service'],
                            password=row['password'],
                            username=row.get('username', ''),
                            created_at=row.get('created_at', datetime.now().isoformat()),
                            notes=row.get('notes', '')
                        )
                        
                        # Calcular la fortaleza de la contraseña
                        strength_enum, _, _ = self.check_strength(entry.password)
                        entry.strength = strength_enum
                        
                        self.passwords[service] = entry
                        imported_count += 1
                    
                    # Guardar los cambios
                    self.save_passwords()
                    print(f"Se importaron {imported_count} contraseñas desde {input_file}")
                    return True
                    
                except Exception as e:
                    print(f"Error al procesar el archivo CSV: {e}")
                    return False
            else:
                print(f"Formato de importación no soportado: {format_type}")
                return False
                
        except Exception as e:
            print(f"Error al importar las contraseñas: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Generador de contraseñas seguras')
    parser.add_argument('-l', '--length', type=int, default=16, help='Longitud de la contraseña')
    parser.add_argument('-n', '--number', type=int, default=1, help='Número de contraseñas a generar')
    parser.add_argument('--no-lower', action='store_false', dest='lower', help='Excluir letras minúsculas')
    parser.add_argument('--no-upper', action='store_false', dest='upper', help='Excluir letras mayúsculas')
    parser.add_argument('--no-digits', action='store_false', dest='digits', help='Excluir números')
    parser.add_argument('--no-symbols', action='store_false', dest='symbols', help='Excluir símbolos')
    parser.add_argument('-p', '--passphrase', action='store_true', help='Generar una frase de contraseña')
    parser.add_argument('-w', '--words', type=int, default=4, help='Número de palabras para la frase de contraseña')
    parser.add_argument('-c', '--copy', action='store_true', help='Copiar la contraseña al portapapeles')
    parser.add_argument('-s', '--save', action='store_true', help='Guardar la contraseña generada')
    parser.add_argument('--service', help='Servicio para el que se genera la contraseña')
    parser.add_argument('-u', '--username', help='Nombre de usuario para guardar con la contraseña')
    parser.add_argument('--check', help='Verificar la fortaleza de una contraseña existente')
    
    args = parser.parse_args()
    
    pg = PasswordGenerator()
    
    if args.check:
        strength = pg.check_strength(args.check)
        print(f"Fortaleza de la contraseña: {strength}")
        return
    
    for _ in range(args.number):
        if args.passphrase:
            password = pg.generate_passphrase(words=args.words)
        else:
            password = pg.generate_password(
                length=args.length,
                use_lower=args.lower,
                use_upper=args.upper,
                use_digits=args.digits,
                use_symbols=args.symbols
            )
        
        print(f"\nContraseña generada: {password}")
        
        if not args.passphrase:
            strength = pg.check_strength(password)
            print(f"Fortaleza: {strength}")
        
        if args.copy:
            try:
                pyperclip.copy(password)
                print("¡Contraseña copiada al portapapeles!")
            except:
                print("No se pudo copiar al portapapeles. Asegúrate de tener xclip/xsel instalado en Linux o pyperclip instalado correctamente.")
        
        if args.save:
            service = args.service or input("¿Para qué servicio es esta contraseña? ")
            username = args.username or input("Nombre de usuario (opcional): ")
            pg.save_password(password, service, username)
            print("Contraseña guardada de forma segura.")

if __name__ == "__main__":
    main()
