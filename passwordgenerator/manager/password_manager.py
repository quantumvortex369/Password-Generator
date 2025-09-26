"""
Módulo principal del gestor de contraseñas.
Proporciona funcionalidades para almacenar, recuperar y gestionar contraseñas de forma segura.
"""
import os
import json
import uuid
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any, Tuple
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .models import PasswordEntry, PasswordCategory, PasswordStrength

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PasswordManager:
    """
    Gestor de contraseñas con cifrado seguro.
    
    Esta clase proporciona métodos para almacenar, recuperar y gestionar
    contraseñas de forma segura utilizando cifrado AES-256.
    """
    
    def __init__(self, storage_path: str = None, master_password: str = None):
        """
        Inicializa el gestor de contraseñas.
        
        Args:
            storage_path: Ruta donde se almacenará la base de datos cifrada.
            master_password: Contraseña maestra para cifrar/descifrar la base de datos.
        """
        self.storage_path = storage_path or os.path.expanduser('~/.password_manager')
        self.master_password = master_password
        self.fernet = None
        self.db = {
            'version': '1.0',
            'entries': {},
            'categories': {},
            'metadata': {
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat(),
                'last_backup': None
            }
        }
        
        # Crear directorio si no existe
        os.makedirs(self.storage_path, exist_ok=True)
        
        # Inicializar cifrado si se proporciona una contraseña maestra
        if self.master_password:
            self._init_encryption()
    
    def _init_encryption(self):
        """Inicializa el sistema de cifrado con la contraseña maestra."""
        # Usar un salt fijo basado en la contraseña maestra para derivación de clave
        salt = hashlib.sha256(self.master_password.encode()).digest()
        
        # Derivar una clave segura usando PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        self.fernet = Fernet(key)
    
    def _encrypt_data(self, data: dict) -> str:
        """Cifra los datos utilizando la contraseña maestra."""
        if not self.fernet:
            raise ValueError("No se ha establecido una contraseña maestra")
        
        json_data = json.dumps(data, default=str).encode()
        return self.fernet.encrypt(json_data).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> dict:
        """Descifra los datos utilizando la contraseña maestra."""
        if not self.fernet:
            raise ValueError("No se ha establecido una contraseña maestra")
        
        try:
            decrypted_data = self.fernet.decrypt(encrypted_data.encode())
            return json.loads(decrypted_data)
        except (InvalidToken, json.JSONDecodeError) as e:
            logger.error("Error al descifrar los datos: %s", str(e))
            raise ValueError("Contraseña maestra incorrecta o datos corruptos") from e
    
    def save(self, filepath: str = None) -> bool:
        """
        Guarda la base de datos cifrada en un archivo.
        
        Args:
            filepath: Ruta del archivo donde guardar la base de datos.
                      Si no se especifica, se usa la ruta por defecto.
        """
        if not self.fernet:
            raise ValueError("No se ha establecido una contraseña maestra")
        
        filepath = filepath or os.path.join(self.storage_path, 'passwords.psafe')
        
        try:
            # Actualizar metadatos
            self.db['metadata']['updated_at'] = datetime.utcnow().isoformat()
            
            # Cifrar y guardar
            encrypted_data = self._encrypt_data(self.db)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
            
            logger.info("Base de datos guardada correctamente en %s", filepath)
            return True
        except Exception as e:
            logger.error("Error al guardar la base de datos: %s", str(e))
            return False
    
    def load(self, filepath: str = None) -> bool:
        """
        Carga una base de datos cifrada desde un archivo.
        
        Args:
            filepath: Ruta del archivo a cargar.
                     Si no se especifica, se usa la ruta por defecto.
        """
        if not self.fernet:
            raise ValueError("No se ha establecido una contraseña maestra")
        
        filepath = filepath or os.path.join(self.storage_path, 'passwords.psafe')
        
        if not os.path.exists(filepath):
            logger.warning("El archivo de base de datos no existe. Se creará uno nuevo al guardar.")
            return False
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            self.db = self._decrypt_data(encrypted_data)
            logger.info("Base de datos cargada correctamente desde %s", filepath)
            return True
        except Exception as e:
            logger.error("Error al cargar la base de datos: %s", str(e))
            return False
    
    # Métodos para gestionar entradas de contraseña
    
    def add_entry(self, entry: PasswordEntry) -> str:
        """
        Añade una nueva entrada de contraseña.
        
        Args:
            entry: Objeto PasswordEntry con los datos de la contraseña.
            
        Returns:
            str: ID de la entrada creada.
        """
        if not entry.id:
            entry.id = str(uuid.uuid4())
        
        entry.updated_at = datetime.utcnow()
        self.db['entries'][entry.id] = entry.to_dict()
        return entry.id
    
    def get_entry(self, entry_id: str) -> Optional[PasswordEntry]:
        """
        Obtiene una entrada de contraseña por su ID.
        
        Args:
            entry_id: ID de la entrada a recuperar.
            
        Returns:
            PasswordEntry: Objeto con los datos de la contraseña, o None si no se encuentra.
        """
        entry_data = self.db['entries'].get(entry_id)
        if entry_data:
            return PasswordEntry.from_dict(entry_data)
        return None
    
    def update_entry(self, entry_id: str, **updates) -> bool:
        """
        Actualiza una entrada de contraseña existente.
        
        Args:
            entry_id: ID de la entrada a actualizar.
            **updates: Campos a actualizar con sus nuevos valores.
            
        Returns:
            bool: True si la actualización fue exitosa, False en caso contrario.
        """
        if entry_id not in self.db['entries']:
            return False
        
        entry_data = self.db['entries'][entry_id]
        entry = PasswordEntry.from_dict(entry_data)
        
        # Actualizar campos
        for key, value in updates.items():
            if hasattr(entry, key):
                setattr(entry, key, value)
        
        entry.updated_at = datetime.utcnow()
        self.db['entries'][entry_id] = entry.to_dict()
        return True
    
    def delete_entry(self, entry_id: str) -> bool:
        """
        Elimina una entrada de contraseña.
        
        Args:
            entry_id: ID de la entrada a eliminar.
            
        Returns:
            bool: True si la eliminación fue exitosa, False en caso contrario.
        """
        if entry_id in self.db['entries']:
            del self.db['entries'][entry_id]
            return True
        return False
    
    def list_entries(self, category_id: str = None, search_query: str = None) -> List[PasswordEntry]:
        """
        Obtiene una lista de entradas de contraseña, opcionalmente filtradas por categoría o búsqueda.
        
        Args:
            category_id: ID de la categoría para filtrar (opcional).
            search_query: Término de búsqueda para filtrar por título o nombre de usuario (opcional).
            
        Returns:
            List[PasswordEntry]: Lista de entradas que coinciden con los criterios.
        """
        entries = []
        search_query = search_query.lower() if search_query else None
        
        for entry_data in self.db['entries'].values():
            entry = PasswordEntry.from_dict(entry_data)
            
            # Aplicar filtros
            if category_id and entry.category_id != category_id:
                continue
                
            if search_query:
                if (search_query not in entry.title.lower() and 
                    search_query not in (entry.username or '').lower()):
                    continue
            
            entries.append(entry)
        
        # Ordenar por título
        return sorted(entries, key=lambda x: x.title.lower())
    
    # Métodos para gestionar categorías
    
    def add_category(self, category: PasswordCategory) -> str:
        """
        Añade una nueva categoría.
        
        Args:
            category: Objeto PasswordCategory con los datos de la categoría.
            
        Returns:
            str: ID de la categoría creada.
        """
        if not category.id:
            category.id = str(uuid.uuid4())
        
        category.updated_at = datetime.utcnow()
        self.db['categories'][category.id] = category.to_dict()
        return category.id
    
    def get_category(self, category_id: str) -> Optional[PasswordCategory]:
        """
        Obtiene una categoría por su ID.
        
        Args:
            category_id: ID de la categoría a recuperar.
            
        Returns:
            PasswordCategory: Objeto con los datos de la categoría, o None si no se encuentra.
        """
        category_data = self.db['categories'].get(category_id)
        if category_data:
            return PasswordCategory.from_dict(category_data)
        return None
    
    def list_categories(self, parent_id: str = None) -> List[PasswordCategory]:
        """
        Obtiene una lista de categorías, opcionalmente filtradas por categoría padre.
        
        Args:
            parent_id: ID de la categoría padre para filtrar (opcional).
            
        Returns:
            List[PasswordCategory]: Lista de categorías que coinciden con los criterios.
        """
        categories = []
        
        for category_data in self.db['categories'].values():
            category = PasswordCategory.from_dict(category_data)
            
            if parent_id is not None and category.parent_id != parent_id:
                continue
                
            categories.append(category)
        
        # Ordenar por nombre
        return sorted(categories, key=lambda x: x.name.lower())
    
    def update_category(self, category_id: str, **updates) -> bool:
        """
        Actualiza una categoría existente.
        
        Args:
            category_id: ID de la categoría a actualizar.
            **updates: Campos a actualizar con sus nuevos valores.
            
        Returns:
            bool: True si la actualización fue exitosa, False en caso contrario.
        """
        if category_id not in self.db['categories']:
            return False
        
        category_data = self.db['categories'][category_id]
        category = PasswordCategory.from_dict(category_data)
        
        # Actualizar campos
        for key, value in updates.items():
            if hasattr(category, key):
                setattr(category, key, value)
        
        category.updated_at = datetime.utcnow()
        self.db['categories'][category_id] = category.to_dict()
        return True
    
    def delete_category(self, category_id: str, move_to_category: str = None) -> bool:
        """
        Elimina una categoría.
        
        Args:
            category_id: ID de la categoría a eliminar.
            move_to_category: ID de la categoría a la que mover las entradas (opcional).
            
        Returns:
            bool: True si la eliminación fue exitosa, False en caso contrario.
        """
        if category_id not in self.db['categories']:
            return False
        
        # Mover o eliminar entradas de la categoría
        if move_to_category and move_to_category in self.db['categories']:
            for entry_id, entry_data in self.db['entries'].items():
                if entry_data.get('category_id') == category_id:
                    entry_data['category_id'] = move_to_category
        else:
            # Eliminar referencias a la categoría en las entradas
            for entry_id, entry_data in self.db['entries'].items():
                if entry_data.get('category_id') == category_id:
                    entry_data['category_id'] = None
        
        # Eliminar la categoría
        del self.db['categories'][category_id]
        return True
    
    # Métodos de utilidad
    
    def get_password_strength(self, password: str) -> PasswordStrength:
        """
        Evalúa la fortaleza de una contraseña.
        
        Args:
            password: Contraseña a evaluar.
            
        Returns:
            PasswordStrength: Nivel de fortaleza de la contraseña.
        """
        if not password:
            return PasswordStrength.VERY_WEAK
            
        score = 0
        length = len(password)
        
        # Puntos por longitud
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if length >= 16:
            score += 1
            
        # Puntos por complejidad
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(not c.isalnum() for c in password):
            score += 1
            
        # Puntos por entropía (simplificado)
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if any(not c.isalnum() for c in password):
            char_set += 32  # Caracteres especiales comunes
            
        entropy = length * (char_set ** 0.5)
        if entropy > 100:
            score += 2
        elif entropy > 60:
            score += 1
            
        # Determinar nivel de fortaleza
        if score >= 8:
            return PasswordStrength.VERY_STRONG
        elif score >= 6:
            return PasswordStrength.STRONG
        elif score >= 4:
            return PasswordStrength.MODERATE
        elif score >= 2:
            return PasswordStrength.WEAK
        else:
            return PasswordStrength.VERY_WEAK
    
    def generate_password(self, length: int = 16, **kwargs) -> str:
        """
        Genera una contraseña segura.
        
        Args:
            length: Longitud de la contraseña (por defecto: 16).
            **kwargs: Opciones adicionales para la generación de contraseñas.
                    (puede incluir use_upper, use_lower, use_digits, etc.)
                    
        Returns:
            str: Contraseña generada.
        """
        import random
        import string
        
        # Configurar conjuntos de caracteres
        chars = []
        
        # Incluir caracteres según las opciones
        if kwargs.get('use_lower', True):
            chars.extend(string.ascii_lowercase)
        if kwargs.get('use_upper', True):
            chars.extend(string.ascii_uppercase)
        if kwargs.get('use_digits', True):
            chars.extend(string.digits)
        if kwargs.get('use_symbols', True):
            chars.extend('!@#$%^&*_+-=')
        if kwargs.get('use_brackets', False):
            chars.extend('[]{}()<>')
        if kwargs.get('use_punctuation', False):
            chars.extend('.,;:!?')
        if kwargs.get('use_math', False):
            chars.extend('+-*/=^')
        if kwargs.get('use_space', False):
            chars.append(' ')
        
        # Asegurarse de que hay al menos un conjunto de caracteres
        if not chars:
            chars = string.ascii_letters + string.digits + '!@#$%^&*_+='
        
        # Generar contraseña
        password = []
        
        # Asegurar al menos un carácter de cada tipo seleccionado
        if kwargs.get('use_lower', True) and string.ascii_lowercase:
            password.append(random.choice(string.ascii_lowercase))
        if kwargs.get('use_upper', True) and string.ascii_uppercase:
            password.append(random.choice(string.ascii_uppercase))
        if kwargs.get('use_digits', True) and string.digits:
            password.append(random.choice(string.digits))
        if kwargs.get('use_symbols', True) and '!@#$%^&*_+=':
            password.append(random.choice('!@#$%^&*_+='))
        
        # Completar el resto de la contraseña
        remaining_length = max(0, length - len(password))
        password.extend(random.choices(chars, k=remaining_length))
        
        # Mezclar los caracteres
        random.shuffle(password)
        
        return ''.join(password)
