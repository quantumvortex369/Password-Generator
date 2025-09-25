import json
import os
import base64
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordStorage:
    """Clase para el almacenamiento seguro de contraseñas."""
    
    def __init__(self, storage_file: str = 'passwords.enc', key_file: str = 'key.key'):
        """
        Inicializa el almacenamiento de contraseñas.
        
        Args:
            storage_file: Archivo donde se guardarán las contraseñas cifradas
            key_file: Archivo donde se guardará la clave de cifrado
        """
        self.storage_file = Path(storage_file)
        self.key_file = Path(key_file)
        self.passwords = []
        self.fernet = None
        
        # Cargar o generar la clave de cifrado
        self._load_or_generate_key()
        
        # Cargar contraseñas existentes
        self._load_passwords()
    
    def _load_or_generate_key(self):
        """Carga una clave existente o genera una nueva."""
        # Si el archivo de clave existe, cargarlo
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generar una nueva clave
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Establecer permisos seguros (solo el usuario puede leer/escribir)
            os.chmod(self.key_file, 0o600)
        
        self.fernet = Fernet(key)
    
    def _encrypt(self, data: str) -> str:
        """Cifra los datos."""
        return self.fernet.encrypt(data.encode()).decode()
    
    def _decrypt(self, data: str) -> str:
        """Descifra los datos."""
        return self.fernet.decrypt(data.encode()).decode()
    
    def _load_passwords(self):
        """Carga las contraseñas desde el archivo cifrado."""
        if self.storage_file.exists():
            try:
                with open(self.storage_file, 'r') as f:
                    encrypted_data = f.read()
                    if encrypted_data:
                        decrypted_data = self._decrypt(encrypted_data)
                        self.passwords = json.loads(decrypted_data)
            except Exception as e:
                print(f"Error al cargar las contraseñas: {e}")
                self.passwords = []
    
    def _save_passwords(self):
        """Guarda las contraseñas en el archivo cifrado."""
        try:
            data = json.dumps(self.passwords, ensure_ascii=False, indent=2)
            encrypted_data = self._encrypt(data)
            
            # Escribir en un archivo temporal primero
            temp_file = f"{self.storage_file}.tmp"
            with open(temp_file, 'w') as f:
                f.write(encrypted_data)
            
            # Reemplazar el archivo original
            if os.path.exists(self.storage_file):
                os.replace(temp_file, self.storage_file)
            else:
                os.rename(temp_file, self.storage_file)
            
            # Establecer permisos seguros
            os.chmod(self.storage_file, 0o600)
            
        except Exception as e:
            print(f"Error al guardar las contraseñas: {e}")
    
    def add_password(
        self,
        password: str,
        service: str,
        username: str = "",
        url: str = "",
        notes: str = "",
        tags: List[str] = None
    ) -> Dict:
        """
        Añade una nueva contraseña al almacenamiento.
        
        Args:
            password: La contraseña a almacenar
            service: Nombre del servicio o sitio web
            username: Nombre de usuario (opcional)
            url: URL del sitio web (opcional)
            notes: Notas adicionales (opcional)
            tags: Etiquetas para organizar (opcional)
            
        Returns:
            Dict: La entrada de contraseña creada
        """
        entry = {
            'id': len(self.passwords) + 1,
            'service': service,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'tags': tags or [],
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat()
        }
        
        self.passwords.append(entry)
        self._save_passwords()
        return entry
    
    def get_passwords(self, query: str = None, tag: str = None) -> List[Dict]:
        """
        Obtiene las contraseñas que coinciden con la consulta.
        
        Args:
            query: Texto para buscar en servicio, usuario o notas
            tag: Etiqueta para filtrar
            
        Returns:
            List[Dict]: Lista de entradas de contraseña
        """
        results = self.passwords
        
        if query:
            query = query.lower()
            results = [
                p for p in results
                if (query in p.get('service', '').lower() or
                     query in p.get('username', '').lower() or
                     query in p.get('notes', '').lower() or
                     any(query in t.lower() for t in p.get('tags', []) if t))
            ]
        
        if tag:
            tag = tag.lower()
            results = [p for p in results if tag in [t.lower() for t in p.get('tags', [])]]
        
        return results
    
    def update_password(
        self,
        entry_id: int,
        password: str = None,
        service: str = None,
        username: str = None,
        url: str = None,
        notes: str = None,
        tags: List[str] = None
    ) -> Optional[Dict]:
        """
        Actualiza una entrada de contraseña existente.
        
        Args:
            entry_id: ID de la entrada a actualizar
            password: Nueva contraseña (opcional)
            service: Nuevo servicio (opcional)
            username: Nuevo nombre de usuario (opcional)
            url: Nueva URL (opcional)
            notes: Nuevas notas (opcional)
            tags: Nuevas etiquetas (opcional)
            
        Returns:
            Optional[Dict]: La entrada actualizada o None si no se encontró
        """
        for entry in self.passwords:
            if entry['id'] == entry_id:
                if password is not None:
                    entry['password'] = password
                if service is not None:
                    entry['service'] = service
                if username is not None:
                    entry['username'] = username
                if url is not None:
                    entry['url'] = url
                if notes is not None:
                    entry['notes'] = notes
                if tags is not None:
                    entry['tags'] = tags
                
                entry['updated_at'] = datetime.now().isoformat()
                self._save_passwords()
                return entry
        
        return None
    
    def delete_password(self, entry_id: int) -> bool:
        """
        Elimina una entrada de contraseña.
        
        Args:
            entry_id: ID de la entrada a eliminar
            
        Returns:
            bool: True si se eliminó, False si no se encontró
        """
        for i, entry in enumerate(self.passwords):
            if entry['id'] == entry_id:
                del self.passwords[i]
                self._save_passwords()
                return True
        
        return False
    
    def export_to_csv(self, output_file: str) -> bool:
        """
        Exporta las contraseñas a un archivo CSV.
        
        Args:
            output_file: Ruta del archivo de salida
            
        Returns:
            bool: True si se exportó correctamente
        """
        try:
            import csv
            
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'id', 'service', 'username', 'password', 'url', 'notes', 'tags', 'created_at', 'updated_at'
                ])
                writer.writeheader()
                
                for entry in self.passwords:
                    # Crear una copia para no modificar el original
                    row = entry.copy()
                    # Convertir la lista de etiquetas a string
                    row['tags'] = ', '.join(row.get('tags', []))
                    writer.writerow(row)
            
            return True
            
        except Exception as e:
            print(f"Error al exportar a CSV: {e}")
            return False
    
    def import_from_csv(self, input_file: str) -> bool:
        """
        Importa contraseñas desde un archivo CSV.
        
        Args:
            input_file: Ruta del archivo CSV de entrada
            
        Returns:
            bool: True si se importó correctamente
        """
        try:
            import csv
            
            with open(input_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    # Convertir el string de etiquetas a lista
                    tags = [t.strip() for t in row.get('tags', '').split(',') if t.strip()]
                    
                    self.add_password(
                        password=row['password'],
                        service=row['service'],
                        username=row.get('username', ''),
                        url=row.get('url', ''),
                        notes=row.get('notes', ''),
                        tags=tags
                    )
            
            return True
            
        except Exception as e:
            print(f"Error al importar desde CSV: {e}")
            return False
