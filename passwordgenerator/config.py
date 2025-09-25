"""Configuration and constants for the password generator."""
from pathlib import Path
from typing import Dict, Any, List
import json
import os

# Default word lists for passphrase generation
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

# Default configuration
DEFAULT_CONFIG = {
    'app': {
        'name': 'Password Generator Pro',
        'version': '2.0.0',
        'author': 'Your Name',
        'license': 'MIT',
    },
    'security': {
        'min_password_length': 8,
        'max_password_length': 128,
        'default_password_length': 16,
        'require_uppercase': True,
        'require_digits': True,
        'require_symbols': True,
        'expire_days': 90,
        'max_login_attempts': 5,
        'lockout_minutes': 15,
    },
    'storage': {
        'data_dir': str(Path.home() / '.password_generator'),
        'passwords_file': 'passwords.json',
        'config_file': 'config.json',
        'history_file': 'history.json',
        'backup_dir': 'backups',
        'max_backups': 5,
    },
    'ui': {
        'theme': 'system',
        'language': 'es',
        'show_strength_meter': True,
        'copy_to_clipboard': True,
        'clear_clipboard_after': 30,  # seconds
    }
}

class Config:
    """Configuration manager for the application."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._config = {}
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self._config = self._load_config()
            self._initialized = True
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or use defaults."""
        config_path = self.get_config_path()
        
        # Create default config if it doesn't exist
        if not config_path.exists():
            self._create_default_config()
            return DEFAULT_CONFIG
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config: {e}. Using default configuration.")
            return DEFAULT_CONFIG
    
    def _create_default_config(self):
        """Create default configuration file."""
        config_path = self.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not create config file: {e}")
    
    def get_config_path(self) -> Path:
        """Get the path to the configuration file."""
        config_dir = os.environ.get('PASSWORD_GENERATOR_CONFIG_DIR')
        if config_dir:
            return Path(config_dir) / 'config.json'
        return Path.home() / '.password_generator' / 'config.json'
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by dot notation."""
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> bool:
        """Set a configuration value by dot notation."""
        keys = key.split('.')
        config = self._config
        
        try:
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            config[keys[-1]] = value
            return True
        except (KeyError, TypeError):
            return False
    
    def save(self) -> bool:
        """Save the current configuration to file."""
        config_path = self.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            return True
        except IOError as e:
            print(f"Error saving config: {e}")
            return False

# Global config instance
config = Config()
