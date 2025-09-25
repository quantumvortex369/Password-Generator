import secrets
from typing import List, Dict, Optional
import requests
from pathlib import Path
import json

class PassphraseGenerator:
    """Clase para generar frases de contraseña fáciles de recordar."""
    
    def __init__(self):
        self.wordlists = {
            'es': self._load_local_wordlist('es'),
            'en': self._load_local_wordlist('en')
        }
    
    def _load_local_wordlist(self, lang: str) -> List[str]:
        """Carga una lista de palabras local."""
        if lang == 'es':
            return [
                'gato', 'perro', 'casa', 'arbol', 'libro', 'agua', 'fuego', 'tierra', 'aire', 'luz',
                'sol', 'luna', 'estrella', 'mar', 'rio', 'montaña', 'ciudad', 'pueblo', 'camino', 'puerta',
                'ventana', 'silla', 'mesa', 'cama', 'ropa', 'comida', 'agua', 'leche', 'pan', 'queso',
                'manzana', 'naranja', 'plátano', 'uva', 'pera', 'coche', 'moto', 'bicicleta', 'tren', 'avión',
                'barco', 'pez', 'pájaro', 'flor', 'árbol', 'hoja', 'piedra', 'arena', 'nube', 'lluvia'
            ]
        else:  # inglés por defecto
            return [
                'apple', 'banana', 'cat', 'dog', 'house', 'tree', 'car', 'bike', 'water', 'fire',
                'earth', 'air', 'light', 'sun', 'moon', 'star', 'sea', 'river', 'mountain', 'city',
                'town', 'road', 'door', 'window', 'chair', 'table', 'bed', 'clothes', 'food', 'milk',
                'bread', 'cheese', 'orange', 'grape', 'pear', 'train', 'plane', 'boat', 'fish', 'bird',
                'flower', 'leaf', 'stone', 'sand', 'cloud', 'rain', 'computer', 'phone', 'book', 'pen'
            ]
    
    def _download_wordlist(self, lang: str = 'en') -> List[str]:
        """Intenta descargar una lista de palabras de Internet."""
        try:
            if lang == 'es':
                url = 'https://raw.githubusercontent.com/bitcoin/bips/master/spanish.txt'
            else:  # inglés por defecto
                url = 'https://raw.githubusercontent.com/bitcoin/bips/master/english.txt'
                
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                words = response.text.splitlines()
                # Filtrar palabras muy cortas o largas
                return [word.strip() for word in words if 3 <= len(word.strip()) <= 10]
        except:
            pass
        return []
    
    def generate_passphrase(
        self,
        words: int = 4,
        separator: str = '-',
        capitalize: bool = True,
        add_number: bool = False,
        add_symbol: bool = False,
        lang: str = 'es',
        use_online: bool = False
    ) -> str:
        """
        Genera una frase de contraseña.
        
        Args:
            words: Número de palabras en la frase
            separator: Separador entre palabras
            capitalize: Poner en mayúscula la primera letra de cada palabra
            add_number: Añadir un número al final
            add_symbol: Añadir un símbolo al final
            lang: Idioma de las palabras ('es' o 'en')
            use_online: Intentar descargar lista de palabras de Internet
            
        Returns:
            str: Frase de contraseña generada
        """
        # Obtener lista de palabras
        wordlist = []
        if use_online:
            wordlist = self._download_wordlist(lang)
        
        if not wordlist:
            wordlist = self.wordlists.get(lang, self.wordlists['es'])
        
        # Seleccionar palabras aleatorias
        selected_words = [secrets.choice(wordlist) for _ in range(words)]
        
        # Aplicar formato
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]
        
        # Unir palabras
        passphrase = separator.join(selected_words)
        
        # Añadir número si se solicita
        if add_number:
            passphrase += str(secrets.randbelow(90) + 10)  # Número de 2 dígitos
        
        # Añadir símbolo si se solicita
        if add_symbol:
            symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            passphrase += secrets.choice(symbols)
        
        return passphrase
    
    def generate_memorable_password(
        self,
        min_length: int = 12,
        max_length: int = 16,
        lang: str = 'es',
        use_online: bool = False
    ) -> str:
        """
        Genera una contraseña memorable basada en patrones.
        
        Ejemplo: 'gato123PERRO!'
        """
        patterns = [
            lambda: self.generate_passphrase(2, '', True, True, False, lang, use_online),
            lambda: self.generate_passphrase(1, '', True, True, True, lang, use_online),
            lambda: self.generate_passphrase(3, '', False, True, False, lang, use_online).upper(),
            lambda: self.generate_passphrase(1, '', True, False, False, lang, use_online) + 
                   str(secrets.randbelow(900) + 100) +  # 3 dígitos
                   secrets.choice('!@#$%^&*')
        ]
        
        while True:
            password = secrets.choice(patterns)()
            if min_length <= len(password) <= max_length:
                return password
