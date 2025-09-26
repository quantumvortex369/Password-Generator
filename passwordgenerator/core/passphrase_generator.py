"""Módulo para generar frases de contraseña seguras y fáciles de recordar."""
import random
from typing import List, Optional

class PassphraseGenerator:
    """Genera frases de contraseña utilizando palabras comunes."""
    
    # Lista de palabras comunes en español (puedes expandir esta lista)
    WORDLIST_ES = [
        'casa', 'perro', 'gato', 'libro', 'agua', 'sol', 'luna', 'cielo', 'arbol', 'flor',
        'mesa', 'silla', 'puerta', 'ventana', 'techo', 'piso', 'pared', 'cocina', 'baño', 'cuarto',
        'manzana', 'naranja', 'plátano', 'uva', 'pan', 'leche', 'queso', 'huevo', 'arroz', 'pasta',
        'coche', 'bicicleta', 'autobús', 'tren', 'avión', 'barco', 'tren', 'moto', 'camión', 'tractor',
        'rojo', 'azul', 'verde', 'amarillo', 'blanco', 'negro', 'gris', 'rosa', 'morado', 'naranja'
    ]
    
    # Separadores comunes para las frases
    SEPARATORS = ['-', '_', '.', ',', '!', '?', ' ', '']
    
    def __init__(self, wordlist: Optional[List[str]] = None):
        """Inicializa el generador con una lista de palabras personalizada o la predeterminada."""
        self.wordlist = wordlist or self.WORDLIST_ES
    
    def generate(self, 
                num_words: int = 4, 
                capitalize: bool = True, 
                add_number: bool = True,
                add_symbol: bool = True,
                separator: str = '-') -> str:
        """
        Genera una frase de contraseña.
        
        Args:
            num_words: Número de palabras en la frase (3-6 recomendado).
            capitalize: Si es True, capitaliza cada palabra.
            add_number: Si es True, añade un número al final.
            add_symbol: Si es True, añade un símbolo al final.
            separator: Separador entre palabras.
            
        Returns:
            str: Una frase de contraseña generada.
        """
        # Asegurarse de que el número de palabras sea razonable
        num_words = max(2, min(8, num_words))
        
        # Seleccionar palabras aleatorias
        words = random.sample(self.wordlist, num_words)
        
        # Aplicar formato a las palabras
        if capitalize:
            words = [word.capitalize() for word in words]
        
        # Unir las palabras con el separador
        passphrase = separator.join(words)
        
        # Añadir un número si se solicita
        if add_number:
            passphrase += str(random.randint(0, 999))
        
        # Añadir un símbolo si se solicita
        if add_symbol and add_number:
            symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            passphrase += random.choice(symbols)
        
        return passphrase
    
    def estimate_strength(self, passphrase: str) -> str:
        """
        Estima la fortaleza de una frase de contraseña.
        
        Args:
            passphrase: La frase de contraseña a evaluar.
            
        Returns:
            str: Un mensaje que describe la fortaleza de la contraseña.
        """
        length = len(passphrase)
        has_upper = any(c.isupper() for c in passphrase)
        has_lower = any(c.islower() for c in passphrase)
        has_digit = any(c.isdigit() for c in passphrase)
        has_symbol = any(not c.isalnum() for c in passphrase)
        
        if length < 12:
            return "Muy débil - Demasiado corta"
        elif length < 16 and not (has_upper and has_lower and has_digit):
            return "Débil - Usa más caracteres y variedad"
        elif length < 20 and not (has_upper and has_lower and has_digit and has_symbol):
            return "Moderada - Considera añadir más símbolos o longitud"
        elif length >= 20 and has_upper and has_lower and has_digit and has_symbol:
            return "Muy fuerte - Excelente elección"
        else:
            return "Fuerte - Buena contraseña"

def generate_passphrase() -> str:
    """Función de conveniencia para generar una frase de contraseña con configuraciones por defecto."""
    generator = PassphraseGenerator()
    return generator.generate()

if __name__ == "__main__":
    # Ejemplo de uso
    generator = PassphraseGenerator()
    for _ in range(5):
        phrase = generator.generate()
        print(f"{phrase} - {generator.estimate_strength(phrase)}")
