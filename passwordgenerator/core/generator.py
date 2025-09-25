"""Core password generation functionality."""
import secrets
import string
from typing import List, Dict, Optional

class PasswordGenerator:
    """Main password generator class."""
    
    def __init__(self):
        """Initialize the password generator with default character sets."""
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?',
            'brackets': '[]{}()<>',
            'punctuation': '!?.,;:',
            'math': '+=-*/><^',
            'space': ' '
        }

    def generate_password(
        self, 
        length: int = 16, 
        use_lower: bool = True, 
        use_upper: bool = True,
        use_digits: bool = True, 
        use_symbols: bool = True,
        use_brackets: bool = False,
        use_punctuation: bool = False,
        use_math: bool = False,
        use_space: bool = False
    ) -> str:
        """Generate a secure password with specified parameters."""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")

        # Collect character sets based on parameters
        chars = []
        char_set_options = {
            'lowercase': use_lower,
            'uppercase': use_upper,
            'digits': use_digits,
            'symbols': use_symbols,
            'brackets': use_brackets,
            'punctuation': use_punctuation,
            'math': use_math,
            'space': use_space
        }

        # Add selected character sets
        for char_set, use in char_set_options.items():
            if use and char_set in self.char_sets:
                chars.append(self.char_sets[char_set])

        if not chars:
            raise ValueError("At least one character set must be selected")

        all_chars = ''.join(chars)
        password = []
        
        # Ensure at least one character from each selected set
        for char_set, use in char_set_options.items():
            if use and char_set in self.char_sets:
                password.append(secrets.choice(self.char_sets[char_set]))

        # Fill the rest randomly
        remaining_length = max(0, length - len(password))
        password.extend(secrets.choice(all_chars) for _ in range(remaining_length))

        # Shuffle to ensure randomness
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
        """Generate a memorable passphrase."""
        from ..config import WORDS_ES, WORDS_EN
        
        wordlist = WORDS_ES if language.lower() == 'es' else WORDS_EN
        selected_words = [secrets.choice(wordlist) for _ in range(words)]
        
        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]
            
        passphrase = separator.join(selected_words)
        
        if add_number:
            number = str(secrets.randbelow(90) + 10)  # 10-99
            if secrets.randbelow(2):
                passphrase = f"{number}{separator}{passphrase}"
            else:
                passphrase = f"{passphrase}{separator}{number}"
                
        if add_symbol and self.char_sets['symbols']:
            symbol = secrets.choice(self.char_sets['symbols'])
            if secrets.randbelow(2):
                passphrase = f"{symbol}{passphrase}"
            else:
                passphrase = f"{passphrase}{symbol}"
                
        return passphrase
