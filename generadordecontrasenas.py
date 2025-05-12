import secrets
import string
import argparse
import pyperclip
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import sys

class PasswordGenerator:
    def __init__(self):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        self.saved_passwords_file = Path('saved_passwords.json')
        self.saved_passwords = self._load_saved_passwords()

    def _load_saved_passwords(self) -> List[Dict]:
        """Carga las contraseñas guardadas desde el archivo JSON."""
        if self.saved_passwords_file.exists():
            try:
                with open(self.saved_passwords_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []

    def _save_passwords(self):
        """Guarda las contraseñas en el archivo JSON."""
        try:
            with open(self.saved_passwords_file, 'w', encoding='utf-8') as f:
                json.dump(self.saved_passwords, f, ensure_ascii=False, indent=2)
        except IOError:
            print("Error al guardar las contraseñas.")

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

    def generate_passphrase(self, words: int = 4, separator: str = '-', capitalize: bool = True) -> str:
        """Genera una frase de contraseña fácil de recordar."""
        try:
            import requests
            word_site = "https://www.mit.edu/~ecprice/wordlist.10000"
            response = requests.get(word_site)
            words_list = response.content.splitlines()
            words_list = [w.decode('utf-8') for w in words_list if len(w) > 3]
            
            passphrase = []
            for _ in range(words):
                word = secrets.choice(words_list)
                if capitalize:
                    word = word.capitalize()
                passphrase.append(word)
            
            return separator.join(passphrase)
        except:
            # Si hay un error al obtener palabras, usar una lista local
            local_words = ["gato", "perro", "casa", "arbol", "sol", "luna", "estrella", "agua", "fuego", "tierra"]
            passphrase = [secrets.choice(local_words) for _ in range(words)]
            if capitalize:
                passphrase = [word.capitalize() for word in passphrase]
            return separator.join(passphrase)

    def check_strength(self, password: str) -> str:
        """Evalúa la fortaleza de una contraseña."""
        score = 0
        if len(password) >= 12:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in self.char_sets['symbols'] for c in password):
            score += 1
        
        strength_levels = {
            0: "Muy débil",
            1: "Débil",
            2: "Moderada",
            3: "Fuerte",
            4: "Muy fuerte",
            5: "Excelente"
        }
        
        return strength_levels.get(score, "Desconocida")

    def save_password(self, password: str, service: str, username: str = ""):
        """Guarda una contraseña de forma segura."""
        self.saved_passwords.append({
            'service': service,
            'username': username,
            'password': password,
            'created_at': datetime.now().isoformat()
        })
        self._save_passwords()

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
