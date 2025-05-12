import argparse
import sys
import pyperclip
from typing import List, Dict, Optional
from .generator import PasswordGenerator
from .passphrase_generator import PassphraseGenerator
from .strength_checker import PasswordStrengthChecker
from .storage import PasswordStorage

class PasswordManagerCLI:
    """Interfaz de línea de comandos para el generador de contraseñas."""
    
    def __init__(self):
        self.generator = PasswordGenerator()
        self.passphrase_gen = PassphraseGenerator()
        self.strength_checker = PasswordStrengthChecker()
        self.storage = PasswordStorage()
        self.setup_parser()
    
    def setup_parser(self):
        """Configura el analizador de argumentos."""
        self.parser = argparse.ArgumentParser(
            description='Generador y gestor de contraseñas seguras',
            epilog='Ejemplos de uso:\n'
                   '  Generar contraseña: passgen generate -l 16\n'
                   '  Generar frase de contraseña: passgen phrase -w 5\n'
                   '  Verificar fortaleza: passgen check "MiContraseña123"\n'
                   '  Guardar contraseña: passgen save -s gmail -u usuario@gmail.com -p "contraseña"',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Subcomandos
        subparsers = self.parser.add_subparsers(dest='command', help='Comando a ejecutar')
        
        # Comando: generate
        gen_parser = subparsers.add_parser('generate', help='Generar una nueva contraseña')
        gen_parser.add_argument('-l', '--length', type=int, default=16, help='Longitud de la contraseña')
        gen_parser.add_argument('--no-lower', action='store_false', dest='lower', help='Excluir letras minúsculas')
        gen_parser.add_argument('--no-upper', action='store_false', dest='upper', help='Excluir letras mayúsculas')
        gen_parser.add_argument('--no-digits', action='store_false', dest='digits', help='Excluir dígitos')
        gen_parser.add_argument('--no-symbols', action='store_false', dest='symbols', help='Excluir símbolos')
        gen_parser.add_argument('--exclude-similar', action='store_true', help='Excluir caracteres similares (1, l, I, 0, O)')
        gen_parser.add_argument('--exclude-ambiguous', action='store_true', help='Excluir caracteres ambiguos')
        gen_parser.add_argument('--custom-chars', type=str, default='', help='Caracteres personalizados a incluir')
        gen_parser.add_argument('-c', '--copy', action='store_true', help='Copiar al portapapeles')
        gen_parser.add_argument('-s', '--save', action='store_true', help='Guardar la contraseña')
        gen_parser.add_argument('--service', type=str, help='Servicio para el que es la contraseña')
        gen_parser.add_argument('-u', '--username', type=str, help='Nombre de usuario')
        
        # Comando: phrase
        phrase_parser = subparsers.add_parser('phrase', help='Generar una frase de contraseña')
        phrase_parser.add_argument('-w', '--words', type=int, default=4, help='Número de palabras')
        phrase_parser.add_argument('--separator', type=str, default='-', help='Separador entre palabras')
        phrase_parser.add_argument('--no-capitalize', action='store_false', dest='capitalize', help='No capitalizar palabras')
        phrase_parser.add_argument('--number', action='store_true', help='Añadir un número al final')
        phrase_parser.add_argument('--symbol', action='store_true', help='Añadir un símbolo al final')
        phrase_parser.add_argument('--lang', type=str, default='es', choices=['es', 'en'], help='Idioma de las palabras')
        phrase_parser.add_argument('--online', action='store_true', help='Usar lista de palabras en línea')
        phrase_parser.add_argument('-c', '--copy', action='store_true', help='Copiar al portapapeles')
        phrase_parser.add_argument('-s', '--save', action='store_true', help='Guardar la frase')
        phrase_parser.add_argument('--service', type=str, help='Servicio para el que es la frase')
        phrase_parser.add_argument('-u', '--username', type=str, help='Nombre de usuario')
        
        # Comando: check
        check_parser = subparsers.add_parser('check', help='Verificar la fortaleza de una contraseña')
        check_parser.add_argument('password', type=str, help='Contraseña a verificar')
        
        # Comando: save
        save_parser = subparsers.add_parser('save', help='Guardar una contraseña')
        save_parser.add_argument('-p', '--password', type=str, help='Contraseña a guardar')
        save_parser.add_argument('-s', '--service', type=str, required=True, help='Servicio para el que es la contraseña')
        save_parser.add_argument('-u', '--username', type=str, help='Nombre de usuario')
        save_parser.add_argument('--url', type=str, help='URL del servicio')
        save_parser.add_argument('--notes', type=str, help='Notas adicionales')
        save_parser.add_argument('--tags', type=str, help='Etiquetas separadas por comas')
        
        # Comando: list
        list_parser = subparsers.add_parser('list', help='Listar contraseñas guardadas')
        list_parser.add_argument('-q', '--query', type=str, help='Texto para buscar')
        list_parser.add_argument('-t', '--tag', type=str, help='Filtrar por etiqueta')
        
        # Comando: get
        get_parser = subparsers.add_parser('get', help='Obtener una contraseña guardada')
        get_parser.add_argument('id', type=int, help='ID de la contraseña')
        get_parser.add_argument('-c', '--copy', action='store_true', help='Copiar al portapapeles')
        
        # Comando: export
        export_parser = subparsers.add_parser('export', help='Exportar contraseñas a un archivo CSV')
        export_parser.add_argument('output_file', type=str, help='Archivo de salida')
        
        # Comando: import
        import_parser = subparsers.add_parser('import', help='Importar contraseñas desde un archivo CSV')
        import_parser.add_argument('input_file', type=str, help='Archivo de entrada')
    
    def run(self, args=None):
        """Ejecuta el comando solicitado."""
        if args is None:
            args = sys.argv[1:]
            
        if not args:
            self.parser.print_help()
            return
            
        args = self.parser.parse_args(args)
        
        if args.command == 'generate':
            self.handle_generate(args)
        elif args.command == 'phrase':
            self.handle_phrase(args)
        elif args.command == 'check':
            self.handle_check(args)
        elif args.command == 'save':
            self.handle_save(args)
        elif args.command == 'list':
            self.handle_list(args)
        elif args.command == 'get':
            self.handle_get(args)
        elif args.command == 'export':
            self.handle_export(args)
        elif args.command == 'import':
            self.handle_import(args)
        else:
            self.parser.print_help()
    
    def handle_generate(self, args):
        """Maneja el comando de generación de contraseña."""
        try:
            password = self.generator.generate_password(
                length=args.length,
                use_lower=args.lower,
                use_upper=args.upper,
                use_digits=args.digits,
                use_symbols=args.symbols,
                exclude_similar=args.exclude_similar,
                exclude_ambiguous=args.exclude_ambiguous,
                custom_chars=args.custom_chars
            )
            
            print(f"\nContraseña generada: {password}")
            
            # Verificar fortaleza
            strength = self.strength_checker.check_strength(password)
            strength_label = self.strength_checker.get_strength_label(strength['score'])
            print(f"Fortaleza: {strength_label} ({strength['score']}/5)")
            print(f"Entropía: {strength['entropy']} bits")
            print(f"Tiempo estimado de descifrado: {strength['crack_time']}")
            
            if strength['feedback']:
                print("\nRecomendaciones:" + "\n- " + "\n- ".join(strength['feedback']))
            
            # Copiar al portapapeles si se solicita
            if args.copy:
                self.copy_to_clipboard(password)
            
            # Guardar si se solicita
            if args.save:
                service = args.service or input("¿Para qué servicio es esta contraseña? ")
                username = args.username or input("Nombre de usuario (opcional): ")
                self.save_password(password, service, username)
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    
    def handle_phrase(self, args):
        """Maneja el comando de generación de frase de contraseña."""
        try:
            phrase = self.passphrase_gen.generate_passphrase(
                words=args.words,
                separator=args.separator,
                capitalize=args.capitalize,
                add_number=args.number,
                add_symbol=args.symbol,
                lang=args.lang,
                use_online=args.online
            )
            
            print(f"\nFrase de contraseña generada: {phrase}")
            
            # Verificar fortaleza
            strength = self.strength_checker.check_strength(phrase)
            strength_label = self.strength_checker.get_strength_label(strength['score'])
            print(f"Fortaleza: {strength_label} ({strength['score']}/5)")
            
            # Copiar al portapapeles si se solicita
            if args.copy:
                self.copy_to_clipboard(phrase)
            
            # Guardar si se solicita
            if args.save:
                service = args.service or input("¿Para qué servicio es esta contraseña? ")
                username = args.username or input("Nombre de usuario (opcional): ")
                self.save_password(phrase, service, username)
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    
    def handle_check(self, args):
        """Maneja el comando de verificación de fortaleza."""
        try:
            strength = self.strength_checker.check_strength(args.password)
            strength_label = self.strength_checker.get_strength_label(strength['score'])
            
            print(f"\nAnálisis de contraseña:")
            print(f"Longitud: {len(args.password)} caracteres")
            print(f"Fortaleza: {strength_label} ({strength['score']}/5)")
            print(f"Entropía: {strength['entropy']} bits")
            print(f"Tiempo estimado de descifrado: {strength['crack_time']}")
            
            if strength['is_common']:
                print("\n¡ADVERTENCIA! Esta contraseña es muy común y fácil de adivinar.")
            
            if strength['is_compromised']:
                print("\n¡CRÍTICO! Esta contraseña ha sido expuesta en filtraciones de datos.")
                print("Se recomienda cambiarla inmediatamente.")
            
            if strength['feedback']:
                print("\nRecomendaciones:" + "\n- " + "\n- ".join(strength['feedback']))
                
            if strength['suggestions']:
                print("\nSugerencias para mejorar la contraseña:" + "\n- " + "\n- ".join(strength['suggestions']))
                
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
    
    def handle_save(self, args):
        """Maneja el comando de guardado de contraseña."""
        try:
            password = args.password
            if not password:
                import getpass
                password = getpass.getpass("Contraseña: ")
                confirm = getpass.getpass("Confirmar contraseña: ")
                
                if password != confirm:
                    print("Las contraseñas no coinciden.", file=sys.stderr)
                    return
            
            tags = [t.strip() for t in args.tags.split(',')] if args.tags else []
            
            entry = self.storage.add_password(
                password=password,
                service=args.service,
                username=args.username or "",
                url=args.url or "",
                notes=args.notes or "",
                tags=tags
            )
            
            print(f"\nContraseña guardada con éxito (ID: {entry['id']})")
            
        except Exception as e:
            print(f"Error al guardar la contraseña: {e}", file=sys.stderr)
    
    def handle_list(self, args):
        """Maneja el comando de listado de contraseñas."""
        try:
            entries = self.storage.get_passwords(query=args.query, tag=args.tag)
            
            if not entries:
                print("No se encontraron contraseñas.")
                return
            
            print(f"\n{'ID':<4} {'Servicio':<20} {'Usuario':<25} {'Última actualización'}")
            print("-" * 70)
            
            for entry in entries:
                updated_at = entry.get('updated_at', '').split('T')[0]
                print(f"{entry['id']:<4} {entry['service']:<20} {entry.get('username', '')[:22]:<25} {updated_at}")
                
        except Exception as e:
            print(f"Error al listar contraseñas: {e}", file=sys.stderr)
    
    def handle_get(self, args):
        """Maneja el comando de obtención de contraseña."""
        try:
            entries = self.storage.get_passwords()
            entry = next((e for e in entries if e['id'] == args.id), None)
            
            if not entry:
                print(f"No se encontró ninguna contraseña con ID {args.id}", file=sys.stderr)
                return
            
            print(f"\nServicio: {entry['service']}")
            print(f"Usuario: {entry.get('username', '')}")
            print(f"Contraseña: {entry['password']}")
            
            if entry.get('url'):
                print(f"URL: {entry['url']}")
                
            if entry.get('notes'):
                print(f"\nNotas: {entry['notes']}")
                
            if entry.get('tags'):
                print(f"\nEtiquetas: {', '.join(entry['tags'])}")
                
            print(f"\nCreada: {entry.get('created_at', '')}")
            print(f"Actualizada: {entry.get('updated_at', '')}")
            
            if args.copy:
                self.copy_to_clipboard(entry['password'])
                
        except Exception as e:
            print(f"Error al obtener la contraseña: {e}", file=sys.stderr)
    
    def handle_export(self, args):
        """Maneja el comando de exportación a CSV."""
        try:
            if self.storage.export_to_csv(args.output_file):
                print(f"\nContraseñas exportadas a {args.output_file}")
            else:
                print("\nError al exportar las contraseñas.", file=sys.stderr)
                
        except Exception as e:
            print(f"Error al exportar las contraseñas: {e}", file=sys.stderr)
    
    def handle_import(self, args):
        """Maneja el comando de importación desde CSV."""
        try:
            if self.storage.import_from_csv(args.input_file):
                print(f"\nContraseñas importadas desde {args.input_file}")
            else:
                print("\nError al importar las contraseñas.", file=sys.stderr)
                
        except Exception as e:
            print(f"Error al importar las contraseñas: {e}", file=sys.stderr)
    
    def copy_to_clipboard(self, text: str):
        """Copia texto al portapapeles."""
        try:
            pyperclip.copy(text)
            print("¡Copiado al portapapeles!")
        except Exception as e:
            print(f"No se pudo copiar al portapapeles: {e}", file=sys.stderr)
    
    def save_password(self, password: str, service: str, username: str = ""):
        """Guarda una contraseña en el almacenamiento."""
        try:
            entry = self.storage.add_password(
                password=password,
                service=service,
                username=username
            )
            print(f"Contraseña guardada con ID: {entry['id']}")
        except Exception as e:
            print(f"Error al guardar la contraseña: {e}", file=sys.stderr)

def main():
    """Función principal para ejecutar la CLI."""
    cli = PasswordManagerCLI()
    cli.run()

if __name__ == "__main__":
    main()
