"""Main CLI module for the Password Generator."""
import argparse
import sys
from typing import List, Optional, Dict, Any

from ..storage.manager import StorageManager
from ..core.generator import PasswordGenerator
from ..security.strength import PasswordStrength, PasswordStrengthChecker
from ..models.password import PasswordEntry

class PasswordCLI:
    """Command-line interface for the Password Generator."""
    
    def __init__(self):
        """Initialize the CLI with a password generator and storage manager."""
        self.generator = PasswordGenerator()
        self.storage = StorageManager()
        self.strength_checker = PasswordStrengthChecker()
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create the argument parser with all commands and options."""
        parser = argparse.ArgumentParser(
            description='A secure password generator and manager.',
            epilog='Use "%(prog)s <command> -h" for help on specific commands.'
        )
        
        # Main subcommands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Generate command
        gen_parser = subparsers.add_parser('generate', help='Generate a new password')
        gen_parser.add_argument(
            '-l', '--length',
            type=int,
            default=16,
            help='Password length (default: 16)'
        )
        gen_parser.add_argument(
            '--no-upper',
            action='store_false',
            dest='use_upper',
            help='Exclude uppercase letters'
        )
        gen_parser.add_argument(
            '--no-lower',
            action='store_false',
            dest='use_lower',
            help='Exclude lowercase letters'
        )
        gen_parser.add_argument(
            '--no-digits',
            action='store_false',
            dest='use_digits',
            help='Exclude digits'
        )
        gen_parser.add_argument(
            '--no-symbols',
            action='store_false',
            dest='use_symbols',
            help='Exclude symbols'
        )
        gen_parser.add_argument(
            '--brackets',
            action='store_true',
            help='Include bracket characters ([](){})'
        )
        gen_parser.add_argument(
            '--punctuation',
            action='store_true',
            help='Include punctuation characters (!?.,;:)'
        )
        gen_parser.add_argument(
            '--math',
            action='store_true',
            help='Include math symbols (+-*/^=)'
        )
        gen_parser.add_argument(
            '--space',
            action='store_true',
            help='Include space character'
        )
        gen_parser.add_argument(
            '-c', '--copy',
            action='store_true',
            help='Copy password to clipboard'
        )
        gen_parser.add_argument(
            '-s', '--save',
            metavar='SERVICE',
            help='Save password for the specified service'
        )
        gen_parser.add_argument(
            '-u', '--username',
            help='Username for the service (use with --save)'
        )
        
        # Passphrase command
        phrase_parser = subparsers.add_parser('passphrase', help='Generate a passphrase')
        phrase_parser.add_argument(
            '-w', '--words',
            type=int,
            default=4,
            help='Number of words (default: 4)'
        )
        phrase_parser.add_argument(
            '-s', '--separator',
            default='-',
            help='Word separator (default: -)'
        )
        phrase_parser.add_argument(
            '--no-caps',
            action='store_false',
            dest='capitalize',
            help='Do not capitalize words'
        )
        phrase_parser.add_argument(
            '--no-number',
            action='store_false',
            dest='add_number',
            help='Do not add a number'
        )
        phrase_parser.add_argument(
            '--no-symbol',
            action='store_false',
            dest='add_symbol',
            help='Do not add a symbol'
        )
        phrase_parser.add_argument(
            '-l', '--language',
            choices=['en', 'es'],
            default='en',
            help='Word list language (default: en)'
        )
        phrase_parser.add_argument(
            '-c', '--copy',
            action='store_true',
            help='Copy passphrase to clipboard'
        )
        phrase_parser.add_argument(
            '--save',
            metavar='SERVICE',
            help='Save passphrase for the specified service'
        )
        phrase_parser.add_argument(
            '-u', '--username',
            help='Username for the service (use with --save)'
        )
        
        # Save command
        save_parser = subparsers.add_parser('save', help='Save a password')
        save_parser.add_argument(
            'service',
            help='Service or website name'
        )
        save_parser.add_argument(
            'password',
            nargs='?',
            help='Password to save (prompt if not provided)'
        )
        save_parser.add_argument(
            '-u', '--username',
            help='Username or email'
        )
        save_parser.add_argument(
            '-n', '--notes',
            help='Additional notes'
        )
        save_parser.add_argument(
            '-t', '--tags',
            help='Comma-separated list of tags'
        )
        save_parser.add_argument(
            '-e', '--expires',
            type=int,
            help='Days until password expires'
        )
        
        # Get command
        get_parser = subparsers.add_parser('get', help='Retrieve a saved password')
        get_parser.add_argument(
            'service',
            nargs='?',
            help='Service or website name (show all if not provided)'
        )
        get_parser.add_argument(
            '-c', '--copy',
            action='store_true',
            help='Copy password to clipboard'
        )
        get_parser.add_argument(
            '-s', '--show',
            action='store_true',
            help='Show password in plain text'
        )
        
        # Search command
        search_parser = subparsers.add_parser('search', help='Search saved passwords')
        search_parser.add_argument(
            'query',
            nargs='?',
            help='Search term (leave empty to list all)'
        )
        search_parser.add_argument(
            '-f', '--field',
            choices=['service', 'username', 'notes', 'all'],
            default='service',
            help='Field to search (default: service)'
        )
        search_parser.add_argument(
            '-t', '--tags',
            help='Filter by tags (comma-separated)'
        )
        
        # Delete command
        del_parser = subparsers.add_parser('delete', help='Delete a saved password')
        del_parser.add_argument(
            'service',
            help='Service or website name'
        )
        del_parser.add_argument(
            '-f', '--force',
            action='store_true',
            help='Skip confirmation'
        )
        
        # Check command
        check_parser = subparsers.add_parser('check', help='Check password strength')
        check_parser.add_argument(
            'password',
            nargs='?',
            help='Password to check (prompt if not provided)'
        )
        
        # Export command
        export_parser = subparsers.add_parser('export', help='Export passwords')
        export_parser.add_argument(
            'file',
            nargs='?',
            default='passwords_export.json',
            help='Output file (default: passwords_export.json)'
        )
        export_parser.add_argument(
            '-f', '--format',
            choices=['json', 'csv'],
            default='json',
            help='Export format (default: json)'
        )
        export_parser.add_argument(
            '-p', '--password',
            help='Encrypt the export with a password'
        )
        
        # Import command
        import_parser = subparsers.add_parser('import', help='Import passwords')
        import_parser.add_argument(
            'file',
            help='Input file'
        )
        import_parser.add_argument(
            '-f', '--format',
            choices=['auto', 'json', 'csv'],
            default='auto',
            help='Input format (default: auto-detect)'
        )
        import_parser.add_argument(
            '-p', '--password',
            help='Password for encrypted imports'
        )
        
        # Version command
        subparsers.add_parser('version', help='Show version information')
        
        return parser
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """Run the CLI with the given arguments."""
        # Parse arguments
        parsed_args = self.parser.parse_args(args)
        
        # If no command is provided, show help
        if not parsed_args.command:
            self.parser.print_help()
            return 0
        
        # Dispatch to the appropriate handler
        try:
            handler = getattr(self, f'handle_{parsed_args.command}')
            return handler(parsed_args)
        except AttributeError:
            print(f"Unknown command: {parsed_args.command}", file=sys.stderr)
            self.parser.print_help()
            return 1
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return 1
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            if hasattr(e, '__traceback__'):
                import traceback
                traceback.print_exc()
            return 1
    
    def handle_generate(self, args: argparse.Namespace) -> int:
        """Handle the generate command."""
        # Generate the password
        try:
            password = self.generator.generate_password(
                length=args.length,
                use_upper=args.use_upper,
                use_lower=args.use_lower,
                use_digits=args.use_digits,
                use_symbols=args.use_symbols,
                use_brackets=args.brackets,
                use_punctuation=args.punctuation,
                use_math=args.math,
                use_space=args.space
            )
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        
        # Save if requested
        if args.save:
            self.storage.add_password(
                service=args.save,
                username=args.username or '',
                password=password,
                expires_in_days=90  # Default to 90 days
            )
            print(f"Password saved for {args.save}")
        
        # Copy to clipboard if requested
        if args.copy:
            try:
                import pyperclip
                pyperclip.copy(password)
                print("Password copied to clipboard!")
            except Exception as e:
                print(f"Could not copy to clipboard: {e}", file=sys.stderr)
        
        # Show the password
        print(f"Generated password: {password}")
        
        # Show strength
        strength, details = self.strength_checker.check_strength(password)
        print(f"Strength: {strength.name.replace('_', ' ').title()}")
        
        return 0
    
    def handle_passphrase(self, args: argparse.Namespace) -> int:
        """Handle the passphrase command."""
        # Generate the passphrase
        passphrase = self.generator.generate_passphrase(
            words=args.words,
            separator=args.separator,
            capitalize=args.capitalize,
            add_number=args.add_number,
            add_symbol=args.add_symbol,
            language=args.language
        )
        
        # Save if requested
        if args.save:
            self.storage.add_password(
                service=args.save,
                username=args.username or '',
                password=passphrase,
                expires_in_days=365  # Longer expiry for passphrases
            )
            print(f"Passphrase saved for {args.save}")
        
        # Copy to clipboard if requested
        if args.copy:
            try:
                import pyperclip
                pyperclip.copy(passphrase)
                print("Passphrase copied to clipboard!")
            except Exception as e:
                print(f"Could not copy to clipboard: {e}", file=sys.stderr)
        
        # Show the passphrase
        print(f"Generated passphrase: {passphrase}")
        
        # Show strength
        strength, details = self.strength_checker.check_strength(passphrase)
        print(f"Strength: {strength.name.replace('_', ' ').title()}")
        
        return 0
    
    def handle_save(self, args: argparse.Namespace) -> int:
        """Handle the save command."""
        # Get the password if not provided
        password = args.password
        if not password:
            import getpass
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Error: Password cannot be empty", file=sys.stderr)
                return 1
        
        # Parse tags
        tags = [t.strip() for t in args.tags.split(',')] if args.tags else []
        
        # Save the password
        success = self.storage.add_password(
            service=args.service,
            username=args.username or '',
            password=password,
            notes=args.notes or '',
            tags=tags,
            expires_in_days=args.expires
        )
        
        if success:
            print(f"Password saved for {args.service}")
            return 0
        else:
            print(f"Failed to save password for {args.service}", file=sys.stderr)
            return 1
    
    def handle_get(self, args: argparse.Namespace) -> int:
        """Handle the get command."""
        if not args.service:
            # List all services
            entries = self.storage.search_passwords("")
            if not entries:
                print("No saved passwords found.")
                return 0
                
            print("\nSaved passwords:")
            print("-" * 80)
            for entry in sorted(entries, key=lambda e: e.service.lower()):
                print(f"{entry.service:<30} {entry.username or ''}")
            print()
            return 0
        
        # Get the specific password
        entry = self.storage.get_password(args.service)
        if not entry:
            print(f"No password found for {args.service}", file=sys.stderr)
            return 1
        
        # Show the entry
        print(f"\nService:  {entry.service}")
        if entry.username:
            print(f"Username: {entry.username}")
        
        # Handle password display
        if args.show:
            print(f"Password: {entry.password}")
        elif args.copy:
            try:
                import pyperclip
                pyperclip.copy(entry.password)
                print("Password copied to clipboard!")
            except Exception as e:
                print(f"Could not copy to clipboard: {e}")
                print(f"Password: {'*' * 12}")
        else:
            print(f"Password: {'*' * 12}")
        
        # Show metadata
        if entry.notes:
            print(f"\nNotes: {entry.notes}")
        if entry.tags:
            print(f"Tags: {', '.join(entry.tags)}")
        
        # Show expiry info
        if entry.expires_in_days:
            days_left = entry.days_until_expiry()
            if days_left is not None:
                if days_left <= 0:
                    print("\n\033[91mWARNING: This password has expired!\033[0m")
                else:
                    print(f"\nExpires in: {days_left} days")
        
        print()
        return 0
    
    def handle_search(self, args: argparse.Namespace) -> int:
        """Handle the search command."""
        # Parse tags
        tags = [t.strip() for t in args.tags.split(',')] if args.tags else None
        
        # Search for passwords
        results = self.storage.search_passwords(
            query=args.query or "",
            search_fields=[args.field] if args.field != 'all' else None,
            tags=tags
        )
        
        if not results:
            print("No matching passwords found.")
            return 0
        
        # Display results
        print(f"\nFound {len(results)} matching passwords:")
        print("-" * 80)
        for entry in sorted(results, key=lambda e: e.service.lower()):
            print(f"{entry.service:<30} {entry.username or ''}")
        print()
        return 0
    
    def handle_delete(self, args: argparse.Namespace) -> int:
        """Handle the delete command."""
        # Confirm deletion
        if not args.force:
            confirm = input(f"Are you sure you want to delete the password for {args.service}? [y/N] ")
            if confirm.lower() != 'y':
                print("Deletion cancelled.")
                return 0
        
        # Delete the password
        if self.storage.delete_password(args.service):
            print(f"Password for {args.service} has been deleted.")
            return 0
        else:
            print(f"Failed to delete password for {args.service}", file=sys.stderr)
            return 1
    
    def handle_check(self, args: argparse.Namespace) -> int:
        """Handle the check command."""
        # Get the password
        password = args.password
        if not password:
            import getpass
            password = getpass.getpass("Enter password to check: ")
            if not password:
                print("Error: Password cannot be empty", file=sys.stderr)
                return 1
        
        # Check the strength
        strength, details = self.strength_checker.check_strength(password)
        
        # Display results
        print(f"\nPassword strength: \033[1m{strength.name.replace('_', ' ').title()}\033[0m")
        print(f"Length: {len(password)} characters")
        print(f"Entropy: {details['entropy']:.1f} bits")
        
        # Character types
        print("\nCharacter types:")
        print(f"  • Uppercase letters: {'✓' if details['has_upper'] else '✗'}")
        print(f"  • Lowercase letters: {'✓' if details['has_lower'] else '✗'}")
        print(f"  • Digits:            {'✓' if details['has_digit'] else '✗'}")
        print(f"  • Symbols:           {'✓' if details['has_symbol'] else '✗'}")
        
        # Feedback
        if details['feedback']:
            print("\nFeedback:")
            for msg in details['feedback']:
                print(f"  • {msg}")
        
        # Suggestions
        if details['suggestions']:
            print("\nSuggestions to improve:")
            for suggestion in details['suggestions']:
                print(f"  • {suggestion}")
        
        # Check for breaches
        from ..security.crypto import check_password_breach
        breach_count = check_password_breach(password)
        if breach_count > 0:
            print(f"\n\033[91mWARNING: This password has been found in {breach_count} data breaches!\033[0m")
            print("Do not use this password. It is not secure!")
        
        print()
        return 0
    
    def handle_export(self, args: argparse.Namespace) -> int:
        """Handle the export command."""
        try:
            success = self.storage.export_passwords(
                output_file=args.file,
                format_type=args.format,
                master_password=args.password
            )
            
            if success:
                print(f"Passwords exported to {args.file}")
                if args.password:
                    print("The export is encrypted with the provided password.")
                return 0
            else:
                print("Failed to export passwords", file=sys.stderr)
                return 1
        except Exception as e:
            print(f"Error exporting passwords: {e}", file=sys.stderr)
            return 1
    
    def handle_import(self, args: argparse.Namespace) -> int:
        """Handle the import command."""
        try:
            format_type = None if args.format == 'auto' else args.format
            
            success = self.storage.import_passwords(
                input_file=args.file,
                format_type=format_type,
                master_password=args.password
            )
            
            if success:
                print("Passwords imported successfully!")
                return 0
            else:
                print("Failed to import passwords", file=sys.stderr)
                return 1
        except Exception as e:
            print(f"Error importing passwords: {e}", file=sys.stderr)
            return 1
    
    def handle_version(self, args: argparse.Namespace) -> int:
        """Handle the version command."""
        from .. import __version__
        print(f"Password Generator v{__version__}")
        return 0

def main():
    """Entry point for the CLI."""
    cli = PasswordCLI()
    return cli.run()

if __name__ == '__main__':
    sys.exit(main())
