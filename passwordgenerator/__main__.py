"""Password Generator - A secure and customizable password generator and manager."""

import sys
import argparse

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Password Generator - A secure and customizable password generator and manager.')
    parser.add_argument(
        '--gui',
        action='store_true',
        help='Launch the graphical user interface (GUI)'
    )
    return parser.parse_known_args()

def main():
    """Main entry point for the application."""
    args, remaining_args = parse_args()
    
    if args.gui:
        # Import GUI only when needed
        from .gui import gui_main
        gui_main()
    else:
        # Default to CLI
        from .cli.main import main as cli_main
        sys.argv = [sys.argv[0]] + remaining_args
        cli_main()

if __name__ == "__main__":
    main()
