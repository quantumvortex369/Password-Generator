"""Password storage and management."""
import json
import os
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import hashlib
from dataclasses import asdict

from ..models.password import PasswordEntry
from ..security.crypto import encrypt_data, decrypt_data
from ..config import config

class StorageManager:
    """Manages password storage and retrieval."""
    
    def __init__(self, data_dir: Optional[str] = None):
        """Initialize the storage manager."""
        self.data_dir = Path(data_dir) if data_dir else Path(config.get('storage.data_dir'))
        self.passwords_file = self.data_dir / config.get('storage.passwords_file', 'passwords.json')
        self.history_file = self.data_dir / config.get('storage.history_file', 'history.json')
        self.backup_dir = self.data_dir / config.get('storage.backup_dir', 'backups')
        self.max_backups = config.get('storage.max_backups', 5)
        
        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        # In-memory cache
        self._passwords: Dict[str, PasswordEntry] = {}
        self._history: Dict[str, List[Dict]] = {}
        
        # Load data
        self._load_data()
    
    def _load_data(self) -> None:
        """Load passwords and history from disk."""
        # Load passwords
        if self.passwords_file.exists():
            try:
                with open(self.passwords_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._passwords = {
                        k: PasswordEntry(**v) for k, v in data.items()
                    }
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading passwords: {e}")
                self._passwords = {}
        
        # Load history
        if self.history_file.exists():
            try:
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    self._history = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"Error loading history: {e}")
                self._history = {}
    
    def _save_data(self) -> bool:
        """Save passwords and history to disk."""
        success = True
        
        # Save passwords
        try:
            with open(self.passwords_file, 'w', encoding='utf-8') as f:
                json.dump(
                    {k: asdict(v) for k, v in self._passwords.items()},
                    f,
                    indent=2,
                    ensure_ascii=False
                )
        except IOError as e:
            print(f"Error saving passwords: {e}")
            success = False
        
        # Save history
        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(self._history, f, indent=2, ensure_ascii=False)
        except IOError as e:
            print(f"Error saving history: {e}")
            success = False
        
        return success
    
    def _create_backup(self) -> None:
        """Create a backup of the passwords file."""
        if not self.passwords_file.exists():
            return
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = self.backup_dir / f"passwords_{timestamp}.json"
        
        try:
            # Copy the file
            shutil.copy2(self.passwords_file, backup_file)
            
            # Clean up old backups
            self._cleanup_old_backups()
        except IOError as e:
            print(f"Error creating backup: {e}")
    
    def _cleanup_old_backups(self) -> None:
        """Remove old backups if we have too many."""
        try:
            # Get all backup files, sorted by modification time (oldest first)
            backups = sorted(
                self.backup_dir.glob('passwords_*.json'),
                key=os.path.getmtime
            )
            
            # Remove the oldest backups if we have too many
            while len(backups) > self.max_backups:
                try:
                    os.remove(backups[0])
                    backups = backups[1:]
                except (IOError, IndexError):
                    break
        except Exception as e:
            print(f"Error cleaning up old backups: {e}")
    
    def add_password(
        self,
        service: str,
        username: str,
        password: str,
        notes: str = '',
        tags: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None
    ) -> bool:
        """
        Add or update a password.
        
        Args:
            service: Service or website name
            username: Username or email
            password: The password to store
            notes: Optional notes
            tags: Optional tags for organization
            expires_in_days: Days until password expires
            
        Returns:
            True if successful, False otherwise
        """
        if not service or not password:
            return False
        
        # Normalize the service name
        service_lower = service.lower().strip()
        tags = tags or []
        
        # Create or update the entry
        if service_lower in self._passwords:
            # Update existing entry
            entry = self._passwords[service_lower]
            self._add_to_history(service_lower, entry.password, entry.updated_at)
            
            entry.username = username or entry.username
            entry.password = password
            entry.notes = notes or entry.notes
            entry.tags = list(set(entry.tags + tags))  # Merge and dedupe tags
            entry.updated_at = datetime.now().isoformat()
            
            if expires_in_days is not None:
                entry.expires_in_days = expires_in_days
        else:
            # Create new entry
            self._passwords[service_lower] = PasswordEntry(
                service=service,
                username=username,
                password=password,
                notes=notes,
                tags=tags,
                expires_in_days=expires_in_days or 90,  # Default 90 days
                created_at=datetime.now().isoformat(),
                updated_at=datetime.now().isoformat()
            )
        
        # Save to disk
        return self._save_data()
    
    def _add_to_history(self, service: str, password: str, timestamp: str) -> None:
        """Add a password to the history."""
        if service not in self._history:
            self._history[service] = []
        
        # Add to history
        self._history[service].append({
            'password': password,
            'updated_at': timestamp,
            'hash': hashlib.sha256(password.encode()).hexdigest()
        })
        
        # Keep only the last 5 versions
        self._history[service] = self._history[service][-5:]
    
    def get_password(self, service: str) -> Optional[PasswordEntry]:
        """Get a password entry by service name."""
        return self._passwords.get(service.lower())
    
    def delete_password(self, service: str) -> bool:
        """Delete a password entry."""
        service_lower = service.lower()
        if service_lower in self._passwords:
            del self._passwords[service_lower]
            return self._save_data()
        return False
    
    def search_passwords(
        self,
        query: str,
        search_fields: List[str] = None,
        tags: List[str] = None
    ) -> List[PasswordEntry]:
        """
        Search for passwords.
        
        Args:
            query: Search query
            search_fields: Fields to search (service, username, notes, all)
            tags: Filter by tags
            
        Returns:
            List of matching password entries
        """
        if not query and not tags:
            return []
        
        search_fields = search_fields or ['service', 'username']
        query = query.lower()
        
        results = []
        
        for entry in self._passwords.values():
            # Skip if tags don't match
            if tags and not any(tag.lower() in [t.lower() for t in entry.tags] for tag in tags):
                continue
            
            # Check if any field matches the query
            if not query:
                results.append(entry)
                continue
                
            for field in search_fields:
                field = field.lower()
                value = ''
                
                if field == 'service' and entry.service:
                    value = entry.service.lower()
                elif field == 'username' and entry.username:
                    value = entry.username.lower()
                elif field == 'notes' and entry.notes:
                    value = entry.notes.lower()
                elif field == 'all':
                    value = f"{entry.service or ''} {entry.username or ''} {entry.notes or ''}".lower()
                
                if query in value:
                    results.append(entry)
                    break
        
        return results
    
    def get_expiring_passwords(self, days_threshold: int = 14) -> List[Dict[str, Any]]:
        """
        Get passwords that will expire soon.
        
        Args:
            days_threshold: Number of days to consider as "soon"
            
        Returns:
            List of dictionaries with password details
        """
        expiring = []
        now = datetime.now()
        
        for service, entry in self._passwords.items():
            if entry.expires_in_days is None:
                continue
                
            created_at = datetime.fromisoformat(entry.created_at)
            expiry_date = created_at + timedelta(days=entry.expires_in_days)
            days_until_expiry = (expiry_date - now).days
            
            if 0 <= days_until_expiry <= days_threshold:
                expiring.append({
                    'service': service,
                    'username': entry.username,
                    'expiry_date': expiry_date.isoformat(),
                    'days_until_expiry': days_until_expiry,
                    'created_at': entry.created_at,
                    'strength': entry.strength
                })
        
        # Sort by days until expiry (ascending)
        return sorted(expiring, key=lambda x: x['days_until_expiry'])
    
    def export_passwords(
        self,
        output_file: str,
        format_type: str = 'json',
        master_password: Optional[str] = None
    ) -> bool:
        """
        Export passwords to a file.
        
        Args:
            output_file: Output file path
            format_type: Export format (json, csv)
            master_password: Optional password for encryption
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Prepare data
            data = {k: asdict(v) for k, v in self._passwords.items()}
            
            if format_type.lower() == 'json':
                output = json.dumps(data, indent=2, ensure_ascii=False)
            elif format_type.lower() == 'csv':
                import csv
                import io
                
                # Prepare rows
                rows = []
                for service, entry in data.items():
                    row = {
                        'service': service,
                        'username': entry.get('username', ''),
                        'password': entry.get('password', ''),
                        'notes': entry.get('notes', ''),
                        'tags': ', '.join(entry.get('tags', [])),
                        'created_at': entry.get('created_at', ''),
                        'updated_at': entry.get('updated_at', ''),
                        'expires_in_days': entry.get('expires_in_days', '')
                    }
                    rows.append(row)
                
                # Write to buffer
                output_buffer = io.StringIO()
                if rows:
                    writer = csv.DictWriter(output_buffer, fieldnames=rows[0].keys())
                    writer.writeheader()
                    writer.writerows(rows)
                output = output_buffer.getvalue()
            else:
                print(f"Unsupported export format: {format_type}")
                return False
            
            # Encrypt if master password is provided
            if master_password:
                output = encrypt_data(output, master_password)
            
            # Write to file
            with open(output_file, 'wb' if master_password else 'w', encoding=None if master_password else 'utf-8') as f:
                f.write(output if isinstance(output, bytes) else output.encode('utf-8'))
            
            return True
            
        except Exception as e:
            print(f"Error exporting passwords: {e}")
            return False
    
    def import_passwords(
        self,
        input_file: str,
        format_type: Optional[str] = None,
        master_password: Optional[str] = None
    ) -> bool:
        """
        Import passwords from a file.
        
        Args:
            input_file: Input file path
            format_type: Import format (json, csv, auto-detect if None)
            master_password: Password if the file is encrypted
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read the file
            with open(input_file, 'rb' if master_password else 'r', encoding=None if master_password else 'utf-8') as f:
                content = f.read()
            
            # Decrypt if needed
            if master_password:
                try:
                    content = decrypt_data(content, master_password).decode('utf-8')
                except Exception as e:
                    print(f"Error decrypting file: {e}")
                    return False
            
            # Auto-detect format if not specified
            if not format_type:
                if input_file.lower().endswith('.json'):
                    format_type = 'json'
                elif input_file.lower().endswith('.csv'):
                    format_type = 'csv'
                else:
                    print("Could not determine file format. Please specify with --format.")
                    return False
            
            # Parse the content
            if format_type.lower() == 'json':
                data = json.loads(content)
                
                # Import each entry
                for service, entry_data in data.items():
                    self.add_password(
                        service=entry_data.get('service', service),
                        username=entry_data.get('username', ''),
                        password=entry_data.get('password', ''),
                        notes=entry_data.get('notes', ''),
                        tags=entry_data.get('tags', []),
                        expires_in_days=entry_data.get('expires_in_days')
                    )
                
                return True
                
            elif format_type.lower() == 'csv':
                import csv
                import io
                
                # Parse CSV
                csv_reader = csv.DictReader(io.StringIO(content))
                
                for row in csv_reader:
                    # Handle different CSV formats
                    service = row.get('service') or row.get('Service') or ''
                    username = row.get('username') or row.get('Username') or ''
                    password = row.get('password') or row.get('Password') or ''
                    notes = row.get('notes') or row.get('Notes') or ''
                    
                    # Parse tags if present
                    tags = []
                    if 'tags' in row:
                        tags = [t.strip() for t in row['tags'].split(',') if t.strip()]
                    elif 'Tags' in row:
                        tags = [t.strip() for t in row['Tags'].split(',') if t.strip()]
                    
                    if service and password:
                        self.add_password(
                            service=service,
                            username=username,
                            password=password,
                            notes=notes,
                            tags=tags
                        )
                
                return True
            else:
                print(f"Unsupported import format: {format_type}")
                return False
                
        except Exception as e:
            print(f"Error importing passwords: {e}")
            return False
