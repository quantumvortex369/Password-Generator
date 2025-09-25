"""Password strength checking and validation."""
import re
import math
from typing import Dict, Any, Tuple, List
from enum import Enum

class PasswordStrength(Enum):
    """Password strength levels."""
    VERY_WEAK = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3
    VERY_STRONG = 4
    EXCELLENT = 5

class PasswordStrengthChecker:
    """Check password strength and provide feedback."""
    
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', '1234', 'qwerty', '12345',
        'dragon', 'baseball', 'football', 'letmein', 'monkey',
        'mustang', 'michael', 'shadow', 'master', 'jennifer',
        '111111', '2000', 'jordan', 'superman', 'harley', '1234567',
        'iloveyou', 'sunshine', 'princess', 'admin', 'welcome', '123123'
    }
    
    def __init__(self, min_length: int = 8, require_upper: bool = True,
                 require_digit: bool = True, require_symbol: bool = True):
        """Initialize with password policy."""
        self.min_length = min_length
        self.require_upper = require_upper
        self.require_digit = require_digit
        self.require_symbol = require_symbol
    
    def check_strength(self, password: str) -> Tuple[PasswordStrength, Dict[str, Any]]:
        """
        Check password strength with detailed feedback.

        Returns:
            Tuple[PasswordStrength, dict]: A tuple containing the password strength and details
        """
        if not password:
            return PasswordStrength.VERY_WEAK, self._get_details(0, {
                'length': 0,
                'has_upper': False,
                'has_lower': False,
                'has_digit': False,
                'has_symbol': False,
                'is_common': False,
                'entropy': 0,
                'feedback': ['Password cannot be empty']
            })
        
        # Calculate password properties
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        length = len(password)
        is_common = password.lower() in self.COMMON_PASSWORDS
        entropy = self._calculate_entropy(password)
        
        # Calculate score (0-100)
        score = 0
        feedback = []
        
        # Length score (max 40 points)
        if length < self.min_length:
            feedback.append(f'Password too short (min {self.min_length} characters)')
        else:
            score += min(40, length * 2)  # 2 points per character up to 40
        
        # Character diversity (max 30 points)
        char_types = sum([has_upper, has_lower, has_digit, has_symbol])
        score += (char_types - 1) * 10  # 0-30 points
        
        # Entropy score (max 30 points)
        if entropy < 28:  # Very weak
            feedback.append('Password is too predictable')
        elif entropy < 36:  # Weak
            score += 10
            feedback.append('Password could be stronger')
        elif entropy < 60:  # Moderate
            score += 20
        else:  # Strong
            score += 30
        
        # Check requirements
        if self.require_upper and not has_upper:
            feedback.append('Add uppercase letters')
        if self.require_digit and not has_digit:
            feedback.append('Add numbers')
        if self.require_symbol and not has_symbol:
            feedback.append('Add symbols')
        
        # Check for common patterns
        if is_common:
            score = max(0, score - 30)  # Heavy penalty for common passwords
            feedback.append('This is a very common password')
        
        # Check for sequential or repeated characters
        if self._has_sequential_chars(password) or self._has_repeated_chars(password):
            score = max(0, score - 15)
            feedback.append('Avoid sequential or repeated characters')
        
        # Cap the score
        score = min(100, max(0, score))
        
        # Convert to PasswordStrength enum
        if score < 30:
            strength = PasswordStrength.VERY_WEAK
        elif score < 50:
            strength = PasswordStrength.WEAK
        elif score < 70:
            strength = PasswordStrength.MODERATE
        elif score < 85:
            strength = PasswordStrength.STRONG
        elif score < 95:
            strength = PasswordStrength.VERY_STRONG
        else:
            strength = PasswordStrength.EXCELLENT
        
        # If no specific feedback, add a positive message
        if not feedback and score > 70:
            feedback.append('Strong password!')
        
        details = self._get_details(score, {
            'length': length,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_symbol': has_symbol,
            'is_common': is_common,
            'entropy': entropy,
            'feedback': feedback
        })
        
        return strength, details
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate the entropy of a password in bits."""
        if not password:
            return 0.0
        
        # Calculate character pool size
        pool_size = 0
        if any(c.islower() for c in password):
            pool_size += 26
        if any(c.isupper() for c in password):
            pool_size += 26
        if any(c.isdigit() for c in password):
            pool_size += 10
        if any(not c.isalnum() for c in password):
            pool_size += 32  # Common symbols
        
        # Calculate entropy
        entropy = len(password) * (math.log(pool_size) / math.log(2)) if pool_size > 0 else 0
        return entropy
    
    def _has_sequential_chars(self, password: str, min_seq: int = 3) -> bool:
        """Check for sequential characters (e.g., 'abc', '123')."""
        if len(password) < min_seq:
            return False
            
        for i in range(len(password) - min_seq + 1):
            # Check forward sequence
            seq_asc = True
            seq_desc = True
            for j in range(min_seq - 1):
                if ord(password[i + j + 1]) != ord(password[i + j]) + 1:
                    seq_asc = False
                if ord(password[i + j + 1]) != ord(password[i + j]) - 1:
                    seq_desc = False
            if seq_asc or seq_desc:
                return True
        return False
    
    def _has_repeated_chars(self, password: str, max_repeat: int = 2) -> bool:
        ""Check for too many repeated characters."""
        if not password:
            return False
            
        current_char = password[0]
        count = 1
        
        for char in password[1:]:
            if char == current_char:
                count += 1
                if count > max_repeat:
                    return True
            else:
                current_char = char
                count = 1
        return False
    
    def _get_details(self, score: int, details: Dict[str, Any]) -> Dict[str, Any]:
        ""Format the details dictionary with additional information."""
        return {
            'score': score,
            'length': details['length'],
            'has_upper': details.get('has_upper', False),
            'has_lower': details.get('has_lower', False),
            'has_digit': details.get('has_digit', False),
            'has_symbol': details.get('has_symbol', False),
            'is_common': details.get('is_common', False),
            'entropy': details.get('entropy', 0),
            'feedback': details.get('feedback', []),
            'suggestions': self._get_suggestions(details)
        }
    
    def _get_suggestions(self, details: Dict[str, Any]) -> List[str]:
        ""Generate suggestions for improving password strength."""
        suggestions = []
        
        if details['length'] < self.min_length:
            suggestions.append(f'Use at least {self.min_length} characters')
        
        if self.require_upper and not details['has_upper']:
            suggestions.append('Add uppercase letters (A-Z)')
        
        if self.require_digit and not details['has_digit']:
            suggestions.append('Add numbers (0-9)')
        
        if self.require_symbol and not details['has_symbol']:
            suggestions.append('Add symbols (!@#$%^&*, etc.)')
        
        if details['is_common']:
            suggestions.append('Avoid common words and patterns')
        
        if details['entropy'] < 36:
            suggestions.append('Use a mix of different character types')
        
        return suggestions

def validate_password_policy(
    password: str,
    min_length: int = 8,
    require_upper: bool = True,
    require_digit: bool = True,
    require_symbol: bool = True
) -> Tuple[bool, List[str]]:
    """Validate a password against a policy.
    
    Args:
        password: The password to validate
        min_length: Minimum password length
        require_upper: Require at least one uppercase letter
        require_digit: Require at least one digit
        require_symbol: Require at least one symbol
        
    Returns:
        Tuple[bool, List[str]]: A tuple of (is_valid, error_messages)
    """
    errors = []
    
    if len(password) < min_length:
        errors.append(f'Password must be at least {min_length} characters long')
    
    if require_upper and not any(c.isupper() for c in password):
        errors.append('Password must contain at least one uppercase letter')
    
    if require_digit and not any(c.isdigit() for c in password):
        errors.append('Password must contain at least one digit')
    
    if require_symbol and not any(not c.isalnum() for c in password):
        errors.append('Password must contain at least one symbol')
    
    return len(errors) == 0, errors
