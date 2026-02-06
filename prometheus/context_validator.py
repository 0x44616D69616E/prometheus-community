"""
PROMETHEUS - CONTEXT VALIDATION SYSTEM

Validates that detected patterns appear in proper context to reduce false positives.

Supports configurable strictness levels:
- STRICT: Requires strong contextual evidence
- MODERATE: Balanced approach
- LENIENT: Minimal validation

Copyright (c) 2026 Damian Donahue
"""

import re
from typing import Optional, Tuple
from prometheus.config import PrometheusConfig, ValidationStrictness


class ContextValidator:
    """
    Validates behavioral patterns based on surrounding context.
    
    Prevents false positives by ensuring patterns appear in realistic contexts.
    For example, ".exe" extension should only be flagged if it appears in an
    actual file path, not just random bytes that happen to be 0x2E 0x65 0x78 0x65.
    """
    
    def __init__(self, config: PrometheusConfig):
        """
        Initialize context validator.
        
        Args:
            config: Prometheus configuration with validation strictness
        """
        self.config = config
        self.rules = config.get_validation_rules()
        
        # Common path indicators
        self.path_separators = ['\\', '/', '\\\\']
        self.common_windows_paths = [
            'C:', 'D:', 'E:',
            'Windows', 'System32', 'Program Files', 'Users', 'Temp',
            'AppData', 'Local', 'Roaming'
        ]
        self.common_linux_paths = [
            '/bin/', '/usr/', '/etc/', '/var/', '/home/', '/tmp/',
            '/lib/', '/opt/', '/proc/', '/sys/'
        ]
        
        # Registry roots
        self.registry_roots = [
            'HKEY_LOCAL_MACHINE', 'HKLM',
            'HKEY_CURRENT_USER', 'HKCU',
            'HKEY_CLASSES_ROOT', 'HKCR',
            'HKEY_USERS', 'HKU',
            'HKEY_CURRENT_CONFIG', 'HKCC'
        ]
        
        # URL schemes
        self.url_schemes = ['http://', 'https://', 'ftp://', 'ftps://']
    
    def validate_file_extension(self, string: str, extension: str) -> Tuple[bool, str]:
        """
        Validate that a file extension appears in proper context.
        
        Args:
            string: The string containing the extension
            extension: The extension to validate (e.g., ".exe", ".cerber")
            
        Returns:
            Tuple of (is_valid, extracted_path_or_reason)
        """
        # Extension must actually be in the string
        if extension not in string:
            return False, "Extension not found in string"
        
        # Get strictness level
        strictness = self.config.validation_strictness
        
        # Extract potential file path around extension
        ext_index = string.find(extension)
        
        # Look backwards for start of path
        start = max(0, ext_index - 200)
        path_segment = string[start:ext_index + len(extension)]
        
        # Check for path separators
        has_separator = any(sep in path_segment for sep in self.path_separators)
        
        # Check for common path components
        has_common_path = (
            any(p in path_segment for p in self.common_windows_paths) or
            any(p in path_segment for p in self.common_linux_paths)
        )
        
        # Check if extension is at end or followed by space/null
        ext_end = ext_index + len(extension)
        proper_ending = (
            ext_end >= len(string) or
            string[ext_end] in [' ', '\x00', '\n', '\r', '"', "'"]
        )
        
        # Apply validation rules based on strictness
        if strictness == ValidationStrictness.STRICT:
            if not has_separator:
                return False, "No path separator found"
            if not has_common_path:
                return False, "No recognizable path structure"
            if not proper_ending:
                return False, "Extension not properly terminated"
            # Extract clean path
            return True, self._extract_clean_path(path_segment, extension)
            
        elif strictness == ValidationStrictness.MODERATE:
            # Needs separator OR file-like structure
            if not has_separator and len(path_segment.split()[-1]) < 4:
                return False, "Doesn't look like a file path"
            if not proper_ending:
                return False, "Extension not properly terminated"
            return True, self._extract_clean_path(path_segment, extension)
            
        else:  # LENIENT
            # Just needs to be somewhat file-like
            if len(extension) < 2:
                return False, "Extension too short"
            if not proper_ending and ext_end < len(string) - 1:
                return False, "Extension appears in middle of data"
            return True, path_segment.strip()
    
    def validate_url(self, string: str, url: str) -> Tuple[bool, str]:
        """
        Validate that a URL appears in proper context.
        
        Args:
            string: The string containing the URL
            url: The URL to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        # Basic URL format check
        url_pattern = re.compile(
            r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b'
        )
        
        if self.rules['require_url_scheme']:
            # Must have proper scheme
            if not any(url.startswith(scheme) for scheme in self.url_schemes):
                return False, "Missing or invalid URL scheme"
        
        # Check format
        if not url_pattern.search(url):
            return False, "Invalid URL format"
        
        # Check for common patterns in URLs (not just random bytes)
        if '.' not in url or len(url) < 10:
            return False, "URL too short or malformed"
        
        return True, url
    
    def validate_ip_address(self, string: str, ip: str) -> Tuple[bool, str]:
        """
        Validate that an IP address appears in proper context.
        
        Args:
            string: The string containing the IP
            ip: The IP address to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if self.rules['require_valid_ip_format']:
            # Strict IPv4 format check
            ipv4_pattern = re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            )
            if not ipv4_pattern.match(ip.strip()):
                return False, "Invalid IPv4 format"
            
            # Check for reserved/invalid IPs
            parts = [int(p) for p in ip.split('.')]
            if parts[0] == 0 or parts[0] >= 240:  # Reserved
                return False, "Reserved or invalid IP range"
        
        # Moderate/lenient: just check basic format
        if ip.count('.') != 3:
            return False, "Not a valid IP address"
        
        return True, ip
    
    def validate_registry_key(self, string: str, key: str) -> Tuple[bool, str]:
        """
        Validate that a registry key appears in proper context.
        
        Args:
            string: The string containing the registry key
            key: The registry key to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if self.rules['require_registry_root']:
            # Must start with valid registry root
            has_root = any(key.startswith(root) for root in self.registry_roots)
            if not has_root:
                return False, "Missing valid registry root"
        
        # Check for backslashes (Windows registry path)
        if '\\' not in key:
            return False, "No path separators in registry key"
        
        # Check minimum length
        if len(key) < 10:
            return False, "Registry key too short"
        
        return True, key
    
    def validate_mutex(self, string: str, mutex: str) -> Tuple[bool, str]:
        """
        Validate mutex name.
        
        Mutexes don't need as much context validation since they're
        typically unique strings.
        
        Args:
            string: The string containing the mutex
            mutex: The mutex name to validate
            
        Returns:
            Tuple of (is_valid, reason)
        """
        # Mutex names should be reasonable length
        if len(mutex) < 4:
            return False, "Mutex name too short"
        
        # Should be printable ASCII
        if not all(32 <= ord(c) <= 126 for c in mutex if c != '\x00'):
            return False, "Contains non-printable characters"
        
        return True, mutex
    
    def validate_general_pattern(self, string: str, pattern: str, 
                                 indicator_type: str) -> Tuple[bool, str]:
        """
        General validation for any behavioral pattern.
        
        Routes to specific validators based on indicator type.
        
        Args:
            string: The string containing the pattern
            pattern: The pattern to validate
            indicator_type: Type of indicator (file_extension, url, etc.)
            
        Returns:
            Tuple of (is_valid, extracted_value_or_reason)
        """
        # Route to specific validators
        if indicator_type == 'file_extension':
            return self.validate_file_extension(string, pattern)
        elif indicator_type == 'url':
            return self.validate_url(string, pattern)
        elif indicator_type == 'ip_address':
            return self.validate_ip_address(string, pattern)
        elif indicator_type == 'registry_key':
            return self.validate_registry_key(string, pattern)
        elif indicator_type == 'mutex':
            return self.validate_mutex(string, pattern)
        else:
            # Default: minimal validation
            if not self.config.enable_context_validation:
                return True, pattern
            
            # At least check it's not just random bytes
            if len(pattern) < 2:
                return False, "Pattern too short"
            
            # Should have some printable characters
            printable_count = sum(1 for c in pattern if 32 <= ord(c) <= 126)
            if printable_count / len(pattern) < 0.5:
                return False, "Too many non-printable characters"
            
            return True, pattern
    
    def _extract_clean_path(self, path_segment: str, extension: str) -> str:
        """
        Extract a clean file path from a segment.
        
        Args:
            path_segment: Segment containing the path
            extension: File extension
            
        Returns:
            Cleaned path string
        """
        # Find the extension position
        ext_pos = path_segment.find(extension)
        
        # Look backwards for start of filename
        start = ext_pos
        while start > 0 and path_segment[start - 1] not in [' ', '\x00', '\n', '\r', '"', "'", '\t']:
            start -= 1
        
        # Extract from start to end of extension
        end = ext_pos + len(extension)
        clean_path = path_segment[start:end].strip()
        
        # Remove any leading/trailing quotes or spaces
        clean_path = clean_path.strip('"\'` \x00\r\n\t')
        
        return clean_path
