"""
FILE TYPE VALIDATOR

Validates that file content matches filename extension.
Detects polyglot files and extension spoofing.

Copyright (c) 2026 Damian Donahue
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class FileTypeValidation:
    """Result of file type validation."""
    filename_type: str
    content_type: str
    detected_types: List[str]
    match: bool
    warning: str = None
    suspicious: bool = False
    polyglot: bool = False


class FileTypeValidator:
    """
    Validates file types and detects mismatches.
    
    Detects:
    - Polyglot files (valid as multiple formats)
    - Extension spoofing (PE renamed to .jpg)
    - Mismatched types (JPEG named .PNG)
    """
    
    # Magic bytes: (signature, offset, description)
    MAGIC_BYTES = {
        'PNG': (b'\x89PNG\r\n\x1a\n', 0, 'PNG image'),
        'JPEG': (b'\xff\xd8\xff', 0, 'JPEG image'),
        'GIF87': (b'GIF87a', 0, 'GIF image (87a)'),
        'GIF89': (b'GIF89a', 0, 'GIF image (89a)'),
        'BMP': (b'BM', 0, 'Windows bitmap'),
        'PE': (b'MZ', 0, 'Windows PE executable'),
        'ELF': (b'\x7fELF', 0, 'Linux ELF executable'),
        'MACHO': (b'\xfe\xed\xfa\xce', 0, 'macOS Mach-O'),
        'PDF': (b'%PDF', 0, 'PDF document'),
        'ZIP': (b'PK\x03\x04', 0, 'ZIP archive'),
        'RAR': (b'Rar!\x1a', 0, 'RAR archive'),
        'GZIP': (b'\x1f\x8b', 0, 'GZIP compressed'),
        'BZIP2': (b'BZ', 0, 'BZIP2 compressed'),
        '7Z': (b'7z\xbc\xaf\x27\x1c', 0, '7-Zip archive'),
    }
    
    # Common extensions mapping to types
    EXTENSION_MAP = {
        'PNG': 'PNG',
        'JPG': 'JPEG',
        'JPEG': 'JPEG',
        'GIF': 'GIF89',
        'BMP': 'BMP',
        'EXE': 'PE',
        'DLL': 'PE',
        'SYS': 'PE',
        'PDF': 'PDF',
        'ZIP': 'ZIP',
        'RAR': 'RAR',
        'GZ': 'GZIP',
        'BZ2': 'BZIP2',
        '7Z': '7Z',
    }
    
    def validate(self, filename: str, content: bytes) -> FileTypeValidation:
        """
        Validate file type matches content.
        
        Args:
            filename: File name with extension
            content: File content (bytes)
            
        Returns:
            FileTypeValidation object with results
        """
        # Get type from filename
        filename_ext = filename.split('.')[-1].upper() if '.' in filename else 'UNKNOWN'
        filename_type = self.EXTENSION_MAP.get(filename_ext, filename_ext)
        
        # Detect actual type from content
        content_type = self._detect_primary_type(content)
        
        # Check for polyglot (multiple valid formats)
        detected_types = self._detect_all_formats(content)
        is_polyglot = len(detected_types) > 1
        
        # Determine if types match
        matches = self._types_match(filename_type, content_type, detected_types)
        
        # Determine if suspicious
        suspicious = not matches or is_polyglot
        
        # Generate warning message
        warning = self._generate_warning(
            filename_ext,
            filename_type,
            content_type,
            detected_types,
            matches,
            is_polyglot
        )
        
        return FileTypeValidation(
            filename_type=filename_type,
            content_type=content_type,
            detected_types=detected_types,
            match=matches,
            warning=warning,
            suspicious=suspicious,
            polyglot=is_polyglot
        )
    
    def _detect_primary_type(self, content: bytes) -> str:
        """Detect primary file type from magic bytes."""
        for file_type, (magic, offset, desc) in self.MAGIC_BYTES.items():
            if len(content) > offset + len(magic):
                if content[offset:offset+len(magic)] == magic:
                    return file_type
        return 'UNKNOWN'
    
    def _detect_all_formats(self, content: bytes) -> List[str]:
        """
        Detect ALL valid formats (for polyglot detection).
        
        Searches:
        - At expected offsets (primary format)
        - In first 4KB (embedded signatures)
        - In last 4KB (appended data)
        """
        detected = set()
        
        # Check magic bytes at expected offsets
        for file_type, (magic, offset, desc) in self.MAGIC_BYTES.items():
            if len(content) > offset + len(magic):
                if content[offset:offset+len(magic)] == magic:
                    detected.add(file_type)
        
        # Scan for embedded signatures (polyglot detection)
        search_size = 4096
        search_regions = [
            ('header', content[:min(search_size, len(content))]),
            ('trailer', content[-min(search_size, len(content)):] if len(content) > search_size else b'')
        ]
        
        for region_name, region in search_regions:
            for file_type, (magic, expected_offset, desc) in self.MAGIC_BYTES.items():
                if expected_offset > 0:
                    continue  # Only scan for offset-0 signatures elsewhere
                
                # Search for magic bytes in this region
                idx = region.find(magic)
                if idx > 0 and file_type not in detected:  # Found at non-zero offset
                    detected.add(f"{file_type}_embedded")
        
        return sorted(list(detected)) if detected else ['UNKNOWN']
    
    def _types_match(self, filename_type: str, content_type: str, detected_types: List[str]) -> bool:
        """Check if filename extension matches content type."""
        # Direct match
        if filename_type == content_type:
            return True
        
        # Check if filename_type is in detected types
        if filename_type in detected_types:
            return True
        
        # Special cases
        if filename_type in ['GIF87', 'GIF89'] and content_type in ['GIF87', 'GIF89']:
            return True
        
        return False
    
    def _generate_warning(
        self,
        filename_ext: str,
        filename_type: str,
        content_type: str,
        detected_types: List[str],
        matches: bool,
        is_polyglot: bool
    ) -> str:
        """Generate appropriate warning message."""
        if is_polyglot:
            # Polyglot file
            types_str = ', '.join([t for t in detected_types if not t.endswith('_embedded')])
            embedded_str = ', '.join([t.replace('_embedded', '') for t in detected_types if t.endswith('_embedded')])
            
            if embedded_str:
                return f"âš ï¸  POLYGLOT: File is valid as {types_str} with embedded {embedded_str}"
            else:
                return f"âš ï¸  POLYGLOT: File is valid as multiple formats ({types_str})"
        
        elif not matches and content_type != 'UNKNOWN':
            # Type mismatch
            return f"âš ï¸  MISMATCH: File named .{filename_ext} but contains {content_type} data"
        
        elif content_type == 'UNKNOWN':
            # Unknown type
            return f"âš ï¸  Unknown file type (named .{filename_ext})"
        
        return None  # No warning needed
    
    def is_benign_type(self, content_type: str) -> bool:
        """Check if file type is typically benign (not executable)."""
        benign_types = ['PNG', 'JPEG', 'GIF87', 'GIF89', 'BMP', 'PDF']
        return content_type in benign_types
    
    def is_executable_type(self, content_type: str) -> bool:
        """Check if file type is executable."""
        executable_types = ['PE', 'ELF', 'MACHO']
        return content_type in executable_types
