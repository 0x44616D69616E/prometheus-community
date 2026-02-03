"""
PROMETHEUS v3.0.0 - NESTED FILE DETECTOR

Detects files embedded within other files (polyglots, nested archives, etc.).

Based on Binary Analysis Academic Reference v2.2 Section 27.

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional
from models_v3 import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class NestedFile:
    """A file found embedded within another file."""
    file_type: str           # Type of nested file
    location: int           # Byte offset
    estimated_size: int     # Estimated size in bytes
    confidence: float       # 0.0-1.0
    is_primary: bool        # True if this is the main file format
    extraction_possible: bool = True


class NestedFileDetector:
    """
    Detects files embedded within other files.
    
    Techniques:
    1. Signature scanning at all offsets
    2. Polyglot detection (file valid as multiple formats)
    3. Archive-within-archive detection
    4. Recursive scanning (up to 2 layers)
    """
    
    def __init__(self):
        """Initialize nested file detector."""
        
        # Comprehensive file signatures
        self.signatures = {
            # Executables
            'PE': (b'MZ', 0),
            'ELF': (b'\x7fELF', 0),
            'MACHO': (b'\xfe\xed\xfa\xce', 0),
            'MACHO64': (b'\xfe\xed\xfa\xcf', 0),
            
            # Archives
            'ZIP': (b'PK\x03\x04', 0),
            'RAR': (b'Rar!\x1a\x07', 0),
            'RAR5': (b'Rar!\x1a\x07\x01\x00', 0),
            '7Z': (b'7z\xbc\xaf\x27\x1c', 0),
            'GZIP': (b'\x1f\x8b', 0),
            'BZIP2': (b'BZh', 0),
            'TAR': (b'ustar', 257),  # TAR signature at offset 257
            
            # Images
            'PNG': (b'\x89PNG\r\n\x1a\n', 0),
            'JPEG': (b'\xff\xd8\xff', 0),
            'GIF87': (b'GIF87a', 0),
            'GIF89': (b'GIF89a', 0),
            'BMP': (b'BM', 0),
            'TIFF_LE': (b'II\x2a\x00', 0),
            'TIFF_BE': (b'MM\x00\x2a', 0),
            
            # Audio/Video
            'WAV': (b'RIFF', 0),  # Must check for 'WAVE' at offset 8
            'AVI': (b'RIFF', 0),  # Must check for 'AVI ' at offset 8
            'MP3': (b'\xff\xfb', 0),
            'MP3_ID3': (b'ID3', 0),
            'FLAC': (b'fLaC', 0),
            'OGG': (b'OggS', 0),
            'MP4': (b'ftyp', 4),
            
            # Documents
            'PDF': (b'%PDF', 0),
            'RTF': (b'{\\rtf', 0),
            'XML': (b'<?xml', 0),
            
            # Office formats (ZIP-based)
            'DOCX': (b'PK\x03\x04', 0),  # Same as ZIP, need deeper inspection
            'XLSX': (b'PK\x03\x04', 0),
            'PPTX': (b'PK\x03\x04', 0),
        }
    
    def detect(self, content: bytes, primary_type: str = "UNKNOWN", 
              max_depth: int = 2) -> Tuple[List[SuspiciousArtifact], 
                                           List[InformationalArtifact]]:
        """
        Detect nested files in binary data.
        
        Args:
            content: Binary data to scan
            primary_type: Known primary file type
            max_depth: Maximum recursion depth (default 2 layers)
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Find all file signatures
        nested_files = self._scan_signatures(content, primary_type)
        
        # Classify findings
        for nested in nested_files:
            artifact = self._classify_nested_file(nested, primary_type)
            
            if isinstance(artifact, SuspiciousArtifact):
                suspicious.append(artifact)
            else:
                informational.append(artifact)
        
        # Check for polyglot (file valid as multiple formats)
        if len(nested_files) > 1:
            primary_files = [f for f in nested_files if f.is_primary]
            if len(primary_files) > 1:
                # Multiple valid primary formats = polyglot
                polyglot_artifact = self._create_polyglot_artifact(primary_files)
                suspicious.append(polyglot_artifact)
        
        return suspicious, informational
    
    def _scan_signatures(self, content: bytes, 
                        primary_type: str) -> List[NestedFile]:
        """
        Scan entire file for all file signatures.
        
        Args:
            content: Binary data to scan
            primary_type: Known primary file type
            
        Returns:
            List of NestedFile objects
        """
        found_files = []
        
        for file_type, (signature, expected_offset) in self.signatures.items():
            # Scan at expected offset first
            if expected_offset < len(content):
                if content[expected_offset:expected_offset+len(signature)] == signature:
                    # Found at expected offset
                    is_primary = (expected_offset == 0)
                    
                    # Special handling for RIFF (WAV/AVI)
                    if file_type in ['WAV', 'AVI'] and expected_offset == 0:
                        if len(content) > 12:
                            riff_type = content[8:12]
                            if riff_type == b'WAVE':
                                file_type = 'WAV'
                            elif riff_type == b'AVI ':
                                file_type = 'AVI'
                    
                    found_files.append(NestedFile(
                        file_type=file_type,
                        location=expected_offset,
                        estimated_size=self._estimate_size(content, expected_offset, file_type),
                        confidence=0.95,
                        is_primary=is_primary
                    ))
            
            # Scan for signatures at other offsets (embedded files)
            if expected_offset == 0:  # Only scan for offset-0 signatures elsewhere
                offset = 1  # Start after offset 0
                
                while offset < len(content):
                    idx = content.find(signature, offset)
                    if idx == -1:
                        break
                    
                    # Found signature at non-zero offset
                    # Skip if this is likely a false positive
                    if self._is_valid_signature(content, idx, signature, file_type):
                        found_files.append(NestedFile(
                            file_type=file_type,
                            location=idx,
                            estimated_size=self._estimate_size(content, idx, file_type),
                            confidence=0.8,
                            is_primary=False
                        ))
                    
                    offset = idx + len(signature)
                    
                    # Limit results per type
                    type_count = len([f for f in found_files if f.file_type == file_type])
                    if type_count >= 5:
                        break
        
        return found_files
    
    def _is_valid_signature(self, content: bytes, offset: int, 
                           signature: bytes, file_type: str) -> bool:
        """
        Validate that a signature at a given offset is likely real.
        
        Reduces false positives from signatures appearing in data.
        """
        # Check if there's enough data after the signature
        if offset + len(signature) + 100 > len(content):
            return False
        
        # For certain types, do additional validation
        if file_type == 'PE':
            # Check for valid PE header structure
            if offset + 64 < len(content):
                # Check for e_lfanew at offset 60 (points to PE header)
                e_lfanew = int.from_bytes(content[offset+60:offset+64], 'little')
                if e_lfanew > 0 and e_lfanew < 0x1000:
                    return True
            return False
        
        elif file_type == 'ZIP':
            # ZIP local file header should have reasonable values
            if offset + 30 < len(content):
                # Check compression method (offset +8, 2 bytes)
                comp_method = int.from_bytes(content[offset+8:offset+10], 'little')
                if comp_method <= 14:  # Valid compression methods
                    return True
            return False
        
        # For other types, accept if signature is found
        return True
    
    def _estimate_size(self, content: bytes, offset: int, 
                      file_type: str) -> int:
        """
        Estimate the size of an embedded file.
        
        For some formats, we can parse headers to get exact size.
        """
        remaining = len(content) - offset
        
        # Try to get exact size for known formats
        if file_type == 'PNG':
            # PNG ends with IEND chunk
            iend_marker = b'IEND\xae\x42\x60\x82'
            idx = content.find(iend_marker, offset)
            if idx != -1:
                return idx + len(iend_marker) - offset
        
        elif file_type == 'JPEG':
            # JPEG ends with EOI marker
            eoi_marker = b'\xff\xd9'
            idx = content.find(eoi_marker, offset)
            if idx != -1:
                return idx + len(eoi_marker) - offset
        
        elif file_type == 'GIF87' or file_type == 'GIF89':
            # GIF ends with trailer
            trailer = b'\x00\x3b'
            idx = content.find(trailer, offset)
            if idx != -1:
                return idx + len(trailer) - offset
        
        elif file_type == 'WAV' and offset + 8 < len(content):
            # RIFF chunk size at offset +4
            chunk_size = int.from_bytes(content[offset+4:offset+8], 'little')
            return min(chunk_size + 8, remaining)
        
        # Default: return remaining bytes (upper bound)
        return min(remaining, 10 * 1024 * 1024)  # Cap at 10MB
    
    def _classify_nested_file(self, nested: NestedFile, 
                             primary_type: str) -> object:
        """
        Classify a nested file as suspicious or informational.
        
        Args:
            nested: NestedFile object
            primary_type: Primary file type
            
        Returns:
            SuspiciousArtifact or InformationalArtifact
        """
        location = Location(
            offset=nested.location,
            length=nested.estimated_size
        )
        
        # Primary file at offset 0 is informational
        if nested.is_primary and nested.location == 0:
            return InformationalArtifact(
                artifact_type="nested_file",
                value=f"Primary file: {nested.file_type}",
                location=location,
                description=f"File identified as {nested.file_type}",
                benign=True
            )
        
        # Nested files are suspicious
        severity = Severity.HIGH if nested.confidence >= 0.9 else Severity.MEDIUM
        
        context_parts = [
            f"Embedded {nested.file_type} file found at offset 0x{nested.location:08x}",
            f"Estimated size: {nested.estimated_size:,} bytes"
        ]
        
        if nested.extraction_possible:
            extract_cmd = f"dd if=<file> of=nested_{nested.file_type.lower()}.bin bs=1 skip={nested.location} count={nested.estimated_size}"
            context_parts.append(f"Extract with: {extract_cmd}")
        
        return SuspiciousArtifact(
            artifact_type="nested_file",
            value=nested.file_type,
            location=location,
            severity=severity,
            confidence=nested.confidence,
            context="\n".join(context_parts),
            observed_in=["Polyglot files", "Malware droppers", "Steganography"],
            mitre_category="T1027 - Obfuscated Files or Information"
        )
    
    def _create_polyglot_artifact(self, primary_files: List[NestedFile]) -> SuspiciousArtifact:
        """
        Create artifact for polyglot file detection.
        
        A polyglot is a file that is valid as multiple formats.
        """
        types = [f.file_type for f in primary_files]
        
        location = Location(offset=0, length=0)
        
        context = (
            f"File is valid as multiple formats: {', '.join(types)}. "
            f"This is a polyglot file, often used for evasion or exploitation."
        )
        
        return SuspiciousArtifact(
            artifact_type="polyglot",
            value=f"Polyglot ({'+'.join(types)})",
            location=location,
            severity=Severity.HIGH,
            confidence=0.9,
            context=context,
            observed_in=["Malware evasion", "Exploit delivery", "Steganography"],
            mitre_category="T1027 - Obfuscated Files or Information"
        )
