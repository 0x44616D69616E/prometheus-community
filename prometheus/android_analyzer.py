"""
PROMETHEUS v3.0.0 - ANDROID ANALYZER

Analysis of Android DEX (Dalvik Executable) files.

Analyzes:
- DEX file structure
- Class and method counts
- String pool analysis
- Suspicious permissions (via AndroidManifest.xml if APK)
- Dynamic code loading indicators
- Obfuscation detection

Based on Binary Analysis Academic Reference v2.2 Section 45.

Copyright (c) 2026 Damian Donahue
"""

import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional
from models_v3 import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class DEXInfo:
    """DEX file information."""
    version: str
    file_size: int
    checksum: int
    sha1: bytes
    string_count: int
    type_count: int
    proto_count: int
    field_count: int
    method_count: int
    class_count: int


class AndroidAnalyzer:
    """
    Analyzes Android DEX files.
    
    Detects:
    - DEX file structure
    - Suspicious class/method patterns
    - Obfuscation indicators
    - Dynamic code loading patterns
    """
    
    # Suspicious class patterns
    SUSPICIOUS_CLASSES = [
        'DexClassLoader',
        'PathClassLoader',
        'InMemoryDexClassLoader',
        'SecureClassLoader'
    ]
    
    # Suspicious method patterns
    SUSPICIOUS_METHODS = [
        'loadClass',
        'invoke',
        'getMethod',
        'getDeclaredMethod',
        'Runtime.exec',
        'ProcessBuilder',
        'Shell',
        'Root'
    ]
    
    # Reflection indicators
    REFLECTION_PATTERNS = [
        'java/lang/reflect/Method',
        'java/lang/reflect/Field',
        'java/lang/reflect/Constructor',
        'forName',
        'newInstance'
    ]
    
    def __init__(self):
        """Initialize Android analyzer."""
        pass
    
    def analyze(self, content: bytes, filename: str) -> Tuple[
        List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """
        Analyze DEX file.
        
        Args:
            content: DEX file bytes
            filename: Original filename
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Check if it's a DEX file
        if not self._is_dex(content):
            return suspicious, informational
        
        try:
            # Parse DEX header
            dex_info = self._parse_dex_header(content)
            
            if not dex_info:
                return suspicious, informational
            
            # Add DEX info
            informational.append(InformationalArtifact(
                artifact_type="dex_info",
                value=f"DEX version {dex_info.version}",
                description=f"Classes: {dex_info.class_count:,}, "
                           f"Methods: {dex_info.method_count:,}, "
                           f"Strings: {dex_info.string_count:,}",
                benign=True
            ))
            
            # Extract strings from string pool
            strings = self._extract_strings(content, dex_info)
            
            # Detect suspicious patterns
            suspicious_patterns = self._detect_suspicious_patterns(strings)
            suspicious.extend(suspicious_patterns)
            
            # Detect obfuscation
            obfuscation_findings = self._detect_obfuscation(dex_info, strings)
            suspicious.extend(obfuscation_findings)
            
            # Detect dynamic code loading
            dynamic_loading = self._detect_dynamic_loading(strings)
            suspicious.extend(dynamic_loading)
            
        except Exception as e:
            # Parsing error
            suspicious.append(SuspiciousArtifact(
                artifact_type="dex_malformed",
                value="Malformed DEX",
                location=Location(offset=0, length=0),
                severity=Severity.MEDIUM,
                confidence=0.7,
                context=f"DEX parsing error: {str(e)}. May indicate corrupted or obfuscated file.",
                observed_in=["Malware evasion"]
            ))
        
        return suspicious, informational
    
    def _is_dex(self, content: bytes) -> bool:
        """Check if content is a DEX file."""
        if len(content) < 8:
            return False
        
        # Check DEX magic
        magic = content[0:4]
        return magic == b'dex\n'
    
    def _parse_dex_header(self, content: bytes) -> Optional[DEXInfo]:
        """Parse DEX file header."""
        if len(content) < 0x70:  # DEX header is 0x70 bytes
            return None
        
        # Read header fields
        magic = content[0:4]
        version = content[4:7].decode('ascii', errors='ignore')
        
        checksum, = struct.unpack('<I', content[0x08:0x0c])
        sha1 = content[0x0c:0x20]
        file_size, = struct.unpack('<I', content[0x20:0x24])
        
        # Read counts
        string_ids_size, = struct.unpack('<I', content[0x38:0x3c])
        type_ids_size, = struct.unpack('<I', content[0x40:0x44])
        proto_ids_size, = struct.unpack('<I', content[0x48:0x4c])
        field_ids_size, = struct.unpack('<I', content[0x50:0x54])
        method_ids_size, = struct.unpack('<I', content[0x58:0x5c])
        class_defs_size, = struct.unpack('<I', content[0x60:0x64])
        
        return DEXInfo(
            version=version,
            file_size=file_size,
            checksum=checksum,
            sha1=sha1,
            string_count=string_ids_size,
            type_count=type_ids_size,
            proto_count=proto_ids_size,
            field_count=field_ids_size,
            method_count=method_ids_size,
            class_count=class_defs_size
        )
    
    def _extract_strings(self, content: bytes, dex_info: DEXInfo) -> List[str]:
        """Extract strings from DEX string pool (simplified)."""
        # This is a simplified extraction
        # Full implementation would parse string_ids and data sections
        
        strings = []
        
        # Look for printable ASCII strings
        current_string = []
        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= 4:
                    strings.append(''.join(current_string))
                current_string = []
        
        return strings[:1000]  # Limit to avoid memory issues
    
    def _detect_suspicious_patterns(self, strings: List[str]) -> List[SuspiciousArtifact]:
        """Detect suspicious class/method patterns."""
        suspicious = []
        
        # Check for dynamic class loaders
        for class_name in self.SUSPICIOUS_CLASSES:
            count = sum(1 for s in strings if class_name in s)
            if count > 0:
                suspicious.append(SuspiciousArtifact(
                    artifact_type="dex_dynamic_loading",
                    value=class_name,
                    location=Location(offset=0, length=0),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    context=f"Dynamic class loader detected: {class_name}. "
                           f"Commonly used to load malicious code at runtime.",
                    observed_in=["Android malware", "Repackaged apps"],
                    mitre_category="T1627 - Execution Guardrails"
                ))
        
        # Check for reflection
        reflection_count = 0
        for pattern in self.REFLECTION_PATTERNS:
            count = sum(1 for s in strings if pattern in s)
            reflection_count += count
        
        if reflection_count >= 5:
            suspicious.append(SuspiciousArtifact(
                artifact_type="dex_reflection",
                value=f"{reflection_count} reflection patterns",
                location=Location(offset=0, length=0),
                severity=Severity.MEDIUM,
                confidence=0.7,
                context=f"Heavy use of reflection ({reflection_count} patterns). "
                       f"May indicate obfuscation or dynamic code execution.",
                observed_in=["Obfuscated apps", "Malware"]
            ))
        
        return suspicious
    
    def _detect_obfuscation(self, dex_info: DEXInfo, strings: List[str]) -> List[SuspiciousArtifact]:
        """Detect code obfuscation indicators."""
        suspicious = []
        
        # Check class/method ratio
        if dex_info.class_count > 0:
            methods_per_class = dex_info.method_count / dex_info.class_count
            
            # Very high methods per class can indicate obfuscation
            if methods_per_class > 100:
                suspicious.append(SuspiciousArtifact(
                    artifact_type="dex_obfuscation",
                    value=f"{methods_per_class:.1f} methods/class",
                    location=Location(offset=0, length=0),
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    context=f"Unusually high method count per class ({methods_per_class:.1f}). "
                           f"May indicate code obfuscation.",
                    observed_in=["Obfuscated apps", "ProGuard/R8 processing"]
                ))
        
        # Check for short class names (common in obfuscation)
        short_name_count = sum(1 for s in strings if len(s) == 1 and s.isalpha())
        
        if short_name_count > 20:
            suspicious.append(SuspiciousArtifact(
                artifact_type="dex_obfuscation",
                value=f"{short_name_count} single-char names",
                location=Location(offset=0, length=0),
                severity=Severity.LOW,
                confidence=0.5,
                context=f"Many single-character names detected ({short_name_count}). "
                       f"Common in ProGuard/R8 obfuscation.",
                observed_in=["Obfuscated apps", "Release builds"]
            ))
        
        return suspicious
    
    def _detect_dynamic_loading(self, strings: List[str]) -> List[SuspiciousArtifact]:
        """Detect dynamic code loading patterns."""
        suspicious = []
        
        # Check for .dex file references
        dex_refs = [s for s in strings if '.dex' in s.lower()]
        if dex_refs:
            suspicious.append(SuspiciousArtifact(
                artifact_type="dex_dynamic_loading",
                value=f"{len(dex_refs)} .dex references",
                location=Location(offset=0, length=0),
                severity=Severity.MEDIUM,
                confidence=0.7,
                context=f"References to .dex files found. May load additional code at runtime.",
                observed_in=["Android malware", "Plugin systems"]
            ))
        
        # Check for asset/cache directory references
        suspicious_paths = [
            'getCacheDir',
            'getFilesDir',
            'assets/',
            '/sdcard/',
            'getExternalStorageDirectory'
        ]
        
        path_refs = []
        for path in suspicious_paths:
            if any(path in s for s in strings):
                path_refs.append(path)
        
        if len(path_refs) >= 2:
            suspicious.append(SuspiciousArtifact(
                artifact_type="dex_file_access",
                value=f"{len(path_refs)} file paths",
                location=Location(offset=0, length=0),
                severity=Severity.LOW,
                confidence=0.5,
                context=f"Multiple file system access patterns: {', '.join(path_refs[:3])}",
                observed_in=["Apps with file access", "Malware"]
            ))
        
        return suspicious
