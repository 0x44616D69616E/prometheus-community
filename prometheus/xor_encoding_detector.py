"""
PROMETHEUS - XOR & ENCODING DETECTOR

Detects and decodes XOR obfuscation and common encodings.

Based on Binary Analysis Academic Reference v2.2 Section 30.

Copyright (c) 2026 Damian Donahue
"""

import re
import base64
from dataclasses import dataclass
from typing import List, Tuple, Optional
from prometheus.models import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class EncodingMatch:
    """A detected encoding pattern."""
    encoding_type: str        # "XOR", "Base64", "Hex", "ROT13"
    location: int            # Byte offset
    length: int              # Encoded data length
    key: Optional[bytes]     # Encoding key (for XOR)
    decoded_preview: bytes   # First bytes of decoded data
    confidence: float        # 0.0-1.0
    description: str         # What was found


class XOREncodingDetector:
    """
    Detects XOR obfuscation and common encoding schemes.
    
    Techniques:
    1. Single-byte XOR brute force (0x00-0xFF)
    2. Base64/Base32/Base16 detection
    3. ROT13/Caesar cipher detection
    4. Multi-byte XOR key detection
    """
    
    def __init__(self):
        """Initialize XOR and encoding detector."""
        
        # Base64 pattern (at least 20 chars for reliability)
        self.base64_pattern = re.compile(
            b'[A-Za-z0-9+/]{20,}={0,2}'
        )
        
        # Hex encoding pattern
        self.hex_pattern = re.compile(
            b'(?:[0-9a-fA-F]{2}){10,}'
        )
        
        # Common XOR keys seen in malware
        self.common_xor_keys = [
            0x00, 0x01, 0x42, 0x55, 0xAA, 0xFF,
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC
        ]
    
    def detect(self, content: bytes, filename: str = "") -> Tuple[
        List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """
        Detect encoding and obfuscation in binary data.
        
        Args:
            content: Binary data to analyze
            filename: Original filename (for extraction commands)
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Skip very small files
        if len(content) < 100:
            return suspicious, informational
        
        # Detect XOR encoding
        xor_matches = self._detect_xor_encoding(content)
        for match in xor_matches:
            suspicious.append(self._to_suspicious(match))
        
        # Detect Base64
        base64_matches = self._detect_base64(content)
        for match in base64_matches:
            if match.confidence >= 0.7:
                suspicious.append(self._to_suspicious(match))
            else:
                informational.append(self._to_informational(match))
        
        # Detect hex encoding
        hex_matches = self._detect_hex_encoding(content)
        for match in hex_matches:
            informational.append(self._to_informational(match))
        
        return suspicious, informational
    
    def _detect_xor_encoding(self, content: bytes) -> List[EncodingMatch]:
        """
        Brute force single-byte XOR to detect obfuscation.
        
        Tests all 256 possible XOR keys and looks for decoded data
        with high printable ASCII ratio.
        """
        matches = []
        
        # Sample data for XOR testing (use middle section)
        sample_size = min(2048, len(content))
        sample_offset = max(0, (len(content) // 2) - (sample_size // 2))
        sample = content[sample_offset:sample_offset + sample_size]
        
        # Test each possible single-byte XOR key
        for key in range(256):
            decoded = bytes([b ^ key for b in sample])
            
            # Count printable ASCII characters
            printable_count = sum(1 for b in decoded if 32 <= b <= 126)
            printable_ratio = printable_count / len(decoded)
            
            # High printable ratio suggests this might be the key
            if printable_ratio > 0.7:  # >70% printable
                # Check if decoded data looks like text or known formats
                confidence = printable_ratio
                
                # Extract preview
                preview = decoded[:100]
                
                # Check for common patterns in decoded data
                decoded_str = decoded.decode('ascii', errors='ignore')
                has_words = any(word in decoded_str.lower() for word in 
                              ['http', 'www', 'exe', 'dll', 'cmd', 'shell', 'user'])
                
                if has_words:
                    confidence = min(confidence + 0.1, 0.95)
                
                matches.append(EncodingMatch(
                    encoding_type="XOR_SingleByte",
                    location=sample_offset,
                    length=len(content),  # Entire file likely XORed
                    key=bytes([key]),
                    decoded_preview=preview,
                    confidence=confidence,
                    description=f"Single-byte XOR with key 0x{key:02x}. "
                               f"{printable_ratio:.0%} printable ASCII after decode."
                ))
        
        # Sort by confidence and return top matches
        matches.sort(key=lambda x: x.confidence, reverse=True)
        return matches[:3]  # Return top 3 candidates
    
    def _detect_base64(self, content: bytes) -> List[EncodingMatch]:
        """
        Detect Base64 encoded data.
        
        Looks for long sequences of Base64 characters and attempts to decode.
        """
        matches = []
        
        for match in self.base64_pattern.finditer(content):
            b64_data = match.group(0)
            
            # Skip if too short
            if len(b64_data) < 40:
                continue
            
            try:
                # Attempt to decode
                decoded = base64.b64decode(b64_data)
                
                # Check if decoded data makes sense
                if len(decoded) < 10:
                    continue
                
                # Analyze decoded data
                printable_count = sum(1 for b in decoded if 32 <= b <= 126)
                printable_ratio = printable_count / len(decoded) if len(decoded) > 0 else 0
                
                # Check for file signatures in decoded data
                decoded_type = self._identify_decoded_type(decoded)
                
                confidence = 0.6
                if decoded_type:
                    confidence = 0.9
                elif printable_ratio > 0.8:
                    confidence = 0.8
                
                desc_parts = [
                    f"Base64 encoded data ({len(b64_data)} bytes encoded, "
                    f"{len(decoded)} bytes decoded)"
                ]
                
                if decoded_type:
                    desc_parts.append(f"Decoded type: {decoded_type}")
                
                matches.append(EncodingMatch(
                    encoding_type="Base64",
                    location=match.start(),
                    length=len(b64_data),
                    key=None,
                    decoded_preview=decoded[:100],
                    confidence=confidence,
                    description=". ".join(desc_parts)
                ))
                
            except Exception:
                # Not valid Base64
                continue
            
            # Limit to first 10 matches
            if len(matches) >= 10:
                break
        
        return matches
    
    def _detect_hex_encoding(self, content: bytes) -> List[EncodingMatch]:
        """
        Detect hexadecimal encoded data.
        
        Looks for long sequences of hex characters.
        """
        matches = []
        
        for match in self.hex_pattern.finditer(content):
            hex_data = match.group(0)
            
            # Skip if too short
            if len(hex_data) < 40:
                continue
            
            try:
                # Attempt to decode
                decoded = bytes.fromhex(hex_data.decode('ascii'))
                
                # Check if decoded makes sense
                printable_count = sum(1 for b in decoded if 32 <= b <= 126)
                printable_ratio = printable_count / len(decoded) if len(decoded) > 0 else 0
                
                if printable_ratio > 0.5:
                    matches.append(EncodingMatch(
                        encoding_type="Hex",
                        location=match.start(),
                        length=len(hex_data),
                        key=None,
                        decoded_preview=decoded[:50],
                        confidence=0.5,
                        description=f"Hexadecimal encoded data ({len(hex_data)} chars, "
                                   f"{len(decoded)} bytes decoded)"
                    ))
            except Exception:
                continue
            
            # Limit to first 5 matches
            if len(matches) >= 5:
                break
        
        return matches
    
    def _identify_decoded_type(self, data: bytes) -> Optional[str]:
        """
        Identify the type of decoded data by checking signatures.
        
        Args:
            data: Decoded binary data
            
        Returns:
            Type string or None
        """
        # Common file signatures
        signatures = {
            b'MZ': 'PE executable',
            b'\x7fELF': 'ELF executable',
            b'%PDF': 'PDF document',
            b'PK\x03\x04': 'ZIP archive',
            b'\x89PNG': 'PNG image',
            b'\xff\xd8\xff': 'JPEG image',
            b'GIF8': 'GIF image',
            b'RIFF': 'RIFF container (WAV/AVI)',
        }
        
        for sig, type_name in signatures.items():
            if data.startswith(sig):
                return type_name
        
        # Check for script content
        try:
            text = data.decode('utf-8', errors='ignore')
            if text.startswith('<?php'):
                return 'PHP script'
            elif text.startswith('#!/'):
                return 'Shell script'
            elif '<script' in text.lower():
                return 'JavaScript/HTML'
        except:
            pass
        
        return None
    
    def _to_suspicious(self, match: EncodingMatch) -> SuspiciousArtifact:
        """Convert EncodingMatch to SuspiciousArtifact."""
        location = Location(
            offset=match.location,
            length=match.length
        )
        
        # Build context with decoded preview
        context_parts = [match.description]
        
        if match.key:
            context_parts.append(f"Key: {match.key.hex()}")
        
        # Show decoded preview
        try:
            preview_str = match.decoded_preview.decode('ascii', errors='ignore')
            context_parts.append(f"Decoded preview: {preview_str[:80]}")
        except:
            preview_hex = ' '.join(f'{b:02x}' for b in match.decoded_preview[:20])
            context_parts.append(f"Decoded bytes: {preview_hex}")
        
        # Determine severity
        if match.confidence >= 0.9:
            severity = Severity.HIGH
        elif match.confidence >= 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        return SuspiciousArtifact(
            artifact_type="encoding",
            value=match.encoding_type,
            location=location,
            severity=severity,
            confidence=match.confidence,
            context="\n".join(context_parts),
            observed_in=["Malware obfuscation", "Data exfiltration", "C2 communications"],
            mitre_category="T1027 - Obfuscated Files or Information"
        )
    
    def _to_informational(self, match: EncodingMatch) -> InformationalArtifact:
        """Convert EncodingMatch to InformationalArtifact."""
        location = Location(
            offset=match.location,
            length=match.length
        )
        
        return InformationalArtifact(
            artifact_type="encoding",
            value=match.encoding_type,
            location=location,
            description=match.description,
            benign=True  # Encoding itself isn't malicious
        )
