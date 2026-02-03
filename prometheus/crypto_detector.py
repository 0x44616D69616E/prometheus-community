"""
PROMETHEUS v3.0.0 - CRYPTOGRAPHIC ARTIFACT DETECTOR

Detects cryptographic constants, algorithms, and implementations.

Based on Binary Analysis Academic Reference v2.2 Section 26.

Copyright (c) 2026 Damian Donahue
"""

import struct
from dataclasses import dataclass
from typing import List, Tuple
from prometheus.models_v3 import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class CryptoArtifact:
    """A detected cryptographic artifact."""
    algorithm: str
    artifact_type: str  # "constant", "s-box", "initialization_vector"
    location: int
    value: bytes
    description: str
    confidence: float


class CryptographicDetector:
    """
    Detects cryptographic algorithms and constants.
    
    Detects:
    - AES (Rijndael S-box, key schedules)
    - DES/3DES (S-boxes, permutation tables)
    - RSA (public exponents, key sizes)
    - MD5/SHA (initialization vectors, constants)
    - RC4 (S-box initialization)
    - Common crypto library signatures
    """
    
    def __init__(self):
        """Initialize crypto detector."""
        
        # AES Rijndael S-box (first 16 bytes)
        self.aes_sbox_signature = bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
        ])
        
        # MD5 initialization vectors
        self.md5_iv = [
            0x67452301,  # A
            0xEFCDAB89,  # B
            0x98BADCFE,  # C
            0x10325476   # D
        ]
        
        # SHA-1 initialization vectors
        self.sha1_iv = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        
        # SHA-256 initialization vectors (first 4)
        self.sha256_iv = [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A
        ]
        
        # DES S-box 1 (first row)
        self.des_sbox1_row0 = bytes([
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
        ])
        
        # RSA common public exponents
        self.rsa_exponents = [
            65537,      # F4, most common
            3,          # F0, sometimes used
            17,         # Less common
        ]
        
        # Common crypto library signatures
        self.crypto_lib_strings = [
            b'OpenSSL',
            b'CryptAcquireContext',
            b'BCryptGenerateSymmetricKey',
            b'Crypto++',
            b'libcrypto',
            b'mbedtls',
        ]
    
    def detect(self, content: bytes) -> Tuple[List[SuspiciousArtifact], List[InformationalArtifact]]:
        """
        Detect cryptographic artifacts.
        
        Args:
            content: Binary data to analyze
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Detect AES
        aes_findings = self._detect_aes(content)
        for artifact in aes_findings:
            if artifact.confidence >= 0.9:
                informational.append(self._to_informational(artifact))
            else:
                informational.append(self._to_informational(artifact))
        
        # Detect MD5
        md5_findings = self._detect_md5(content)
        for artifact in md5_findings:
            informational.append(self._to_informational(artifact))
        
        # Detect SHA
        sha_findings = self._detect_sha(content)
        for artifact in sha_findings:
            informational.append(self._to_informational(artifact))
        
        # Detect DES
        des_findings = self._detect_des(content)
        for artifact in des_findings:
            informational.append(self._to_informational(artifact))
        
        # Detect RSA
        rsa_findings = self._detect_rsa(content)
        for artifact in rsa_findings:
            informational.append(self._to_informational(artifact))
        
        # Detect crypto libraries
        lib_findings = self._detect_crypto_libraries(content)
        for artifact in lib_findings:
            informational.append(self._to_informational(artifact))
        
        return suspicious, informational
    
    def _detect_aes(self, content: bytes) -> List[CryptoArtifact]:
        """Detect AES Rijndael S-box."""
        artifacts = []
        
        # Search for S-box signature (first 16 bytes are highly distinctive)
        idx = content.find(self.aes_sbox_signature)
        
        if idx != -1:
            # Found the distinctive S-box signature
            if idx + 256 <= len(content):
                sbox_data = content[idx:idx+256]
                
                # Full S-box should contain all values 0-255 exactly once
                if len(set(sbox_data)) == 256:
                    artifacts.append(CryptoArtifact(
                        algorithm="AES",
                        artifact_type="s-box",
                        location=idx,
                        value=sbox_data[:16],
                        description="AES Rijndael S-box (256 bytes, full). "
                                   "Used in AES encryption key schedule.",
                        confidence=0.95
                    ))
                else:
                    # Partial or modified S-box
                    artifacts.append(CryptoArtifact(
                        algorithm="AES",
                        artifact_type="s-box",
                        location=idx,
                        value=content[idx:idx+16],
                        description="AES Rijndael S-box signature detected (first 16 bytes). "
                                   "May be partial S-box or custom variant.",
                        confidence=0.85
                    ))
            else:
                # Found signature but not enough data for full S-box
                artifacts.append(CryptoArtifact(
                    algorithm="AES",
                    artifact_type="s-box",
                    location=idx,
                    value=self.aes_sbox_signature,
                    description="AES Rijndael S-box signature detected. "
                               "Truncated or partial implementation.",
                    confidence=0.80
                ))
        
        return artifacts
    
    def _detect_md5(self, content: bytes) -> List[CryptoArtifact]:
        """Detect MD5 initialization vectors."""
        artifacts = []
        
        # Search for MD5 IV sequence
        for i in range(0, len(content) - 16, 4):
            dwords = struct.unpack('<4I', content[i:i+16])
            
            if list(dwords) == self.md5_iv:
                artifacts.append(CryptoArtifact(
                    algorithm="MD5",
                    artifact_type="initialization_vector",
                    location=i,
                    value=content[i:i+16],
                    description="MD5 initialization vectors. "
                               "Indicates MD5 hashing implementation.",
                    confidence=0.95
                ))
                break  # Only report first occurrence
        
        return artifacts
    
    def _detect_sha(self, content: bytes) -> List[CryptoArtifact]:
        """Detect SHA initialization vectors."""
        artifacts = []
        
        # Search for SHA-1 IV
        for i in range(0, len(content) - 20, 4):
            dwords = struct.unpack('<5I', content[i:i+20])
            
            if list(dwords) == self.sha1_iv:
                artifacts.append(CryptoArtifact(
                    algorithm="SHA-1",
                    artifact_type="initialization_vector",
                    location=i,
                    value=content[i:i+20],
                    description="SHA-1 initialization vectors. "
                               "Indicates SHA-1 hashing implementation.",
                    confidence=0.95
                ))
                break
        
        # Search for SHA-256 IV (first 4 constants)
        for i in range(0, len(content) - 16, 4):
            dwords = struct.unpack('>4I', content[i:i+16])  # Big-endian
            
            if list(dwords) == self.sha256_iv:
                artifacts.append(CryptoArtifact(
                    algorithm="SHA-256",
                    artifact_type="initialization_vector",
                    location=i,
                    value=content[i:i+16],
                    description="SHA-256 initialization vectors. "
                               "Indicates SHA-256 hashing implementation.",
                    confidence=0.9
                ))
                break
        
        return artifacts
    
    def _detect_des(self, content: bytes) -> List[CryptoArtifact]:
        """Detect DES S-boxes."""
        artifacts = []
        
        # Search for DES S-box
        idx = content.find(self.des_sbox1_row0)
        
        if idx != -1:
            artifacts.append(CryptoArtifact(
                algorithm="DES",
                artifact_type="s-box",
                location=idx,
                value=self.des_sbox1_row0,
                description="DES S-box pattern. "
                           "Indicates DES encryption implementation.",
                confidence=0.85
            ))
        
        return artifacts
    
    def _detect_rsa(self, content: bytes) -> List[CryptoArtifact]:
        """Detect RSA public exponents."""
        artifacts = []
        
        # Search for common RSA public exponents
        for exponent in self.rsa_exponents:
            # Try both little-endian and big-endian
            for endian in ['<', '>']:
                exponent_bytes = struct.pack(f'{endian}I', exponent)
                
                idx = content.find(exponent_bytes)
                if idx != -1:
                    artifacts.append(CryptoArtifact(
                        algorithm="RSA",
                        artifact_type="constant",
                        location=idx,
                        value=exponent_bytes,
                        description=f"RSA public exponent: {exponent} (0x{exponent:X}). "
                                   f"Common in RSA key generation.",
                        confidence=0.7
                    ))
                    break  # Only report first occurrence per exponent
        
        return artifacts
    
    def _detect_crypto_libraries(self, content: bytes) -> List[CryptoArtifact]:
        """Detect crypto library signatures."""
        artifacts = []
        
        for lib_sig in self.crypto_lib_strings:
            idx = content.find(lib_sig)
            if idx != -1:
                artifacts.append(CryptoArtifact(
                    algorithm="Library",
                    artifact_type="signature",
                    location=idx,
                    value=lib_sig,
                    description=f"Cryptographic library: {lib_sig.decode('ascii', errors='ignore')}",
                    confidence=0.9
                ))
        
        return artifacts
    
    def _to_informational(self, artifact: CryptoArtifact) -> InformationalArtifact:
        """Convert CryptoArtifact to InformationalArtifact."""
        location = Location(
            offset=artifact.location,
            length=len(artifact.value)
        )
        
        # Format value
        value_hex = ' '.join(f'{b:02x}' for b in artifact.value[:16])
        if len(artifact.value) > 16:
            value_hex += '...'
        
        description = f"{artifact.description}\nBytes: {value_hex}"
        
        return InformationalArtifact(
            artifact_type="cryptographic",
            value=f"{artifact.algorithm} - {artifact.artifact_type}",
            location=location,
            description=description,
            benign=True  # Crypto itself isn't malicious
        )
