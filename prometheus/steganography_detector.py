"""
PROMETHEUS v3.0.0 - STEGANOGRAPHY DETECTOR

Detects hidden data in files using multiple steganography techniques.

Based on Binary Analysis Academic Reference v2.2 Section 8.

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from prometheus.models_v3 import Location, ExactMatch, SuspiciousArtifact, InformationalArtifact


@dataclass
class SteganographyMatch:
    """A steganography detection finding."""
    technique: str              # "EOF_Append", "Embedded_Signature", "LSB_Anomaly"
    confidence: float           # 0.0-1.0
    location: int              # Byte offset
    size_estimate: int         # Estimated hidden data size
    evidence: str              # What was detected
    hidden_type: Optional[str] = None  # Type of hidden file (WAV, ZIP, etc.)
    extraction_command: Optional[str] = None  # Command to extract


class SteganographyDetector:
    """
    Detects hidden data using steganography techniques.
    
    Implements:
    1. EOF Append Detection - Data after file end markers
    2. Embedded Signature Scanning - File signatures within files
    3. LSB Analysis - Statistical anomalies in image data
    4. Size Anomaly Detection - Files larger than expected
    """
    
    def __init__(self):
        """Initialize steganography detector."""
        
        # Audio file signatures
        self.audio_signatures = {
            'WAV': b'RIFF',
            'MP3': b'\xff\xfb',  # MP3 frame sync
            'MP3_ID3': b'ID3',
            'FLAC': b'fLaC',
            'OGG': b'OggS',
            'M4A': b'ftypM4A',
        }
        
        # Archive signatures
        self.archive_signatures = {
            'ZIP': b'PK\x03\x04',
            'RAR': b'Rar!\x1a\x07',
            'RAR5': b'Rar!\x1a\x07\x01\x00',
            '7Z': b'7z\xbc\xaf\x27\x1c',
            'GZIP': b'\x1f\x8b',
            'BZIP2': b'BZh',
            'TAR': b'ustar',  # At offset 257
        }
        
        # Executable signatures
        self.executable_signatures = {
            'PE': b'MZ',
            'ELF': b'\x7fELF',
            'MACHO': b'\xfe\xed\xfa\xce',
            'MACHO64': b'\xfe\xed\xfa\xcf',
        }
        
        # Image signatures (for nested detection)
        self.image_signatures = {
            'PNG': b'\x89PNG\r\n\x1a\n',
            'JPEG': b'\xff\xd8\xff',
            'GIF87': b'GIF87a',
            'GIF89': b'GIF89a',
            'BMP': b'BM',
        }
        
        # EOF markers for different file types
        self.eof_markers = {
            'JPEG': b'\xff\xd9',              # EOI (End of Image)
            'PNG': b'IEND\xae\x42\x60\x82',  # IEND chunk (includes CRC)
            'GIF': b'\x00\x3b',               # GIF trailer
        }
    
    def detect(self, filename: str, content: bytes, file_type: str) -> Tuple[
        List[ExactMatch], List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """
        Scan file for steganography.
        
        Args:
            filename: Original filename
            content: File bytes
            file_type: Detected file type (PNG, JPEG, etc.)
            
        Returns:
            Tuple of (exact_matches, suspicious_artifacts, informational)
        """
        exact_matches = []
        suspicious_artifacts = []
        informational = []
        
        # Only scan image files for steganography
        if file_type not in ['PNG', 'JPEG', 'GIF', 'BMP']:
            return exact_matches, suspicious_artifacts, informational
        
        # Technique 1: EOF append detection
        eof_matches = self._detect_eof_append(content, file_type, filename)
        for match in eof_matches:
            # High confidence matches are EXACT (known file signatures)
            if match.confidence >= 0.9 and match.hidden_type:
                exact_matches.append(self._to_exact_match(match))
            else:
                suspicious_artifacts.append(self._to_suspicious(match))
        
        # Technique 2: Embedded signature scanning
        embedded_matches = self._detect_embedded_signatures(content, file_type)
        for match in embedded_matches:
            suspicious_artifacts.append(self._to_suspicious(match))
        
        # Technique 3: LSB analysis (for uncompressed formats)
        if file_type in ['PNG', 'BMP'] and len(content) > 20000:
            lsb_matches = self._detect_lsb_anomalies(content)
            for match in lsb_matches:
                suspicious_artifacts.append(self._to_suspicious(match))
        
        # Technique 4: Size anomalies
        size_matches = self._detect_size_anomalies(filename, content, file_type)
        for match in size_matches:
            informational.append(self._to_informational(match))
        
        return exact_matches, suspicious_artifacts, informational
    
    def _detect_eof_append(self, content: bytes, file_type: str, 
                           filename: str) -> List[SteganographyMatch]:
        """
        Detect data appended after end-of-file marker.
        
        This is the technique used in the test case - data appended after
        legitimate file EOF markers.
        """
        matches = []
        
        if file_type not in self.eof_markers:
            return matches
        
        eof_marker = self.eof_markers[file_type]
        
        # Find last occurrence of EOF marker
        eof_pos = content.rfind(eof_marker)
        
        if eof_pos == -1:
            return matches
        
        # Calculate data after EOF
        eof_end = eof_pos + len(eof_marker)
        data_after = len(content) - eof_end
        
        if data_after < 100:  # Less than 100 bytes, probably just padding
            return matches
        
        # Extract appended data
        appended = content[eof_end:]
        
        # Check for known file signatures in appended data
        all_sigs = {
            **self.audio_signatures,
            **self.archive_signatures,
            **self.executable_signatures,
            **self.image_signatures
        }
        
        for sig_type, signature in all_sigs.items():
            # Check if signature appears at start of appended data
            if appended.startswith(signature):
                # Found a known file type!
                
                # For WAV, parse RIFF header to get size
                if sig_type == 'WAV' and len(appended) >= 8:
                    # RIFF header: "RIFF" + size(4) + "WAVE"
                    if appended[8:12] == b'WAVE':
                        # Read chunk size (little-endian)
                        chunk_size = int.from_bytes(appended[4:8], 'little')
                        actual_size = min(chunk_size + 8, data_after)
                        
                        # Generate extraction command
                        extract_cmd = f"dd if={filename} of=hidden.wav bs=1 skip={eof_end} count={actual_size}"
                        
                        matches.append(SteganographyMatch(
                            technique="EOF_Append",
                            confidence=0.95,
                            location=eof_end,
                            size_estimate=actual_size,
                            evidence=f"{sig_type} file appended after {file_type} EOF (RIFF/WAVE format detected)",
                            hidden_type=sig_type,
                            extraction_command=extract_cmd
                        ))
                        return matches
                
                # For other formats, estimate size
                extract_cmd = f"dd if={filename} of=hidden.{sig_type.lower()} bs=1 skip={eof_end} count={data_after}"
                
                matches.append(SteganographyMatch(
                    technique="EOF_Append",
                    confidence=0.95,
                    location=eof_end,
                    size_estimate=data_after,
                    evidence=f"{sig_type} file appended after {file_type} EOF",
                    hidden_type=sig_type,
                    extraction_command=extract_cmd
                ))
                return matches
        
        # Unknown data appended (no recognizable signature)
        if data_after > 100:  # Significant amount of unknown data (lowered from 1000)
            matches.append(SteganographyMatch(
                technique="EOF_Append",
                confidence=0.7,
                location=eof_end,
                size_estimate=data_after,
                evidence=f"{data_after:,} bytes of unknown data appended after {file_type} EOF",
                hidden_type=None,
                extraction_command=f"dd if={filename} of=hidden.bin bs=1 skip={eof_end}"
            ))
        
        return matches
    
    def _detect_embedded_signatures(self, content: bytes, 
                                    file_type: str) -> List[SteganographyMatch]:
        """
        Scan entire file for embedded file signatures.
        
        Detects files hidden within the image data itself.
        """
        matches = []
        
        # Skip first 512 bytes (header area)
        search_start = 512
        
        all_sigs = {
            **self.audio_signatures,
            **self.archive_signatures,
            **self.executable_signatures
        }
        
        for sig_type, signature in all_sigs.items():
            offset = search_start
            
            while True:
                idx = content.find(signature, offset)
                if idx == -1:
                    break
                
                # Found embedded signature
                matches.append(SteganographyMatch(
                    technique="Embedded_Signature",
                    confidence=0.75,
                    location=idx,
                    size_estimate=0,  # Unknown without parsing
                    evidence=f"{sig_type} signature found embedded at offset 0x{idx:08x}",
                    hidden_type=sig_type
                ))
                
                offset = idx + len(signature)
                
                # Limit to first 5 occurrences per type
                if len([m for m in matches if m.hidden_type == sig_type]) >= 5:
                    break
        
        return matches
    
    def _detect_lsb_anomalies(self, content: bytes) -> List[SteganographyMatch]:
        """
        Detect LSB (Least Significant Bit) steganography.
        
        Analyzes bit distribution in image data to detect hidden data.
        Statistical approach - checks if LSB distribution is unnatural.
        """
        matches = []
        
        # Sample from middle of file (avoid headers)
        if len(content) < 20000:
            return matches
        
        sample_start = len(content) // 3
        sample_size = min(10000, len(content) - sample_start)
        sample = content[sample_start:sample_start + sample_size]
        
        # Count LSB distribution
        lsb_0_count = 0
        lsb_1_count = 0
        
        for byte in sample:
            if byte & 1:  # LSB is 1
                lsb_1_count += 1
            else:  # LSB is 0
                lsb_0_count += 1
        
        # In natural images, LSB should be approximately 50/50
        total = lsb_0_count + lsb_1_count
        ratio = min(lsb_0_count, lsb_1_count) / max(lsb_0_count, lsb_1_count)
        
        # If ratio < 0.9, there's >10% deviation from expected
        if ratio < 0.9:
            deviation = abs(0.5 - (lsb_1_count / total))
            confidence = min(0.6 + (deviation * 2), 0.95)
            
            matches.append(SteganographyMatch(
                technique="LSB_Anomaly",
                confidence=confidence,
                location=sample_start,
                size_estimate=0,
                evidence=f"LSB distribution anomaly (ratio: {ratio:.2f}, expected: ~1.0). Suggests LSB steganography."
            ))
        
        return matches
    
    def _detect_size_anomalies(self, filename: str, content: bytes,
                               file_type: str) -> List[SteganographyMatch]:
        """
        Detect suspicious file sizes.
        
        Images with steganography are often larger than expected.
        """
        matches = []
        
        # Flag very large image files
        if len(content) > 10 * 1024 * 1024:  # > 10MB
            matches.append(SteganographyMatch(
                technique="Size_Anomaly",
                confidence=0.3,
                location=0,
                size_estimate=0,
                evidence=f"Large file size ({len(content) / 1024 / 1024:.1f} MB) for {file_type} image. May contain hidden data."
            ))
        
        return matches
    
    def _to_exact_match(self, steg_match: SteganographyMatch) -> ExactMatch:
        """Convert SteganographyMatch to ExactMatch."""
        location = Location(
            offset=steg_match.location,
            length=steg_match.size_estimate
        )
        
        # Build evidence description
        evidence_parts = [steg_match.evidence]
        if steg_match.extraction_command:
            evidence_parts.append(f"Extraction: {steg_match.extraction_command}")
        
        return ExactMatch(
            artifact_type="steganography",
            value=f"Hidden {steg_match.hidden_type} file" if steg_match.hidden_type else "Hidden data",
            location=location,
            database_entry={
                'technique': steg_match.technique,
                'extraction_command': steg_match.extraction_command
            },
            malware_family="Steganography",
            confidence=steg_match.confidence,
            references=[
                "Common in C2 communications",
                "Used for data exfiltration",
                "Payload delivery mechanism"
            ],
            mitre_category="T1027.003 - Steganography"
        )
    
    def _to_suspicious(self, steg_match: SteganographyMatch) -> SuspiciousArtifact:
        """Convert SteganographyMatch to SuspiciousArtifact."""
        from models_v3 import Severity
        
        location = Location(
            offset=steg_match.location,
            length=steg_match.size_estimate
        )
        
        # Determine severity based on confidence and technique
        if steg_match.confidence >= 0.8:
            severity = Severity.HIGH
        elif steg_match.confidence >= 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        
        context_parts = [steg_match.evidence]
        if steg_match.extraction_command:
            context_parts.append(f"Extract with: {steg_match.extraction_command}")
        
        return SuspiciousArtifact(
            artifact_type="steganography",
            value=steg_match.technique,
            location=location,
            severity=severity,
            confidence=steg_match.confidence,
            context="\n".join(context_parts),
            observed_in=["APT groups", "Malware campaigns", "Data exfiltration"],
            mitre_category="T1027.003 - Steganography"
        )
    
    def _to_informational(self, steg_match: SteganographyMatch) -> InformationalArtifact:
        """Convert SteganographyMatch to InformationalArtifact."""
        location = Location(
            offset=steg_match.location,
            length=steg_match.size_estimate
        ) if steg_match.location > 0 else None
        
        return InformationalArtifact(
            artifact_type="file_characteristic",
            value=steg_match.technique,
            location=location,
            description=steg_match.evidence,
            benign=False  # Size anomalies are noteworthy
        )
