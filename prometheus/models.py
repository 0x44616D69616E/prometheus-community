"""
PROMETHEUS COMMUNITY EDITION - CORE DATA MODELS

Simplified models for malware analysis results.
Enterprise Edition includes knowledge graph and advanced features.

Copyright (c) 2026 Damian Donahue
License: See LICENSE file
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import hashlib


# ==================================================
# ENUMS
# ==================================================

class FileType(str, Enum):
    """Detected file type."""
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    PDF = "pdf"
    OFFICE = "office"
    SCRIPT = "script"
    ARCHIVE = "archive"
    ZIP = "zip"
    RAW = "raw"
    UNKNOWN = "unknown"


class Platform(str, Enum):
    """Target platform."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


# ==================================================
# CORE MODELS
# ==================================================

@dataclass
class Sample:
    """
    Analyzed binary sample.
    """
    # Hashes
    sha256: str
    md5: str
    sha1: str
    
    # Metadata
    filename: str
    file_size: int
    file_type: FileType
    
    # Timestamps
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
    
    # Classification
    family: Optional[str] = None
    platform: Optional[Platform] = None
    tags: List[str] = field(default_factory=list)
    
    @classmethod
    def from_file(cls, file_path: str, file_data: bytes) -> 'Sample':
        """Create Sample from file."""
        import os
        
        return cls(
            sha256=hashlib.sha256(file_data).hexdigest(),
            md5=hashlib.md5(file_data).hexdigest(),
            sha1=hashlib.sha1(file_data).hexdigest(),
            filename=os.path.basename(file_path),
            file_size=len(file_data),
            file_type=FileType.UNKNOWN
        )


@dataclass
class SignatureMatch:
    """A matched signature."""
    signature_name: str
    category: str
    confidence: float = 1.0


@dataclass
class BehavioralMatch:
    """A matched behavioral indicator."""
    family: str
    indicator_type: str
    matched_value: str
    confidence: float = 0.8


@dataclass
class ExploitMatch:
    """A matched exploit pattern."""
    technique: str
    pattern_type: str
    offset: int
    severity: str = "medium"


@dataclass
class StaticAnalysis:
    """Static analysis results."""
    entropy: float
    is_packed: bool
    packer_name: Optional[str] = None
    signature_matches: List[SignatureMatch] = field(default_factory=list)
    strings_count: int = 0


@dataclass
class AnalysisResult:
    """
    Complete analysis result for a sample.
    
    Community Edition provides core detection.
    Enterprise Edition adds knowledge graph, advanced reporting, etc.
    """
    # Sample info
    sample: Sample
    
    # Detection results
    family: str = "Unknown"
    confidence: float = 0.0
    
    # Layer results
    static: Optional[StaticAnalysis] = None
    behavioral_matches: List[BehavioralMatch] = field(default_factory=list)
    exploit_matches: List[ExploitMatch] = field(default_factory=list)
    
    # Extracted intelligence
    iocs: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            'sample': {
                'filename': self.sample.filename,
                'sha256': self.sample.sha256,
                'md5': self.sample.md5,
                'sha1': self.sample.sha1,
                'file_size': self.sample.file_size,
                'file_type': self.sample.file_type.value,
            },
            'detection': {
                'family': self.family,
                'confidence': round(self.confidence, 2),
            },
            'layers': {
                'signatures': len(self.static.signature_matches) if self.static else 0,
                'behavioral': len(self.behavioral_matches),
                'exploits': len(self.exploit_matches),
            },
            'intelligence': {
                'iocs': self.iocs,
                'ttps': self.ttps,
            },
            'metadata': {
                'analyzed_at': self.sample.analyzed_at.isoformat(),
                'duration_seconds': round(self.analysis_duration, 3),
            }
        }
