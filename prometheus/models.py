"""
PROMETHEUS COMMUNITY EDITION - ENHANCED MODELS WITH LOCATION TRACKING

Models with location data for forensic analysis.

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
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


class Severity(str, Enum):
    """Indicator severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Uniqueness(str, Enum):
    """How unique an indicator is."""
    UNIQUE = "unique"      # Only seen in one family
    RARE = "rare"          # Seen in 2-3 families
    COMMON = "common"      # Seen in many families


# ==================================================
# LOCATION MODELS
# ==================================================

@dataclass
class Location:
    """Precise location of a finding in the file."""
    offset: int  # Byte offset from start of file
    length: int  # Length of the matched data
    section: Optional[str] = None  # PE section name (.text, .data, etc.)
    line_number: Optional[int] = None  # For text files
    context: Optional[str] = None  # Surrounding bytes/text for context
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'offset': self.offset,
            'offset_hex': f"0x{self.offset:08x}",
            'length': self.length
        }
        if self.section:
            result['section'] = self.section
        if self.line_number:
            result['line_number'] = self.line_number
        if self.context:
            result['context'] = self.context
        return result
    
    def __str__(self) -> str:
        """Human-readable location."""
        parts = [f"offset 0x{self.offset:08x}"]
        if self.section:
            parts.append(f"section {self.section}")
        if self.line_number:
            parts.append(f"line {self.line_number}")
        return ", ".join(parts)


# ==================================================
# CORE MODELS
# ==================================================

@dataclass
class Sample:
    """Analyzed binary sample."""
    sha256: str
    md5: str
    sha1: str
    filename: str
    file_size: int
    file_type: FileType
    analyzed_at: datetime = field(default_factory=datetime.utcnow)
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
    """A matched file signature with location."""
    signature_name: str
    category: str
    location: Location
    confidence: float = 1.0
    explanation: Optional[str] = None
    context: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'signature': self.signature_name,
            'category': self.category,
            'location': self.location.to_dict(),
            'confidence': self.confidence
        }


@dataclass
class BehavioralMatch:
    """Enhanced behavioral match with location and full context."""
    family: str
    indicator_type: str
    matched_value: str
    location: Location  # Where in the file this was found
    
    # Rich metadata for explainability
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    uniqueness: Uniqueness = Uniqueness.COMMON
    explanation: str = ""
    commonly_found_in: List[str] = field(default_factory=list)
    ttp_category: str = ""
    context: str = ""
    
    def get_severity_icon(self) -> str:
        """Get emoji for severity."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "⚪"
        }
        return icons.get(self.severity, "⚪")
    
    def get_uniqueness_badge(self) -> str:
        """Get badge for uniqueness."""
        badges = {
            Uniqueness.UNIQUE: "💎 UNIQUE",
            Uniqueness.RARE: "⭐ RARE",
            Uniqueness.COMMON: "📋 COMMON"
        }
        return badges.get(self.uniqueness, "")
    
    def is_high_confidence(self) -> bool:
        """Check if this is a high-confidence indicator."""
        return self.confidence >= 0.8 or self.uniqueness == Uniqueness.UNIQUE
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'family': self.family,
            'type': self.indicator_type,
            'value': self.matched_value,
            'location': self.location.to_dict(),
            'severity': self.severity.value,
            'confidence': self.confidence,
            'uniqueness': self.uniqueness.value,
            'explanation': self.explanation
        }


@dataclass
class ExploitMatch:
    """Enhanced exploit pattern match with location."""
    technique: str
    pattern_type: str
    location: Location  # Where the pattern was found
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.7
    explanation: str = ""
    context: str = ""
    ttp_category: str = ""
    commonly_found_in: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    mitre_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            'technique': self.technique,
            'pattern_type': self.pattern_type,
            'location': self.location.to_dict(),
            'severity': self.severity.value,
            'confidence': self.confidence
        }
        if self.cve:
            result['cve'] = self.cve
        if self.mitre_id:
            result['mitre_id'] = self.mitre_id
        return result


@dataclass
class StringMatch:
    """A matched string with its location."""
    value: str
    location: Location
    category: str  # 'url', 'ip', 'email', 'path', 'generic'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'value': self.value,
            'location': self.location.to_dict(),
            'category': self.category
        }


@dataclass
class StaticAnalysis:
    """Static analysis results."""
    entropy: float
    is_packed: bool
    packer_name: Optional[str] = None
    signature_matches: List[SignatureMatch] = field(default_factory=list)
    strings: List[StringMatch] = field(default_factory=list)
    strings_count: int = 0


@dataclass
class DetectionReasoning:
    """Explanation of why a family was detected."""
    family: str
    confidence: float
    unique_indicator_count: int
    total_indicator_count: int
    reasoning: str
    key_indicators: List[str] = field(default_factory=list)
    
    def __str__(self) -> str:
        """Human-readable reasoning."""
        return f"{self.family} ({self.confidence:.0%}): {self.reasoning}"


@dataclass
class AnalysisResult:
    """Complete analysis result with reasoning and locations."""
    sample: Sample
    
    # Detection results
    family: str = "Unknown"
    confidence: float = 0.0
    reasoning: Optional[DetectionReasoning] = None
    
    # Layer results with locations
    static: Optional[StaticAnalysis] = None
    behavioral_matches: List[BehavioralMatch] = field(default_factory=list)
    exploit_matches: List[ExploitMatch] = field(default_factory=list)
    
    # Extracted intelligence
    iocs: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    
    # Metadata
    analysis_duration: float = 0.0
    
    def get_unique_indicators(self) -> List[BehavioralMatch]:
        """Get all unique/rare indicators."""
        return [m for m in self.behavioral_matches 
                if m.uniqueness in [Uniqueness.UNIQUE, Uniqueness.RARE]]
    
    def get_critical_indicators(self) -> List[BehavioralMatch]:
        """Get critical severity indicators."""
        return [m for m in self.behavioral_matches 
                if m.severity == Severity.CRITICAL]
    
    def get_locations_map(self) -> Dict[str, List[int]]:
        """Get map of finding types to their offsets."""
        locations = {}
        
        # Signature locations
        locations['signatures'] = [m.location.offset for m in self.static.signature_matches] if self.static else []
        
        # Behavioral indicator locations
        locations['behavioral'] = [m.location.offset for m in self.behavioral_matches]
        
        # Exploit pattern locations
        locations['exploits'] = [m.location.offset for m in self.exploit_matches]
        
        return locations
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON output."""
        result = {
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
        
        # Add reasoning if available
        if self.reasoning:
            result['detection']['reasoning'] = {
                'explanation': self.reasoning.reasoning,
                'unique_indicators': self.reasoning.unique_indicator_count,
                'total_indicators': self.reasoning.total_indicator_count,
                'key_indicators': self.reasoning.key_indicators
            }
        
        # Add detailed behavioral matches with locations
        if self.behavioral_matches:
            result['behavioral_details'] = [m.to_dict() for m in self.behavioral_matches]
        
        # Add exploit matches with locations
        if self.exploit_matches:
            result['exploit_details'] = [m.to_dict() for m in self.exploit_matches]
        
        # Add signature matches with locations
        if self.static and self.static.signature_matches:
            result['signature_details'] = [m.to_dict() for m in self.static.signature_matches]
        
        # Add location map
        result['location_map'] = self.get_locations_map()
        
        return result
