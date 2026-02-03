"""
PROMETHEUS v3.0.0 - DATA MODELS

Enhanced models with 3-tier classification system:
- EXACT MATCHES: Definitive signatures (100% certain)
- SUSPICIOUS: Patterns that warrant investigation
- INFORMATIONAL: Context and metadata

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import hashlib
import os


class ClassificationTier(Enum):
    """Three-tier classification system for artifacts."""
    EXACT = "exact"           # Definitive match - 100% certain
    SUSPICIOUS = "suspicious" # Pattern match - warrants investigation
    INFORMATIONAL = "info"    # Context/metadata - not inherently malicious


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Uniqueness(Enum):
    """Uniqueness ratings for indicators."""
    UNIQUE = "unique"     # Appears in only one malware family
    RARE = "rare"         # Appears in few families
    COMMON = "common"     # Appears in many places


class FileType(Enum):
    """File type classifications."""
    PE = "PE"
    ELF = "ELF"
    MACHO = "Mach-O"
    PDF = "PDF"
    ZIP = "ZIP"
    JPEG = "JPEG"
    PNG = "PNG"
    GIF = "GIF"
    BMP = "BMP"
    UNKNOWN = "unknown"


@dataclass
class Location:
    """Precise location of an artifact in a file."""
    offset: int
    length: int = 0
    section: Optional[str] = None
    context_before: bytes = b''
    context_after: bytes = b''
    
    def __str__(self) -> str:
        return f"0x{self.offset:08x}"


@dataclass
class ExactMatch:
    """
    TIER 1: Exact signature match - definitive identification.
    
    These are 100% certain matches to known unique signatures.
    No interpretation needed - the artifact IS what the database says it is.
    """
    artifact_type: str              # "mutex", "registry_key", "hash", "signature"
    value: str                      # The actual value found
    location: Location              # Exact offset in file
    database_entry: Dict[str, Any]  # Full database record
    malware_family: str             # e.g., "WannaCry", "Cerber"
    confidence: float = 1.0         # Always 1.0 for exact matches
    uniqueness: Uniqueness = Uniqueness.UNIQUE
    first_seen: Optional[str] = None
    references: List[str] = field(default_factory=list)  # CVEs, reports, MITRE
    mitre_category: Optional[str] = None
    
    def get_assessment(self) -> str:
        """Generate assessment text for exact match."""
        return f"DEFINITIVE - This IS {self.malware_family} (exact signature match)"


@dataclass
class SuspiciousArtifact:
    """
    TIER 2: Suspicious pattern - requires investigation.
    
    These patterns are seen in malware but not unique to one family.
    Could be malicious OR could appear in legitimate software.
    """
    artifact_type: str              # "pattern", "behavior", "structure"
    value: str                      # What was found
    location: Location              # Where it was found
    severity: Severity              # How concerning this is
    confidence: float               # 0.0-1.0 (never 1.0, that's EXACT)
    context: str                    # Surrounding context/explanation
    observed_in: List[str]          # Malware families this appears in
    also_found_in: Optional[str] = None  # Legitimate uses (if any)
    uniqueness: Uniqueness = Uniqueness.COMMON
    mitre_category: Optional[str] = None
    
    def get_assessment(self) -> str:
        """Generate assessment text for suspicious artifact."""
        if self.also_found_in:
            return f"SUSPICIOUS - Common in {', '.join(self.observed_in[:2])}, but {self.also_found_in}"
        return f"SUSPICIOUS - Observed in {', '.join(self.observed_in[:2])}"


@dataclass  
class InformationalArtifact:
    """
    TIER 3: Informational - context and metadata.
    
    These provide context about the file but aren't inherently malicious.
    File types, software signatures, metadata, etc.
    """
    artifact_type: str              # "file_type", "metadata", "software_signature"
    value: str                      # The information
    location: Optional[Location] = None  # May not have specific location
    description: str = ""           # What this tells us
    benign: bool = True             # True if this is expected/normal
    
    def get_assessment(self) -> str:
        """Generate assessment text for informational artifact."""
        if self.benign:
            return "BENIGN - Normal/expected artifact"
        return "NEUTRAL - Informational only, not inherently malicious"


@dataclass
class FileTypeValidationResult:
    """Results from file type validation."""
    filename_type: str              # Type based on extension
    content_type: str               # Type based on magic bytes
    detected_types: List[str]       # All detected types
    match: bool                     # Does extension match content?
    warning: Optional[str] = None   # Warning message if mismatch
    suspicious: bool = False        # Is this suspicious?
    polyglot: bool = False          # Valid as multiple formats?


@dataclass
class Sample:
    """Information about the analyzed file."""
    filename: str
    file_path: str
    file_size: int
    sha256: str
    md5: str
    sha1: str
    file_type: FileType = FileType.UNKNOWN
    
    @classmethod
    def from_file(cls, file_path: str, content: bytes) -> 'Sample':
        """Create Sample from file."""
        return cls(
            filename=os.path.basename(file_path),
            file_path=file_path,
            file_size=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            md5=hashlib.md5(content).hexdigest(),
            sha1=hashlib.sha1(content).hexdigest()
        )


@dataclass
class StaticAnalysis:
    """Static analysis results."""
    entropy: float
    is_packed: bool
    signature_matches: List[Any] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    strings_count: int = 0


@dataclass
class AnalysisResult:
    """
    Complete analysis results with 3-tier classification.
    
    Organizes all findings into three tiers:
    - EXACT: Definitive identifications
    - SUSPICIOUS: Patterns requiring investigation  
    - INFORMATIONAL: Context and metadata
    """
    sample: Sample
    
    # Three-tier classification
    exact_matches: List[ExactMatch] = field(default_factory=list)
    suspicious_artifacts: List[SuspiciousArtifact] = field(default_factory=list)
    informational: List[InformationalArtifact] = field(default_factory=list)
    
    # File type validation
    file_type_validation: Optional[FileTypeValidationResult] = None
    
    # Static analysis
    static: Optional[StaticAnalysis] = None
    
    # Legacy compatibility (for gradual migration)
    behavioral_matches: List[Any] = field(default_factory=list)
    exploit_matches: List[Any] = field(default_factory=list)
    
    # Metadata
    analysis_duration: float = 0.0
    iocs: List[str] = field(default_factory=list)
    ttps: List[str] = field(default_factory=list)
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary counts."""
        return {
            'exact_matches': len(self.exact_matches),
            'suspicious': len(self.suspicious_artifacts),
            'informational': len(self.informational),
            'total': len(self.exact_matches) + len(self.suspicious_artifacts) + len(self.informational)
        }
    
    def get_malware_families(self) -> List[str]:
        """Get all malware families from exact matches."""
        return list(set(m.malware_family for m in self.exact_matches))
    
    def get_assessment(self) -> str:
        """Generate overall assessment."""
        exact_count = len(self.exact_matches)
        suspicious_count = len(self.suspicious_artifacts)
        
        if exact_count > 0:
            families = self.get_malware_families()
            if len(families) == 1:
                return f"HIGH CONFIDENCE - Contains definitive {families[0]} signatures"
            else:
                return f"HIGH CONFIDENCE - Contains signatures from multiple families: {', '.join(families)}"
        elif suspicious_count > 5:
            return "MEDIUM CONFIDENCE - Multiple suspicious patterns detected, manual review recommended"
        elif suspicious_count > 0:
            return "LOW CONFIDENCE - Some suspicious patterns, could be legitimate software"
        else:
            return "NO MALWARE DETECTED - No known malicious signatures found"


@dataclass
class DetectionReasoning:
    """Reasoning for detection decisions (legacy compatibility)."""
    family: str
    confidence: float
    unique_indicator_count: int
    total_indicator_count: int
    reasoning: str
    key_indicators: List[str] = field(default_factory=list)
