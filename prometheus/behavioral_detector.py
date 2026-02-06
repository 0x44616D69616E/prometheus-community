"""
PROMETHEUS - BEHAVIORAL DETECTOR WITH CONTEXT VALIDATION

Enhanced behavioral detection with comprehensive context validation.
Validates ALL patterns to prevent false positives from random data.

Copyright (c) 2026 Damian Donahue
"""

from typing import List, Dict, Any, Tuple
from prometheus.models import (
    ExactMatch, SuspiciousArtifact, InformationalArtifact,
    Location, Severity, Uniqueness, ClassificationTier
)
from prometheus.context_validator import ContextValidator
from prometheus.config import PrometheusConfig


class BehavioralDetector:
    """
    Behavioral indicator detection with context validation.
    
    Key improvements over v2:
    - Validates ALL patterns in proper context
    - Three-tier classification (EXACT/SUSPICIOUS/INFO)
    - Configurable validation strictness
    - Prevents false positives from random bytes
    """
    
    def __init__(self, intel_db: Dict[str, Any], config: PrometheusConfig):
        """
        Initialize detector with intelligence database and config.
        
        Args:
            intel_db: Intelligence database dictionary
            config: Prometheus configuration
        """
        self.indicators = intel_db.get('behavioral_indicators', [])
        self.config = config
        self.validator = ContextValidator(config)
    
    def detect(self, data: Dict[str, Any]) -> Tuple[List[ExactMatch], 
                                                      List[SuspiciousArtifact],
                                                      List[InformationalArtifact]]:
        """
        Detect behavioral indicators with context validation.
        
        Args:
            data: Dict with 'content' (bytes), 'strings' (list), 'filename' (str)
            
        Returns:
            Tuple of (exact_matches, suspicious_artifacts, informational_artifacts)
        """
        exact_matches = []
        suspicious_artifacts = []
        informational_artifacts = []
        
        content = data.get('content', b'')
        strings = data.get('strings', [])
        
        # Convert content to string for pattern matching
        try:
            content_str = content.decode('utf-8', errors='ignore')
        except:
            content_str = str(content)
        
        for indicator in self.indicators:
            family = indicator.get('family', 'Unknown')
            indicator_type = indicator.get('indicator_type', 'unknown')
            value = indicator.get('value', '').strip('`')
            
            if not value:
                continue
            
            # Search for indicator in strings (with location data)
            for string_data in strings:
                string_value = string_data.get('value', '')
                
                if value.lower() in string_value.lower():
                    # Found the pattern - now validate context
                    is_valid, extracted_or_reason = self._validate_pattern(
                        string_value, value, indicator_type
                    )
                    
                    if not is_valid:
                        # Context validation failed - skip this match
                        continue
                    
                    # Valid context - create appropriate artifact
                    location = Location(
                        offset=string_data.get('offset', 0),
                        length=string_data.get('length', len(string_value))
                    )
                    
                    artifact = self._classify_and_create_artifact(
                        indicator, extracted_or_reason, location
                    )
                    
                    # Add to appropriate tier
                    if isinstance(artifact, ExactMatch):
                        exact_matches.append(artifact)
                    elif isinstance(artifact, SuspiciousArtifact):
                        suspicious_artifacts.append(artifact)
                    else:
                        informational_artifacts.append(artifact)
                    
                    break  # Only match once per indicator
            else:
                # Not found in strings, search in raw content
                value_bytes = value.encode('utf-8', errors='ignore')
                idx = content.find(value_bytes)
                
                if idx != -1:
                    # Found in raw content - validate context
                    context_start = max(0, idx - 100)
                    context_end = min(len(content), idx + len(value_bytes) + 100)
                    context_segment = content[context_start:context_end]
                    
                    try:
                        context_str = context_segment.decode('utf-8', errors='ignore')
                    except:
                        context_str = ''
                    
                    # Validate context
                    is_valid, extracted_or_reason = self._validate_pattern(
                        context_str, value, indicator_type
                    )
                    
                    if not is_valid:
                        # Context validation failed
                        continue
                    
                    # Valid context - create artifact
                    location = Location(
                        offset=idx,
                        length=len(value_bytes)
                    )
                    
                    artifact = self._classify_and_create_artifact(
                        indicator, extracted_or_reason, location
                    )
                    
                    # Add to appropriate tier
                    if isinstance(artifact, ExactMatch):
                        exact_matches.append(artifact)
                    elif isinstance(artifact, SuspiciousArtifact):
                        suspicious_artifacts.append(artifact)
                    else:
                        informational_artifacts.append(artifact)
        
        return exact_matches, suspicious_artifacts, informational_artifacts
    
    def _validate_pattern(self, string: str, pattern: str, 
                         indicator_type: str) -> Tuple[bool, str]:
        """
        Validate that pattern appears in proper context.
        
        Args:
            string: String containing the pattern
            pattern: The pattern to validate
            indicator_type: Type of indicator
            
        Returns:
            Tuple of (is_valid, extracted_value_or_reason)
        """
        if not self.config.enable_context_validation:
            # Context validation disabled - accept everything
            return True, pattern
        
        return self.validator.validate_general_pattern(string, pattern, indicator_type)
    
    def _classify_and_create_artifact(self, indicator: Dict, value: str, 
                                      location: Location):
        """
        Classify indicator and create appropriate artifact type.
        
        Uses uniqueness rating to determine tier:
        - UNIQUE indicators → ExactMatch (Tier 1)
        - RARE indicators → SuspiciousArtifact (Tier 2)
        - COMMON indicators → SuspiciousArtifact or Informational (Tier 2/3)
        
        Args:
            indicator: Indicator database entry
            value: Matched value
            location: Location where found
            
        Returns:
            ExactMatch, SuspiciousArtifact, or InformationalArtifact
        """
        uniqueness_str = indicator.get('uniqueness', 'common')
        uniqueness = Uniqueness(uniqueness_str)
        severity_str = indicator.get('severity', 'medium')
        severity = Severity(severity_str)
        family = indicator.get('family', 'Unknown')
        
        # UNIQUE indicators are EXACT matches (Tier 1)
        if uniqueness == Uniqueness.UNIQUE:
            return ExactMatch(
                artifact_type=indicator.get('indicator_type', 'unknown'),
                value=value,
                location=location,
                database_entry=indicator,
                malware_family=family,
                confidence=1.0,
                uniqueness=Uniqueness.UNIQUE,
                first_seen=indicator.get('first_seen'),
                references=indicator.get('references', []),
                mitre_category=indicator.get('ttp_category')
            )
        
        # RARE and HIGH/CRITICAL severity → SUSPICIOUS (Tier 2)
        elif uniqueness == Uniqueness.RARE or severity in [Severity.HIGH, Severity.CRITICAL]:
            return SuspiciousArtifact(
                artifact_type=indicator.get('indicator_type', 'unknown'),
                value=value,
                location=location,
                severity=severity,
                confidence=indicator.get('confidence_weight', 0.5),
                context=indicator.get('context', ''),
                observed_in=[family],
                also_found_in=indicator.get('also_found_in'),
                uniqueness=uniqueness,
                mitre_category=indicator.get('ttp_category')
            )
        
        # COMMON and LOW/INFO severity → INFORMATIONAL (Tier 3)
        else:
            return InformationalArtifact(
                artifact_type=indicator.get('indicator_type', 'unknown'),
                value=value,
                location=location,
                description=indicator.get('explanation', ''),
                benign=(severity == Severity.INFO)
            )
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get statistics about loaded indicators.
        
        Returns:
            Dictionary with indicator counts by tier
        """
        unique_count = sum(1 for i in self.indicators if i.get('uniqueness') == 'unique')
        rare_count = sum(1 for i in self.indicators if i.get('uniqueness') == 'rare')
        common_count = len(self.indicators) - unique_count - rare_count
        
        return {
            'total': len(self.indicators),
            'unique': unique_count,
            'rare': rare_count,
            'common': common_count
        }
