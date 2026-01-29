"""
PROMETHEUS - BEHAVIORAL DETECTOR WITH LOCATION TRACKING

Enhanced to show exactly WHERE behavioral indicators are found.

Copyright (c) 2026 Damian Donahue
"""

from typing import List, Dict, Any
from .models import BehavioralMatch, Location, Severity, Uniqueness


class BehavioralDetector:
    """
    Behavioral indicator detection with location tracking.
    
    Detects malware families based on behavioral indicators.
    Now tracks EXACTLY where each indicator is found.
    """
    
    def __init__(self, intel_db: Dict[str, Any]):
        """Initialize with intelligence database."""
        self.indicators = intel_db.get('behavioral_indicators', [])
    
    def detect(self, data: Dict[str, Any]) -> List[BehavioralMatch]:
        """
        Detect behavioral indicators and return matches with locations.
        
        Args:
            data: Dict with 'content' (bytes), 'strings' (list of dicts), 'filename' (str)
            
        Returns:
            List of BehavioralMatch objects with location data
        """
        matches = []
        
        content = data.get('content', b'')
        strings = data.get('strings', [])  # Now list of dicts with 'value', 'offset', 'length'
        
        # Convert content to string for pattern matching
        try:
            content_str = content.decode('utf-8', errors='ignore')
        except:
            content_str = str(content)
        
        for indicator in self.indicators:
            family = indicator.get('family', 'Unknown')
            indicator_type = indicator.get('indicator_type', 'unknown')
            value = indicator.get('value', '')
            
            # Clean up value (remove backticks)
            value = value.strip('`')
            
            if not value:
                continue
            
            # Search for indicator in strings (with location data)
            for string_data in strings:
                string_value = string_data.get('value', '')
                if value.lower() in string_value.lower():
                    # Found in a string - we have exact location!
                    location = Location(
                        offset=string_data.get('offset', 0),
                        length=string_data.get('length', len(string_value)),
                        context=f"String: {string_value[:60]}..."
                    )
                    
                    matches.append(self._create_match(indicator, value, location))
                    break  # Only match once per indicator
            else:
                # Not found in strings, search in raw content
                value_bytes = value.encode('utf-8', errors='ignore')
                idx = content.find(value_bytes)
                
                if idx != -1:
                    # Found in raw content
                    # Get context
                    context_start = max(0, idx - 20)
                    context_end = min(len(content), idx + len(value_bytes) + 20)
                    context_bytes = content[context_start:context_end]
                    
                    try:
                        context_str = context_bytes.decode('utf-8', errors='ignore')
                    except:
                        context_str = ' '.join(f'{b:02x}' for b in context_bytes[:40])
                    
                    location = Location(
                        offset=idx,
                        length=len(value_bytes),
                        context=context_str[:80]
                    )
                    
                    matches.append(self._create_match(indicator, value, location))
        
        return matches
    
    def _create_match(self, indicator: Dict, value: str, location: Location) -> BehavioralMatch:
        """Create a BehavioralMatch with full metadata."""
        return BehavioralMatch(
            family=indicator.get('family', 'Unknown'),
            indicator_type=indicator.get('indicator_type', 'unknown'),
            matched_value=value,
            location=location,
            severity=Severity(indicator.get('severity', 'medium')),
            confidence=indicator.get('confidence_weight', 0.5),
            uniqueness=Uniqueness(indicator.get('uniqueness', 'common')),
            explanation=indicator.get('explanation', ''),
            commonly_found_in=indicator.get('commonly_found_in', []),
            ttp_category=indicator.get('ttp_category', ''),
            context=indicator.get('context', '')
        )
