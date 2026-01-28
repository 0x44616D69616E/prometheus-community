"""
PROMETHEUS COMMUNITY EDITION - BEHAVIORAL DETECTOR

Detects malware by behavioral indicators.

Copyright (c) 2026 Damian Donahue
"""

from typing import List, Dict, Any
from .models import BehavioralMatch


class BehavioralDetector:
    """Behavioral indicator detection."""
    
    def __init__(self, intelligence_db: dict):
        """Initialize with intelligence database."""
        self.indicators = intelligence_db.get('behavioral_indicators', [])
        print(f"Loaded {len(self.indicators)} behavioral indicators")
    
    def detect(self, data: Dict[str, Any]) -> List[BehavioralMatch]:
        """Detect behavioral indicators in sample data."""
        matches = []
        
        content = data.get('content', b'')
        strings = data.get('strings', [])
        
        # Convert bytes to string for searching
        try:
            content_str = content.decode('utf-8', errors='ignore')
        except:
            content_str = str(content)
        
        for indicator in self.indicators:
            family = indicator.get('family', 'Unknown')
            indicator_type = indicator.get('indicator_type', 'unknown')
            value = indicator.get('value', '')
            
            # Search in content and strings
            found = False
            if value:
                if value.lower() in content_str.lower():
                    found = True
                elif any(value.lower() in s.lower() for s in strings):
                    found = True
            
            if found:
                matches.append(BehavioralMatch(
                    family=family,
                    indicator_type=indicator_type,
                    matched_value=value
                ))
        
        return matches
