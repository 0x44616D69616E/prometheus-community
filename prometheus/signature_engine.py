"""
PROMETHEUS - SIGNATURE ENGINE WITH LOCATION TRACKING

Enhanced to show exactly WHERE signatures are found.

Copyright (c) 2026 Damian Donahue
"""

from typing import List, Dict, Any
from .models import SignatureMatch, Location
import re


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    from collections import Counter
    import math
    
    counts = Counter(data)
    length = len(data)
    
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
    """
    Extract printable strings with their locations.
    
    Returns list of dicts with 'value', 'offset', 'length'
    """
    strings = []
    current_string = bytearray()
    start_offset = 0
    
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # Printable ASCII
            if not current_string:
                start_offset = i
            current_string.append(byte)
        else:
            if len(current_string) >= min_length:
                try:
                    string_value = current_string.decode('ascii', errors='ignore')
                    strings.append({
                        'value': string_value,
                        'offset': start_offset,
                        'length': len(current_string)
                    })
                except:
                    pass
            current_string = bytearray()
    
    # Handle final string
    if len(current_string) >= min_length:
        try:
            string_value = current_string.decode('ascii', errors='ignore')
            strings.append({
                'value': string_value,
                'offset': start_offset,
                'length': len(current_string)
            })
        except:
            pass
    
    return strings[:1000]  # Limit to first 1000 strings


class SignatureEngine:
    """
    Signature-based detection with location tracking.
    
    Scans binary data for known file format signatures and patterns.
    Now tracks EXACTLY where each signature is found.
    """
    
    def __init__(self, intel_db: Dict[str, Any]):
        """Initialize with intelligence database."""
        self.signatures = intel_db.get('file_signatures', [])
    
    def scan(self, data: bytes) -> List[SignatureMatch]:
        """
        Scan data for file signatures and return matches with locations.
        
        Args:
            data: Binary data to scan
            
        Returns:
            List of SignatureMatch objects with location data
        """
        matches = []
        
        for sig in self.signatures:
            format_name = sig.get('format_name', 'Unknown')
            hex_pattern = sig.get('hex_pattern', '')
            offset_hint = sig.get('offset', 0)
            category = sig.get('category', 'unknown')
            
            # Convert hex pattern to bytes
            try:
                # Remove b' and ' wrapper, handle escape sequences
                pattern_str = hex_pattern.strip("b'\"")
                pattern_bytes = bytes(pattern_str, 'utf-8').decode('unicode_escape').encode('latin1')
            except:
                continue
            
            # Search for pattern in data
            search_offset = 0
            while True:
                idx = data.find(pattern_bytes, search_offset)
                if idx == -1:
                    break
                
                # Found a match!
                # Get some context (16 bytes before and after)
                context_start = max(0, idx - 16)
                context_end = min(len(data), idx + len(pattern_bytes) + 16)
                context_bytes = data[context_start:context_end]
                context_hex = ' '.join(f'{b:02x}' for b in context_bytes)
                
                # Create location object
                location = Location(
                    offset=idx,
                    length=len(pattern_bytes),
                    context=context_hex
                )
                
                # Create match
                match = SignatureMatch(
                    signature_name=format_name,
                    category=category,
                    location=location,
                    confidence=sig.get('confidence_weight', 1.0),
                    explanation=sig.get('explanation', ''),
                    context=sig.get('context', '')
                )
                
                matches.append(match)
                
                # Continue searching for more instances
                search_offset = idx + 1
                
                # Limit matches per signature to avoid flooding
                if len([m for m in matches if m.signature_name == format_name]) >= 3:
                    break
        
        return matches
