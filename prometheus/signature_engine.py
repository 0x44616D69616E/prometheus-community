"""
PROMETHEUS COMMUNITY EDITION - SIGNATURE ENGINE

Simplified signature matching for malware detection.

Copyright (c) 2026 Damian Donahue
"""

import json
import re
import math
from pathlib import Path
from typing import List
from .models import SignatureMatch


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    entropy = 0.0
    for x in range(256):
        p_x = data.count(bytes([x])) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Extract printable strings from binary data."""
    pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
    strings = re.findall(pattern, data)
    return [s.decode('ascii', errors='ignore') for s in strings[:100]]  # Limit to 100


class SignatureEngine:
    """Simple signature matching engine."""
    
    def __init__(self, intelligence_db: dict):
        """Initialize with intelligence database."""
        self.signatures = intelligence_db.get('file_signatures', [])
        print(f"Loaded {len(self.signatures)} file signatures")
    
    def scan(self, data: bytes) -> List[SignatureMatch]:
        """Scan data for signature matches."""
        matches = []
        
        for sig in self.signatures:
            try:
                pattern = sig.get('hex_pattern', '')
                # Remove b' and ' from pattern string
                pattern = pattern.replace("b'", "").replace("'", "")
                
                # Convert hex pattern to bytes
                try:
                    # Handle escaped sequences
                    pattern_bytes = pattern.encode('utf-8').decode('unicode_escape').encode('latin1')
                except:
                    continue
                
                # Search for pattern
                if pattern_bytes in data:
                    matches.append(SignatureMatch(
                        signature_name=sig.get('format_name', 'Unknown'),
                        category=sig.get('category', 'unknown')
                    ))
            except Exception:
                continue
        
        return matches
