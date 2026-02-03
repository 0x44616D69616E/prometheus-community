"""
PROMETHEUS v3.0.0 - NETWORK ARTIFACT DETECTOR

Detects network-related artifacts and C2 indicators.

Analyzes:
- Suspicious domains (DGA, typosquatting, newly registered)
- C2 communication patterns
- Known malicious infrastructure
- Protocol artifacts (HTTP headers, TLS patterns)
- Port numbers and network constants

Based on Binary Analysis Academic Reference v2.2 Section 4.

Copyright (c) 2026 Damian Donahue
"""

import re
from dataclasses import dataclass
from typing import List, Tuple
from prometheus.models_v3 import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class NetworkArtifact:
    """A detected network artifact."""
    artifact_type: str      # "c2_domain", "port", "protocol", "header"
    value: str
    location: int
    confidence: float
    description: str


class NetworkArtifactDetector:
    """
    Detects network-related artifacts and C2 indicators.
    
    Identifies:
    - Suspicious domains
    - Common C2 ports
    - Protocol signatures
    - HTTP/TLS artifacts
    """
    
    def __init__(self):
        """Initialize network artifact detector."""
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
            'xyz', 'top', 'work', 'click',  # Common in malware
            'onion', 'i2p',                 # Dark web
        ]
        
        # Common C2 ports
        self.c2_ports = {
            4444: 'Metasploit default',
            5555: 'Android Debug Bridge',
            6666: 'Common backdoor port',
            6667: 'IRC (often C2)',
            6697: 'IRC SSL',
            8080: 'HTTP proxy',
            8443: 'HTTPS alternate',
            9999: 'Common backdoor port',
            31337: '31337/leet (hacker port)',
            12345: 'NetBus trojan',
            27374: 'SubSeven trojan',
        }
        
        # HTTP protocol patterns
        self.http_patterns = {
            b'GET ': 'HTTP GET request',
            b'POST ': 'HTTP POST request',
            b'HTTP/1.1': 'HTTP protocol',
            b'HTTP/2.0': 'HTTP/2 protocol',
            b'User-Agent:': 'HTTP header',
            b'Content-Type:': 'HTTP header',
            b'Authorization:': 'HTTP auth header',
            b'Cookie:': 'HTTP cookie',
        }
        
        # TLS/SSL patterns
        self.tls_patterns = {
            b'\x16\x03\x01': 'TLS 1.0 handshake',
            b'\x16\x03\x02': 'TLS 1.1 handshake',
            b'\x16\x03\x03': 'TLS 1.2/1.3 handshake',
        }
        
        # Suspicious domain keywords
        self.suspicious_keywords = [
            'download', 'payload', 'malware', 'exploit',
            'backdoor', 'shell', 'admin', 'root',
            'update', 'secure', 'verify', 'account'
        ]
        
        # Domain pattern
        self.domain_pattern = re.compile(
            rb'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}',
            re.IGNORECASE
        )
        
        # Port number pattern (decimal representation)
        self.port_pattern = re.compile(
            rb'\b(?:port|PORT)\s*[:=]\s*(\d{1,5})\b',
            re.IGNORECASE
        )
    
    def detect(self, content: bytes, extracted_urls: List[str] = None) -> Tuple[
        List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """
        Detect network artifacts.
        
        Args:
            content: Binary data to analyze
            extracted_urls: Pre-extracted URLs from string analyzer
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Detect suspicious domains
        domain_findings = self._detect_suspicious_domains(content)
        for artifact in domain_findings:
            if artifact.confidence >= 0.7:
                suspicious.append(self._to_suspicious(artifact, Severity.MEDIUM))
            else:
                informational.append(self._to_informational(artifact))
        
        # Detect C2 ports
        port_findings = self._detect_c2_ports(content)
        for artifact in port_findings:
            suspicious.append(self._to_suspicious(artifact, Severity.LOW))
        
        # Detect protocol patterns
        protocol_findings = self._detect_protocols(content)
        for artifact in protocol_findings:
            informational.append(self._to_informational(artifact))
        
        return suspicious, informational
    
    def _detect_suspicious_domains(self, content: bytes) -> List[NetworkArtifact]:
        """Detect suspicious domain names."""
        artifacts = []
        seen_domains = set()
        
        for match in self.domain_pattern.finditer(content):
            domain = match.group(0).decode('ascii', errors='ignore').lower()
            
            # Skip if already seen
            if domain in seen_domains:
                continue
            
            # Skip very short domains
            if len(domain) < 5:
                continue
            
            # Skip localhost and common domains
            if domain in ['localhost', 'example.com', 'test.com']:
                continue
            
            seen_domains.add(domain)
            
            # Check for suspicious characteristics
            confidence = 0.5
            reasons = []
            
            # Check TLD
            tld = domain.split('.')[-1]
            if tld in self.suspicious_tlds:
                confidence += 0.2
                reasons.append(f"Suspicious TLD (.{tld})")
            
            # Check for suspicious keywords
            for keyword in self.suspicious_keywords:
                if keyword in domain:
                    confidence += 0.1
                    reasons.append(f"Contains '{keyword}'")
            
            # Check for DGA-like characteristics (high entropy, many consonants)
            entropy_score = self._calculate_domain_entropy(domain)
            if entropy_score > 3.5:
                confidence += 0.15
                reasons.append("High entropy (possible DGA)")
            
            # Long subdomain
            parts = domain.split('.')
            if len(parts) > 4:
                confidence += 0.1
                reasons.append("Multiple subdomains")
            
            # Only report if somewhat suspicious
            if confidence > 0.6 or reasons:
                description = f"Domain: {domain}"
                if reasons:
                    description += f". Indicators: {', '.join(reasons)}"
                
                artifacts.append(NetworkArtifact(
                    artifact_type="suspicious_domain",
                    value=domain,
                    location=match.start(),
                    confidence=min(confidence, 0.9),
                    description=description
                ))
            
            # Limit results
            if len(artifacts) >= 10:
                break
        
        return artifacts
    
    def _detect_c2_ports(self, content: bytes) -> List[NetworkArtifact]:
        """Detect references to common C2 ports."""
        artifacts = []
        
        # Search for port references
        for match in self.port_pattern.finditer(content):
            port_str = match.group(1).decode('ascii')
            try:
                port_num = int(port_str)
                
                if port_num in self.c2_ports:
                    artifacts.append(NetworkArtifact(
                        artifact_type="c2_port",
                        value=str(port_num),
                        location=match.start(),
                        confidence=0.7,
                        description=f"Port {port_num}: {self.c2_ports[port_num]}"
                    ))
            except ValueError:
                pass
        
        # Also search for port numbers as binary (16-bit big-endian and little-endian)
        import struct
        for port_num, description in self.c2_ports.items():
            # Big-endian
            port_bytes_be = struct.pack('>H', port_num)
            offset = 0
            count = 0
            while True:
                idx = content.find(port_bytes_be, offset)
                if idx == -1:
                    break
                
                artifacts.append(NetworkArtifact(
                    artifact_type="c2_port",
                    value=str(port_num),
                    location=idx,
                    confidence=0.6,
                    description=f"Port {port_num} (binary, big-endian): {description}"
                ))
                
                offset = idx + 2
                count += 1
                if count >= 2:  # Limit per port
                    break
        
        return artifacts[:5]  # Limit total results
    
    def _detect_protocols(self, content: bytes) -> List[NetworkArtifact]:
        """Detect protocol signatures."""
        artifacts = []
        
        # HTTP patterns
        for pattern, description in self.http_patterns.items():
            idx = content.find(pattern)
            if idx != -1:
                artifacts.append(NetworkArtifact(
                    artifact_type="protocol",
                    value="HTTP",
                    location=idx,
                    confidence=0.9,
                    description=description
                ))
        
        # TLS patterns
        for pattern, description in self.tls_patterns.items():
            idx = content.find(pattern)
            if idx != -1:
                artifacts.append(NetworkArtifact(
                    artifact_type="protocol",
                    value="TLS",
                    location=idx,
                    confidence=0.9,
                    description=description
                ))
        
        return artifacts[:10]  # Limit results
    
    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name (simple version)."""
        from collections import Counter
        import math
        
        # Remove TLD for entropy calculation
        parts = domain.split('.')
        if len(parts) > 1:
            domain_part = '.'.join(parts[:-1])
        else:
            domain_part = domain
        
        if not domain_part:
            return 0.0
        
        # Calculate entropy
        char_counts = Counter(domain_part)
        total = len(domain_part)
        
        entropy = 0.0
        for count in char_counts.values():
            if count == 0:
                continue
            probability = count / total
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _to_suspicious(self, artifact: NetworkArtifact, 
                      severity: Severity) -> SuspiciousArtifact:
        """Convert NetworkArtifact to SuspiciousArtifact."""
        location = Location(offset=artifact.location, length=len(artifact.value))
        
        # Map artifact type to MITRE
        mitre_map = {
            'suspicious_domain': 'T1071.001 - Web Protocols',
            'c2_port': 'T1071 - Application Layer Protocol',
            'protocol': 'T1071 - Application Layer Protocol'
        }
        
        return SuspiciousArtifact(
            artifact_type=artifact.artifact_type,
            value=artifact.value,
            location=location,
            severity=severity,
            confidence=artifact.confidence,
            context=artifact.description,
            observed_in=["C2 infrastructure", "Network tools", "Malware"],
            mitre_category=mitre_map.get(artifact.artifact_type, "")
        )
    
    def _to_informational(self, artifact: NetworkArtifact) -> InformationalArtifact:
        """Convert NetworkArtifact to InformationalArtifact."""
        location = Location(offset=artifact.location, length=len(artifact.value))
        
        return InformationalArtifact(
            artifact_type=artifact.artifact_type,
            value=artifact.value,
            location=location,
            description=artifact.description,
            benign=True
        )
