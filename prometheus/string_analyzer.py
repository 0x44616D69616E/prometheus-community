"""
PROMETHEUS - STRING ANALYZER

Advanced string extraction and classification.

Extracts and categorizes:
- URLs (http, https, ftp)
- IP addresses
- Email addresses
- File paths (Windows, Linux)
- Registry keys
- Commands and scripts
- Domain names
- User agents

Based on Binary Analysis Academic Reference v2.2 Section 49 & 54.

Copyright (c) 2026 Damian Donahue
"""

import re
from dataclasses import dataclass
from typing import List, Tuple, Set
from prometheus.models import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class ClassifiedString:
    """A classified extracted string."""
    value: str
    category: str       # "url", "ip", "email", "path", "command", etc.
    location: int
    confidence: float


class StringAnalyzer:
    """
    Advanced string extraction and classification.
    
    Goes beyond basic string extraction to identify and categorize
    interesting strings like URLs, IPs, paths, and commands.
    """
    
    def __init__(self):
        """Initialize string analyzer."""
        
        # Regex patterns
        self.url_pattern = re.compile(
            rb'(?:https?|ftp)://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        
        self.ip_pattern = re.compile(
            rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.email_pattern = re.compile(
            rb'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        )
        
        self.domain_pattern = re.compile(
            rb'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        )
        
        # Windows path pattern
        self.win_path_pattern = re.compile(
            rb'[A-Za-z]:\\(?:[^\x00-\x1f"<>|*?\r\n\\]+\\)*[^\x00-\x1f"<>|*?\r\n\\]*'
        )
        
        # Linux path pattern
        self.linux_path_pattern = re.compile(
            rb'/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+'
        )
        
        # Registry key pattern
        self.registry_pattern = re.compile(
            rb'HK(?:EY_)?(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\x00\r\n]+'
        )
        
        # User agent pattern
        self.useragent_pattern = re.compile(
            rb'(?:Mozilla|Opera|Chrome|Safari|MSIE|Trident)[^\r\n]{10,200}',
            re.IGNORECASE
        )
        
        # Suspicious commands
        self.suspicious_commands = [
            b'cmd.exe', b'powershell', b'bash', b'sh', b'/bin/sh',
            b'wget', b'curl', b'nc', b'netcat', b'python',
            b'rundll32', b'regsvr32', b'mshta', b'wscript', b'cscript'
        ]
    
    def analyze(self, content: bytes) -> Tuple[List[SuspiciousArtifact], List[InformationalArtifact]]:
        """
        Extract and classify strings from binary data.
        
        Args:
            content: Binary data to analyze
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Extract classified strings
        classified = self._extract_classified_strings(content)
        
        # Process each category
        urls = [s for s in classified if s.category == 'url']
        ips = [s for s in classified if s.category == 'ip']
        emails = [s for s in classified if s.category == 'email']
        paths = [s for s in classified if s.category == 'path']
        registry = [s for s in classified if s.category == 'registry']
        commands = [s for s in classified if s.category == 'command']
        useragents = [s for s in classified if s.category == 'useragent']
        
        # URLs - always suspicious in executables
        for url_str in urls[:10]:  # Limit to first 10
            suspicious.append(SuspiciousArtifact(
                artifact_type="url",
                value=url_str.value,
                location=Location(offset=url_str.location, length=len(url_str.value)),
                severity=Severity.MEDIUM,
                confidence=url_str.confidence,
                context=f"URL found: {url_str.value}",
                observed_in=["C2 communication", "Downloaders", "Network tools"],
                mitre_category="T1071 - Application Layer Protocol"
            ))
        
        # IPs - suspicious if not private ranges
        for ip_str in ips[:10]:
            if not self._is_private_ip(ip_str.value):
                suspicious.append(SuspiciousArtifact(
                    artifact_type="ip_address",
                    value=ip_str.value,
                    location=Location(offset=ip_str.location, length=len(ip_str.value)),
                    severity=Severity.MEDIUM,
                    confidence=ip_str.confidence,
                    context=f"Public IP address: {ip_str.value}",
                    observed_in=["C2 servers", "Exfiltration targets"]
                ))
            else:
                informational.append(InformationalArtifact(
                    artifact_type="ip_address",
                    value=ip_str.value,
                    location=Location(offset=ip_str.location, length=len(ip_str.value)),
                    description=f"Private IP address: {ip_str.value}",
                    benign=True
                ))
        
        # Commands - suspicious
        for cmd_str in commands[:5]:
            suspicious.append(SuspiciousArtifact(
                artifact_type="command",
                value=cmd_str.value,
                location=Location(offset=cmd_str.location, length=len(cmd_str.value)),
                severity=Severity.MEDIUM,
                confidence=cmd_str.confidence,
                context=f"Command reference: {cmd_str.value}",
                observed_in=["Malware", "Remote access tools"],
                mitre_category="T1059 - Command and Scripting Interpreter"
            ))
        
        # Registry keys - informational for Windows
        for reg_str in registry[:5]:
            informational.append(InformationalArtifact(
                artifact_type="registry_key",
                value=reg_str.value,
                location=Location(offset=reg_str.location, length=len(reg_str.value)),
                description=f"Registry key: {reg_str.value}",
                benign=False  # Noteworthy
            ))
        
        # Paths - informational
        for path_str in paths[:10]:
            informational.append(InformationalArtifact(
                artifact_type="file_path",
                value=path_str.value,
                location=Location(offset=path_str.location, length=len(path_str.value)),
                description=f"File path: {path_str.value}",
                benign=True
            ))
        
        # User agents - informational
        for ua_str in useragents[:3]:
            informational.append(InformationalArtifact(
                artifact_type="user_agent",
                value=ua_str.value[:100],  # Truncate for display
                location=Location(offset=ua_str.location, length=len(ua_str.value)),
                description=f"User-Agent string (network activity)",
                benign=True
            ))
        
        return suspicious, informational
    
    def _extract_classified_strings(self, content: bytes) -> List[ClassifiedString]:
        """Extract and classify all interesting strings."""
        classified = []
        
        # URLs
        for match in self.url_pattern.finditer(content):
            url = match.group(0).decode('ascii', errors='ignore')
            classified.append(ClassifiedString(
                value=url,
                category='url',
                location=match.start(),
                confidence=0.95
            ))
        
        # IPs
        for match in self.ip_pattern.finditer(content):
            ip = match.group(0).decode('ascii', errors='ignore')
            # Validate it's a real IP
            if self._is_valid_ip(ip):
                classified.append(ClassifiedString(
                    value=ip,
                    category='ip',
                    location=match.start(),
                    confidence=0.9
                ))
        
        # Emails
        for match in self.email_pattern.finditer(content):
            email = match.group(0).decode('ascii', errors='ignore')
            classified.append(ClassifiedString(
                value=email,
                category='email',
                location=match.start(),
                confidence=0.85
            ))
        
        # Registry keys
        for match in self.registry_pattern.finditer(content):
            reg = match.group(0).decode('ascii', errors='ignore')
            classified.append(ClassifiedString(
                value=reg,
                category='registry',
                location=match.start(),
                confidence=0.9
            ))
        
        # Windows paths
        for match in self.win_path_pattern.finditer(content):
            path = match.group(0).decode('ascii', errors='ignore')
            # Filter out noise
            if len(path) >= 10 and '\\' in path:
                classified.append(ClassifiedString(
                    value=path,
                    category='path',
                    location=match.start(),
                    confidence=0.7
                ))
        
        # Linux paths (more conservative)
        for match in self.linux_path_pattern.finditer(content):
            path = match.group(0).decode('ascii', errors='ignore')
            # Only if it looks like a real path
            if len(path) >= 10 and path.count('/') >= 2:
                classified.append(ClassifiedString(
                    value=path,
                    category='path',
                    location=match.start(),
                    confidence=0.6
                ))
        
        # User agents
        for match in self.useragent_pattern.finditer(content):
            ua = match.group(0).decode('ascii', errors='ignore')
            classified.append(ClassifiedString(
                value=ua,
                category='useragent',
                location=match.start(),
                confidence=0.7
            ))
        
        # Suspicious commands
        for command in self.suspicious_commands:
            offset = 0
            while True:
                idx = content.find(command, offset)
                if idx == -1:
                    break
                
                classified.append(ClassifiedString(
                    value=command.decode('ascii'),
                    category='command',
                    location=idx,
                    confidence=0.8
                ))
                
                offset = idx + len(command)
                
                # Limit per command
                if len([c for c in classified if c.value == command.decode('ascii')]) >= 3:
                    break
        
        return classified
    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Validate IP address format."""
        try:
            parts = ip_str.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            return True
        except:
            return False
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is in private range."""
        try:
            parts = [int(p) for p in ip_str.split('.')]
            
            # Private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127:  # Loopback
                return True
            
            return False
        except:
            return False
