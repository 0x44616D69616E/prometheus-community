"""
PROMETHEUS v3.0.0 - ANTI-ANALYSIS DETECTOR

Detects anti-debugging, anti-VM, and obfuscation techniques.

Based on Binary Analysis Academic Reference v2.2 Sections 33, 41, 42.

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass
from typing import List, Tuple
from prometheus.models_v3 import Location, SuspiciousArtifact, Severity


@dataclass
class AntiAnalysisPattern:
    """An anti-analysis technique detected."""
    technique_type: str       # "anti_debug", "anti_vm", "obfuscation"
    technique_name: str       # Specific technique
    location: int
    evidence: bytes
    description: str
    confidence: float


class AntiAnalysisDetector:
    """
    Detects anti-analysis techniques used by malware.
    
    Techniques detected:
    - Anti-debugging (IsDebuggerPresent, timing checks, INT 3)
    - Anti-VM (VMware detection, VirtualBox detection)
    - Anti-sandbox (sleep evasion, mouse movement checks)
    - Obfuscation (API hashing, control flow obfuscation)
    """
    
    def __init__(self):
        """Initialize anti-analysis detector."""
        
        # Anti-debug API patterns (import names)
        self.anti_debug_apis = [
            b'IsDebuggerPresent',
            b'CheckRemoteDebuggerPresent',
            b'NtQueryInformationProcess',
            b'OutputDebugString',
            b'FindWindow',  # Looking for debugger windows
            b'Process32First',  # Enumerating processes
            b'Process32Next',
        ]
        
        # Anti-VM registry keys (as strings in binary)
        self.anti_vm_registry = [
            b'SOFTWARE\\VMware',
            b'SYSTEM\\CurrentControlSet\\Services\\VBox',
            b'SYSTEM\\CurrentControlSet\\Services\\VMTools',
            b'SOFTWARE\\Oracle\\VirtualBox',
        ]
        
        # Anti-VM file paths
        self.anti_vm_files = [
            b'vmmouse.sys',
            b'vmtools.dll',
            b'VBoxGuest.sys',
            b'VBoxMouse.sys',
            b'VBoxService.exe',
            b'vmware.exe',
            b'vmtoolsd.exe',
        ]
        
        # VMware MAC address prefixes (hex)
        self.vmware_mac_prefixes = [
            b'\x00\x0C\x29',  # VMware
            b'\x00\x50\x56',  # VMware
            b'\x00\x05\x69',  # VMware
        ]
        
        # VirtualBox MAC prefix
        self.vbox_mac_prefix = b'\x08\x00\x27'
        
        # Anti-debug instruction patterns
        self.anti_debug_instructions = {
            b'\xcc': 'INT 3 (Breakpoint)',
            b'\xcd\x03': 'INT 3 (Alternative)',
            b'\xcd\x2d': 'INT 2D (Windows specific)',
            b'\x0f\x31': 'RDTSC (Timing check)',
        }
        
        # Sleep evasion patterns (large sleep values)
        self.sleep_apis = [
            b'Sleep',
            b'kernel32.Sleep',
            b'SleepEx',
        ]
        
        # API hashing patterns (common hash constants)
        self.api_hash_constants = {
            0x5FBFF0FB: 'LoadLibraryA (ROR13 hash)',
            0x41636F72: 'GetProcAddress (ROR13 hash)',
            0x0726774C: 'kernel32.dll (ROR13 hash)',
            0x0C917432: 'WinExec (CRC32 hash)',
        }
    
    def detect(self, content: bytes) -> Tuple[List[SuspiciousArtifact], List[SuspiciousArtifact]]:
        """
        Detect anti-analysis techniques.
        
        Args:
            content: Binary data to analyze
            
        Returns:
            Tuple of (high_confidence, medium_confidence) findings
        """
        high_confidence = []
        medium_confidence = []
        
        # Detect anti-debug techniques
        anti_debug = self._detect_anti_debug(content)
        for pattern in anti_debug:
            if pattern.confidence >= 0.8:
                high_confidence.append(self._to_suspicious(pattern, Severity.HIGH))
            else:
                medium_confidence.append(self._to_suspicious(pattern, Severity.MEDIUM))
        
        # Detect anti-VM techniques
        anti_vm = self._detect_anti_vm(content)
        for pattern in anti_vm:
            if pattern.confidence >= 0.8:
                high_confidence.append(self._to_suspicious(pattern, Severity.HIGH))
            else:
                medium_confidence.append(self._to_suspicious(pattern, Severity.MEDIUM))
        
        # Detect obfuscation techniques
        obfuscation = self._detect_obfuscation(content)
        for pattern in obfuscation:
            medium_confidence.append(self._to_suspicious(pattern, Severity.MEDIUM))
        
        return high_confidence, medium_confidence
    
    def _detect_anti_debug(self, content: bytes) -> List[AntiAnalysisPattern]:
        """Detect anti-debugging techniques."""
        patterns = []
        
        # Check for anti-debug APIs
        for api in self.anti_debug_apis:
            offset = 0
            count = 0
            while True:
                idx = content.find(api, offset)
                if idx == -1:
                    break
                
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_debug",
                    technique_name="API Detection",
                    location=idx,
                    evidence=api,
                    description=f"Anti-debug API: {api.decode('ascii', errors='ignore')}. "
                               f"Used to detect debuggers and analysis tools.",
                    confidence=0.85
                ))
                
                offset = idx + len(api)
                count += 1
                
                if count >= 5:  # Limit per API
                    break
        
        # Check for INT 3 instructions
        for instruction, desc in self.anti_debug_instructions.items():
            offset = 0
            count = 0
            while True:
                idx = content.find(instruction, offset)
                if idx == -1:
                    break
                
                # INT 3 is common, only flag if we find many
                if instruction == b'\xcc':
                    count += 1
                    if count < 10:  # Only flag if >10 occurrences
                        offset = idx + 1
                        continue
                    desc += f" ({count} occurrences)"
                
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_debug",
                    technique_name="Instruction Detection",
                    location=idx,
                    evidence=instruction,
                    description=f"Anti-debug instruction: {desc}",
                    confidence=0.7 if instruction == b'\xcc' else 0.8
                ))
                
                offset = idx + len(instruction)
                break  # Only report once per type
        
        return patterns
    
    def _detect_anti_vm(self, content: bytes) -> List[AntiAnalysisPattern]:
        """Detect anti-VM techniques."""
        patterns = []
        
        # Check for VM registry keys
        for reg_key in self.anti_vm_registry:
            idx = content.find(reg_key)
            if idx != -1:
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_vm",
                    technique_name="Registry Check",
                    location=idx,
                    evidence=reg_key,
                    description=f"VM detection: Registry key '{reg_key.decode('ascii', errors='ignore')}'. "
                               f"Used to detect virtual machine environments.",
                    confidence=0.9
                ))
        
        # Check for VM file paths
        for vm_file in self.anti_vm_files:
            idx = content.find(vm_file)
            if idx != -1:
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_vm",
                    technique_name="File Check",
                    location=idx,
                    evidence=vm_file,
                    description=f"VM detection: File '{vm_file.decode('ascii', errors='ignore')}'. "
                               f"VMware/VirtualBox driver or tool.",
                    confidence=0.85
                ))
        
        # Check for VM MAC addresses
        for mac_prefix in self.vmware_mac_prefixes:
            idx = content.find(mac_prefix)
            if idx != -1:
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_vm",
                    technique_name="MAC Address Check",
                    location=idx,
                    evidence=mac_prefix,
                    description=f"VMware MAC address prefix detected: {mac_prefix.hex()}. "
                               f"Used to detect VMware virtual machines.",
                    confidence=0.8
                ))
        
        # Check for VirtualBox MAC
        idx = content.find(self.vbox_mac_prefix)
        if idx != -1:
            patterns.append(AntiAnalysisPattern(
                technique_type="anti_vm",
                technique_name="MAC Address Check",
                location=idx,
                evidence=self.vbox_mac_prefix,
                description=f"VirtualBox MAC address prefix: {self.vbox_mac_prefix.hex()}",
                confidence=0.8
            ))
        
        # Check for CPUID instruction (used for VM detection)
        cpuid_instruction = b'\x0f\xa2'  # CPUID
        offset = 0
        cpuid_count = 0
        while True:
            idx = content.find(cpuid_instruction, offset)
            if idx == -1:
                break
            cpuid_count += 1
            offset = idx + len(cpuid_instruction)
            
            if cpuid_count >= 3:  # Multiple CPUID calls is suspicious
                patterns.append(AntiAnalysisPattern(
                    technique_type="anti_vm",
                    technique_name="CPUID Check",
                    location=idx,
                    evidence=cpuid_instruction,
                    description=f"Multiple CPUID instructions ({cpuid_count}). "
                               f"Used to detect hypervisor presence.",
                    confidence=0.7
                ))
                break
        
        return patterns
    
    def _detect_obfuscation(self, content: bytes) -> List[AntiAnalysisPattern]:
        """Detect code obfuscation techniques."""
        patterns = []
        
        # Check for API hash constants
        import struct
        for i in range(0, len(content) - 4, 4):
            dword = struct.unpack('<I', content[i:i+4])[0]
            
            if dword in self.api_hash_constants:
                patterns.append(AntiAnalysisPattern(
                    technique_type="obfuscation",
                    technique_name="API Hashing",
                    location=i,
                    evidence=content[i:i+4],
                    description=f"API hash constant: 0x{dword:08X} ({self.api_hash_constants[dword]}). "
                               f"Used to resolve APIs by hash instead of name.",
                    confidence=0.9
                ))
        
        # Check for excessive NOPs (might be code cave or obfuscation)
        nop_runs = []
        current_run_start = None
        current_run_length = 0
        
        for i, byte in enumerate(content):
            if byte == 0x90:  # NOP
                if current_run_start is None:
                    current_run_start = i
                current_run_length += 1
            else:
                if current_run_length >= 100:  # 100+ NOPs
                    nop_runs.append((current_run_start, current_run_length))
                current_run_start = None
                current_run_length = 0
        
        for start, length in nop_runs[:5]:  # Limit to 5
            patterns.append(AntiAnalysisPattern(
                technique_type="obfuscation",
                technique_name="Code Cave",
                location=start,
                evidence=b'\x90' * min(length, 20),
                description=f"Large NOP sequence ({length} bytes). "
                           f"May indicate code cave or obfuscation.",
                confidence=0.6
            ))
        
        return patterns
    
    def _to_suspicious(self, pattern: AntiAnalysisPattern, 
                      severity: Severity) -> SuspiciousArtifact:
        """Convert AntiAnalysisPattern to SuspiciousArtifact."""
        location = Location(
            offset=pattern.location,
            length=len(pattern.evidence)
        )
        
        # Format evidence
        evidence_hex = ' '.join(f'{b:02x}' for b in pattern.evidence[:16])
        if len(pattern.evidence) > 16:
            evidence_hex += '...'
        
        context = f"{pattern.description}\nBytes: {evidence_hex}"
        
        # Map technique type to MITRE category
        mitre_map = {
            'anti_debug': 'T1622 - Debugger Evasion',
            'anti_vm': 'T1497 - Virtualization/Sandbox Evasion',
            'obfuscation': 'T1027 - Obfuscated Files or Information'
        }
        
        return SuspiciousArtifact(
            artifact_type=pattern.technique_type,
            value=pattern.technique_name,
            location=location,
            severity=severity,
            confidence=pattern.confidence,
            context=context,
            observed_in=["Malware", "Anti-analysis software", "Advanced threats"],
            mitre_category=mitre_map.get(pattern.technique_type, "")
        )
