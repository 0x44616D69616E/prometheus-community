"""
PROMETHEUS v3.0.0 - SHELLCODE DETECTOR

Detects shellcode patterns in binary data.

Based on Binary Analysis Academic Reference v2.2 Section 29.

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional
from prometheus.models_v3 import Location, SuspiciousArtifact, Severity


@dataclass
class ShellcodePattern:
    """A detected shellcode pattern."""
    pattern_type: str          # "NOP_Sled", "GetPC", "XOR_Decoder", "Syscall"
    location: int             # Byte offset
    length: int               # Pattern length
    bytes_found: bytes        # Actual bytes
    description: str          # What this pattern does
    confidence: float         # 0.0-1.0


class ShellcodeDetector:
    """
    Detects common shellcode patterns used in exploits.
    
    Patterns detected:
    1. NOP Sleds - Padding before shellcode
    2. GetPC Techniques - Position-independent code
    3. XOR Decoder Stubs - Self-decrypting shellcode
    4. Syscall Instructions - Direct system calls
    """
    
    def __init__(self):
        """Initialize shellcode detector."""
        
        # NOP instruction variants
        self.nop_instructions = {
            b'\x90': 'NOP (0x90)',
            b'\x66\x90': 'Multi-byte NOP (xchg ax,ax)',
            b'\x0f\x1f\x00': '3-byte NOP',
            b'\x0f\x1f\x40\x00': '4-byte NOP',
            b'\x0f\x1f\x44\x00\x00': '5-byte NOP',
        }
        
        # GetPC patterns (get program counter / EIP)
        self.getpc_patterns = {
            b'\xe8\x00\x00\x00\x00\x58': 'CALL $+5; POP EAX (x86)',
            b'\xe8\x00\x00\x00\x00\x5b': 'CALL $+5; POP EBX (x86)',
            b'\xe8\x00\x00\x00\x00\x59': 'CALL $+5; POP ECX (x86)',
            b'\xe8\x00\x00\x00\x00\x5a': 'CALL $+5; POP EDX (x86)',
        }
        
        # XOR decoder stub patterns
        self.xor_decoder_patterns = {
            # Common XOR decoder stub: XOR ECX,ECX; XOR byte [esi+ecx],KEY; INC ECX
            b'\x31\xc9\x80\x34\x0e': 'XOR decoder stub (variable key)',
            # XOR EAX,EAX; XOR byte [eax+offset],KEY
            b'\x31\xc0\x80\x34': 'XOR decoder (EAX-based)',
        }
        
        # Syscall instructions
        self.syscall_patterns = {
            b'\xcd\x80': 'INT 0x80 (Linux x86 syscall)',
            b'\x0f\x05': 'SYSCALL (Linux x64)',
            b'\x0f\x34': 'SYSENTER (Fast syscall x86)',
        }
        
        # Common shellcode instruction sequences
        self.common_sequences = {
            # PUSH string patterns (little-endian)
            b'\x68\x2f\x2f\x73\x68': 'PUSH "//sh" (shell)',
            b'\x68\x2f\x62\x69\x6e': 'PUSH "/bin" (shell path)',
            # Zero registers
            b'\x31\xc0': 'XOR EAX,EAX (zero register)',
            b'\x31\xdb': 'XOR EBX,EBX (zero register)',
            b'\x31\xc9': 'XOR ECX,ECX (zero register)',
            b'\x31\xd2': 'XOR EDX,EDX (zero register)',
        }
    
    def detect(self, content: bytes) -> Tuple[List[SuspiciousArtifact], List[SuspiciousArtifact]]:
        """
        Detect shellcode patterns in binary data.
        
        Args:
            content: Binary data to scan
            
        Returns:
            Tuple of (high_confidence_patterns, medium_confidence_patterns)
        """
        high_confidence = []
        medium_confidence = []
        
        # Detect NOP sleds
        nop_sleds = self._detect_nop_sleds(content)
        for pattern in nop_sleds:
            if pattern.confidence >= 0.8:
                high_confidence.append(self._to_suspicious(pattern, Severity.HIGH))
            else:
                medium_confidence.append(self._to_suspicious(pattern, Severity.MEDIUM))
        
        # Detect GetPC techniques
        getpc_patterns = self._detect_getpc(content)
        for pattern in getpc_patterns:
            high_confidence.append(self._to_suspicious(pattern, Severity.HIGH))
        
        # Detect XOR decoders
        xor_patterns = self._detect_xor_decoders(content)
        for pattern in xor_patterns:
            high_confidence.append(self._to_suspicious(pattern, Severity.HIGH))
        
        # Detect syscalls
        syscall_patterns = self._detect_syscalls(content)
        for pattern in syscall_patterns:
            medium_confidence.append(self._to_suspicious(pattern, Severity.MEDIUM))
        
        return high_confidence, medium_confidence
    
    def _detect_nop_sleds(self, content: bytes) -> List[ShellcodePattern]:
        """
        Detect NOP sleds (long sequences of NOP instructions).
        
        NOP sleds are used in buffer overflow exploits to increase the
        chance of hitting the shellcode.
        """
        patterns = []
        
        # Check for single-byte NOP sleds (0x90)
        i = 0
        while i < len(content) - 16:
            # Count consecutive 0x90 bytes
            nop_count = 0
            start = i
            
            while i < len(content) and content[i] == 0x90:
                nop_count += 1
                i += 1
            
            # Flag if we found a significant NOP sled
            if nop_count >= 16:  # At least 16 consecutive NOPs
                confidence = min(0.5 + (nop_count / 100), 0.95)
                
                patterns.append(ShellcodePattern(
                    pattern_type="NOP_Sled",
                    location=start,
                    length=nop_count,
                    bytes_found=content[start:start+min(nop_count, 32)],
                    description=f"NOP sled ({nop_count} consecutive 0x90 bytes). "
                               f"Common in buffer overflow exploits.",
                    confidence=confidence
                ))
            else:
                i += 1
        
        # Check for multi-byte NOP patterns
        for nop_bytes, desc in self.nop_instructions.items():
            if len(nop_bytes) == 1:
                continue  # Already checked single-byte
            
            offset = 0
            while True:
                idx = content.find(nop_bytes, offset)
                if idx == -1:
                    break
                
                # Count consecutive occurrences
                count = 1
                check_offset = idx + len(nop_bytes)
                
                while check_offset < len(content):
                    if content[check_offset:check_offset+len(nop_bytes)] == nop_bytes:
                        count += 1
                        check_offset += len(nop_bytes)
                    else:
                        break
                
                if count >= 4:  # At least 4 consecutive multi-byte NOPs
                    total_length = count * len(nop_bytes)
                    patterns.append(ShellcodePattern(
                        pattern_type="NOP_Sled",
                        location=idx,
                        length=total_length,
                        bytes_found=content[idx:idx+min(total_length, 32)],
                        description=f"Multi-byte NOP sled ({count} × {desc}). "
                                   f"Advanced evasion technique.",
                        confidence=0.8
                    ))
                
                offset = idx + len(nop_bytes)
        
        return patterns
    
    def _detect_getpc(self, content: bytes) -> List[ShellcodePattern]:
        """
        Detect GetPC (Get Program Counter) techniques.
        
        These are used in position-independent shellcode to determine
        the current execution address.
        """
        patterns = []
        
        for getpc_bytes, desc in self.getpc_patterns.items():
            offset = 0
            while True:
                idx = content.find(getpc_bytes, offset)
                if idx == -1:
                    break
                
                patterns.append(ShellcodePattern(
                    pattern_type="GetPC",
                    location=idx,
                    length=len(getpc_bytes),
                    bytes_found=getpc_bytes,
                    description=f"GetPC technique: {desc}. "
                               f"Used in position-independent shellcode.",
                    confidence=0.9
                ))
                
                offset = idx + len(getpc_bytes)
                
                # Limit to first 10 occurrences
                if len([p for p in patterns if p.pattern_type == "GetPC"]) >= 10:
                    break
        
        return patterns
    
    def _detect_xor_decoders(self, content: bytes) -> List[ShellcodePattern]:
        """
        Detect XOR decoder stubs.
        
        Self-decrypting shellcode uses XOR decoders to unpack itself
        at runtime, evading static analysis.
        """
        patterns = []
        
        for xor_bytes, desc in self.xor_decoder_patterns.items():
            offset = 0
            while True:
                idx = content.find(xor_bytes, offset)
                if idx == -1:
                    break
                
                # Try to extract the XOR key if present
                key_info = ""
                if idx + len(xor_bytes) + 1 < len(content):
                    potential_key = content[idx + len(xor_bytes)]
                    key_info = f" (potential key: 0x{potential_key:02x})"
                
                patterns.append(ShellcodePattern(
                    pattern_type="XOR_Decoder",
                    location=idx,
                    length=len(xor_bytes),
                    bytes_found=content[idx:idx+len(xor_bytes)+2],
                    description=f"XOR decoder stub: {desc}{key_info}. "
                               f"Self-decrypting shellcode.",
                    confidence=0.85
                ))
                
                offset = idx + len(xor_bytes)
                
                # Limit to first 5 occurrences
                if len([p for p in patterns if p.pattern_type == "XOR_Decoder"]) >= 5:
                    break
        
        return patterns
    
    def _detect_syscalls(self, content: bytes) -> List[ShellcodePattern]:
        """
        Detect direct syscall instructions.
        
        Shellcode often uses direct syscalls to avoid API hooking.
        """
        patterns = []
        
        for syscall_bytes, desc in self.syscall_patterns.items():
            offset = 0
            count = 0
            
            while True:
                idx = content.find(syscall_bytes, offset)
                if idx == -1:
                    break
                
                # Get context around syscall
                context_start = max(0, idx - 4)
                context_end = min(len(content), idx + len(syscall_bytes) + 4)
                context = content[context_start:context_end]
                
                patterns.append(ShellcodePattern(
                    pattern_type="Syscall",
                    location=idx,
                    length=len(syscall_bytes),
                    bytes_found=syscall_bytes,
                    description=f"Syscall instruction: {desc}. "
                               f"Direct system call (common in shellcode).",
                    confidence=0.6
                ))
                
                offset = idx + len(syscall_bytes)
                count += 1
                
                # Limit to first 20 occurrences
                if count >= 20:
                    break
        
        return patterns
    
    def _to_suspicious(self, pattern: ShellcodePattern, 
                      severity: Severity) -> SuspiciousArtifact:
        """Convert ShellcodePattern to SuspiciousArtifact."""
        location = Location(
            offset=pattern.location,
            length=pattern.length
        )
        
        # Format bytes for display
        bytes_hex = ' '.join(f'{b:02x}' for b in pattern.bytes_found[:16])
        if len(pattern.bytes_found) > 16:
            bytes_hex += '...'
        
        context = f"{pattern.description}\nBytes: {bytes_hex}"
        
        return SuspiciousArtifact(
            artifact_type="shellcode_pattern",
            value=pattern.pattern_type,
            location=location,
            severity=severity,
            confidence=pattern.confidence,
            context=context,
            observed_in=["Exploit payloads", "Buffer overflow attacks", "Code injection"],
            mitre_category="T1059 - Command and Scripting Interpreter"
        )
