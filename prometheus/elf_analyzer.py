"""
PROMETHEUS v3.0.0 - ELF ANALYZER

Deep analysis of Linux ELF (Executable and Linkable Format) files.

Analyzes:
- ELF header (class, endianness, ABI)
- Program headers (segments)
- Section headers (.text, .data, .plt, .got, etc.)
- Dynamic section (NEEDED libraries, RPATH, interpreter)
- Symbol tables
- Suspicious indicators (unusual interpreter, packed binaries)

Based on Binary Analysis Academic Reference v2.2 Section 2.4 & Section 10.

Copyright (c) 2026 Damian Donahue
"""

import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
from models_v3 import Location, SuspiciousArtifact, InformationalArtifact, Severity


@dataclass
class ELFSection:
    """An ELF section."""
    name: str
    address: int
    offset: int
    size: int
    type: int
    flags: int
    writable: bool
    executable: bool
    allocatable: bool


@dataclass
class ELFSegment:
    """An ELF program header (segment)."""
    type: str
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    flags: int
    readable: bool
    writable: bool
    executable: bool


class ELFAnalyzer:
    """
    Analyzes Linux ELF file structure.
    
    Detects:
    - Unusual interpreter paths
    - Suspicious section names
    - RWX segments
    - Missing standard sections (stripped binaries)
    - Packer signatures (UPX)
    - Dangerous dynamic dependencies
    """
    
    # Standard ELF sections
    STANDARD_SECTIONS = [
        '.text', '.data', '.bss', '.rodata', '.plt', '.got',
        '.init', '.fini', '.dynsym', '.symtab', '.strtab',
        '.dynamic', '.interp'
    ]
    
    # Standard interpreter paths
    STANDARD_INTERPRETERS = [
        '/lib/ld-linux.so.2',           # 32-bit
        '/lib64/ld-linux-x86-64.so.2',  # 64-bit
        '/lib/ld-musl-x86_64.so.1',     # musl (Alpine)
        '/lib/ld-linux-aarch64.so.1',   # ARM64
        '/lib/ld-linux-armhf.so.3',     # ARM
    ]
    
    # Suspicious libraries
    SUSPICIOUS_LIBRARIES = [
        'libcrypt.so',      # Crypto (not always suspicious)
        'libssl.so',        # SSL (network crypto)
        'libcrypto.so',     # OpenSSL crypto
        'libpcap.so',       # Packet capture
        'libnetfilter',     # Firewall manipulation
    ]
    
    def __init__(self):
        """Initialize ELF analyzer."""
        pass
    
    def analyze(self, content: bytes, filename: str) -> Tuple[
        List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """
        Analyze ELF file structure.
        
        Args:
            content: ELF file bytes
            filename: Original filename
            
        Returns:
            Tuple of (suspicious_artifacts, informational_artifacts)
        """
        suspicious = []
        informational = []
        
        # Verify it's an ELF file
        if len(content) < 64 or content[0:4] != b'\x7fELF':
            return suspicious, informational
        
        try:
            # Parse ELF structure
            elf_info = self._parse_elf(content)
            
            if not elf_info:
                return suspicious, informational
            
            # Analyze sections
            section_findings = self._analyze_sections(elf_info['sections'], content)
            suspicious.extend(section_findings[0])
            informational.extend(section_findings[1])
            
            # Analyze segments
            segment_findings = self._analyze_segments(elf_info['segments'])
            suspicious.extend(segment_findings)
            
            # Analyze interpreter
            interp_findings = self._analyze_interpreter(elf_info.get('interpreter', ''))
            suspicious.extend(interp_findings)
            
            # Analyze dynamic dependencies
            lib_findings = self._analyze_libraries(elf_info.get('needed_libraries', []))
            suspicious.extend(lib_findings)
            
            # Check for packers
            packer_findings = self._detect_packers(content)
            suspicious.extend(packer_findings)
            
            # Add general ELF info
            info_findings = self._create_elf_info(elf_info)
            informational.extend(info_findings)
            
        except Exception as e:
            # Parsing error
            suspicious.append(SuspiciousArtifact(
                artifact_type="elf_malformed",
                value="Malformed ELF",
                location=Location(offset=0, length=0),
                severity=Severity.MEDIUM,
                confidence=0.7,
                context=f"ELF parsing error: {str(e)}. May indicate corrupted or obfuscated file.",
                observed_in=["Malware evasion", "Anti-analysis"]
            ))
        
        return suspicious, informational
    
    def _parse_elf(self, content: bytes) -> Optional[Dict]:
        """Parse ELF file structure."""
        # Read ELF header
        ei_class = content[4]  # 1=32-bit, 2=64-bit
        ei_data = content[5]   # 1=little-endian, 2=big-endian
        
        is_64bit = (ei_class == 2)
        is_little_endian = (ei_data == 1)
        endian = '<' if is_little_endian else '>'
        
        # Parse header fields
        if is_64bit:
            # 64-bit ELF header
            e_type, e_machine = struct.unpack(f'{endian}HH', content[16:20])
            e_entry, e_phoff, e_shoff = struct.unpack(f'{endian}QQQ', content[24:48])
            e_phentsize, e_phnum = struct.unpack(f'{endian}HH', content[54:58])
            e_shentsize, e_shnum, e_shstrndx = struct.unpack(f'{endian}HHH', content[58:64])
        else:
            # 32-bit ELF header
            e_type, e_machine = struct.unpack(f'{endian}HH', content[16:20])
            e_entry, e_phoff, e_shoff = struct.unpack(f'{endian}III', content[24:36])
            e_phentsize, e_phnum = struct.unpack(f'{endian}HH', content[42:46])
            e_shentsize, e_shnum, e_shstrndx = struct.unpack(f'{endian}HHH', content[46:52])
        
        # Parse sections
        sections = self._parse_sections(content, e_shoff, e_shnum, e_shentsize, 
                                       e_shstrndx, is_64bit, endian)
        
        # Parse program headers (segments)
        segments = self._parse_segments(content, e_phoff, e_phnum, e_phentsize,
                                       is_64bit, endian)
        
        # Extract interpreter
        interpreter = self._extract_interpreter(content, segments)
        
        # Extract dynamic section info
        needed_libraries = self._extract_needed_libraries(content, sections, is_64bit, endian)
        
        return {
            'is_64bit': is_64bit,
            'is_little_endian': is_little_endian,
            'type': e_type,
            'machine': e_machine,
            'entry': e_entry,
            'sections': sections,
            'segments': segments,
            'interpreter': interpreter,
            'needed_libraries': needed_libraries
        }
    
    def _parse_sections(self, content: bytes, offset: int, count: int, entsize: int,
                       strndx: int, is_64bit: bool, endian: str) -> List[ELFSection]:
        """Parse ELF section headers."""
        sections = []
        
        # First, read section header string table
        if strndx >= count or offset + strndx * entsize > len(content):
            return sections
        
        shstrtab_offset_field = offset + strndx * entsize + (24 if is_64bit else 16)
        shstrtab_offset = struct.unpack(f'{endian}{"Q" if is_64bit else "I"}',
                                       content[shstrtab_offset_field:shstrtab_offset_field+(8 if is_64bit else 4)])[0]
        
        for i in range(count):
            sec_offset = offset + i * entsize
            if sec_offset + entsize > len(content):
                break
            
            if is_64bit:
                # 64-bit section header
                sh_name, sh_type, sh_flags = struct.unpack(f'{endian}IIQ', 
                                                           content[sec_offset:sec_offset+16])
                sh_addr, sh_offset, sh_size = struct.unpack(f'{endian}QQQ',
                                                            content[sec_offset+16:sec_offset+40])
            else:
                # 32-bit section header
                sh_name, sh_type, sh_flags = struct.unpack(f'{endian}III',
                                                           content[sec_offset:sec_offset+12])
                sh_addr, sh_offset, sh_size = struct.unpack(f'{endian}III',
                                                            content[sec_offset+12:sec_offset+24])
            
            # Read section name
            name_offset = shstrtab_offset + sh_name
            name_end = content.find(b'\x00', name_offset)
            if name_end != -1:
                name = content[name_offset:name_end].decode('ascii', errors='ignore')
            else:
                name = f"section_{i}"
            
            # Parse flags
            SHF_WRITE = 0x1
            SHF_ALLOC = 0x2
            SHF_EXECINSTR = 0x4
            
            sections.append(ELFSection(
                name=name,
                address=sh_addr,
                offset=sh_offset,
                size=sh_size,
                type=sh_type,
                flags=sh_flags,
                writable=bool(sh_flags & SHF_WRITE),
                executable=bool(sh_flags & SHF_EXECINSTR),
                allocatable=bool(sh_flags & SHF_ALLOC)
            ))
        
        return sections
    
    def _parse_segments(self, content: bytes, offset: int, count: int, entsize: int,
                       is_64bit: bool, endian: str) -> List[ELFSegment]:
        """Parse ELF program headers (segments)."""
        segments = []
        
        PT_TYPES = {
            0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP',
            4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS'
        }
        
        for i in range(count):
            seg_offset = offset + i * entsize
            if seg_offset + entsize > len(content):
                break
            
            if is_64bit:
                # 64-bit program header
                p_type, p_flags = struct.unpack(f'{endian}II', content[seg_offset:seg_offset+8])
                p_offset, p_vaddr, p_paddr = struct.unpack(f'{endian}QQQ',
                                                           content[seg_offset+8:seg_offset+32])
                p_filesz, p_memsz = struct.unpack(f'{endian}QQ',
                                                  content[seg_offset+32:seg_offset+48])
            else:
                # 32-bit program header
                p_type = struct.unpack(f'{endian}I', content[seg_offset:seg_offset+4])[0]
                p_offset, p_vaddr, p_paddr = struct.unpack(f'{endian}III',
                                                           content[seg_offset+4:seg_offset+16])
                p_filesz, p_memsz, p_flags = struct.unpack(f'{endian}III',
                                                           content[seg_offset+16:seg_offset+28])
            
            # Parse flags
            PF_X = 0x1  # Execute
            PF_W = 0x2  # Write
            PF_R = 0x4  # Read
            
            segments.append(ELFSegment(
                type=PT_TYPES.get(p_type, f'UNKNOWN_{p_type}'),
                offset=p_offset,
                vaddr=p_vaddr,
                paddr=p_paddr,
                filesz=p_filesz,
                memsz=p_memsz,
                flags=p_flags,
                readable=bool(p_flags & PF_R),
                writable=bool(p_flags & PF_W),
                executable=bool(p_flags & PF_X)
            ))
        
        return segments
    
    def _extract_interpreter(self, content: bytes, segments: List[ELFSegment]) -> str:
        """Extract interpreter path from INTERP segment."""
        for segment in segments:
            if segment.type == 'INTERP':
                if segment.offset < len(content) and segment.filesz > 0:
                    interp_data = content[segment.offset:segment.offset+segment.filesz]
                    # Remove null terminator
                    interp = interp_data.rstrip(b'\x00').decode('ascii', errors='ignore')
                    return interp
        return ""
    
    def _extract_needed_libraries(self, content: bytes, sections: List[ELFSection],
                                  is_64bit: bool, endian: str) -> List[str]:
        """Extract NEEDED libraries from dynamic section."""
        libraries = []
        
        # Find .dynamic section
        dynamic_section = None
        for section in sections:
            if section.name == '.dynamic':
                dynamic_section = section
                break
        
        if not dynamic_section:
            return libraries
        
        # Find .dynstr section (dynamic string table)
        dynstr_section = None
        for section in sections:
            if section.name == '.dynstr':
                dynstr_section = section
                break
        
        if not dynstr_section:
            return libraries
        
        # Parse dynamic section entries
        entry_size = 16 if is_64bit else 8
        offset = dynamic_section.offset
        
        DT_NEEDED = 1
        DT_NULL = 0
        
        while offset < dynamic_section.offset + dynamic_section.size:
            if offset + entry_size > len(content):
                break
            
            if is_64bit:
                d_tag, d_val = struct.unpack(f'{endian}qq', content[offset:offset+16])
            else:
                d_tag, d_val = struct.unpack(f'{endian}ii', content[offset:offset+8])
            
            if d_tag == DT_NULL:
                break
            
            if d_tag == DT_NEEDED:
                # d_val is offset into .dynstr
                str_offset = dynstr_section.offset + d_val
                str_end = content.find(b'\x00', str_offset)
                if str_end != -1:
                    lib_name = content[str_offset:str_end].decode('ascii', errors='ignore')
                    libraries.append(lib_name)
            
            offset += entry_size
        
        return libraries
    
    def _analyze_sections(self, sections: List[ELFSection], content: bytes) -> Tuple[
        List[SuspiciousArtifact], List[InformationalArtifact]
    ]:
        """Analyze section characteristics for anomalies."""
        suspicious = []
        informational = []
        
        for section in sections:
            location = Location(offset=section.offset, length=section.size)
            
            # Check for RWX sections
            if section.writable and section.executable:
                suspicious.append(SuspiciousArtifact(
                    artifact_type="elf_section_rwx",
                    value=section.name,
                    location=location,
                    severity=Severity.HIGH,
                    confidence=0.9,
                    context=f"Section '{section.name}' has RWX permissions (Read-Write-Execute). "
                           f"Extremely rare in legitimate binaries.",
                    observed_in=["Code injection", "Malware", "JIT abuse"],
                    mitre_category="T1055 - Process Injection"
                ))
            
            # Add section info
            informational.append(InformationalArtifact(
                artifact_type="elf_section",
                value=section.name,
                location=location,
                description=f"Size: {section.size:,} bytes, "
                           f"Permissions: {'R' if section.allocatable else '-'}"
                           f"{'W' if section.writable else '-'}"
                           f"{'X' if section.executable else '-'}",
                benign=True
            ))
        
        # Check for missing standard sections (stripped binary)
        section_names = set(s.name for s in sections)
        if '.symtab' not in section_names:
            informational.append(InformationalArtifact(
                artifact_type="elf_stripped",
                value="Stripped Binary",
                description="Symbol table (.symtab) missing. Binary has been stripped.",
                benign=False  # Noteworthy but not malicious
            ))
        
        return suspicious, informational
    
    def _analyze_segments(self, segments: List[ELFSegment]) -> List[SuspiciousArtifact]:
        """Analyze program headers for anomalies."""
        suspicious = []
        
        for segment in segments:
            if segment.type == 'LOAD':
                # Check for RWX LOAD segments
                if segment.readable and segment.writable and segment.executable:
                    suspicious.append(SuspiciousArtifact(
                        artifact_type="elf_segment_rwx",
                        value=f"{segment.type} segment",
                        location=Location(offset=segment.offset, length=segment.filesz),
                        severity=Severity.HIGH,
                        confidence=0.9,
                        context=f"LOAD segment with RWX permissions at 0x{segment.vaddr:x}. "
                               f"Indicates self-modifying code or code injection.",
                        observed_in=["Malware", "Exploits", "JIT compilers"]
                    ))
        
        return suspicious
    
    def _analyze_interpreter(self, interpreter: str) -> List[SuspiciousArtifact]:
        """Analyze interpreter path for anomalies."""
        suspicious = []
        
        if not interpreter:
            return suspicious
        
        # Check if interpreter is standard
        if interpreter not in self.STANDARD_INTERPRETERS:
            suspicious.append(SuspiciousArtifact(
                artifact_type="elf_unusual_interpreter",
                value=interpreter,
                location=Location(offset=0, length=0),
                severity=Severity.MEDIUM,
                confidence=0.7,
                context=f"Unusual interpreter path: {interpreter}. "
                       f"Standard paths: {', '.join(self.STANDARD_INTERPRETERS[:3])}",
                observed_in=["Malware", "Custom builds"]
            ))
        
        return suspicious
    
    def _analyze_libraries(self, libraries: List[str]) -> List[SuspiciousArtifact]:
        """Analyze dynamic library dependencies."""
        suspicious = []
        
        for lib in libraries:
            # Check for suspicious libraries
            for sus_lib in self.SUSPICIOUS_LIBRARIES:
                if sus_lib in lib:
                    suspicious.append(SuspiciousArtifact(
                        artifact_type="elf_suspicious_library",
                        value=lib,
                        location=Location(offset=0, length=0),
                        severity=Severity.LOW,
                        confidence=0.5,
                        context=f"Library '{lib}' can be used for: network operations, crypto, or packet capture. "
                               f"Not inherently malicious but noteworthy.",
                        observed_in=["Network tools", "Malware", "Legitimate software"]
                    ))
        
        return suspicious
    
    def _detect_packers(self, content: bytes) -> List[SuspiciousArtifact]:
        """Detect known ELF packers."""
        suspicious = []
        
        # Check for UPX
        if b'UPX!' in content:
            idx = content.find(b'UPX!')
            suspicious.append(SuspiciousArtifact(
                artifact_type="elf_packer",
                value="UPX",
                location=Location(offset=idx, length=4),
                severity=Severity.MEDIUM,
                confidence=0.9,
                context="UPX packer signature found. Binary is packed with UPX.",
                observed_in=["Malware", "Legitimate software"],
                mitre_category="T1027.002 - Software Packing"
            ))
        
        return suspicious
    
    def _create_elf_info(self, elf_info: Dict) -> List[InformationalArtifact]:
        """Create informational artifacts about ELF file."""
        informational = []
        
        # Architecture
        arch = "ELF64" if elf_info['is_64bit'] else "ELF32"
        endian = "LSB" if elf_info['is_little_endian'] else "MSB"
        
        informational.append(InformationalArtifact(
            artifact_type="elf_info",
            value=arch,
            description=f"Architecture: {arch}, Endianness: {endian}",
            benign=True
        ))
        
        # Entry point
        informational.append(InformationalArtifact(
            artifact_type="elf_info",
            value="Entry Point",
            description=f"Entry point: 0x{elf_info['entry']:x}",
            benign=True
        ))
        
        # Interpreter
        if elf_info['interpreter']:
            informational.append(InformationalArtifact(
                artifact_type="elf_info",
                value="Interpreter",
                description=f"Interpreter: {elf_info['interpreter']}",
                benign=True
            ))
        
        # Libraries
        if elf_info['needed_libraries']:
            lib_list = ', '.join(elf_info['needed_libraries'][:5])
            if len(elf_info['needed_libraries']) > 5:
                lib_list += f", ... ({len(elf_info['needed_libraries'])} total)"
            
            informational.append(InformationalArtifact(
                artifact_type="elf_info",
                value="Dynamic Libraries",
                description=f"NEEDED: {lib_list}",
                benign=True
            ))
        
        return informational
