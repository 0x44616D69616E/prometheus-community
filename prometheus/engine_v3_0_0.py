"""
PROMETHEUS COMMUNITY EDITION v3.0.0 - COMPLETE ANALYSIS ENGINE

Forensic binary analysis with comprehensive detection capabilities.

Block 1: Foundation (3-tier classification, context validation)
Block 2: Advanced Detection (steganography, shellcode, XOR, nested files)  
Block 3: Executable Deep Dive (PE analysis, anti-analysis, crypto)
Block 4: Cross-Platform & Network (ELF analysis, strings, network artifacts)

This is the COMPLETE Prometheus v3.0.0 system with all 13 detectors!

Copyright (c) 2026 Damian Donahue
"""

import time
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from models_v3 import (
    Sample, AnalysisResult, FileType, StaticAnalysis,
    ExactMatch, SuspiciousArtifact, InformationalArtifact,
    FileTypeValidationResult
)
from config import PrometheusConfig
from behavioral_detector_v3 import BehavioralDetectorV3
from file_type_validator import FileTypeValidator
from output_formatter import OutputFormatter

# Block 2 detectors
from steganography_detector import SteganographyDetector
from shellcode_detector import ShellcodeDetector
from xor_encoding_detector import XOREncodingDetector
from nested_file_detector import NestedFileDetector

# Block 3 detectors
from pe_analyzer import PEAnalyzer
from anti_analysis_detector import AntiAnalysisDetector
from crypto_detector import CryptographicDetector

# Block 4 detectors
from elf_analyzer import ELFAnalyzer
from string_analyzer import StringAnalyzer
from network_detector import NetworkArtifactDetector


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data."""
    if not data:
        return 0.0
    
    import math
    from collections import Counter
    
    byte_counts = Counter(data)
    total = len(data)
    
    entropy = 0.0
    for count in byte_counts.values():
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    
    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
    """Extract ASCII strings from binary data with location tracking."""
    strings = []
    current_string = []
    string_start = 0
    
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:  # Printable ASCII
            if not current_string:
                string_start = i
            current_string.append(chr(byte))
        else:
            if len(current_string) >= min_length:
                strings.append({
                    'value': ''.join(current_string),
                    'offset': string_start,
                    'length': len(current_string)
                })
            current_string = []
    
    if len(current_string) >= min_length:
        strings.append({
            'value': ''.join(current_string),
            'offset': string_start,
            'length': len(current_string)
        })
    
    return strings


class PrometheusEngineV3:
    """
    Prometheus v3.0.0 COMPLETE analysis engine.
    
    13 integrated detectors across 4 blocks:
    - Block 1: File type validation, behavioral detection, context validation
    - Block 2: Steganography, shellcode, XOR/encoding, nested files
    - Block 3: PE analysis, anti-analysis, cryptography
    - Block 4: ELF analysis, string analysis, network artifacts
    
    ~85% coverage of Binary Analysis Academic Reference!
    """
    
    def __init__(self, config: Optional[PrometheusConfig] = None, 
                 intel_path: Optional[str] = None):
        """
        Initialize Prometheus engine with ALL detectors.
        
        Args:
            config: PrometheusConfig object (uses default if None)
            intel_path: Path to intelligence database JSON
        """
        self.config = config or PrometheusConfig.default()
        
        # Load intelligence database
        if intel_path is None:
            intel_path = '/mnt/project/intelligence_v2_1_cleaned.json'
            if not Path(intel_path).exists():
                intel_path = '/mnt/project/intelligence.json'
        
        with open(intel_path, 'r') as f:
            self.intel_db = json.load(f)
        
        # Initialize Block 1 components
        self.behavioral_detector = BehavioralDetectorV3(self.intel_db, self.config)
        self.file_type_validator = FileTypeValidator()
        self.output_formatter = OutputFormatter(quiet=self.config.quiet_mode)
        
        # Initialize Block 2 components
        self.steganography_detector = SteganographyDetector()
        self.shellcode_detector = ShellcodeDetector()
        self.xor_encoding_detector = XOREncodingDetector()
        self.nested_file_detector = NestedFileDetector()
        
        # Initialize Block 3 components
        self.pe_analyzer = PEAnalyzer()
        self.anti_analysis_detector = AntiAnalysisDetector()
        self.crypto_detector = CryptographicDetector()
        
        # Initialize Block 4 components
        self.elf_analyzer = ELFAnalyzer()
        self.string_analyzer = StringAnalyzer()
        self.network_detector = NetworkArtifactDetector()
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Perform COMPLETE forensic analysis on a file.
        
        Runs all 13 detectors unless disabled in config.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            AnalysisResult with complete findings
        """
        start_time = time.time()
        
        # Read file
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Create sample
        sample = Sample.from_file(file_path, content)
        
        # Create result
        result = AnalysisResult(sample=sample)
        
        # Print header
        if not self.config.quiet_mode:
            print(self.output_formatter.format_header(result))
        
        # STEP 1: File Type Validation (runs FIRST)
        if self.config.enable_file_type_validation:
            file_type_result = self.file_type_validator.validate(
                sample.filename, content
            )
            
            result.file_type_validation = FileTypeValidationResult(
                filename_type=file_type_result.filename_type,
                content_type=file_type_result.content_type,
                detected_types=file_type_result.detected_types,
                match=file_type_result.match,
                warning=file_type_result.warning,
                suspicious=file_type_result.suspicious,
                polyglot=file_type_result.polyglot
            )
            
            sample.file_type = self._map_to_file_type(file_type_result.content_type)
            
            if not self.config.quiet_mode:
                print(self.output_formatter.format_file_type_validation(
                    result.file_type_validation
                ))
        
        # STEP 2: Static Analysis
        if not self.config.quiet_mode:
            print("─" * 70)
            print("STATIC ANALYSIS")
            print("─" * 70)
            print()
        
        entropy = calculate_entropy(content)
        is_packed = entropy > 7.0
        strings_data = extract_strings(content)
        
        result.static = StaticAnalysis(
            entropy=entropy,
            is_packed=is_packed,
            strings=strings_data,
            strings_count=len(strings_data)
        )
        
        if not self.config.quiet_mode:
            print(f"Entropy: {entropy:.2f}")
            if is_packed:
                print("⚠️  HIGH ENTROPY - Likely packed/encrypted")
            print(f"Strings Extracted: {len(strings_data):,}")
            print()
        
        # STEP 3: Behavioral Detection (Block 1)
        if self.config.enable_behavioral_detection:
            behavioral_data = {
                'content': content,
                'strings': strings_data,
                'filename': sample.filename
            }
            
            exact, suspicious, informational = self.behavioral_detector.detect(
                behavioral_data
            )
            
            result.exact_matches.extend(exact)
            result.suspicious_artifacts.extend(suspicious)
            result.informational.extend(informational)
        
        # STEP 4: Steganography Detection (Block 2)
        if self.config.enable_steganography_detection:
            steg_exact, steg_suspicious, steg_info = self.steganography_detector.detect(
                sample.filename,
                content,
                file_type_result.content_type if result.file_type_validation else "UNKNOWN"
            )
            
            result.exact_matches.extend(steg_exact)
            result.suspicious_artifacts.extend(steg_suspicious)
            result.informational.extend(steg_info)
        
        # STEP 5: Shellcode Detection (Block 2)
        if self.config.enable_shellcode_detection:
            shellcode_high, shellcode_medium = self.shellcode_detector.detect(content)
            
            result.suspicious_artifacts.extend(shellcode_high)
            result.suspicious_artifacts.extend(shellcode_medium)
        
        # STEP 6: XOR/Encoding Detection (Block 2)
        if self.config.enable_xor_encoding_detection:
            xor_suspicious, xor_info = self.xor_encoding_detector.detect(
                content, sample.filename
            )
            
            result.suspicious_artifacts.extend(xor_suspicious)
            result.informational.extend(xor_info)
        
        # STEP 7: Nested File Detection (Block 2)
        if self.config.enable_nested_file_detection:
            nested_suspicious, nested_info = self.nested_file_detector.detect(
                content,
                file_type_result.content_type if result.file_type_validation else "UNKNOWN"
            )
            
            result.suspicious_artifacts.extend(nested_suspicious)
            result.informational.extend(nested_info)
        
        # STEP 8: PE Structure Analysis (Block 3)
        if self.config.enable_pe_analysis and file_type_result.content_type == "PE":
            pe_suspicious, pe_info = self.pe_analyzer.analyze(content, sample.filename)
            
            result.suspicious_artifacts.extend(pe_suspicious)
            result.informational.extend(pe_info)
        
        # STEP 9: Anti-Analysis Detection (Block 3)
        if self.config.enable_anti_analysis_detection:
            anti_high, anti_medium = self.anti_analysis_detector.detect(content)
            
            result.suspicious_artifacts.extend(anti_high)
            result.suspicious_artifacts.extend(anti_medium)
        
        # STEP 10: Cryptographic Detection (Block 3)
        if self.config.enable_crypto_detection:
            crypto_suspicious, crypto_info = self.crypto_detector.detect(content)
            
            result.suspicious_artifacts.extend(crypto_suspicious)
            result.informational.extend(crypto_info)
        
        # STEP 11: ELF Structure Analysis (Block 4)
        if self.config.enable_elf_analysis and file_type_result.content_type == "ELF":
            elf_suspicious, elf_info = self.elf_analyzer.analyze(content, sample.filename)
            
            result.suspicious_artifacts.extend(elf_suspicious)
            result.informational.extend(elf_info)
        
        # STEP 12: String Analysis (Block 4)
        if self.config.enable_string_analysis:
            string_suspicious, string_info = self.string_analyzer.analyze(content)
            
            result.suspicious_artifacts.extend(string_suspicious)
            result.informational.extend(string_info)
        
        # STEP 13: Network Artifact Detection (Block 4)
        if self.config.enable_network_detection:
            # Extract URLs from string findings
            extracted_urls = [s.value for s in result.suspicious_artifacts if s.artifact_type == 'url']
            
            network_suspicious, network_info = self.network_detector.detect(
                content, extracted_urls
            )
            
            result.suspicious_artifacts.extend(network_suspicious)
            result.informational.extend(network_info)
        
        # Extract IOCs and TTPs
        result.iocs = self._extract_iocs(result)
        result.ttps = self._extract_ttps(result)
        
        # Calculate duration
        result.analysis_duration = time.time() - start_time
        
        # Print results
        if not self.config.quiet_mode:
            print(self.output_formatter.format_exact_matches(result.exact_matches))
            print(self.output_formatter.format_suspicious_artifacts(result.suspicious_artifacts))
            print(self.output_formatter.format_informational(result.informational))
            print(self.output_formatter.format_summary(result))
        
        return result
    
    def _map_to_file_type(self, type_string: str) -> FileType:
        """Map type string to FileType enum."""
        type_map = {
            'PE': FileType.PE,
            'ELF': FileType.ELF,
            'MACHO': FileType.MACHO,
            'PDF': FileType.PDF,
            'ZIP': FileType.ZIP,
            'JPEG': FileType.JPEG,
            'PNG': FileType.PNG,
            'GIF': FileType.GIF,
            'BMP': FileType.BMP
        }
        return type_map.get(type_string, FileType.UNKNOWN)
    
    def _extract_iocs(self, result: AnalysisResult) -> List[str]:
        """Extract IOCs from findings."""
        iocs = set()
        
        for match in result.exact_matches:
            if match.artifact_type in ['url', 'ip_address', 'mutex', 'registry_key']:
                iocs.add(match.value)
        
        for artifact in result.suspicious_artifacts:
            if artifact.artifact_type in ['url', 'ip_address', 'suspicious_domain', 'file_extension']:
                iocs.add(artifact.value)
        
        return sorted(list(iocs))
    
    def _extract_ttps(self, result: AnalysisResult) -> List[str]:
        """Extract TTPs from findings."""
        ttps = set()
        
        for match in result.exact_matches:
            if match.mitre_category:
                ttps.add(match.mitre_category.split(' - ')[0])
        
        for artifact in result.suspicious_artifacts:
            if artifact.mitre_category:
                ttps.add(artifact.mitre_category.split(' - ')[0])
        
        return sorted(list(ttps))
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics - all 13 detectors!"""
        return {
            'version': '3.0.0',
            'block': '4 (COMPLETE)',
            'total_detectors': 13,
            'config': {
                'validation_strictness': self.config.validation_strictness.value,
                'context_validation_enabled': self.config.enable_context_validation,
                # Block 2
                'steganography_detection': self.config.enable_steganography_detection,
                'shellcode_detection': self.config.enable_shellcode_detection,
                'xor_encoding_detection': self.config.enable_xor_encoding_detection,
                'nested_file_detection': self.config.enable_nested_file_detection,
                # Block 3
                'pe_analysis': self.config.enable_pe_analysis,
                'anti_analysis_detection': self.config.enable_anti_analysis_detection,
                'crypto_detection': self.config.enable_crypto_detection,
                # Block 4
                'elf_analysis': self.config.enable_elf_analysis,
                'string_analysis': self.config.enable_string_analysis,
                'network_detection': self.config.enable_network_detection
            },
            'indicators': self.behavioral_detector.get_statistics(),
            'intel_database': {
                'behavioral_indicators': len(self.intel_db.get('behavioral_indicators', [])),
                'file_signatures': len(self.intel_db.get('file_signatures', []))
            },
            'coverage': '~85% of Binary Analysis Academic Reference'
        }
