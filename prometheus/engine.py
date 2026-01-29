"""
PROMETHEUS COMMUNITY EDITION v2.0.0 - ANALYSIS ENGINE

The most transparent malware analyzer with explainable detection 
and forensic-grade location tracking.

Copyright (c) 2026 Damian Donahue
"""

import time
from typing import Dict, Any, List
from .models import (
    Sample, 
    AnalysisResult, 
    FileType, 
    StaticAnalysis,
    DetectionReasoning,
    Severity,
    Uniqueness
)
from .signature_engine import SignatureEngine, calculate_entropy, extract_strings
from .behavioral_detector import BehavioralDetector
from .exploit_detector import ExploitDetector
import json
import os


class PrometheusEngine:
    """
    Prometheus 6-layer malware analysis engine with explainable detection.
    
    Now with complete transparency showing WHAT was found, WHY it matters,
    and WHERE it's located in the file.
    """
    
    def __init__(self, intel_path: str = None, quiet: bool = False):
        """
        Initialize Prometheus engine.
        
        Args:
            intel_path: Path to intelligence database JSON
            quiet: Suppress console output
        """
        self.quiet = quiet
        
        # Load intelligence database
        if intel_path is None:
            # Default to packaged intelligence
            import pkg_resources
            intel_path = pkg_resources.resource_filename(
                'prometheus', 'data/intelligence.json'
            )
        
        with open(intel_path, 'r') as f:
            self.intel_db = json.load(f)
        
        # Initialize detection layers
        self.signature_engine = SignatureEngine(self.intel_db)
        self.behavioral_detector = BehavioralDetector(self.intel_db)
        self.exploit_detector = ExploitDetector(self.intel_db)
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Perform complete 6-layer analysis on a file.
        
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
        sample.file_type = self._detect_file_type(content)
        
        # Create result
        result = AnalysisResult(sample=sample)
        
        if not self.quiet:
            print("╔══════════════════════════════════════════════════════════╗")
            print("║   🔥 PROMETHEUS COMMUNITY EDITION v2.0.0                ║")
            print("║   The Most Transparent Malware Analyzer                 ║")
            print("╚══════════════════════════════════════════════════════════╝")
            print()
            print(f"Analyzing: {sample.filename}")
            print(f"SHA256: {sample.sha256}")
            print(f"Size: {sample.file_size:,} bytes")
            print(f"Type: {sample.file_type.value}")
            print()
            print("━" * 70)
        
        # Layer 1: File Signatures & Entropy
        if not self.quiet:
            print("📄 Layer 1: File Signatures & Entropy")
            print()
        
        entropy = calculate_entropy(content)
        is_packed = entropy > 7.0
        
        sig_matches = self.signature_engine.scan(content)
        strings_data = extract_strings(content)
        
        result.static = StaticAnalysis(
            entropy=entropy,
            is_packed=is_packed,
            signature_matches=sig_matches,
            strings=strings_data,
            strings_count=len(strings_data)
        )
        
        if not self.quiet:
            print(f"  Entropy: {entropy:.2f}")
            if is_packed:
                print(f"  ⚠️  HIGH ENTROPY - Likely packed/encrypted")
            print(f"  Strings: {len(strings_data):,}")
            print()
            
            if sig_matches:
                print(f"  📝 File Signatures: {len(sig_matches)} matches")
                for match in sig_matches[:5]:
                    print(f"     • {match.signature_name} ({match.category})")
                    if match.location:
                        print(f"       📍 offset 0x{match.location.offset:08x}")
                if len(sig_matches) > 5:
                    print(f"     ... and {len(sig_matches) - 5} more")
            else:
                print(f"  📝 File Signatures: No matches")
            print()
        
        print("━" * 70)
        
        # Layer 2: Behavioral Indicators
        if not self.quiet:
            print("🎯 Layer 2: Behavioral Indicators")
            print()
        
        behavioral_data = {
            'content': content,
            'strings': strings_data,
            'filename': sample.filename
        }
        result.behavioral_matches = self.behavioral_detector.detect(behavioral_data)
        
        if not self.quiet:
            if result.behavioral_matches:
                # Group by severity
                critical = [m for m in result.behavioral_matches if m.severity == Severity.CRITICAL]
                high = [m for m in result.behavioral_matches if m.severity == Severity.HIGH]
                medium = [m for m in result.behavioral_matches if m.severity == Severity.MEDIUM]
                
                # Show critical first
                if critical:
                    print(f"  🔴 CRITICAL Indicators ({len(critical)}):\n")
                    for match in critical[:3]:
                        print(f"     {match.get_severity_icon()} {match.indicator_type.replace('_', ' ').title()}: {match.matched_value}")
                        print(f"        {match.get_uniqueness_badge()} | Confidence: {match.confidence:.0%}")
                        if match.location:
                            print(f"        📍 offset 0x{match.location.offset:08x}, length {match.location.length} bytes")
                        if match.explanation:
                            print(f"        Why: {match.explanation[:100]}...")
                        if match.ttp_category:
                            print(f"        Category: {match.ttp_category}")
                        print()
                
                # Show high severity
                if high:
                    print(f"  🟠 HIGH Severity Indicators ({len(high)}):\n")
                    for match in high[:2]:
                        print(f"     {match.get_severity_icon()} {match.indicator_type.replace('_', ' ').title()}: {match.matched_value}")
                        print(f"        {match.get_uniqueness_badge()} | Confidence: {match.confidence:.0%}")
                        if match.location:
                            print(f"        📍 offset 0x{match.location.offset:08x}")
                        print()
                    if len(high) > 2:
                        print(f"     ... and {len(high) - 2} more high-severity indicators\n")
                
                # Summary
                unique_count = len([m for m in result.behavioral_matches if m.uniqueness == Uniqueness.UNIQUE])
                rare_count = len([m for m in result.behavioral_matches if m.uniqueness == Uniqueness.RARE])
                families = set(m.family for m in result.behavioral_matches)
                
                print(f"  📊 Summary:")
                print(f"     • {unique_count} unique indicators")
                print(f"     • {rare_count} rare indicators")
                print(f"     • {len(families)} families detected: {', '.join(list(families)[:3])}")
                
            else:
                print("  No behavioral indicators matched")
            print()
        
        print("━" * 70)
        
        # Layer 3: Exploit Patterns
        if not self.quiet:
            print("💥 Layer 3: Exploit Patterns")
            print()
        
        result.exploit_matches = self.exploit_detector.detect(content)
        
        if not self.quiet:
            if result.exploit_matches:
                print(f"  💥 Exploit Patterns: {len(result.exploit_matches)} detected\n")
                for match in result.exploit_matches:
                    severity_icon = "🔴" if match.severity == Severity.HIGH else "🟡"
                    print(f"     {severity_icon} {match.technique}")
                    if match.location:
                        print(f"        📍 offset 0x{match.location.offset:08x}, length {match.location.length} bytes")
                    print(f"        Type: {match.pattern_type}, Severity: {match.severity.value}")
                    if match.explanation:
                        print(f"        Why: {match.explanation[:100]}...")
                    print()
            else:
                print("  No exploit patterns detected")
            print()
        
        print("━" * 70)
        
        # Determine family and confidence
        if result.behavioral_matches:
            family, confidence, reasoning = self._determine_family(result)
            result.family = family
            result.confidence = confidence
            result.reasoning = reasoning
        
        # Extract IOCs and TTPs
        result.iocs = self._extract_iocs(result)
        result.ttps = self._extract_ttps(result)
        
        # Calculate duration
        result.analysis_duration = time.time() - start_time
        
        if not self.quiet:
            print("══════════════════════════════════════════════════════════")
            print("VERDICT")
            print("══════════════════════════════════════════════════════════")
            print()
            print(f"🏷️  Family: {result.family}")
            print(f"📊 Confidence: {result.confidence:.0%}")
            print()
            
            # Show reasoning if available
            if result.reasoning:
                print("🧠 Why this family?")
                unique_indicators = result.get_unique_indicators()
                if unique_indicators:
                    print(f"\n   💎 {len(unique_indicators)} UNIQUE Indicators:")
                    for match in unique_indicators[:3]:
                        print(f"      ✓ {match.indicator_type.replace('_', ' ').title()}: {match.matched_value}")
                        if match.location:
                            print(f"        📍 offset 0x{match.location.offset:08x}")
                        print(f"        {match.explanation[:80]}...")
                
                print(f"\n   📊 Detection Summary:")
                print(f"      • {result.reasoning.unique_indicator_count} unique to {result.family}")
                print(f"      • {result.reasoning.total_indicator_count} total indicators")
                print(f"      • Confidence: {result.confidence:.0%}")
                print()
            
            # Show location map
            location_map = result.get_locations_map()
            if any(location_map.values()):
                print("📍 Key Findings Map:")
                if location_map['behavioral']:
                    for i, offset in enumerate(location_map['behavioral'][:3]):
                        match = result.behavioral_matches[i]
                        print(f"   0x{offset:08x}: {match.indicator_type} ({match.severity.value}, {match.uniqueness.value})")
                if location_map['exploits']:
                    for i, offset in enumerate(location_map['exploits'][:3]):
                        match = result.exploit_matches[i]
                        print(f"   0x{offset:08x}: {match.technique} (exploit)")
                print()
            
            # IOCs with locations
            if result.iocs:
                print(f"🔍 Indicators of Compromise ({len(result.iocs)}):")
                for ioc in result.iocs[:10]:
                    print(f"   • {ioc}")
                if len(result.iocs) > 10:
                    print(f"   ... and {len(result.iocs) - 10} more")
            else:
                print("🔍 Indicators of Compromise: None extracted")
            print()
            
            # TTPs
            if result.ttps:
                print(f"⚔️  Tactics, Techniques & Procedures ({len(result.ttps)}):")
                for ttp in result.ttps:
                    print(f"   • {ttp}")
            else:
                print("⚔️  Tactics, Techniques & Procedures: None identified")
            print()
            
            print(f"⏱️  Duration: {result.analysis_duration:.3f}s")
            print()
        
        return result
    
    def _detect_file_type(self, data: bytes) -> FileType:
        """Simple file type detection."""
        if data.startswith(b'MZ'):
            return FileType.PE
        elif data.startswith(b'\x7fELF'):
            return FileType.ELF
        elif data.startswith(b'%PDF'):
            return FileType.PDF
        elif data.startswith(b'PK\x03\x04'):
            return FileType.ZIP
        else:
            return FileType.UNKNOWN
    
    def _determine_family(self, result: AnalysisResult) -> tuple[str, float, DetectionReasoning]:
        """
        Determine malware family with transparent reasoning.
        
        Returns: (family, confidence, reasoning object)
        """
        if not result.behavioral_matches:
            reasoning = DetectionReasoning(
                family="Unknown",
                confidence=0.0,
                unique_indicator_count=0,
                total_indicator_count=0,
                reasoning="No behavioral indicators found"
            )
            return "Unknown", 0.0, reasoning
        
        # Group indicators by family
        families = {}
        for match in result.behavioral_matches:
            if match.family not in families:
                families[match.family] = {
                    'matches': [],
                    'total_confidence': 0.0,
                    'unique_count': 0,
                    'critical_count': 0
                }
            
            families[match.family]['matches'].append(match)
            families[match.family]['total_confidence'] += match.confidence
            
            if match.uniqueness == Uniqueness.UNIQUE:
                families[match.family]['unique_count'] += 1
            
            if match.severity == Severity.CRITICAL:
                families[match.family]['critical_count'] += 1
        
        # Find best match - prioritize unique indicators
        best_family = max(
            families.items(),
            key=lambda x: (
                x[1]['unique_count'],      # Unique most important
                x[1]['critical_count'],     # Then critical severity
                x[1]['total_confidence']    # Then overall confidence
            )
        )
        
        family_name = best_family[0]
        data = best_family[1]
        
        # Calculate confidence
        unique_count = data['unique_count']
        total_count = len(data['matches'])
        
        # Confidence: each unique indicator adds 40%, others add based on weight
        confidence = 0.0
        for match in data['matches']:
            if match.uniqueness == Uniqueness.UNIQUE:
                confidence += 0.4
            else:
                confidence += match.confidence * 0.2
        
        confidence = min(confidence, 1.0)  # Cap at 100%
        
        # Build reasoning
        key_indicators = []
        reasoning_text = f"Detected based on {unique_count} UNIQUE indicators, {total_count} total indicators"
        
        for match in data['matches']:
            if match.uniqueness == Uniqueness.UNIQUE:
                key_indicators.append(f"{match.indicator_type}: {match.matched_value}")
        
        reasoning = DetectionReasoning(
            family=family_name,
            confidence=confidence,
            unique_indicator_count=unique_count,
            total_indicator_count=total_count,
            reasoning=reasoning_text,
            key_indicators=key_indicators
        )
        
        return family_name, confidence, reasoning
    
    def _extract_iocs(self, result: AnalysisResult) -> List[str]:
        """Extract IOCs from all findings."""
        iocs = set()
        
        # From behavioral matches
        for match in result.behavioral_matches:
            if match.indicator_type in ['url', 'ip_address', 'file_name', 'mutex', 'registry_key']:
                iocs.add(match.matched_value)
        
        return sorted(list(iocs))
    
    def _extract_ttps(self, result: AnalysisResult) -> List[str]:
        """Extract TTPs from all findings."""
        ttps = set()
        
        # From behavioral matches
        for match in result.behavioral_matches:
            if match.ttp_category:
                ttps.add(match.ttp_category.split(' - ')[0])  # Get main category
        
        # From exploit matches
        for match in result.exploit_matches:
            if match.ttp_category:
                ttps.add(match.ttp_category.split(' - ')[0])
        
        return sorted(list(ttps))
