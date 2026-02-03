"""
PROMETHEUS v3.0.0 - OUTPUT FORMATTER

Forensic-style output formatting for 3-tier classification system.

Presents evidence clearly without making unwarranted assumptions.

Copyright (c) 2026 Damian Donahue
"""

from typing import List
from models_v3 import (
    AnalysisResult, ExactMatch, SuspiciousArtifact, InformationalArtifact,
    FileTypeValidationResult
)


class OutputFormatter:
    """
    Formats analysis results in forensic evidence presentation style.
    
    Key principles:
    - Show WHAT was found (not assumptions)
    - Show WHERE it was found (exact locations)
    - Show WHY it matters (context and references)
    - Let analyst make final decisions
    """
    
    def __init__(self, quiet: bool = False):
        """
        Initialize formatter.
        
        Args:
            quiet: Suppress output if True
        """
        self.quiet = quiet
    
    def format_header(self, result: AnalysisResult) -> str:
        """Format analysis header."""
        output = []
        output.append("╔" + "═" * 58 + "╗")
        output.append("║   🔥 PROMETHEUS COMMUNITY EDITION v3.0.0                ║")
        output.append("║   Forensic Binary Analysis Engine                      ║")
        output.append("╚" + "═" * 58 + "╝")
        output.append("")
        output.append(f"File: {result.sample.filename}")
        output.append(f"SHA256: {result.sample.sha256}")
        output.append(f"Size: {result.sample.file_size:,} bytes")
        output.append("")
        
        return "\n".join(output)
    
    def format_file_type_validation(self, validation: FileTypeValidationResult) -> str:
        """Format file type validation results."""
        if not validation:
            return ""
        
        output = []
        output.append("─" * 70)
        output.append("FILE TYPE ANALYSIS")
        output.append("─" * 70)
        output.append("")
        
        output.append(f"Declared Type: {validation.filename_type} (from extension)")
        output.append(f"Actual Type: {validation.content_type} (from magic bytes)")
        
        if validation.warning:
            output.append("")
            output.append(validation.warning)
        
        if validation.polyglot:
            output.append("")
            output.append("⚠️  POLYGLOT DETECTED: File valid as multiple formats")
            output.append(f"   Detected formats: {', '.join(validation.detected_types)}")
        
        if validation.suspicious:
            output.append("")
            output.append("⚠️  SUSPICIOUS: Type mismatch may indicate evasion or malicious intent")
        
        output.append("")
        return "\n".join(output)
    
    def format_exact_matches(self, matches: List[ExactMatch]) -> str:
        """Format exact matches (Tier 1 - Definitive)."""
        if not matches:
            return ""
        
        output = []
        output.append("═" * 70)
        output.append("EXACT MATCHES (Definitive Signatures)")
        output.append("═" * 70)
        output.append("")
        output.append(f"Count: {len(matches)} exact match{'es' if len(matches) != 1 else ''}")
        output.append("")
        
        for i, match in enumerate(matches, 1):
            output.append(f"[{i}] {match.artifact_type.replace('_', ' ').title()}: {match.value}")
            output.append(f"    📍 Location: {match.location}")
            if match.location.length:
                output.append(f"    📏 Length: {match.location.length} bytes")
            if match.location.section:
                output.append(f"    📂 Section: {match.location.section}")
            output.append(f"    🏷️  Family: {match.malware_family}")
            output.append(f"    💎 Uniqueness: {match.uniqueness.value.upper()}")
            
            if match.mitre_category:
                output.append(f"    🎯 MITRE ATT&CK: {match.mitre_category}")
            
            if match.first_seen:
                output.append(f"    📅 First Seen: {match.first_seen}")
            
            if match.references:
                output.append(f"    📚 References:")
                for ref in match.references[:3]:
                    output.append(f"       • {ref}")
            
            output.append("")
            output.append(f"    ✅ ASSESSMENT: {match.get_assessment()}")
            output.append("")
        
        return "\n".join(output)
    
    def format_suspicious_artifacts(self, artifacts: List[SuspiciousArtifact]) -> str:
        """Format suspicious artifacts (Tier 2 - Investigate)."""
        if not artifacts:
            return ""
        
        output = []
        output.append("═" * 70)
        output.append("SUSPICIOUS ARTIFACTS (Investigate Further)")
        output.append("═" * 70)
        output.append("")
        output.append(f"Count: {len(artifacts)} suspicious artifact{'s' if len(artifacts) != 1 else ''}")
        output.append("")
        
        # Group by severity
        critical = [a for a in artifacts if a.severity.value == 'critical']
        high = [a for a in artifacts if a.severity.value == 'high']
        medium = [a for a in artifacts if a.severity.value == 'medium']
        low = [a for a in artifacts if a.severity.value == 'low']
        
        for severity_name, severity_list in [
            ("CRITICAL", critical), ("HIGH", high), 
            ("MEDIUM", medium), ("LOW", low)
        ]:
            if not severity_list:
                continue
            
            output.append(f"🔴 {severity_name} Severity ({len(severity_list)}):")
            output.append("")
            
            for i, artifact in enumerate(severity_list[:5], 1):  # Show top 5 per severity
                output.append(f"   [{i}] {artifact.artifact_type.replace('_', ' ').title()}: {artifact.value}")
                output.append(f"       📍 Location: {artifact.location}")
                output.append(f"       📊 Confidence: {artifact.confidence:.0%}")
                output.append(f"       🔍 Observed in: {', '.join(artifact.observed_in[:2])}")
                
                if artifact.also_found_in:
                    output.append(f"       ℹ️  Also found in: {artifact.also_found_in}")
                
                if artifact.context:
                    output.append(f"       💬 Context: {artifact.context[:80]}...")
                
                if artifact.mitre_category:
                    output.append(f"       🎯 MITRE: {artifact.mitre_category}")
                
                output.append(f"       ⚠️  {artifact.get_assessment()}")
                output.append("")
            
            if len(severity_list) > 5:
                output.append(f"   ... and {len(severity_list) - 5} more {severity_name.lower()} artifacts")
                output.append("")
        
        return "\n".join(output)
    
    def format_informational(self, artifacts: List[InformationalArtifact]) -> str:
        """Format informational artifacts (Tier 3 - Context)."""
        if not artifacts:
            return ""
        
        output = []
        output.append("═" * 70)
        output.append("INFORMATIONAL ARTIFACTS (Context & Metadata)")
        output.append("═" * 70)
        output.append("")
        output.append(f"Count: {len(artifacts)} informational artifact{'s' if len(artifacts) != 1 else ''}")
        output.append("")
        
        for i, artifact in enumerate(artifacts[:10], 1):  # Show top 10
            icon = "✓" if artifact.benign else "ℹ️"
            output.append(f"{icon} [{i}] {artifact.artifact_type.replace('_', ' ').title()}: {artifact.value}")
            
            if artifact.location:
                output.append(f"    📍 {artifact.location}")
            
            if artifact.description:
                output.append(f"    💬 {artifact.description[:100]}...")
            
            output.append(f"    {artifact.get_assessment()}")
            output.append("")
        
        if len(artifacts) > 10:
            output.append(f"... and {len(artifacts) - 10} more informational artifacts")
            output.append("")
        
        return "\n".join(output)
    
    def format_summary(self, result: AnalysisResult) -> str:
        """Format analysis summary."""
        output = []
        output.append("═" * 70)
        output.append("ANALYSIS SUMMARY")
        output.append("═" * 70)
        output.append("")
        
        summary = result.get_summary()
        output.append(f"Artifacts Found:")
        output.append(f"  • Exact matches: {summary['exact_matches']}")
        output.append(f"  • Suspicious: {summary['suspicious']}")
        output.append(f"  • Informational: {summary['informational']}")
        output.append(f"  • Total: {summary['total']}")
        output.append("")
        
        # Malware families
        families = result.get_malware_families()
        if families:
            output.append(f"Known Malware Families Detected:")
            for family in families:
                output.append(f"  • {family}")
            output.append("")
        
        # Overall assessment
        output.append("Overall Assessment:")
        output.append(f"  {result.get_assessment()}")
        output.append("")
        
        # Static analysis
        if result.static:
            output.append(f"File Characteristics:")
            output.append(f"  • Entropy: {result.static.entropy:.2f}")
            if result.static.is_packed:
                output.append(f"  • ⚠️  HIGH ENTROPY - Likely packed/encrypted")
            output.append(f"  • Strings: {result.static.strings_count:,}")
            output.append("")
        
        # IOCs
        if result.iocs:
            output.append(f"Indicators of Compromise ({len(result.iocs)}):")
            for ioc in result.iocs[:10]:
                output.append(f"  • {ioc}")
            if len(result.iocs) > 10:
                output.append(f"  ... and {len(result.iocs) - 10} more")
            output.append("")
        
        # TTPs
        if result.ttps:
            output.append(f"Tactics, Techniques & Procedures ({len(result.ttps)}):")
            for ttp in result.ttps:
                output.append(f"  • {ttp}")
            output.append("")
        
        output.append(f"⏱️  Analysis Duration: {result.analysis_duration:.3f}s")
        output.append("")
        
        return "\n".join(output)
    
    def format_complete_output(self, result: AnalysisResult) -> str:
        """
        Format complete analysis output.
        
        Args:
            result: Analysis result to format
            
        Returns:
            Formatted output string
        """
        sections = []
        
        # Header
        sections.append(self.format_header(result))
        
        # File type validation
        if result.file_type_validation:
            sections.append(self.format_file_type_validation(result.file_type_validation))
        
        # Static analysis basic info
        if result.static:
            sections.append("─" * 70)
            sections.append("STATIC ANALYSIS")
            sections.append("─" * 70)
            sections.append("")
            sections.append(f"Entropy: {result.static.entropy:.2f}")
            if result.static.is_packed:
                sections.append("⚠️  HIGH ENTROPY - Likely packed/encrypted")
            sections.append(f"Strings Extracted: {result.static.strings_count:,}")
            sections.append("")
        
        # Three-tier classification
        sections.append(self.format_exact_matches(result.exact_matches))
        sections.append(self.format_suspicious_artifacts(result.suspicious_artifacts))
        sections.append(self.format_informational(result.informational))
        
        # Summary
        sections.append(self.format_summary(result))
        
        return "\n".join(sections)
