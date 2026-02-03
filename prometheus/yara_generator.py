"""
PROMETHEUS v3.0.0 - YARA RULE GENERATOR

Automatically generates YARA rules from analysis findings.

Generates rules based on:
- Exact matches (definitive indicators)
- File signatures found
- String patterns
- Behavioral indicators
- Cryptographic constants

Copyright (c) 2026 Damian Donahue
"""

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from datetime import datetime
from models_v3 import AnalysisResult, ExactMatch, SuspiciousArtifact


@dataclass
class YARARule:
    """A generated YARA rule."""
    name: str
    description: str
    strings: List[Dict[str, str]]  # List of {name, type, value, modifiers}
    condition: str
    metadata: Dict[str, str]
    tags: List[str]


class YARARuleGenerator:
    """
    Generates YARA rules from analysis findings.
    
    Creates detection rules based on:
    - High-confidence exact matches
    - Unique string patterns
    - Cryptographic constants
    - File structure anomalies
    """
    
    def __init__(self):
        """Initialize YARA rule generator."""
        pass
    
    def generate_rules(self, result: AnalysisResult, rule_name_prefix: str = "prometheus") -> List[YARARule]:
        """
        Generate YARA rules from analysis result.
        
        Args:
            result: AnalysisResult from analysis
            rule_name_prefix: Prefix for rule names
            
        Returns:
            List of YARARule objects
        """
        rules = []
        
        # Generate rule from exact matches
        if result.exact_matches:
            exact_rule = self._generate_exact_match_rule(
                result.exact_matches,
                result,
                rule_name_prefix
            )
            if exact_rule:
                rules.append(exact_rule)
        
        # Generate rule from suspicious strings
        suspicious_strings = [a for a in result.suspicious_artifacts 
                             if a.artifact_type in ['url', 'command', 'suspicious_domain']]
        if suspicious_strings:
            string_rule = self._generate_string_rule(
                suspicious_strings,
                result,
                rule_name_prefix
            )
            if string_rule:
                rules.append(string_rule)
        
        # Generate rule from crypto artifacts
        crypto_artifacts = [a for a in result.informational 
                           if a.artifact_type == 'cryptographic']
        if crypto_artifacts:
            crypto_rule = self._generate_crypto_rule(
                crypto_artifacts,
                result,
                rule_name_prefix
            )
            if crypto_rule:
                rules.append(crypto_rule)
        
        return rules
    
    def _generate_exact_match_rule(self, matches: List[ExactMatch], 
                                   result: AnalysisResult,
                                   prefix: str) -> Optional[YARARule]:
        """Generate YARA rule from exact matches."""
        if not matches:
            return None
        
        # Generate rule name
        timestamp = datetime.now().strftime("%Y%m%d")
        rule_name = f"{prefix}_exact_indicators_{timestamp}"
        
        # Generate strings section
        strings = []
        string_count = 0
        
        for match in matches[:10]:  # Limit to 10 strings
            if match.artifact_type == 'file_signature':
                # Binary signature
                hex_val = match.value.encode('latin-1').hex() if isinstance(match.value, str) else match.value.hex()
                strings.append({
                    'name': f'sig{string_count}',
                    'type': 'hex',
                    'value': hex_val,
                    'modifiers': ''
                })
                string_count += 1
            
            elif match.artifact_type in ['url', 'mutex', 'registry_key']:
                # ASCII string
                strings.append({
                    'name': f'str{string_count}',
                    'type': 'ascii',
                    'value': match.value,
                    'modifiers': 'nocase'
                })
                string_count += 1
        
        if not strings:
            return None
        
        # Generate condition
        string_names = [s['name'] for s in strings]
        if len(string_names) == 1:
            condition = f"${string_names[0]}"
        else:
            # Require multiple matches
            condition = f"any of them"
        
        # Generate metadata
        metadata = {
            'author': 'Prometheus v3.0.0',
            'date': datetime.now().strftime("%Y-%m-%d"),
            'description': f'Generated from {len(matches)} exact matches',
            'hash': result.sample.sha256 if result.sample else 'unknown',
            'confidence': 'high'
        }
        
        # Generate tags
        tags = ['malware', 'prometheus_generated']
        if result.sample and result.sample.file_type:
            tags.append(result.sample.file_type.value.lower())
        
        return YARARule(
            name=rule_name,
            description=f"Detects indicators from {result.sample.filename if result.sample else 'sample'}",
            strings=strings,
            condition=condition,
            metadata=metadata,
            tags=tags
        )
    
    def _generate_string_rule(self, artifacts: List[SuspiciousArtifact],
                             result: AnalysisResult,
                             prefix: str) -> Optional[YARARule]:
        """Generate YARA rule from suspicious strings."""
        if not artifacts:
            return None
        
        # Generate rule name
        timestamp = datetime.now().strftime("%Y%m%d")
        rule_name = f"{prefix}_suspicious_strings_{timestamp}"
        
        # Generate strings section
        strings = []
        string_count = 0
        
        for artifact in artifacts[:10]:  # Limit to 10
            strings.append({
                'name': f'sus{string_count}',
                'type': 'ascii',
                'value': artifact.value,
                'modifiers': 'nocase'
            })
            string_count += 1
        
        if not strings:
            return None
        
        # Generate condition (require at least 2 matches for strings)
        if len(strings) >= 2:
            condition = "2 of them"
        else:
            condition = "any of them"
        
        # Generate metadata
        metadata = {
            'author': 'Prometheus v3.0.0',
            'date': datetime.now().strftime("%Y-%m-%d"),
            'description': f'Suspicious string patterns from {result.sample.filename if result.sample else "sample"}',
            'hash': result.sample.sha256 if result.sample else 'unknown',
            'confidence': 'medium'
        }
        
        # Generate tags
        tags = ['suspicious', 'prometheus_generated', 'strings']
        
        return YARARule(
            name=rule_name,
            description=f"Detects suspicious string patterns",
            strings=strings,
            condition=condition,
            metadata=metadata,
            tags=tags
        )
    
    def _generate_crypto_rule(self, artifacts: List,
                             result: AnalysisResult,
                             prefix: str) -> Optional[YARARule]:
        """Generate YARA rule from cryptographic artifacts."""
        if not artifacts:
            return None
        
        # Generate rule name
        timestamp = datetime.now().strftime("%Y%m%d")
        rule_name = f"{prefix}_crypto_constants_{timestamp}"
        
        # Generate strings section
        strings = []
        string_count = 0
        
        for artifact in artifacts[:5]:  # Limit to 5
            # Try to get the actual bytes from location
            if artifact.location and artifact.location.length > 0:
                # Placeholder - would need actual bytes
                desc = artifact.description.split("Bytes: ")
                if len(desc) > 1:
                    hex_str = desc[1].split("\n")[0].replace(" ", "").replace("...", "")
                    if hex_str:
                        strings.append({
                            'name': f'crypto{string_count}',
                            'type': 'hex',
                            'value': hex_str,
                            'modifiers': ''
                        })
                        string_count += 1
        
        if not strings:
            return None
        
        # Generate condition
        condition = "any of them"
        
        # Generate metadata
        metadata = {
            'author': 'Prometheus v3.0.0',
            'date': datetime.now().strftime("%Y-%m-%d"),
            'description': 'Cryptographic constants detected',
            'hash': result.sample.sha256 if result.sample else 'unknown',
            'confidence': 'medium'
        }
        
        # Generate tags
        tags = ['crypto', 'prometheus_generated']
        
        return YARARule(
            name=rule_name,
            description=f"Detects cryptographic constants",
            strings=strings,
            condition=condition,
            metadata=metadata,
            tags=tags
        )
    
    def format_rule(self, rule: YARARule) -> str:
        """
        Format YARARule as valid YARA syntax.
        
        Args:
            rule: YARARule object
            
        Returns:
            Formatted YARA rule string
        """
        lines = []
        
        # Add header comment
        lines.append("/*")
        lines.append(f" * {rule.description}")
        lines.append(f" * Generated by Prometheus v3.0.0")
        lines.append(f" * Date: {rule.metadata.get('date', 'unknown')}")
        lines.append(" */")
        lines.append("")
        
        # Rule declaration
        tags_str = f" : {' '.join(rule.tags)}" if rule.tags else ""
        lines.append(f"rule {rule.name}{tags_str}")
        lines.append("{")
        
        # Metadata section
        if rule.metadata:
            lines.append("    meta:")
            for key, value in rule.metadata.items():
                lines.append(f'        {key} = "{value}"')
            lines.append("")
        
        # Strings section
        if rule.strings:
            lines.append("    strings:")
            for string in rule.strings:
                name = string['name']
                stype = string['type']
                value = string['value']
                modifiers = f" {string['modifiers']}" if string['modifiers'] else ""
                
                if stype == 'hex':
                    # Hex string
                    formatted_hex = ' '.join(value[i:i+2] for i in range(0, len(value), 2))
                    lines.append(f'        ${name} = {{ {formatted_hex} }}{modifiers}')
                elif stype == 'ascii':
                    # ASCII string
                    escaped_value = value.replace('\\', '\\\\').replace('"', '\\"')
                    lines.append(f'        ${name} = "{escaped_value}"{modifiers}')
            lines.append("")
        
        # Condition section
        lines.append("    condition:")
        lines.append(f"        {rule.condition}")
        
        # Close rule
        lines.append("}")
        
        return "\n".join(lines)
    
    def generate_ruleset(self, result: AnalysisResult, 
                        rule_name_prefix: str = "prometheus") -> str:
        """
        Generate complete YARA ruleset from analysis.
        
        Args:
            result: AnalysisResult from analysis
            rule_name_prefix: Prefix for rule names
            
        Returns:
            Complete YARA ruleset as string
        """
        rules = self.generate_rules(result, rule_name_prefix)
        
        if not rules:
            return "// No YARA rules generated (insufficient indicators)"
        
        # Format all rules
        formatted_rules = []
        for rule in rules:
            formatted_rules.append(self.format_rule(rule))
        
        # Add header
        header = f"""/*
 * YARA Rules Generated by Prometheus v3.0.0
 * Source: {result.sample.filename if result.sample else 'unknown'}
 * SHA256: {result.sample.sha256 if result.sample else 'unknown'}
 * Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
 * 
 * Rules: {len(rules)}
 */

"""
        
        return header + "\n\n".join(formatted_rules)
