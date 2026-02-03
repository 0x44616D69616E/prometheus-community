"""
PROMETHEUS v3.0.0 - IOC EXPORTER

Exports Indicators of Compromise (IOCs) in multiple formats.

Supported formats:
- JSON: Structured data for APIs
- CSV: For spreadsheets and databases
- STIX 2.1: For threat intelligence platforms
- OpenIOC: XML-based IOC format

Copyright (c) 2026 Damian Donahue
"""

import json
import csv
from datetime import datetime
from typing import List, Dict, Any
from io import StringIO
from prometheus.models_v3 import AnalysisResult, ExactMatch, SuspiciousArtifact


class IOCExporter:
    """
    Exports IOCs in multiple standard formats.
    
    Formats:
    - JSON: Simple structured format
    - CSV: Spreadsheet-compatible
    - STIX 2.1: Threat intelligence standard
    """
    
    def __init__(self):
        """Initialize IOC exporter."""
        pass
    
    def export_json(self, result: AnalysisResult) -> str:
        """
        Export IOCs as JSON.
        
        Args:
            result: AnalysisResult from analysis
            
        Returns:
            JSON string
        """
        iocs = {
            'metadata': {
                'generator': 'Prometheus v3.0.0',
                'generated': datetime.now().isoformat(),
                'sample': {
                    'filename': result.sample.filename if result.sample else 'unknown',
                    'md5': result.sample.md5 if result.sample else None,
                    'sha1': result.sample.sha1 if result.sample else None,
                    'sha256': result.sample.sha256 if result.sample else None,
                    'size': result.sample.file_size if result.sample else 0,
                    'file_type': result.sample.file_type.value if result.sample and result.sample.file_type else 'unknown'
                },
                'analysis_duration': result.analysis_duration,
                'timestamp': datetime.now().isoformat()
            },
            'indicators': {
                'exact_matches': [],
                'suspicious': [],
                'urls': [],
                'domains': [],
                'ip_addresses': [],
                'file_hashes': [],
                'registry_keys': [],
                'mutexes': [],
                'ttps': result.ttps
            }
        }
        
        # Extract exact matches
        for match in result.exact_matches:
            iocs['indicators']['exact_matches'].append({
                'type': match.artifact_type,
                'value': match.value,
                'confidence': match.confidence,
                'context': match.context,
                'mitre': match.mitre_category
            })
        
        # Extract suspicious artifacts by type
        for artifact in result.suspicious_artifacts:
            if artifact.artifact_type == 'url':
                iocs['indicators']['urls'].append({
                    'value': artifact.value,
                    'confidence': artifact.confidence,
                    'severity': artifact.severity.value
                })
            elif artifact.artifact_type in ['ip_address', 'suspicious_domain']:
                if '.' in artifact.value and len(artifact.value.split('.')) == 4:
                    # IP address
                    iocs['indicators']['ip_addresses'].append({
                        'value': artifact.value,
                        'confidence': artifact.confidence,
                        'severity': artifact.severity.value
                    })
                else:
                    # Domain
                    iocs['indicators']['domains'].append({
                        'value': artifact.value,
                        'confidence': artifact.confidence,
                        'severity': artifact.severity.value
                    })
            elif artifact.artifact_type == 'registry_key':
                iocs['indicators']['registry_keys'].append({
                    'value': artifact.value,
                    'confidence': artifact.confidence
                })
            elif artifact.artifact_type == 'mutex':
                iocs['indicators']['mutexes'].append({
                    'value': artifact.value,
                    'confidence': artifact.confidence
                })
            else:
                iocs['indicators']['suspicious'].append({
                    'type': artifact.artifact_type,
                    'value': artifact.value,
                    'confidence': artifact.confidence,
                    'severity': artifact.severity.value
                })
        
        # Add file hashes
        if result.sample:
            iocs['indicators']['file_hashes'].append({
                'type': 'md5',
                'value': result.sample.md5
            })
            iocs['indicators']['file_hashes'].append({
                'type': 'sha1',
                'value': result.sample.sha1
            })
            iocs['indicators']['file_hashes'].append({
                'type': 'sha256',
                'value': result.sample.sha256
            })
        
        return json.dumps(iocs, indent=2)
    
    def export_csv(self, result: AnalysisResult) -> str:
        """
        Export IOCs as CSV.
        
        Args:
            result: AnalysisResult from analysis
            
        Returns:
            CSV string
        """
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Type', 'Value', 'Confidence', 'Severity', 
            'Context', 'MITRE ATT&CK'
        ])
        
        # Write exact matches
        for match in result.exact_matches:
            writer.writerow([
                match.artifact_type,
                match.value,
                f"{match.confidence:.2f}",
                'HIGH',
                match.context[:100] if match.context else '',
                match.mitre_category or ''
            ])
        
        # Write suspicious artifacts
        for artifact in result.suspicious_artifacts:
            writer.writerow([
                artifact.artifact_type,
                artifact.value,
                f"{artifact.confidence:.2f}",
                artifact.severity.value,
                artifact.context[:100] if artifact.context else '',
                artifact.mitre_category or ''
            ])
        
        return output.getvalue()
    
    def export_stix(self, result: AnalysisResult) -> str:
        """
        Export IOCs as STIX 2.1.
        
        Args:
            result: AnalysisResult from analysis
            
        Returns:
            STIX 2.1 JSON string
        """
        import uuid
        
        # Generate IDs
        def generate_id(obj_type: str) -> str:
            return f"{obj_type}--{str(uuid.uuid4())}"
        
        timestamp = datetime.now().isoformat() + 'Z'
        
        # Create STIX bundle
        bundle = {
            'type': 'bundle',
            'id': generate_id('bundle'),
            'objects': []
        }
        
        # Add identity (creator)
        identity = {
            'type': 'identity',
            'spec_version': '2.1',
            'id': generate_id('identity'),
            'created': timestamp,
            'modified': timestamp,
            'name': 'Prometheus Analysis Engine',
            'identity_class': 'system',
            'description': 'Automated malware analysis system'
        }
        bundle['objects'].append(identity)
        
        # Add malware object
        if result.sample:
            malware = {
                'type': 'malware',
                'spec_version': '2.1',
                'id': generate_id('malware'),
                'created': timestamp,
                'modified': timestamp,
                'name': result.sample.filename,
                'is_family': False,
                'malware_types': ['unknown']
            }
            bundle['objects'].append(malware)
            
            # Add file object with hashes
            file_obj = {
                'type': 'file',
                'spec_version': '2.1',
                'id': generate_id('file'),
                'name': result.sample.filename,
                'size': result.sample.file_size,
                'hashes': {
                    'MD5': result.sample.md5,
                    'SHA-1': result.sample.sha1,
                    'SHA-256': result.sample.sha256
                }
            }
            bundle['objects'].append(file_obj)
        
        # Add indicators
        for match in result.exact_matches:
            if match.artifact_type == 'url':
                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': generate_id('indicator'),
                    'created': timestamp,
                    'modified': timestamp,
                    'name': f"URL: {match.value}",
                    'pattern': f"[url:value = '{match.value}']",
                    'pattern_type': 'stix',
                    'valid_from': timestamp,
                    'indicator_types': ['malicious-activity']
                }
                bundle['objects'].append(indicator)
            
            elif match.artifact_type == 'ip_address':
                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': generate_id('indicator'),
                    'created': timestamp,
                    'modified': timestamp,
                    'name': f"IP: {match.value}",
                    'pattern': f"[ipv4-addr:value = '{match.value}']",
                    'pattern_type': 'stix',
                    'valid_from': timestamp,
                    'indicator_types': ['malicious-activity']
                }
                bundle['objects'].append(indicator)
        
        # Add suspicious artifacts as indicators
        for artifact in result.suspicious_artifacts[:20]:  # Limit to 20
            if artifact.artifact_type == 'url':
                indicator = {
                    'type': 'indicator',
                    'spec_version': '2.1',
                    'id': generate_id('indicator'),
                    'created': timestamp,
                    'modified': timestamp,
                    'name': f"Suspicious URL: {artifact.value}",
                    'description': artifact.context[:200] if artifact.context else '',
                    'pattern': f"[url:value = '{artifact.value}']",
                    'pattern_type': 'stix',
                    'valid_from': timestamp,
                    'indicator_types': ['anomalous-activity'],
                    'confidence': int(artifact.confidence * 100)
                }
                bundle['objects'].append(indicator)
        
        # Add TTPs as attack patterns
        for ttp in result.ttps[:10]:  # Limit to 10
            attack_pattern = {
                'type': 'attack-pattern',
                'spec_version': '2.1',
                'id': generate_id('attack-pattern'),
                'created': timestamp,
                'modified': timestamp,
                'name': ttp,
                'external_references': [{
                    'source_name': 'mitre-attack',
                    'external_id': ttp
                }]
            }
            bundle['objects'].append(attack_pattern)
        
        return json.dumps(bundle, indent=2)
    
    def export_all_formats(self, result: AnalysisResult, base_filename: str = "iocs") -> Dict[str, str]:
        """
        Export IOCs in all supported formats.
        
        Args:
            result: AnalysisResult from analysis
            base_filename: Base name for output files
            
        Returns:
            Dict mapping format name to content
        """
        return {
            'json': self.export_json(result),
            'csv': self.export_csv(result),
            'stix': self.export_stix(result)
        }
    
    def save_exports(self, result: AnalysisResult, output_dir: str, base_filename: str = "iocs"):
        """
        Save all IOC exports to files.
        
        Args:
            result: AnalysisResult from analysis
            output_dir: Directory to save files
            base_filename: Base name for output files
        """
        import os
        
        exports = self.export_all_formats(result, base_filename)
        
        for format_name, content in exports.items():
            output_path = os.path.join(output_dir, f"{base_filename}.{format_name}")
            with open(output_path, 'w') as f:
                f.write(content)
            
            print(f"✓ Saved: {output_path}")
