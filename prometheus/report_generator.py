"""
PROMETHEUS v3.0.0 - REPORT GENERATOR

Generates professional analysis reports in multiple formats.

Formats:
- HTML: Interactive web report
- Markdown: Documentation-friendly format
- Text: Plain text summary

Copyright (c) 2026 Damian Donahue
"""

from datetime import datetime
from typing import Dict, Any
from models_v3 import AnalysisResult, Severity


class ReportGenerator:
    """
    Generates professional analysis reports.
    
    Creates comprehensive reports with:
    - Executive summary
    - Detailed findings
    - IOC lists
    - TTP mappings
    - Recommendations
    """
    
    def __init__(self):
        """Initialize report generator."""
        pass
    
    def generate_html(self, result: AnalysisResult) -> str:
        """
        Generate HTML report.
        
        Args:
            result: AnalysisResult from analysis
            
        Returns:
            HTML report string
        """
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prometheus Analysis Report - {result.sample.filename if result.sample else 'Unknown'}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .section {{
            background: white;
            padding: 30px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        h2 {{
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f0f0;
        }}
        
        h3 {{
            color: #764ba2;
            margin-top: 20px;
            margin-bottom: 10px;
        }}
        
        .meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        
        .meta-item {{
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .meta-item strong {{
            display: block;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .severity-high {{
            color: #dc3545;
            font-weight: bold;
        }}
        
        .severity-medium {{
            color: #fd7e14;
            font-weight: bold;
        }}
        
        .severity-low {{
            color: #ffc107;
            font-weight: bold;
        }}
        
        .severity-info {{
            color: #17a2b8;
        }}
        
        .finding {{
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #ddd;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .finding-high {{
            border-left-color: #dc3545;
        }}
        
        .finding-medium {{
            border-left-color: #fd7e14;
        }}
        
        .finding-low {{
            border-left-color: #ffc107;
        }}
        
        .finding-title {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .finding-context {{
            color: #666;
            font-size: 0.95em;
            margin-top: 10px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
            margin-right: 5px;
        }}
        
        .badge-high {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-medium {{
            background: #fd7e14;
            color: white;
        }}
        
        .badge-low {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-confidence {{
            background: #6c757d;
            color: white;
        }}
        
        .ioc-list {{
            list-style: none;
            padding: 0;
        }}
        
        .ioc-list li {{
            padding: 8px 12px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .summary-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Prometheus Analysis Report</h1>
            <div class="subtitle">Forensic Binary Analysis | Version 3.0.0</div>
        </header>
"""
        
        # Executive Summary
        html += self._generate_executive_summary_html(result)
        
        # Sample Information
        html += self._generate_sample_info_html(result)
        
        # Findings
        html += self._generate_findings_html(result)
        
        # IOCs
        html += self._generate_iocs_html(result)
        
        # TTPs
        html += self._generate_ttps_html(result)
        
        # Footer
        html += f"""
        <footer>
            <p>Generated by Prometheus v3.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>© 2026 Damian Donahue | Forensic Binary Analysis Engine</p>
        </footer>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_executive_summary_html(self, result: AnalysisResult) -> str:
        """Generate executive summary section."""
        assessment = result.get_assessment()
        
        # Count findings by severity
        high_count = sum(1 for a in result.suspicious_artifacts if a.severity == Severity.HIGH)
        medium_count = sum(1 for a in result.suspicious_artifacts if a.severity == Severity.MEDIUM)
        low_count = sum(1 for a in result.suspicious_artifacts if a.severity == Severity.LOW)
        
        html = f"""
        <div class="section">
            <h2>Executive Summary</h2>
            
            <div class="summary-stats">
                <div class="stat-card">
                    <div class="stat-number">{len(result.exact_matches)}</div>
                    <div class="stat-label">Exact Matches</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{high_count}</div>
                    <div class="stat-label">High Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{medium_count}</div>
                    <div class="stat-label">Medium Severity</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(result.iocs)}</div>
                    <div class="stat-label">IOCs Extracted</div>
                </div>
            </div>
            
            <h3>Assessment</h3>
            <p><strong>{assessment}</strong></p>
            
            <h3>Analysis Details</h3>
            <div class="meta">
                <div class="meta-item">
                    <strong>Analysis Duration</strong>
                    {result.analysis_duration:.2f} seconds
                </div>
                <div class="meta-item">
                    <strong>File Entropy</strong>
                    {result.static.entropy:.2f} {'(HIGH - likely packed)' if result.static.is_packed else '(NORMAL)'}
                </div>
                <div class="meta-item">
                    <strong>Strings Extracted</strong>
                    {result.static.strings_count:,}
                </div>
            </div>
        </div>
"""
        return html
    
    def _generate_sample_info_html(self, result: AnalysisResult) -> str:
        """Generate sample information section."""
        if not result.sample:
            return ""
        
        html = f"""
        <div class="section">
            <h2>Sample Information</h2>
            
            <div class="meta">
                <div class="meta-item">
                    <strong>Filename</strong>
                    {result.sample.filename}
                </div>
                <div class="meta-item">
                    <strong>File Type</strong>
                    {result.sample.file_type.value if result.sample.file_type else 'Unknown'}
                </div>
                <div class="meta-item">
                    <strong>File Size</strong>
                    {result.sample.file_size:,} bytes
                </div>
                <div class="meta-item">
                    <strong>MD5</strong>
                    <span style="font-family: monospace; font-size: 0.9em;">{result.sample.md5}</span>
                </div>
                <div class="meta-item">
                    <strong>SHA1</strong>
                    <span style="font-family: monospace; font-size: 0.9em;">{result.sample.sha1}</span>
                </div>
                <div class="meta-item">
                    <strong>SHA256</strong>
                    <span style="font-family: monospace; font-size: 0.9em;">{result.sample.sha256}</span>
                </div>
            </div>
        </div>
"""
        return html
    
    def _generate_findings_html(self, result: AnalysisResult) -> str:
        """Generate findings section."""
        html = '<div class="section"><h2>Findings</h2>'
        
        # Exact matches
        if result.exact_matches:
            html += '<h3>Exact Matches (High Confidence)</h3>'
            for match in result.exact_matches:
                html += f"""
                <div class="finding finding-high">
                    <div class="finding-title">
                        <span class="badge badge-high">EXACT</span>
                        <span class="badge badge-confidence">{match.confidence*100:.0f}%</span>
                        {match.artifact_type.upper()}: {match.value}
                    </div>
                    <div class="finding-context">{match.context}</div>
                </div>
"""
        
        # Suspicious artifacts by severity
        high_findings = [a for a in result.suspicious_artifacts if a.severity == Severity.HIGH]
        if high_findings:
            html += '<h3>High Severity Findings</h3>'
            for artifact in high_findings[:10]:  # Limit to 10
                html += f"""
                <div class="finding finding-high">
                    <div class="finding-title">
                        <span class="badge badge-high">HIGH</span>
                        <span class="badge badge-confidence">{artifact.confidence*100:.0f}%</span>
                        {artifact.artifact_type.upper()}: {artifact.value}
                    </div>
                    <div class="finding-context">{artifact.context}</div>
                </div>
"""
        
        medium_findings = [a for a in result.suspicious_artifacts if a.severity == Severity.MEDIUM]
        if medium_findings:
            html += '<h3>Medium Severity Findings</h3>'
            for artifact in medium_findings[:10]:
                html += f"""
                <div class="finding finding-medium">
                    <div class="finding-title">
                        <span class="badge badge-medium">MEDIUM</span>
                        <span class="badge badge-confidence">{artifact.confidence*100:.0f}%</span>
                        {artifact.artifact_type.upper()}: {artifact.value}
                    </div>
                    <div class="finding-context">{artifact.context}</div>
                </div>
"""
        
        html += '</div>'
        return html
    
    def _generate_iocs_html(self, result: AnalysisResult) -> str:
        """Generate IOCs section."""
        if not result.iocs:
            return ""
        
        html = f"""
        <div class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            <p>{len(result.iocs)} unique indicators extracted</p>
            <ul class="ioc-list">
"""
        for ioc in result.iocs[:50]:  # Limit to 50
            html += f"                <li>{ioc}</li>\n"
        
        if len(result.iocs) > 50:
            html += f"                <li><em>... and {len(result.iocs) - 50} more</em></li>\n"
        
        html += """            </ul>
        </div>
"""
        return html
    
    def _generate_ttps_html(self, result: AnalysisResult) -> str:
        """Generate TTPs section."""
        if not result.ttps:
            return ""
        
        html = f"""
        <div class="section">
            <h2>MITRE ATT&CK TTPs</h2>
            <p>{len(result.ttps)} tactics, techniques, and procedures identified</p>
            <ul class="ioc-list">
"""
        for ttp in result.ttps:
            html += f"                <li>{ttp}</li>\n"
        
        html += """            </ul>
        </div>
"""
        return html
    
    def generate_markdown(self, result: AnalysisResult) -> str:
        """
        Generate Markdown report.
        
        Args:
            result: AnalysisResult from analysis
            
        Returns:
            Markdown report string
        """
        md = f"""# Prometheus Analysis Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**File:** {result.sample.filename if result.sample else 'Unknown'}  
**Assessment:** {result.get_assessment()}

---

## Executive Summary

- **Exact Matches:** {len(result.exact_matches)}
- **Suspicious Artifacts:** {len(result.suspicious_artifacts)}
- **IOCs Extracted:** {len(result.iocs)}
- **TTPs Identified:** {len(result.ttps)}
- **Analysis Duration:** {result.analysis_duration:.2f}s

---

## Sample Information

"""
        
        if result.sample:
            md += f"""- **Filename:** {result.sample.filename}
- **File Type:** {result.sample.file_type.value if result.sample.file_type else 'Unknown'}
- **Size:** {result.sample.file_size:,} bytes
- **MD5:** `{result.sample.md5}`
- **SHA1:** `{result.sample.sha1}`
- **SHA256:** `{result.sample.sha256}`

"""
        
        md += f"""---

## Static Analysis

- **Entropy:** {result.static.entropy:.2f} {'**(HIGH - likely packed)**' if result.static.is_packed else '(normal)'}
- **Strings:** {result.static.strings_count:,}

---

## Findings

### Exact Matches

"""
        
        if result.exact_matches:
            for match in result.exact_matches:
                md += f"**{match.artifact_type}:** `{match.value}` (Confidence: {match.confidence*100:.0f}%)  \n"
                md += f"  - {match.context}\n\n"
        else:
            md += "*None*\n\n"
        
        md += "### High Severity\n\n"
        
        high_findings = [a for a in result.suspicious_artifacts if a.severity == Severity.HIGH]
        if high_findings:
            for artifact in high_findings[:10]:
                md += f"**{artifact.artifact_type}:** `{artifact.value}` (Confidence: {artifact.confidence*100:.0f}%)  \n"
                md += f"  - {artifact.context}\n\n"
        else:
            md += "*None*\n\n"
        
        if result.iocs:
            md += "---\n\n## Indicators of Compromise\n\n"
            for ioc in result.iocs[:50]:
                md += f"- `{ioc}`\n"
        
        if result.ttps:
            md += "\n---\n\n## MITRE ATT&CK TTPs\n\n"
            for ttp in result.ttps:
                md += f"- {ttp}\n"
        
        md += f"\n---\n\n*Report generated by Prometheus v3.0.0*"
        
        return md
