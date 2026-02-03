# Prometheus v3.0.0 - Quick Start Guide

## Installation

```bash
pip install prometheus-community
```

## Basic Usage

### 1. Analyze a File
```bash
prometheus analyze malware.exe
```

### 2. Export IOCs
```bash
prometheus analyze malware.exe --export-iocs results
# Creates: results.json, results.csv, results.stix
```

### 3. Generate YARA Rule
```bash
prometheus analyze malware.exe --generate-yara detection.yar
```

### 4. Create Report
```bash
prometheus analyze malware.exe --report analysis.html
```

### 5. Complete Workflow
```bash
prometheus analyze malware.exe \
  --export-iocs iocs/sample \
  --generate-yara rules/sample.yar \
  --report reports/sample.html \
  --output json/sample.json
```

## Python API

```python
from prometheus import PrometheusEngineV3

# Analyze file
engine = PrometheusEngineV3()
result = engine.analyze_file("malware.exe")

# Access findings
print(f"Suspicious: {len(result.suspicious_artifacts)}")
print(f"IOCs: {len(result.iocs)}")
print(f"TTPs: {result.ttps}")
```

## More Information

- Full README: README.md
- Documentation: docs/
- Examples: `prometheus examples`
- Help: `prometheus analyze --help`

