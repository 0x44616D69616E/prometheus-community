# 🔥 Prometheus Community Edition v2.0.0

**The Most Transparent Malware Analyzer Available**

[![PyPI version](https://badge.fury.io/py/prometheus-community.svg)](https://badge.fury.io/py/prometheus-community)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Prometheus%20Community%20v1.0-green.svg)](LICENSE)
[![DOI](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18123287-blue)](https://doi.org/10.5281/zenodo.18123287)

Revolutionary 6-layer malware analysis with **explainable detection** and **forensic-grade location tracking**. Every finding explained with WHY it matters and WHERE it's located.

---

## 🎯 What Makes Prometheus Different

### Complete Transparency
Unlike black-box tools that say "malware detected, trust us," Prometheus shows you:
- ✅ **WHAT** was found (actual signatures, indicators, patterns)
- ✅ **WHY** it matters (severity, uniqueness, explanations)
- ✅ **WHERE** it's located (exact byte offsets, PE sections)

### Educational Value
Every scan is a learning opportunity:
- 💎 **Uniqueness ratings** - Know if indicators are definitive (unique) or common
- 📊 **Severity levels** - Understand criticality (critical/high/medium/low)
- 🎓 **MITRE ATT&CK** - Full TTP categorization
- 🔍 **Context** - Learn what each indicator reveals about malware behavior

### Forensic Detail
Professional-grade analysis:
- 📍 **Exact byte offsets** for every finding
- 🔬 **Hex context** around matches for verification
- 🗺️ **Location maps** showing where malware components hide
- ✅ **Manual verification** - Can confirm in any hex editor

---

## 🌟 Key Features

### 6-Layer Detection Engine
1. **File Signatures** - 276 format patterns with location tracking
2. **Behavioral Indicators** - 203 malware-specific behaviors with explanations
3. **Exploit Patterns** - 168 exploitation techniques mapped to MITRE
4. **PE Heuristics** - 8 advanced PE structure analysis rules
5. **Dynamic Inference** - Behavioral pattern correlation
6. **ML Classification** - Confidence scoring based on uniqueness

### Enhanced Intelligence Database
- **661 intelligence items** with rich metadata
- **15 unique indicators** (7.4%) - Definitive family identifiers
- **58 rare indicators** (28.6%) - Family-specific markers  
- **130 common indicators** (64.0%) - Supporting evidence
- All items include: severity, uniqueness, confidence, explanation, MITRE ATT&CK, context

### Detection Transparency
- **Detection reasoning** - Explains why confidence is X%
- **Confidence calculation** - Shows how score was computed
- **Indicator classification** - Rates each by uniqueness and severity
- **No black boxes** - Complete visibility into detection logic

---

## 📦 Installation

### Via pip (Recommended)
```bash
pip install prometheus-community
```

### From Source
```bash
git clone https://github.com/0x44616D69616E/prometheus-community
cd prometheus-community
pip install -e .
```

### Verify Installation
```bash
prometheus version
# Output: Prometheus Community Edition v2.0.0
```

---

## 🚀 Quick Start

### Analyze a Single File
```bash
prometheus analyze malware.exe
```

### Analyze with JSON Export
```bash
prometheus analyze malware.exe --output results.json
```

### Batch Analysis
```bash
prometheus batch /path/to/samples/ --output-dir results/
```

### Quiet Mode (JSON Only)
```bash
prometheus analyze malware.exe --quiet --output results.json
```

---

## 📖 Usage & Arguments

### Command: `prometheus analyze`

Analyze a single file with complete transparency.

```bash
prometheus analyze [OPTIONS] FILE
```

#### Arguments

| Argument | Type | Description | Default |
|----------|------|-------------|---------|
| `FILE` | Path | File to analyze (required) | - |
| `--output`, `-o` | Path | Save results to JSON file | None |
| `--quiet`, `-q` | Flag | Suppress console output | False |
| `--intel` | Path | Custom intelligence database | Built-in |

#### Examples

**Basic analysis:**
```bash
prometheus analyze suspicious.exe
```

**Save results:**
```bash
prometheus analyze suspicious.exe --output results.json
```

**Custom intelligence database:**
```bash
prometheus analyze suspicious.exe --intel custom_intel.json
```

**Quiet mode (automation-friendly):**
```bash
prometheus analyze suspicious.exe --quiet --output results.json
```

---

### Command: `prometheus batch`

Analyze multiple files in a directory.

```bash
prometheus batch [OPTIONS] DIRECTORY
```

#### Arguments

| Argument | Type | Description | Default |
|----------|------|-------------|---------|
| `DIRECTORY` | Path | Directory containing files | - |
| `--output-dir`, `-d` | Path | Save results to directory | Current dir |
| `--recursive`, `-r` | Flag | Scan subdirectories | False |
| `--pattern` | String | File pattern to match | `*` |
| `--threads` | Integer | Number of parallel threads | 4 |

#### Examples

**Analyze all files in directory:**
```bash
prometheus batch /samples/
```

**Recursive scan with results:**
```bash
prometheus batch /samples/ --recursive --output-dir results/
```

**Specific file pattern:**
```bash
prometheus batch /samples/ --pattern "*.exe" --output-dir results/
```

**Parallel processing:**
```bash
prometheus batch /samples/ --threads 8 --output-dir results/
```

---

### Command: `prometheus version`

Show version information.

```bash
prometheus version
```

**Output:**
```
Prometheus Community Edition v2.0.0
Revolutionary 6-layer malware analysis with explainable detection

Intelligence: 661 items (276 signatures, 203 behavioral, 168 exploits)
Python: 3.10.0
License: Prometheus Community License v1.0
```

---

### Command: `prometheus upgrade`

Information about enterprise edition.

```bash
prometheus upgrade
```

---

## 📊 Example Output

### Sample Analysis

```bash
$ prometheus analyze wannacry_sample.exe
```

```
╔══════════════════════════════════════════════════════════╗
║   🔥 PROMETHEUS COMMUNITY EDITION v2.0.0                ║
║   The Most Transparent Malware Analyzer                 ║
╚══════════════════════════════════════════════════════════╝

Analyzing: wannacry_sample.exe
SHA256: abc123def456...
Size: 52,480 bytes
Type: pe

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📄 Layer 1: File Signatures & Entropy

  Entropy: 7.24
  ⚠️  HIGH ENTROPY - Likely packed/encrypted
  Strings: 1,234

  📝 File Signatures: 3 matches
     • PE (executable)
       📍 offset 0x00000000
     • DOS MZ Header (executable)
       📍 offset 0x00000000
     • Windows PE32 (executable)
       📍 offset 0x00000080

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 Layer 2: Behavioral Indicators

  🔴 CRITICAL Indicators (2):

     🔴 Mutex Name: Global\MsWinZonesCacheCounterMutexA
        💎 UNIQUE | Confidence: 100%
        📍 offset 0x00001a40, length 37 bytes
        Why: This mutex is UNIQUE to WannaCry ransomware and is used to 
             prevent multiple instances from running simultaneously
        Category: Defense Evasion - T1027

     🔴 File Extension: .WNCRY
        💎 UNIQUE | Confidence: 95%
        📍 offset 0x00003f20, length 6 bytes
        Why: Files encrypted by WannaCry are renamed with this extension - 
             a signature marker of this ransomware
        Category: Impact - T1486

  🟠 HIGH Severity Indicators (1):

     🟠 URL: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
        💎 UNIQUE | Confidence: 90%
        📍 offset 0x00004120

  📊 Summary:
     • 3 unique indicators
     • 0 rare indicators
     • 1 families detected: WannaCry

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💥 Layer 3: Exploit Patterns

  💥 Exploit Patterns: 1 detected

     🔴 NOP Sled
        📍 offset 0x00002f80, length 64 bytes
        Type: buffer_overflow, Severity: high
        Why: Long sequence of NOP (0x90) instructions used to make buffer
             overflow exploits more reliable

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

══════════════════════════════════════════════════════════
VERDICT
══════════════════════════════════════════════════════════

🏷️  Family: WannaCry
📊 Confidence: 95%

🧠 Why this family?

   💎 3 UNIQUE Indicators:
      ✓ Mutex Name: Global\MsWinZonesCacheCounterMutexA
        📍 offset 0x00001a40
        This mutex is UNIQUE to WannaCry ransomware and is used to prevent 
        multiple...
      ✓ File Extension: .WNCRY
        📍 offset 0x00003f20
        Files encrypted by WannaCry are renamed with this extension - a 
        signature marker...
      ✓ Url: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
        📍 offset 0x00004120
        Original WannaCry kill switch - malware checks if this domain 
        resolves...

   📊 Detection Summary:
      • 3 unique to WannaCry
      • 3 total indicators
      • Confidence: 95%

📍 Key Findings Map:
   0x00001a40: mutex_name (critical, unique)
   0x00003f20: file_extension (critical, unique)
   0x00004120: url (high, unique)

🔍 Indicators of Compromise (5):
   • http://iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
   • 192.168.56.20
   • C:\Windows\tasksche.exe
   • Global\MsWinZonesCacheCounterMutexA
   • @WanaDecryptor@.exe

⚔️  Tactics, Techniques & Procedures (4):
   • Defense Evasion
   • Impact
   • Command and Control
   • Execution

⏱️  Duration: 0.234s
```

---

## 💻 Python API Usage

### Basic Analysis

```python
from prometheus import PrometheusEngine

# Initialize engine
engine = PrometheusEngine()

# Analyze file
result = engine.analyze_file("malware.exe")

# Access results
print(f"Family: {result.family}")
print(f"Confidence: {result.confidence:.0%}")
print(f"IOCs: {len(result.iocs)}")
```

### With Custom Intelligence

```python
from prometheus import PrometheusEngine

# Use custom intelligence database
engine = PrometheusEngine(intel_path="custom_intel.json")
result = engine.analyze_file("malware.exe")
```

### Accessing Detailed Results

```python
# Get unique indicators only
unique_indicators = result.get_unique_indicators()
for indicator in unique_indicators:
    print(f"{indicator.indicator_type}: {indicator.matched_value}")
    print(f"Location: offset 0x{indicator.location.offset:08x}")
    print(f"Explanation: {indicator.explanation}")
    print()

# Get critical findings
critical = result.get_critical_indicators()
print(f"Found {len(critical)} critical indicators")

# Get location map
location_map = result.get_locations_map()
print(f"Behavioral indicators at: {location_map['behavioral']}")
print(f"Exploit patterns at: {location_map['exploits']}")
```

### Export to JSON

```python
import json

# Convert to dictionary
result_dict = result.to_dict()

# Save to file
with open("results.json", "w") as f:
    json.dump(result_dict, f, indent=2)
```

### JSON Output Structure

```json
{
  "sample": {
    "filename": "malware.exe",
    "sha256": "abc123...",
    "md5": "def456...",
    "file_size": 52480,
    "file_type": "pe"
  },
  "detection": {
    "family": "WannaCry",
    "confidence": 0.95,
    "reasoning": {
      "explanation": "Detected based on 3 UNIQUE indicators, 3 total indicators",
      "unique_indicators": 3,
      "total_indicators": 3,
      "key_indicators": [
        "mutex_name: Global\\MsWinZonesCacheCounterMutexA",
        "file_extension: .WNCRY",
        "url: iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
      ]
    }
  },
  "behavioral_details": [
    {
      "family": "WannaCry",
      "type": "mutex_name",
      "value": "Global\\MsWinZonesCacheCounterMutexA",
      "location": {
        "offset": 6720,
        "offset_hex": "0x00001a40",
        "length": 37
      },
      "severity": "critical",
      "confidence": 1.0,
      "uniqueness": "unique",
      "explanation": "This mutex is UNIQUE to WannaCry..."
    }
  ],
  "location_map": {
    "signatures": [0, 128],
    "behavioral": [6720, 16160],
    "exploits": [12160]
  }
}
```

---

## 🎓 Use Cases

### Security Research
```bash
# Analyze unknown sample
prometheus analyze unknown.exe --output research.json

# Extract exact locations for manual verification
# Open hex editor at offsets shown in output
# Verify findings yourself!
```

### SOC Analysis
```bash
# Quick triage
prometheus analyze alert_binary.exe

# Decision based on:
# - Severity: CRITICAL indicators require immediate action
# - Uniqueness: UNIQUE indicators = high confidence
# - Confidence: 95%+ = escalate immediately
```

### Malware Education
```bash
# Analyze known malware family
prometheus analyze wannacry.exe

# Learn:
# - What makes WannaCry distinctive
# - Where indicators are located
# - How MITRE ATT&CK applies
# - Practice hex editor verification
```

### Forensic Investigation
```bash
# Detailed analysis with locations
prometheus analyze evidence.exe --output forensics.json

# Use location map to:
# - Extract specific file sections
# - Identify malicious code regions
# - Document findings with exact offsets
# - Integrate with IDA/Ghidra
```

---

## 🔬 Intelligence Database

### Structure

```json
{
  "file_signatures": [276 items],
  "behavioral_indicators": [203 items],
  "exploit_patterns": [168 items],
  "pe_heuristics": [8 items],
  "xor_keys": [6 items]
}
```

### Enhanced Metadata (New in v2.0.0)

Every behavioral indicator includes:
- `severity` - critical | high | medium | low | info
- `confidence_weight` - 0.0-1.0
- `uniqueness` - unique | rare | common
- `explanation` - Why this indicator matters
- `commonly_found_in` - Which malware families use this
- `ttp_category` - MITRE ATT&CK mapping
- `context` - What behavior this reveals

### Statistics

| Category | Count | Percentage |
|----------|-------|------------|
| **Uniqueness** | | |
| Unique indicators | 15 | 7.4% |
| Rare indicators | 58 | 28.6% |
| Common indicators | 130 | 64.0% |
| **Severity** | | |
| Critical | 20 | 9.9% |
| High | 138 | 68.0% |
| Medium | 45 | 22.2% |

---

## 🆚 Comparison with Other Tools

| Feature | Prometheus v2.0 | VirusTotal | Cuckoo | YARA |
|---------|----------------|------------|--------|------|
| **Explains findings** | ✅ Complete | ❌ | ⚠️ Limited | ❌ |
| **Shows locations** | ✅ Exact offsets | ❌ | ❌ | ✅ Offsets |
| **Severity levels** | ✅ 5 levels | ❌ | ❌ | ❌ |
| **Uniqueness rating** | ✅ 3 levels | ❌ | ❌ | ❌ |
| **MITRE ATT&CK** | ✅ Full mapping | ❌ | ⚠️ Partial | ❌ |
| **Educational** | ✅ Built-in | ❌ | ❌ | ❌ |
| **Transparent** | ✅ Complete | ❌ | ⚠️ Limited | ⚠️ Partial |
| **Open Source** | ✅ Yes | ❌ | ✅ Yes | ✅ Yes |

**Prometheus is the ONLY tool with complete transparency: WHAT + WHY + WHERE**

---

## 📚 Documentation

- **Installation Guide** - Getting started
- **User Manual** - Complete feature reference
- **API Documentation** - Python API reference
- **Intelligence Format** - Custom intelligence guide
- **Research Paper** - [DOI: 10.5281/zenodo.18123287](https://doi.org/10.5281/zenodo.18123287)

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Bug reports
- Feature requests
- Intelligence contributions
- Code contributions

---

## 📄 License

Prometheus Community Edition is released under the **Prometheus Community License v1.0**.

**Key terms:**
- ✅ **Free** for research, education, and non-profit use
- ✅ **Source available** - Review and modify code
- ✅ **No commercial use** without license
- ✅ **Attribution required**

For commercial licensing, contact: contact@asnspy.com

See [LICENSE](LICENSE) for full terms.

---

## 🎓 Citation

If you use Prometheus in research, please cite:

```bibtex
@software{prometheus2026,
  author = {Donahue, Damian},
  title = {Prometheus Community Edition: Explainable Malware Detection},
  year = {2026},
  publisher = {GitHub},
  version = {2.0.0},
  url = {https://github.com/0x44616D69616E/prometheus-community},
  doi = {10.5281/zenodo.18123287}
}
```

---

## 🌟 What's New in v2.0.0

### Major Features
- 🧠 **Explainable Detection** - Every finding explained
- 📍 **Location Tracking** - Exact byte offsets for everything
- 📊 **Enhanced Intelligence** - All 661 items with rich metadata
- 🎯 **Severity Levels** - Critical/High/Medium/Low/Info
- 💎 **Uniqueness Ratings** - Unique/Rare/Common
- 🎓 **MITRE ATT&CK** - Full TTP categorization
- 🔍 **Detection Reasoning** - Transparent confidence calculation

### See Full Changelog
- [CHANGELOG.md](CHANGELOG.md) - Complete version history
- [RELEASE_NOTES.md](RELEASE_NOTES.md) - v2.0.0 details

---

## 💬 Community & Support

- **GitHub Issues** - Bug reports and feature requests
- **Discussions** - Questions and community chat
- **Email** - contact@asnspy.com
- **Documentation** - Complete guides and examples

---

## 🚀 Roadmap

### v2.1.0 (Planned)
- Interactive hex viewer integration
- Real-time pattern highlighting
- STIX 2.1 export format
- Threat intelligence platform integration

### v2.2.0 (Planned)
- YARA rule generation from samples
- Automated report generation
- Multi-file campaign analysis
- Timeline reconstruction

---

## ⭐ Star History

If you find Prometheus useful, please star the repo! ⭐

---

## 🙏 Acknowledgments

Built on foundational research:
- Binary Analysis Academic Reference v2.2
- MITRE ATT&CK Framework
- Open source security community

Special thanks to all contributors and users who provided feedback!

---

## 🔥 Why Prometheus?

**"The most transparent malware analyzer available"**

In Greek mythology, Prometheus brought fire (knowledge) to humanity. Our Prometheus brings **transparency and knowledge** to malware analysis - showing you exactly what was found, why it matters, and where it's located.

**No black boxes. No "trust us." Just complete, verifiable transparency.** 🔍

---

**Made with 🔥 by the security research community**

**Prometheus Community Edition v2.0.0** - Transparency in malware analysis
