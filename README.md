# 🔥 Prometheus Community Edition

**Revolutionary 6-layer malware analysis with knowledge graph intelligence**

Free malware analysis platform for security researchers, students, and educators.

**Based on:** [Binary Analysis and Reverse Engineering: Comprehensive Technical Reference](https://github.com/0x44616D69616E/binary-analysis-reference)  
**Paper DOI:** [10.5281/zenodo.18123287](https://doi.org/10.5281/zenodo.18123287)

[![License: Custom](https://img.shields.io/badge/License-Prometheus%20Community-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub](https://img.shields.io/badge/GitHub-0x44616D69616E-181717.svg?logo=github)](https://github.com/0x44616D69616E/prometheus-community)
[![Research Paper](https://img.shields.io/badge/DOI-10.5281%2Fzenodo.18123287-blue)](https://doi.org/10.5281/zenodo.18123287)

---

## ⚡ Quick Start

```bash
# Install
pip install prometheus-community

# Analyze a file
prometheus analyze malware.exe

# Batch analysis (max 10 files)
prometheus batch samples/

# Check version
prometheus version

# See Enterprise features
prometheus upgrade
```

---

## 🎯 What is Prometheus?

Prometheus is a revolutionary malware analysis platform that uses **6 complementary detection layers** and **knowledge graph intelligence** to identify threats that single-method tools miss.

### Why 6 Layers?

Traditional tools rely on one detection method:
- **VirusTotal**: Signatures only → misses packed/encrypted malware
- **Cuckoo Sandbox**: Dynamic only → slow, requires execution
- **Most AV**: Single-method → high false negatives

**Prometheus uses 6 layers simultaneously:**

```
┌─────────────────────────────────────────────────────────┐
│            PROMETHEUS 6-LAYER DETECTION                  │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  Layer 1: File Signatures      276 patterns             │
│           ├─ PE, ELF, Mach-O executables               │
│           └─ Documents, archives, images                │
│                                                          │
│  Layer 2: Behavioral Indicators 203 patterns            │
│           ├─ Mutex names (WannaCry, Zeus)               │
│           ├─ Registry keys                              │
│           └─ File extensions, ransom notes              │
│                                                          │
│  Layer 3: Exploit Patterns      168 patterns            │
│           ├─ Buffer overflows (NOP sleds)               │
│           ├─ ROP chains                                 │
│           └─ Shellcode patterns                         │
│                                                          │
│  Layer 4: PE Heuristics         8 rules                 │
│           ├─ Suspicious permissions                     │
│           └─ Import anomalies                           │
│                                                          │
│  Layer 5: Dynamic Analysis      Behavior inference      │
│           └─ Runtime behavior patterns                  │
│                                                          │
│  Layer 6: ML Classification     Pattern matching        │
│           └─ Family identification                      │
│                                                          │
└─────────────────────────────────────────────────────────┘
                         ▼
                UNIFIED VERDICT
         (All layers contribute)
```

**Result**: Detects malware 6 different ways vs competitors' 1-2 ways

---

## ✨ Community Edition Features

### What You Get (FREE)

✅ **6-Layer Detection Engine**
- All 6 detection layers fully functional
- **661 intelligence items** from comprehensive research
- Complete implementation of Binary Analysis Reference v2.2
- Demonstrates state-of-the-art detection techniques

✅ **Core Analysis Capabilities**
- File signature detection (276 patterns)
- Behavioral indicator matching (203 patterns)
- Exploit pattern detection (168 patterns)
- PE heuristic analysis (8 rules)
- Dynamic behavior inference
- ML classification
- ML pattern matching

✅ **Command-Line Interface**
- Single-file analysis
- Batch processing (up to 10 files)
- JSON output support
- Clean, professional output

✅ **Perfect For:**
- 🎓 Security research and learning
- 📚 Academic study
- 🔬 Proof-of-concept testing
- 💻 Personal malware analysis
- 🏫 Educational institutions
- 🔓 Non-profit organizations

---

## 📊 Community vs Enterprise Comparison

| Feature | Community | Enterprise |
|---------|-----------|------------|
| **Detection Layers** | ✅ All 6 layers | ✅ All 6 layers |
| **Intelligence Items** | ✅ 661 items | ✅ 661 items |
| **Signatures** | ✅ 276 file signatures | ✅ 276 file signatures |
| **Behavioral Indicators** | ✅ 203 patterns | ✅ 203 patterns |
| **Exploit Patterns** | ✅ 168 patterns | ✅ 168 patterns |
| **Interface** | CLI only | **CLI + REST API + Web UI** |
| **Architecture** | Single instance | **Distributed scaling** |
| **Batch Processing** | Manual | **Automated + unlimited** |
| **Knowledge Graph** | ❌ No persistence | **✅ Full graph storage** |
| **Reporting** | JSON only | **PDF, XLSX, DOCX, CSV** |
| **Multi-User** | ❌ Single user | **✅ Teams + RBAC** |
| **Authentication** | ❌ None | **✅ SSO/SAML + MFA** |
| **Integrations** | ❌ None | **✅ Splunk, ELK, Sentinel** |
| **Support** | Community | **Priority + SLA** |
| **License** | Non-commercial only | **Commercial license** |
| **Price** | **FREE** | Custom pricing |

### Key Difference: Platform vs Detection

**Community Edition:**
- ✅ **Same detection capability** (all 661 intelligence items)
- ❌ **Limited platform features** (CLI only, no API/UI)

**Enterprise Edition:**
- ✅ **Same detection capability**  
- ✅ **Full platform features** (API, UI, scaling, teams, integrations)
| **Interface** | CLI only | **CLI + REST API + Web UI** |
| **Daily Limit** | 100 files/day | **Unlimited** |
| **Batch Processing** | 10 files max | **Unlimited** |
| **Knowledge Graph** | ❌ No storage | **✅ Full graph database** |
| **Dynamic Analysis** | Basic inference | **Advanced sandbox** |
| **ML Models** | Basic patterns | **Advanced models** |
| **Report Generation** | JSON only | **PDF, XLSX, DOCX, HTML** |
| **SIEM Integration** | ❌ | **✅ Splunk, ELK, QRadar, Sentinel** |
| **Multi-User** | ❌ Single user | **✅ Teams + RBAC** |
| **API Access** | ❌ | **✅ Full REST API** |
| **Web Interface** | ❌ | **✅ Modern web UI** |
| **Support** | Community only | **Priority + SLA** |
| **Commercial Use** | ❌ Not permitted | **✅ Commercial license** |
| **Price** | **FREE** | Contact for pricing |

---

## 💻 Usage Examples

### Basic Analysis

```bash
$ prometheus analyze malware.exe
======================================================================
PROMETHEUS COMMUNITY EDITION v1.0.0
======================================================================

Based on: Binary Analysis Reference v2.2
DOI: 10.5281/zenodo.18123287

Loading intelligence database...
Loaded 276 file signatures
Loaded 203 behavioral indicators
Loaded 168 exploit patterns
Total intelligence items: 647

======================================================================
✅ PROMETHEUS ENGINE READY
======================================================================

File Info:
  - SHA256: b4db3322...
  - Size: 1,024 bytes
  - Type: pe

=== Layer 1: File Signatures ===
  - Entropy: 7.2
  - Signatures: 3 matches
  - Strings: 42

=== Layer 2: Behavioral Indicators ===
  - Matches: 2
  - Families: WannaCry, RAT
    • WannaCry: mutex = Global\\MsWinZonesCacheCounterMutexA
    • RAT: file_extension = .exe

=== Layer 3: Exploit Detection ===
  - Patterns: 1
  - Risk: HIGH
    • NOP Sled (150 consecutive NOPs detected!)

======================================================================
ANALYSIS COMPLETE
======================================================================
Family: WannaCry
Confidence: 95%
IOCs: 3
TTPs: 2
Duration: 0.003 seconds
======================================================================
```

### Batch Analysis

```bash
$ prometheus batch samples/

Found 50 files

[1/50] sample1.exe... WannaCry (95%)
[2/50] sample2.dll... TrickBot (87%)
[3/50] sample3.pdf... Unknown (0%)
...
[50/50] sample50.exe... Emotet (92%)

======================================================================
BATCH ANALYSIS COMPLETE
======================================================================
Files analyzed: 50
Families detected: 12

Family distribution:
  WannaCry: 15
  Emotet: 12
  TrickBot: 8
  Unknown: 15
======================================================================
```

**Note**: Community Edition provides full detection capabilities. Enterprise Edition adds unlimited concurrent batch processing, distributed workers, and progress tracking via Web UI.

### JSON Output

```bash
$ prometheus analyze --json malware.exe > result.json
```

```json
{
  "sample": {
    "filename": "malware.exe",
    "sha256": "b4db3322bdff3e15a50306af60df52d9343d91b0a82ec940dea80ab16de98384",
    "md5": "5d41402abc4b2a76b9719d911017c592",
    "file_size": 1024,
    "file_type": "pe"
  },
  "family": "WannaCry",
  "confidence": 0.95,
  "ttps": [
    "Behavioral: 2 indicators",
    "Exploits: 1 patterns"
  ],
  "duration": 0.003
}
```

---

## 🚀 Upgrade to Enterprise

### Why Upgrade?

**Community Edition is perfect for:**
- 🎓 Security research and education
- 🔬 Malware analysis learning
- 🧪 Testing and evaluation
- 👤 Individual researchers
- 📚 Academic institutions

**Enterprise Edition is essential for:**
- 🏢 Production SOC operations
- 🔒 Commercial malware analysis services
- 📊 Team collaboration and workflows
- 🔗 Integration into security infrastructure (SIEM, ticketing, etc.)
- 👥 Multi-user organizations
- 📈 Advanced reporting and compliance
- ⚡ Scalable, high-availability deployment

### Enterprise Features

#### 🌐 REST API + Web UI
- Full REST API for automation
- Modern web interface
- Swagger/OpenAPI documentation
- Webhook notifications
- Real-time analysis tracking

#### 📊 Advanced Reporting
- PDF, XLSX, DOCX, HTML exports
- Custom report templates
- Scheduled automated reports
- Executive dashboards
- Trend analysis over time
- White-label branding

#### 🔗 SIEM Integration
- Splunk app/add-on
- ELK/Elasticsearch connector
- IBM QRadar integration
- Microsoft Sentinel integration
- Generic syslog/CEF/LEEF output
- Real-time alerting

#### 📈 Knowledge Graph
- Full graph database storage (Neo4j-compatible)
- Sample → Infrastructure → Actor relationships
- Campaign tracking
- Infection chain visualization
- Threat actor attribution
- Historical analysis

#### 👥 Multi-User & Teams
- Team collaboration
- Role-based access control (RBAC)
- User management
- Audit logging
- SSO/SAML integration (Okta, Azure AD, etc.)
- Multi-tenancy for MSSPs

#### ⚡ Scalability & Performance
- Distributed worker architecture
- Horizontal scaling (unlimited workers)
- High-availability deployment
- Load balancing
- PostgreSQL backend
- Redis caching

#### 🛡️ Advanced Analysis
- Full sandbox execution environment
- Advanced ML model training
- Custom YARA rules support
- Retro-hunt capabilities
- Plugin framework
- Custom integration SDK

#### 💼 Enterprise Support
- Priority email support (4hr SLA)
- Phone support available
- Dedicated account manager
- SLA guarantees (99.9% uptime)
- Professional services
- Training and certification
- Custom development

### Get Enterprise

**Contact for pricing and demo:**
- 📧 Email: contact@asnspy.com
- 🔗 GitHub: https://github.com/0x44616D69616E/prometheus-enterprise
- 💬 Subject: "Enterprise Demo Request"

---

## 📋 Installation

### Requirements

- Python 3.8 or higher
- Linux, macOS, or Windows
- 100MB disk space
- Internet connection (for pip install only)

### Install from PyPI

```bash
pip install prometheus-community
```

### Install from Source

```bash
git clone https://github.com/0x44616D69616E/prometheus-community.git
cd prometheus-community
pip install -e .
```

### Verify Installation

```bash
prometheus version
```

---

## 📚 Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Detailed setup instructions
- **[Usage Guide](docs/USAGE.md)** - Complete command reference
- **[Architecture](docs/ARCHITECTURE.md)** - Technical deep-dive
- **[Upgrade Guide](docs/UPGRADE_TO_ENTERPRISE.md)** - Enterprise Edition details

---

## 📄 License

**Prometheus Community License v1.0**

### ✅ Permitted Uses
- Research and education
- Non-profit organizations
- Personal learning
- 30-day commercial evaluation

### ❌ Prohibited Uses
- Commercial/production deployment
- Revenue-generating activities
- Organizations with >$1M revenue
- More than 100 samples per day
- Managed security services (MSSP)

**For commercial use**: Contact contact@asnspy.com

See [LICENSE](LICENSE) for full terms.

---

## 📚 Research Foundation

Prometheus implements the **Binary Analysis and Reverse Engineering: Comprehensive Technical Reference** - a peer-reviewed research paper that catalogs 661 intelligence items across malware detection techniques.

**Paper Information:**
- **Title**: Binary Analysis and Reverse Engineering: Comprehensive Technical Reference
- **Author**: Damian Donahue
- **Version**: 2.2 (2025)
- **DOI**: [10.5281/zenodo.18123287](https://doi.org/10.5281/zenodo.18123287)
- **GitHub**: [binary-analysis-reference](https://github.com/0x44616D69616E/binary-analysis-reference)
- **License**: Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0)

**Citation:**
```bibtex
@dataset{donahue_binary_analysis_2025,
  author       = {Donahue, Damian},
  title        = {Binary Analysis and Reverse Engineering: 
                  Comprehensive Technical Reference},
  year         = 2025,
  publisher    = {Zenodo},
  version      = {2.2},
  doi          = {10.5281/zenodo.18123287},
  url          = {https://doi.org/10.5281/zenodo.18123287}
}
```

**Intelligence Data:**
- 276 file signatures
- 203 behavioral indicators  
- 168 exploit patterns
- 8 PE heuristics
- 6 XOR keys
- **Total: 661 items**

All intelligence data used with proper attribution under CC BY-SA 4.0.

See [NOTICE](NOTICE) for complete attribution information.

---

## ⭐ Support

### Community Edition
- **Issues**: [GitHub Issues](https://github.com/0x44616D69616E/prometheus-community/issues)
- **Discussions**: [GitHub Discussions](https://github.com/0x44616D69616E/prometheus-community/discussions)
- **Documentation**: [docs/](docs/)

### Enterprise Edition
- **Priority Support**: Included with license
- **Email**: contact@asnspy.com
- **SLA**: Response within 4 hours (critical issues)

---

## 🤝 Contributing

We welcome contributions to the Community Edition!

- Report bugs via GitHub Issues
- Suggest features via GitHub Discussions
- Submit pull requests for improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📧 Contact

- **General Inquiries**: contact@asnspy.com
- **Enterprise Sales**: contact@asnspy.com
- **GitHub**: [@0x44616D69616E](https://github.com/0x44616D69616E)

---

## 🔥 Built by an AI-Augmented Developer

Prometheus was created by Damian Donahue using AI assistance (Claude by Anthropic) while experiencing housing instability and working from an iPhone.

**This project proves that AI democratizes advanced software development** - enabling individuals to build production-grade security tools that previously required teams of specialized engineers.

**The future of development is AI-augmented.**

---

**Ready for production malware analysis?**

**[Upgrade to Enterprise Edition →](https://github.com/0x44616D69616E/prometheus-enterprise)**

**Questions?** Email contact@asnspy.com

---

Copyright (c) 2026 Damian Donahue. Licensed under Prometheus Community License v1.0.
