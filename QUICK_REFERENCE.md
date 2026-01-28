# 📋 PROMETHEUS COMMUNITY EDITION - QUICK REFERENCE

## Intelligence Included (ALL 661 ITEMS)

```
✅ 276 file format signatures
✅ 203 behavioral indicators
✅ 168 exploit patterns
✅ 8 PE heuristics
✅ 6 XOR keys
━━━━━━━━━━━━━━━━━━━━━━
   661 TOTAL ITEMS
```

## Based On Research Paper

**Binary Analysis and Reverse Engineering: Comprehensive Technical Reference**
- Author: Damian Donahue
- Version: 2.2 (2025)
- DOI: [10.5281/zenodo.18123287](https://doi.org/10.5281/zenodo.18123287)
- GitHub: https://github.com/0x44616D69616E/binary-analysis-reference

## Installation

```bash
pip install prometheus-community
```

## Basic Commands

```bash
# Analyze single file
prometheus analyze malware.exe

# Analyze with JSON output
prometheus analyze malware.exe --json

# Batch analysis
prometheus batch /path/to/samples/

# Version info
prometheus version

# See Enterprise features
prometheus upgrade

# Help
prometheus --help
```

## What's Included vs Enterprise

### SAME (Both Editions)
- ✅ All 661 intelligence items
- ✅ All 6 detection layers
- ✅ Complete research implementation

### DIFFERENT (Platform)
- Community: CLI only
- Enterprise: CLI + REST API + Web UI + Teams + Integrations

## License

- Community: Free for research, education, non-profits
- Enterprise: Commercial license required

Contact: contact@asnspy.com
