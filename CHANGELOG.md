## [3.1.0] - 2026-02-06

### 🏗️ Major Refactoring - Version-Agnostic Architecture

This release represents a complete architectural refactoring to remove version-numbered modules and classes, establishing a stable, future-proof foundation that won't require import updates with version changes.

### Breaking Changes

**⚠️ API Users Only** - CLI users experience no changes

#### Module Renames
- `models_v3.py` → `models.py`
- `engine_v3_0_0.py` → `engine.py`
- `behavioral_detector_v3.py` → `behavioral_detector.py`

#### Class Renames
- `PrometheusEngineV3` → `PrometheusEngine`
- `BehavioralDetectorV3` → `BehavioralDetector`

#### Import Updates Required for API Users
```python
# Before (v3.0.x)
from prometheus import PrometheusEngineV3
from prometheus.models_v3 import Severity

# After (v3.1.0+)
from prometheus import PrometheusEngine
from prometheus.models import Severity
```

### Changed

#### Architecture
- **Removed version numbers from all module names** - Establishes stable import paths
- **Removed version numbers from class names** - Cleaner API surface
- **Centralized version tracking** - Single source of truth in `__init__.py`
- **Updated all 19 modules** - Consistent import patterns throughout codebase

#### Documentation
- **Cleaned all docstrings** - Removed hardcoded version numbers
- **Updated module headers** - Version-agnostic documentation
- **Updated test suite** - All tests use new import patterns

### Fixed

- **Steganography detector import** - Includes critical bugfix from v3.0.6
- **All imports validated** - Comprehensive testing ensures zero import errors

### Benefits

#### For Users
- ✅ **CLI remains 100% compatible** - No changes needed for command-line usage
- ✅ **Cleaner, more intuitive imports** - No confusing version numbers
- ✅ **Future-proof** - No import breakage with version updates

#### For Developers
- ✅ **Professional standards** - Aligns with Python packaging best practices
- ✅ **Easier maintenance** - No need to update filenames when incrementing versions
- ✅ **Reduced cognitive load** - Clear, obvious naming conventions
- ✅ **Stable API** - Import paths won't change with new releases

### Technical Details

#### Files Modified
- **24 Python files** updated with new imports
- **19 modules** refactored with version-agnostic patterns
- **1 test suite** updated for new module structure
- **100+ import statements** corrected

#### Quality Assurance
- ✅ All imports validated (8/8 tests passed)
- ✅ Zero syntax errors (23/23 files compiled)
- ✅ Zero functional regressions
- ✅ All 16 detection components functional
- ✅ Complete end-to-end testing

#### Package Details
- **Version**: 3.1.0
- **Wheel size**: 112KB
- **Source tarball**: 127KB
- **Intelligence DB**: 376KB (unchanged)

### Migration Guide

#### CLI Users
**No action required.** Commands work identically:
```bash
prometheus analyze malware.exe
prometheus version  # Shows "v3.1.0"
```

#### Library/API Users
Update imports in your code:
```python
# Update package imports
from prometheus import PrometheusEngine  # was PrometheusEngineV3
from prometheus import PrometheusConfig

# Update module imports  
from prometheus.models import Severity, Location  # was models_v3
from prometheus.behavioral_detector import BehavioralDetector  # was behavioral_detector_v3

# Initialize engine with new class name
engine = PrometheusEngine()  # was PrometheusEngineV3()
```

### Validation

#### Pre-Release Checklist
- ✅ File structure validated
- ✅ All imports working
- ✅ Package builds successfully
- ✅ CLI commands functional
- ✅ Analysis runs correctly
- ✅ No placeholders or TODOs
- ✅ No broken imports
- ✅ Zero test failures

#### Compatibility
- **Python**: 3.8+ (unchanged)
- **Platforms**: Windows, Linux, macOS (unchanged)
- **File Formats**: PE, ELF, DEX (unchanged)
- **Export Formats**: YARA, JSON, CSV, STIX 2.1, HTML, Markdown (unchanged)

### Upgrade Instructions

#### From PyPI
```bash
pip install --upgrade prometheus-community
```

#### Verify Installation
```bash
pip show prometheus-community  # Should show 3.1.0
prometheus version            # Should display v3.1.0
```

---

# Changelog

All notable changes to Prometheus Community Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-01-30

### 🎉 Major Release - Enterprise-Grade Analysis Engine

This is a revolutionary upgrade from v2.0.0, increasing coverage from ~18% to **~95%** of the Binary Analysis Academic Reference. The system has grown from 6 detection layers to **16 integrated components** with comprehensive automation capabilities.

### Added

#### 13 New Detection Components (Blocks 2-5)

**Block 2: Advanced Detection**
- **Steganography Detector** - Detects EOF append, embedded files, LSB anomalies
- **Shellcode Detector** - Identifies NOP sleds, GetPC patterns, syscalls
- **XOR/Encoding Detector** - Brute force 256 keys, Base64, hexadecimal
- **Nested File Detector** - Scans for 31 embedded file signatures, polyglots

**Block 3: Executable Deep Dive**
- **PE Analyzer** - Windows PE structure parsing, 15 packer signatures, RWX detection
- **Anti-Analysis Detector** - Anti-debug (7 APIs), anti-VM (4 keys, 5 files), obfuscation
- **Cryptographic Detector** - AES/DES/MD5/SHA/RSA constant detection

**Block 4: Cross-Platform & Network**
- **ELF Analyzer** - Linux ELF parsing, 13 sections, RWX segments, dynamic linking
- **String Analyzer** - URLs, IPs, paths, commands, registry keys
- **Network Artifact Detector** - C2 domains (11 TLDs), suspicious ports (11 C2 ports)

**Block 5: Intelligence Automation**
- **YARA Rule Generator** - Auto-generate detection rules from findings
- **IOC Exporter** - Export to JSON, CSV, STIX 2.1 formats
- **Android Analyzer** - DEX file parsing, dynamic loading, obfuscation detection
- **Report Generator** - Professional HTML and Markdown reports

#### Platform Support
- **Windows PE Analysis** - Complete PE structure parsing, packer detection, API analysis
- **Linux ELF Analysis** - ELF header/section/segment parsing, interpreter detection
- **Android APK/DEX Analysis** - DEX structure, dynamic loading, reflection patterns

#### Export & Automation
- **YARA Rule Generation** - Automatic YARA rule creation with metadata
- **JSON Export** - Structured data export for APIs and automation
- **CSV Export** - Spreadsheet-compatible format for analysis
- **STIX 2.1 Export** - Threat intelligence platform integration
- **HTML Reports** - Professional analyst reports with CSS styling
- **Markdown Reports** - Documentation-friendly format

#### CLI Enhancements
- `--export-iocs PATH` - Export IOCs in all formats (JSON/CSV/STIX)
- `--generate-yara FILE` - Generate YARA detection rule
- `--report FILE` - Generate HTML report
- `--report-md FILE` - Generate Markdown report
- `--android` - Analyze Android APK/DEX files
- `--pe` / `--elf` - Force platform-specific analysis
- `--disable-stego` / `--disable-shellcode` / etc. - Selective detection
- `prometheus examples` - Show comprehensive usage examples

### Changed

#### Core Architecture
- **Upgraded** from 6-layer detection to 16-component modular system
- **Increased** coverage from ~18% to ~95% (+5.3x improvement)
- **Expanded** codebase from ~1,500 to 9,223 lines (+6.1x growth)
- **Enhanced** detection patterns from ~100 to 400+ (+4x increase)

#### Detection Capabilities
- **PE Analysis**: Added 15 packer signatures, RWX detection, API analysis
- **Cross-Platform**: Added complete Linux ELF and Android DEX support
- **Network**: Added C2 domain detection, port analysis, DGA identification
- **Steganography**: Added EOF append, embedded signature, LSB analysis
- **Shellcode**: Added NOP sled, GetPC, syscall pattern detection
- **Crypto**: Added AES/DES/MD5/SHA/RSA constant detection

#### Intelligence Database
- **Cleaned** intelligence_v2_1_cleaned.json with 193 high-quality indicators
- **Organized** indicators by type: signatures, behavioral, network, registry, mutex
- **Enhanced** metadata for all indicators

#### Output & Reporting
- **Professional Reports**: Color-coded severity, responsive design, executive summaries
- **STIX 2.1**: Full threat intelligence standard compliance
- **CSV**: Spreadsheet-compatible for SOC workflows
- **YARA**: Production-ready detection rules

### Improved

#### Quality & Reliability
- **Production-Ready**: Comprehensive testing with 39/39 tests passing
- **Error Handling**: Graceful degradation on malformed files
- **Performance**: <0.01s typical analysis, <2s for 10MB files
- **Memory**: Efficient processing, no leaks detected

#### Enterprise Features
- **Offline Capable**: No internet connection required
- **Air-Gapped**: Deploy in secure environments
- **Zero Dependencies**: Python stdlib only
- **Commercial Use**: Enterprise-friendly licensing
- **Scalability**: Process millions of files

#### Documentation
- Added `BLOCK_1_IMPLEMENTATION.md` - Foundation components
- Added `BLOCK_2_IMPLEMENTATION.md` - Advanced detection
- Added `BLOCK_3_IMPLEMENTATION.md` - Executable analysis
- Added `BLOCK_4_IMPLEMENTATION.md` - Cross-platform & network
- Added `BLOCK_5_IMPLEMENTATION.md` - Intelligence automation
- Added `COMPREHENSIVE_TEST_REPORT.md` - Complete test validation
- Updated `README.md` with v3.0.0 features and examples
- Updated CLI help with comprehensive examples

### Fixed

- **Context Validator**: Fixed operator precedence bug in file extension validation
- **Crypto Detector**: Enhanced AES S-box detection (full/partial/truncated)
- **Steganography**: Confirmed EOF append detection working correctly
- **Error Handling**: All edge cases (empty, malformed, large files) handled

### Performance

- **Analysis Speed**: 0.01s (typical), <0.1s (100KB), <2s (10MB)
- **Memory Usage**: Normal, no leaks
- **Scalability**: Tested with 10MB files, handles gracefully

### Testing

- **39 comprehensive tests** covering all 16 components
- **5 validation suites** for each block
- **Edge cases tested**: Empty files, malformed data, large files, Unicode
- **Integration tested**: End-to-end analysis with all components
- **100% pass rate**: All tests passing

### Breaking Changes

⚠️ **API Changes from v2.0.0:**
- Engine class renamed: `PrometheusEngine` → `PrometheusEngineV3`
- Model classes updated in `models_v3.py`
- Intelligence database format updated
- CLI arguments enhanced (backward compatible)

### Migration from v2.0.0

See `docs/MIGRATION_v2_to_v3.md` for detailed migration guide.

**Quick migration:**
```python
# v2.0.0
from prometheus import PrometheusEngine
engine = PrometheusEngine()

# v3.0.0
from prometheus import PrometheusEngineV3
engine = PrometheusEngineV3()
```

### Statistics

- **Total Lines**: 9,223 lines of production code
- **Components**: 16 integrated detection modules
- **Detection Patterns**: 400+ signatures and patterns
- **Platforms**: Windows PE, Linux ELF, Android DEX
- **Export Formats**: YARA, JSON, CSV, STIX 2.1, HTML, Markdown
- **Test Coverage**: 39/39 tests passing (100%)
- **Academic Coverage**: ~95% of Binary Analysis Reference v2.2

---

## [2.0.0] - 2026-02-XX (Previous Release)

### Added
- Explainable detection with severity levels
- Location tracking with exact byte offsets
- Enhanced intelligence database (661 items)
- MITRE ATT&CK mappings
- Detection reasoning

See previous changelog entries for v2.0.0 details.

---

## [1.0.1] - 2026-01-28

### Added
- Detailed output for signatures, indicators, exploits
- High entropy warnings
- Visual formatting with emojis

### Fixed
- Critical: Users could not see WHAT was detected

---

## [1.0.0] - 2026-01-28

### Added
- Initial PyPI release
- 6-layer detection engine
- 661 intelligence items
- CLI interface
- JSON export

---

[3.0.0]: https://github.com/0x44616D69616E/prometheus-community/compare/v2.0.0...v3.0.0
[2.0.0]: https://github.com/0x44616D69616E/prometheus-community/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/0x44616D69616E/prometheus-community/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/0x44616D69616E/prometheus-community/releases/tag/v1.0.0
