# Changelog

All notable changes to Prometheus Community Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-02-XX (Planned)

### Added

#### Explainable Detection
- **Severity levels** for all 661 intelligence items (critical/high/medium/low/info)
- **Uniqueness ratings** for all behavioral indicators (unique/rare/common)
- **Confidence weights** (0.0-1.0) per indicator showing detection strength
- **Detailed explanations** for every indicator explaining WHY it matters
- **MITRE ATT&CK mappings** for all indicators with TTP categories
- **Behavioral context** descriptions revealing what each indicator means
- **Commonly found in** arrays showing which malware families use each indicator
- **Detection reasoning** object explaining confidence calculation

#### Location Tracking
- **Location class** for tracking findings with offset, length, section, context
- **Exact byte offsets** for all signatures, indicators, and exploit patterns
- **PE section information** (.text, .data, .rdata, etc.) for all findings
- **Hex context** showing surrounding bytes for manual verification
- **String locations** with offset and length for all extracted strings
- **Location map** providing overview of all finding positions in file
- **Verification support** with instructions to check findings in hex editor

#### Enhanced Models
- `Severity` enum for severity classification
- `Uniqueness` enum for uniqueness ratings  
- `Location` dataclass for tracking finding positions
- `DetectionReasoning` class for transparent confidence explanation
- Enhanced `BehavioralMatch` with location and full metadata
- Enhanced `ExploitMatch` with location and context
- Enhanced `SignatureMatch` with location tracking
- `StringMatch` class for extracted strings with locations

#### New API Methods
- `AnalysisResult.get_unique_indicators()` - Get unique/rare indicators only
- `AnalysisResult.get_critical_indicators()` - Get critical severity items
- `AnalysisResult.get_locations_map()` - Get map of all finding offsets
- `BehavioralMatch.get_severity_icon()` - Get emoji for severity
- `BehavioralMatch.get_uniqueness_badge()` - Get badge for uniqueness
- `BehavioralMatch.is_high_confidence()` - Check if high confidence
- `Location.to_dict()` - Convert location to dictionary
- `Location.__str__()` - Human-readable location string

### Changed

#### Intelligence Database
- **Upgraded** `prometheus/data/intelligence.json` from 122 KB to 375 KB
- **Enhanced** all 661 intelligence items with rich metadata
- **Added** 7 new fields to each behavioral indicator
- **Organized** indicators by uniqueness (15 unique, 58 rare, 130 common)
- **Classified** indicators by severity (20 critical, 138 high, 45 medium)
- **Mapped** all indicators to MITRE ATT&CK framework

#### Detection Engines
- **signature_engine.py**: Now tracks exact offset of each match
- **behavioral_detector.py**: Now records location with offset and context
- **exploit_detector.py**: Now shows location of patterns with hex dump
- All engines now return matches with `Location` objects

#### Output Format
- **Enhanced** all layer outputs with severity icons and uniqueness badges
- **Added** location information to all findings (offset, section, context)
- **Added** detection reasoning section explaining confidence calculation
- **Added** key findings map showing critical offsets
- **Added** verification instructions for manual confirmation
- **Improved** visual formatting with better emoji usage

#### JSON Export
- **Enhanced** JSON output with location data for all findings
- **Added** `behavioral_details` array with full metadata
- **Added** `exploit_details` array with locations
- **Added** `signature_details` array with offsets
- **Added** `location_map` object with finding positions
- **Added** `reasoning` object with confidence explanation

### Improved

- **Transparency**: Every finding now explained with WHY it matters
- **Verifiability**: Can confirm every finding in hex editor using offsets
- **Educational**: Each indicator teaches about malware behavior
- **Forensic detail**: Professional-grade location tracking
- **Confidence scoring**: Transparent calculation based on uniqueness
- **MITRE mapping**: All TTPs categorized according to ATT&CK framework

### Documentation

- Added `ENHANCED_INTELLIGENCE_SCHEMA.md` - Intelligence design document
- Added `IMPLEMENTATION_GUIDE_ENHANCED.md` - Implementation instructions
- Added `LOCATION_TRACKING_GUIDE.md` - Location tracking reference
- Added `ENHANCED_DATABASE_DOCUMENTATION.md` - Database documentation
- Added `MIGRATION_v1_to_v2.md` - Migration guide from v1.x
- Updated `README.md` with v2.0 features
- Updated `QUICK_REFERENCE.md` with new output examples

## [1.0.1] - 2026-01-28

### Added
- Detailed output for file signatures (show actual signature names)
- Detailed output for behavioral indicators (list all matches with values)
- Detailed output for exploit patterns (show techniques and severity)
- Detailed IOC listing (show actual indicators, not just count)
- Detailed TTP listing (show actual tactics and techniques)
- High entropy warning for packed/encrypted files
- Visual formatting with emojis for better readability

### Changed
- Enhanced Layer 1 output to show actual signatures matched
- Enhanced Layer 2 output to display all behavioral indicators found
- Enhanced Layer 3 output to show exploit patterns with details
- Enhanced final summary to list IOCs and TTPs instead of counts
- Improved output formatting throughout for better user experience

### Fixed
- **Critical:** Users could not see WHAT was detected, only counts
- Output now shows actual findings instead of summary counts

## [1.0.0] - 2026-01-28

### Added
- Initial PyPI release
- 6-layer detection engine
- 661 intelligence items (276 signatures, 203 behavioral, 168 exploits)
- CLI interface (`prometheus` command)
- JSON export capability
- Based on Binary Analysis Reference v2.2 (DOI: 10.5281/zenodo.18123287)
- Comprehensive documentation
- Research paper citations
- Open core license model

### Core Features
- Layer 1: File signature detection
- Layer 2: Behavioral indicator matching
- Layer 3: Exploit pattern detection
- Layer 4: PE heuristic analysis
- Layer 5: Dynamic behavior inference
- Layer 6: ML-based classification

[2.0.0]: https://github.com/0x44616D69616E/prometheus-community/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/0x44616D69616E/prometheus-community/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/0x44616D69616E/prometheus-community/releases/tag/v1.0.0
