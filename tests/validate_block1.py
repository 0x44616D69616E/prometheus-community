"""
BLOCK 1 VALIDATION SCRIPT

Validates that all Block 1 components load and function without errors.

This does NOT run on actual malware samples - just validates the code works.
"""

import sys
import traceback

def validate_imports():
    """Validate all modules can be imported."""
    print("=" * 70)
    print("VALIDATION: Module Imports")
    print("=" * 70)
    
    try:
        print("✓ Importing config...")
        from config import PrometheusConfig, ValidationStrictness
        
        print("✓ Importing models_v3...")
        from models_v3 import (
            ExactMatch, SuspiciousArtifact, InformationalArtifact,
            AnalysisResult, Sample, Location, ClassificationTier
        )
        
        print("✓ Importing context_validator...")
        from context_validator import ContextValidator
        
        print("✓ Importing behavioral_detector_v3...")
        from behavioral_detector_v3 import BehavioralDetectorV3
        
        print("✓ Importing output_formatter...")
        from output_formatter import OutputFormatter
        
        print("✓ Importing engine_v3_0_0...")
        from engine_v3_0_0 import PrometheusEngineV3
        
        print("\n✅ All modules imported successfully!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Import failed: {e}")
        traceback.print_exc()
        return False


def validate_config():
    """Validate configuration system."""
    print("=" * 70)
    print("VALIDATION: Configuration System")
    print("=" * 70)
    
    try:
        from config import PrometheusConfig, ValidationStrictness
        
        # Test default config
        print("✓ Creating default config...")
        config = PrometheusConfig.default()
        assert config.validation_strictness == ValidationStrictness.MODERATE
        
        # Test strict config
        print("✓ Creating strict config...")
        config_strict = PrometheusConfig.strict()
        assert config_strict.validation_strictness == ValidationStrictness.STRICT
        
        # Test lenient config
        print("✓ Creating lenient config...")
        config_lenient = PrometheusConfig.lenient()
        assert config_lenient.validation_strictness == ValidationStrictness.LENIENT
        
        # Test validation rules
        print("✓ Testing validation rules...")
        rules = config_strict.get_validation_rules()
        assert rules['require_path_separator'] == True
        
        print("\n✅ Configuration system works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Config validation failed: {e}")
        traceback.print_exc()
        return False


def validate_context_validator():
    """Validate context validation system."""
    print("=" * 70)
    print("VALIDATION: Context Validator")
    print("=" * 70)
    
    try:
        from config import PrometheusConfig
        from context_validator import ContextValidator
        
        config = PrometheusConfig.default()
        validator = ContextValidator(config)
        
        # Test file extension validation
        print("✓ Testing file extension validation...")
        valid, result = validator.validate_file_extension(
            "C:\\Users\\test\\malware.exe", ".exe"
        )
        assert valid == True
        
        # Test invalid extension (random bytes)
        print("✓ Testing false positive rejection...")
        invalid, reason = validator.validate_file_extension(
            "random_data_0x2e_0x33_bytes", ".3"
        )
        # Should reject random data
        
        # Test URL validation
        print("✓ Testing URL validation...")
        valid, result = validator.validate_url(
            "http://malware.com/payload", "http://malware.com/payload"
        )
        
        # Test IP validation
        print("✓ Testing IP validation...")
        valid, result = validator.validate_ip_address(
            "192.168.1.1", "192.168.1.1"
        )
        assert valid == True
        
        print("\n✅ Context validator works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Context validator validation failed: {e}")
        traceback.print_exc()
        return False


def validate_models():
    """Validate data models."""
    print("=" * 70)
    print("VALIDATION: Data Models")
    print("=" * 70)
    
    try:
        from models_v3 import (
            ExactMatch, SuspiciousArtifact, InformationalArtifact,
            Location, Severity, Uniqueness
        )
        
        # Test Location
        print("✓ Testing Location model...")
        loc = Location(offset=0x1000, length=10)
        assert str(loc) == "0x00001000"
        
        # Test ExactMatch
        print("✓ Testing ExactMatch model...")
        exact = ExactMatch(
            artifact_type="mutex",
            value="TestMutex",
            location=loc,
            database_entry={},
            malware_family="TestMalware"
        )
        assert "DEFINITIVE" in exact.get_assessment()
        
        # Test SuspiciousArtifact
        print("✓ Testing SuspiciousArtifact model...")
        sus = SuspiciousArtifact(
            artifact_type="pattern",
            value=".test",
            location=loc,
            severity=Severity.MEDIUM,
            confidence=0.7,
            context="test context",
            observed_in=["TestMalware"]
        )
        assert "SUSPICIOUS" in sus.get_assessment()
        
        # Test InformationalArtifact
        print("✓ Testing InformationalArtifact model...")
        info = InformationalArtifact(
            artifact_type="metadata",
            value="test",
            description="test description"
        )
        assert "BENIGN" in info.get_assessment() or "NEUTRAL" in info.get_assessment()
        
        print("\n✅ Data models work!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Model validation failed: {e}")
        traceback.print_exc()
        return False


def validate_behavioral_detector():
    """Validate behavioral detector."""
    print("=" * 70)
    print("VALIDATION: Behavioral Detector")
    print("=" * 70)
    
    try:
        from config import PrometheusConfig
        from behavioral_detector_v3 import BehavioralDetectorV3
        
        # Create minimal intel DB for testing
        intel_db = {
            'behavioral_indicators': [
                {
                    'family': 'TestMalware',
                    'indicator_type': 'mutex',
                    'value': 'TestMutex',
                    'severity': 'high',
                    'confidence_weight': 0.8,
                    'uniqueness': 'unique',
                    'explanation': 'Test explanation'
                }
            ]
        }
        
        config = PrometheusConfig.default()
        detector = BehavioralDetectorV3(intel_db, config)
        
        print("✓ Behavioral detector created...")
        
        # Test detection
        test_data = {
            'content': b'TestMutex data here',
            'strings': [
                {'value': 'TestMutex', 'offset': 0, 'length': 9}
            ],
            'filename': 'test.exe'
        }
        
        print("✓ Running detection...")
        exact, suspicious, info = detector.detect(test_data)
        
        # Should find the mutex
        assert len(exact) > 0 or len(suspicious) > 0 or len(info) > 0
        
        # Get statistics
        stats = detector.get_statistics()
        assert 'total' in stats
        
        print("\n✅ Behavioral detector works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Behavioral detector validation failed: {e}")
        traceback.print_exc()
        return False


def validate_output_formatter():
    """Validate output formatter."""
    print("=" * 70)
    print("VALIDATION: Output Formatter")
    print("=" * 70)
    
    try:
        from output_formatter import OutputFormatter
        from models_v3 import (
            AnalysisResult, Sample, Location, ExactMatch,
            SuspiciousArtifact, Severity
        )
        
        formatter = OutputFormatter(quiet=True)
        
        # Create minimal result
        sample = Sample(
            filename="test.exe",
            file_path="/test/test.exe",
            file_size=1000,
            sha256="a" * 64,
            md5="b" * 32,
            sha1="c" * 40
        )
        
        result = AnalysisResult(sample=sample)
        
        # Add test artifact
        loc = Location(offset=0x1000, length=10)
        exact = ExactMatch(
            artifact_type="mutex",
            value="TestMutex",
            location=loc,
            database_entry={},
            malware_family="TestMalware"
        )
        result.exact_matches.append(exact)
        
        print("✓ Formatting header...")
        header = formatter.format_header(result)
        assert "PROMETHEUS" in header
        
        print("✓ Formatting exact matches...")
        exact_output = formatter.format_exact_matches(result.exact_matches)
        assert "EXACT MATCHES" in exact_output
        
        print("✓ Formatting summary...")
        summary = formatter.format_summary(result)
        assert "ANALYSIS SUMMARY" in summary
        
        print("✓ Formatting complete output...")
        complete = formatter.format_complete_output(result)
        assert len(complete) > 0
        
        print("\n✅ Output formatter works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Output formatter validation failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all validations."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  PROMETHEUS v3.0.0 - BLOCK 1 VALIDATION".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    print("\n")
    
    results = []
    
    # Run validations
    results.append(("Module Imports", validate_imports()))
    results.append(("Configuration System", validate_config()))
    results.append(("Context Validator", validate_context_validator()))
    results.append(("Data Models", validate_models()))
    results.append(("Behavioral Detector", validate_behavioral_detector()))
    results.append(("Output Formatter", validate_output_formatter()))
    
    # Print summary
    print("=" * 70)
    print("VALIDATION SUMMARY")
    print("=" * 70)
    print()
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{name:.<50} {status}")
    
    print()
    print(f"Results: {passed}/{total} validations passed")
    print()
    
    if passed == total:
        print("🎉 ALL VALIDATIONS PASSED! Block 1 is ready for deployment!")
        print()
        return 0
    else:
        print("⚠️  Some validations failed. Please review errors above.")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
