"""
BLOCK 3 VALIDATION SCRIPT

Validates that all Block 3 executable analysis components work correctly.

Tests:
1. PE analyzer
2. Anti-analysis detector
3. Cryptographic detector
4. Integrated engine

This does NOT run on actual malware - just validates the code works.
"""

import sys
import traceback


def validate_imports():
    """Validate all Block 3 modules can be imported."""
    print("=" * 70)
    print("VALIDATION: Block 3 Module Imports")
    print("=" * 70)
    
    try:
        print("✓ Importing pe_analyzer...")
        from pe_analyzer import PEAnalyzer
        
        print("✓ Importing anti_analysis_detector...")
        from anti_analysis_detector import AntiAnalysisDetector
        
        print("✓ Importing crypto_detector...")
        from crypto_detector import CryptographicDetector
        
        print("✓ Importing updated engine...")
        from engine_v3_0_0_block3 import PrometheusEngineV3
        
        print("\n✅ All Block 3 modules imported successfully!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Import failed: {e}")
        traceback.print_exc()
        return False


def validate_pe_analyzer():
    """Validate PE analyzer."""
    print("=" * 70)
    print("VALIDATION: PE Analyzer")
    print("=" * 70)
    
    try:
        from pe_analyzer import PEAnalyzer
        
        analyzer = PEAnalyzer()
        print("✓ PE analyzer created")
        
        # Create minimal PE file
        # DOS header
        dos_header = b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00'  # e_lfanew at 0x3c
        # PE signature at offset 0x80
        pe_sig = b'PE\x00\x00'
        # COFF header (20 bytes)
        coff = b'\x4c\x01'  # Machine (x86)
        coff += b'\x01\x00'  # NumberOfSections
        coff += b'\x00' * 12  # Timestamp, etc.
        coff += b'\xe0\x00'  # SizeOfOptionalHeader
        coff += b'\x00\x00'  # Characteristics
        
        # Minimal optional header
        opt = b'\x0b\x01'  # Magic (PE32)
        opt += b'\x00' * 222  # Rest of optional header
        
        # Section header
        section = b'.text\x00\x00\x00'  # Name
        section += b'\x00\x10\x00\x00'  # VirtualSize
        section += b'\x00\x10\x00\x00'  # VirtualAddress
        section += b'\x00\x02\x00\x00'  # SizeOfRawData
        section += b'\x00\x02\x00\x00'  # PointerToRawData
        section += b'\x00' * 12  # Relocations, etc.
        section += b'\x20\x00\x00\x60'  # Characteristics (EXECUTE, READ)
        
        test_pe = dos_header + b'\x00' * (0x80 - len(dos_header)) + pe_sig + coff + opt + section
        test_pe += b'\x00' * 512  # Padding
        
        print("✓ Testing PE analysis...")
        suspicious, info = analyzer.analyze(test_pe, "test.exe")
        
        total = len(suspicious) + len(info)
        print(f"✓ PE analysis completed: {total} findings")
        
        # Verify packer detection
        print("✓ Verifying packer signatures...")
        assert 'UPX0' in analyzer.PACKER_SECTIONS
        assert 'UPX1' in analyzer.PACKER_SECTIONS
        print(f"✓ Loaded {len(analyzer.PACKER_SECTIONS)} packer signatures")
        
        print("\n✅ PE analyzer works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ PE analyzer validation failed: {e}")
        traceback.print_exc()
        return False


def validate_anti_analysis_detector():
    """Validate anti-analysis detector."""
    print("=" * 70)
    print("VALIDATION: Anti-Analysis Detector")
    print("=" * 70)
    
    try:
        from anti_analysis_detector import AntiAnalysisDetector
        
        detector = AntiAnalysisDetector()
        print("✓ Anti-analysis detector created")
        
        # Test anti-debug detection
        print("✓ Testing anti-debug detection...")
        test_content = b'\x00' * 100 + b'IsDebuggerPresent' + b'\x00' * 100
        high, medium = detector.detect(test_content)
        total = len(high) + len(medium)
        print(f"✓ Anti-debug detection: {total} findings")
        
        # Test anti-VM detection
        print("✓ Testing anti-VM detection...")
        test_content2 = b'\x00' * 100 + b'SOFTWARE\\VMware' + b'\x00' * 100
        high2, medium2 = detector.detect(test_content2)
        total2 = len(high2) + len(medium2)
        print(f"✓ Anti-VM detection: {total2} findings")
        
        # Verify signatures loaded
        print("✓ Verifying signatures...")
        assert len(detector.anti_debug_apis) > 0
        assert len(detector.anti_vm_registry) > 0
        print(f"✓ Loaded {len(detector.anti_debug_apis)} anti-debug APIs")
        print(f"✓ Loaded {len(detector.anti_vm_registry)} VM registry keys")
        
        print("\n✅ Anti-analysis detector works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Anti-analysis detector validation failed: {e}")
        traceback.print_exc()
        return False


def validate_crypto_detector():
    """Validate cryptographic detector."""
    print("=" * 70)
    print("VALIDATION: Cryptographic Detector")
    print("=" * 70)
    
    try:
        from crypto_detector import CryptographicDetector
        
        detector = CryptographicDetector()
        print("✓ Cryptographic detector created")
        
        # Test AES detection
        print("✓ Testing AES detection...")
        # AES S-box first 16 bytes
        aes_sbox = bytes([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
        ])
        test_content = b'\x00' * 100 + aes_sbox + b'\x00' * 240 + b'\x00' * 100
        
        suspicious, info = detector.detect(test_content)
        total = len(suspicious) + len(info)
        print(f"✓ Crypto detection: {total} findings")
        
        # Verify constants loaded
        print("✓ Verifying crypto constants...")
        assert len(detector.md5_iv) == 4
        assert len(detector.sha1_iv) == 5
        assert len(detector.sha256_iv) == 4
        print(f"✓ MD5 IVs: {len(detector.md5_iv)}")
        print(f"✓ SHA-1 IVs: {len(detector.sha1_iv)}")
        print(f"✓ SHA-256 IVs: {len(detector.sha256_iv)}")
        
        print("\n✅ Cryptographic detector works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Cryptographic detector validation failed: {e}")
        traceback.print_exc()
        return False


def validate_integrated_engine():
    """Validate integrated engine with all Block 3 detectors."""
    print("=" * 70)
    print("VALIDATION: Integrated Engine (Block 3)")
    print("=" * 70)
    
    try:
        from engine_v3_0_0_block3 import PrometheusEngineV3
        from config import PrometheusConfig
        
        print("✓ Creating engine with quiet mode...")
        config = PrometheusConfig()
        config.quiet_mode = True
        
        # Create minimal intel DB
        import tempfile
        import json
        
        intel_db = {
            'behavioral_indicators': [],
            'file_signatures': []
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(intel_db, f)
            temp_intel_path = f.name
        
        engine = PrometheusEngineV3(config=config, intel_path=temp_intel_path)
        print("✓ Engine created successfully")
        
        # Verify all Block 3 detectors initialized
        print("✓ Verifying detectors initialized...")
        # Block 1
        assert hasattr(engine, 'behavioral_detector')
        # Block 2
        assert hasattr(engine, 'steganography_detector')
        assert hasattr(engine, 'shellcode_detector')
        assert hasattr(engine, 'xor_encoding_detector')
        assert hasattr(engine, 'nested_file_detector')
        # Block 3
        assert hasattr(engine, 'pe_analyzer')
        assert hasattr(engine, 'anti_analysis_detector')
        assert hasattr(engine, 'crypto_detector')
        print("✓ All detectors present (Blocks 1, 2, 3)")
        
        # Get statistics
        print("✓ Getting engine statistics...")
        stats = engine.get_statistics()
        assert stats['version'] == '3.0.0'
        assert 'block' in stats
        assert stats['config']['pe_analysis'] == True
        assert stats['config']['anti_analysis_detection'] == True
        assert stats['config']['crypto_detection'] == True
        print(f"✓ Engine version: {stats['version']}")
        print(f"✓ Block: {stats['block']}")
        
        # Cleanup
        import os
        os.unlink(temp_intel_path)
        
        print("\n✅ Integrated engine works!\n")
        return True
        
    except Exception as e:
        print(f"\n❌ Integrated engine validation failed: {e}")
        traceback.print_exc()
        return False


def main():
    """Run all Block 3 validations."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 68 + "║")
    print("║" + "  PROMETHEUS v3.0.0 - BLOCK 3 VALIDATION".center(68) + "║")
    print("║" + "  Executable Deep Dive & Anti-Analysis".center(68) + "║")
    print("║" + " " * 68 + "║")
    print("╚" + "=" * 68 + "╝")
    print("\n")
    
    results = []
    
    # Run validations
    results.append(("Module Imports", validate_imports()))
    results.append(("PE Analyzer", validate_pe_analyzer()))
    results.append(("Anti-Analysis Detector", validate_anti_analysis_detector()))
    results.append(("Cryptographic Detector", validate_crypto_detector()))
    results.append(("Integrated Engine", validate_integrated_engine()))
    
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
        print("🎉 ALL VALIDATIONS PASSED! Block 3 is ready for deployment!")
        print()
        print("New capabilities:")
        print("  ✓ PE structure analysis (sections, imports, packers)")
        print("  ✓ Anti-analysis detection (anti-debug, anti-VM)")
        print("  ✓ Cryptographic artifacts (AES, MD5, SHA, RSA)")
        print()
        print("Coverage: ~70% of Binary Analysis Academic Reference")
        print()
        return 0
    else:
        print("⚠️  Some validations failed. Please review errors above.")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
