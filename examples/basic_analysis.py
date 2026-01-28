#!/usr/bin/env python3
"""
Prometheus Community Edition - Basic Analysis Example

This example shows how to use Prometheus programmatically in Python.
"""

from prometheus import PrometheusEngine
import sys

def main():
    """Basic analysis example."""
    
    if len(sys.argv) < 2:
        print("Usage: python basic_analysis.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    # Initialize engine
    print("Initializing Prometheus...")
    engine = PrometheusEngine()
    
    # Analyze file
    print(f"\nAnalyzing: {file_path}")
    result = engine.analyze_file(file_path)
    
    # Print results
    print("\n" + "="*70)
    print("RESULTS SUMMARY")
    print("="*70)
    print(f"File: {result.sample.filename}")
    print(f"SHA256: {result.sample.sha256}")
    print(f"Size: {result.sample.file_size:,} bytes")
    print(f"Type: {result.sample.file_type.value}")
    print()
    print(f"Family: {result.family}")
    print(f"Confidence: {result.confidence:.0%}")
    print(f"Analysis Time: {result.analysis_duration:.3f}s")
    
    if result.ttps:
        print(f"\nTTPs Found: {len(result.ttps)}")
        for ttp in result.ttps:
            print(f"  - {ttp}")
    
    if result.static:
        print(f"\nStatic Analysis:")
        print(f"  - Entropy: {result.static.get('entropy', 0):.2f}")
        print(f"  - Strings: {result.static.get('strings_count', 0)}")
        print(f"  - Packed: {result.static.get('is_packed', False)}")
    
    print("="*70)

if __name__ == '__main__':
    main()
