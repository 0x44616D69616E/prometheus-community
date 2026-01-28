"""
PROMETHEUS COMMUNITY EDITION - CLI

Command-line interface for malware analysis.

Copyright (c) 2026 Damian Donahue
License: See LICENSE file
"""

import argparse
import json
import sys
from pathlib import Path
from .engine import PrometheusEngine
from . import __version__


def show_banner():
    """Show Prometheus banner."""
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🔥 PROMETHEUS COMMUNITY EDITION v1.0.0                ║
║                                                          ║
║   Revolutionary 6-layer malware analysis                 ║
║   Based on Binary Analysis Reference v2.2                ║
║                                                          ║
║   DOI: 10.5281/zenodo.18123287                          ║
║   661 intelligence items from peer-reviewed research     ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)


def show_upgrade_info():
    """Show Enterprise Edition information."""
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   🚀 PROMETHEUS ENTERPRISE EDITION                      ║
║                                                          ║
╟──────────────────────────────────────────────────────────╢
║                                                          ║
║  Community Edition (Current):                            ║
║    ✅ 661 intelligence items (full research)            ║
║    ✅ 6-layer detection                                 ║
║    ✅ CLI interface                                     ║
║    ✅ JSON output                                       ║
║    ✅ Free for research & education                    ║
║                                                          ║
║  Enterprise Edition Adds:                                ║
║    🚀 REST API + Web UI                                 ║
║    🚀 Knowledge graph storage                           ║
║    🚀 Advanced reporting (PDF, XLSX)                    ║
║    🚀 Batch processing (unlimited)                      ║
║    🚀 Multi-user support + RBAC                         ║
║    🚀 SSO/SAML integration                              ║
║    🚀 SIEM integration                                  ║
║    🚀 Commercial license                                ║
║    🚀 Priority support + SLA                            ║
║                                                          ║
║  Research Foundation:                                    ║
║    📚 Binary Analysis Reference v2.2                    ║
║    📚 DOI: 10.5281/zenodo.18123287                     ║
║    📚 github.com/0x44616D69616E/binary-analysis-reference  ║
║                                                          ║
║  Learn More:                                             ║
║    GitHub: github.com/0x44616D69616E/prometheus-enterprise ║
║    Email:  contact@asnspy.com                           ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
    """)


def analyze_command(args):
    """Analyze a single file."""
    if not Path(args.file).exists():
        print(f"Error: File not found: {args.file}")
        return 1
    
    try:
        engine = PrometheusEngine(quiet=args.quiet or args.json)
        result = engine.analyze_file(args.file)
        
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        elif not args.quiet:
            # Already printed by engine
            pass
        
        # Save output if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dumps(result.to_dict(), f, indent=2)
            if not args.quiet:
                print(f"\nSaved to: {args.output}")
        
        return 0
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def batch_command(args):
    """Analyze multiple files in a directory."""
    directory = Path(args.directory)
    
    if not directory.exists():
        print(f"Error: Directory not found: {args.directory}")
        return 1
    
    if not directory.is_dir():
        print(f"Error: Not a directory: {args.directory}")
        return 1
    
    # Find all files
    files = [f for f in directory.iterdir() if f.is_file()]
    
    if not files:
        print(f"No files found in: {args.directory}")
        return 1
    
    print(f"Found {len(files)} files")
    print()
    
    results = []
    engine = PrometheusEngine(quiet=True)
    
    for i, file_path in enumerate(files, 1):
        try:
            print(f"[{i}/{len(files)}] {file_path.name}...", end=' ')
            result = engine.analyze_file(str(file_path))
            print(f"{result.family} ({result.confidence:.0%})")
            results.append(result)
        except Exception as e:
            print(f"ERROR: {e}")
    
    print()
    print("="*70)
    print("BATCH ANALYSIS COMPLETE")
    print("="*70)
    print(f"Files analyzed: {len(results)}")
    print(f"Families detected: {len(set(r.family for r in results))}")
    print()
    
    # Summary by family
    from collections import Counter
    families = Counter(r.family for r in results)
    print("Family distribution:")
    for family, count in families.most_common():
        print(f"  {family}: {count}")
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
        print(f"\nSaved to: {args.output}")
    
    return 0


def version_command(args):
    """Show version information."""
    print(f"Prometheus Community Edition v{__version__}")
    print(f"Copyright (c) 2026 Damian Donahue")
    print(f"License: Prometheus Community License v1.0")
    print()
    print(f"Based on: Binary Analysis and Reverse Engineering Reference v2.2")
    print(f"DOI: 10.5281/zenodo.18123287")
    print(f"Paper: https://github.com/0x44616D69616E/binary-analysis-reference")
    print()
    print(f"Intelligence: 661 items (276 signatures, 203 behavioral, 168 exploits)")
    print()
    print(f"For commercial use, contact: contact@asnspy.com")
    print(f"GitHub: https://github.com/0x44616D69616E/prometheus-community")
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Prometheus Community Edition - Revolutionary Malware Analysis\n' +
                    'Based on Binary Analysis Reference v2.2 (DOI: 10.5281/zenodo.18123287)',
        epilog='Research: https://github.com/0x44616D69616E/binary-analysis-reference\n' +
               'Enterprise: https://github.com/0x44616D69616E/prometheus-enterprise',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single file')
    analyze_parser.add_argument('file', help='File to analyze')
    analyze_parser.add_argument('--json', action='store_true', help='Output as JSON')
    analyze_parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    analyze_parser.add_argument('--output', '-o', help='Save results to file')
    analyze_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Batch command
    batch_parser = subparsers.add_parser('batch', help='Analyze multiple files')
    batch_parser.add_argument('directory', help='Directory containing files')
    batch_parser.add_argument('--output', '-o', help='Save results to file')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    # Upgrade command
    upgrade_parser = subparsers.add_parser('upgrade', help='Show Enterprise Edition info')
    
    args = parser.parse_args()
    
    # Show banner for interactive commands
    if args.command in ['analyze', 'batch'] and not (hasattr(args, 'json') and args.json):
        show_banner()
    
    # Execute command
    if args.command == 'analyze':
        return analyze_command(args)
    elif args.command == 'batch':
        return batch_command(args)
    elif args.command == 'version':
        return version_command(args)
    elif args.command == 'upgrade':
        show_upgrade_info()
        return 0
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
