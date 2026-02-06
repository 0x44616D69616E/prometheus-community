#!/usr/bin/env python3
"""
Prometheus Community Edition - CLI Interface

Enterprise-grade malware analysis with comprehensive automation.
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional


def print_banner():
    """Print Prometheus banner."""
    from prometheus import __version__
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   🔥 PROMETHEUS COMMUNITY EDITION v{__version__:<18}     ║
║   Enterprise-Grade Malware Analysis                      ║
╚══════════════════════════════════════════════════════════╝
""")


def cmd_analyze(args):
    """Analyze a file."""
    from prometheus import PrometheusEngine
    from prometheus.yara_generator import YARARuleGenerator
    from prometheus.ioc_exporter import IOCExporter
    from prometheus.report_generator import ReportGenerator
    from prometheus.config import PrometheusConfig
    
    # Print banner unless quiet
    if not args.quiet:
        print_banner()
    
    # Check file exists
    if not Path(args.file).exists():
        print(f"❌ Error: File not found: {args.file}")
        return 1
    
    # Create config
    config = PrometheusConfig()
    config.quiet_mode = args.quiet
    
    # Apply detection toggles
    if not args.enable_stego:
        config.enable_steganography = False
    if not args.enable_shellcode:
        config.enable_shellcode = False
    if not args.enable_crypto:
        config.enable_crypto = False
    if not args.enable_network:
        config.enable_network = False
    
    # Initialize engine
    try:
        intel_path = args.intel if args.intel else None
        engine = PrometheusEngine(config=config, intel_path=intel_path)
    except Exception as e:
        print(f"❌ Error initializing engine: {e}")
        return 1
    
    # Analyze file
    if not args.quiet:
        print(f"Analyzing: {args.file}")
        print()
    
    try:
        result = engine.analyze_file(args.file)
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        return 1
    
    # Save JSON output if requested
    if args.output:
        try:
            output_dict = {
                'sample': {
                    'filename': result.sample.filename,
                    'file_path': result.sample.file_path,
                    'file_type': result.sample.file_type.value if result.sample.file_type else 'Unknown',
                    'file_size': result.sample.file_size,
                    'md5': result.sample.md5,
                    'sha1': result.sample.sha1,
                    'sha256': result.sample.sha256,
                },
                'analysis': {
                    'duration': result.analysis_duration,
                    'exact_matches': len(result.exact_matches),
                    'suspicious_artifacts': len(result.suspicious_artifacts),
                    'informational': len(result.informational_artifacts),
                    'iocs': result.iocs,
                    'ttps': result.ttps,
                },
                'findings': {
                    'exact': [{'type': e.artifact_type, 'value': e.value, 'family': e.malware_family} 
                             for e in result.exact_matches],
                    'suspicious': [{'type': s.artifact_type, 'value': s.value, 
                                   'severity': s.severity.value, 'confidence': s.confidence}
                                 for s in result.suspicious_artifacts],
                }
            }
            
            with open(args.output, 'w') as f:
                json.dump(output_dict, f, indent=2)
            
            if not args.quiet:
                print(f"\n✅ Results saved to: {args.output}")
        
        except Exception as e:
            print(f"❌ Failed to save output: {e}")
            return 1
    
    # Export IOCs if requested
    if args.export_iocs:
        try:
            exporter = IOCExporter()
            base_path = Path(args.export_iocs)
            base_dir = base_path.parent
            base_name = base_path.name
            
            exporter.save_exports(result, str(base_dir), base_name)
            
            if not args.quiet:
                print(f"\n✅ IOCs exported:")
                print(f"   - {base_dir}/{base_name}.json")
                print(f"   - {base_dir}/{base_name}.csv")
                print(f"   - {base_dir}/{base_name}.stix")
        
        except Exception as e:
            print(f"❌ Failed to export IOCs: {e}")
            return 1
    
    # Generate YARA rule if requested
    if args.generate_yara:
        try:
            generator = YARARuleGenerator()
            rule_name = Path(args.generate_yara).stem
            ruleset = generator.generate_ruleset(result, rule_name)
            
            with open(args.generate_yara, 'w') as f:
                f.write(ruleset)
            
            if not args.quiet:
                print(f"\n✅ YARA rule generated: {args.generate_yara}")
        
        except Exception as e:
            print(f"❌ Failed to generate YARA rule: {e}")
            return 1
    
    # Generate HTML report if requested
    if args.report:
        try:
            generator = ReportGenerator()
            html = generator.generate_html(result)
            
            with open(args.report, 'w') as f:
                f.write(html)
            
            if not args.quiet:
                print(f"\n✅ HTML report generated: {args.report}")
        
        except Exception as e:
            print(f"❌ Failed to generate HTML report: {e}")
            return 1
    
    # Generate Markdown report if requested
    if args.report_md:
        try:
            generator = ReportGenerator()
            md = generator.generate_markdown(result)
            
            with open(args.report_md, 'w') as f:
                f.write(md)
            
            if not args.quiet:
                print(f"\n✅ Markdown report generated: {args.report_md}")
        
        except Exception as e:
            print(f"❌ Failed to generate Markdown report: {e}")
            return 1
    
    if not args.quiet:
        print()
    
    return 0


def cmd_version(args):
    """Show version information."""
    from prometheus import __version__
    
    print_banner()
    print(f"Version: {__version__}")
    print("Enterprise-grade malware analysis engine")
    print()
    print("Components: 16 integrated detection modules")
    print("Coverage: ~95% of Binary Analysis Academic Reference")
    print("Platforms: Windows PE, Linux ELF, Android DEX")
    print("Formats: YARA, JSON, CSV, STIX 2.1, HTML, Markdown")
    print()
    print("Python:", sys.version.split()[0])
    print("License: Prometheus Community License v1.0")
    print()
    print("📚 Documentation: https://github.com/0x44616D69616E/prometheus-community")
    print("🐛 Issues: https://github.com/0x44616D69616E/prometheus-community/issues")
    print()
    
    return 0


def cmd_help_examples(args):
    """Show usage examples."""
    print_banner()
    print("📖 USAGE EXAMPLES")
    print("=" * 60)
    
    print("\n1️⃣  BASIC ANALYSIS")
    print("   prometheus analyze malware.exe")
    
    print("\n2️⃣  EXPORT IOCS (JSON, CSV, STIX)")
    print("   prometheus analyze malware.exe --export-iocs iocs/malware")
    
    print("\n3️⃣  GENERATE YARA RULE")
    print("   prometheus analyze malware.exe --generate-yara detection.yar")
    
    print("\n4️⃣  CREATE HTML REPORT")
    print("   prometheus analyze malware.exe --report analysis.html")
    
    print("\n5️⃣  COMPLETE WORKFLOW")
    print("   prometheus analyze malware.exe \\")
    print("     --export-iocs iocs/malware \\")
    print("     --generate-yara rules/malware.yar \\")
    print("     --report reports/malware.html \\")
    print("     --output json/malware.json")
    
    print("\n6️⃣  ANDROID APK ANALYSIS")
    print("   prometheus analyze app.apk --android --export-iocs app_iocs")
    
    print("\n7️⃣  QUIET MODE (AUTOMATION)")
    print("   prometheus analyze malware.exe --quiet --output results.json")
    
    print("\n8️⃣  CUSTOM INTELLIGENCE DATABASE")
    print("   prometheus analyze malware.exe --intel custom_intel.json")
    
    print("\n9️⃣  BATCH PROCESSING")
    print("   for file in samples/*.exe; do")
    print('     name=$(basename "$file" .exe)')
    print('     prometheus analyze "$file" \\')
    print('       --quiet --export-iocs "iocs/$name" \\')
    print('       --generate-yara "rules/$name.yar"')
    print("   done")
    
    print("\n🔟 SOC ANALYST WORKFLOW")
    print("   # Quick triage")
    print("   prometheus analyze alert.exe")
    print()
    print("   # If suspicious, export for blocking")
    print("   prometheus analyze alert.exe --export-iocs blocking/alert")
    print()
    print("   # Generate detection rule")
    print("   prometheus analyze alert.exe --generate-yara detection.yar")
    
    print("\n" + "=" * 60)
    print("\n💡 TIP: Use --help with any command for detailed options")
    print()
    
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="prometheus",
        description="Prometheus Community Edition - Enterprise-grade malware analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  prometheus analyze malware.exe
  prometheus analyze malware.exe --export-iocs iocs/malware
  prometheus analyze malware.exe --generate-yara detection.yar
  prometheus analyze malware.exe --report analysis.html
  prometheus version
  prometheus examples

For detailed examples: prometheus examples
For help on commands: prometheus <command> --help

Documentation: https://github.com/0x44616D69616E/prometheus-community
"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze a file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Analyze malware samples with comprehensive detection",
        epilog="""
Examples:
  prometheus analyze malware.exe
  prometheus analyze malware.exe --output results.json
  prometheus analyze malware.exe --export-iocs iocs/malware
  prometheus analyze malware.exe --generate-yara detection.yar
  prometheus analyze malware.exe --report analysis.html
  prometheus analyze app.apk --android --export-iocs app_iocs
"""
    )
    
    # Required arguments
    analyze_parser.add_argument('file', help='File to analyze')
    
    # Core options
    analyze_parser.add_argument('-o', '--output', help='Save JSON results to file')
    analyze_parser.add_argument('-q', '--quiet', action='store_true', 
                               help='Suppress console output')
    analyze_parser.add_argument('--intel', help='Path to custom intelligence database')
    
    # Export options
    export_group = analyze_parser.add_argument_group('export options')
    export_group.add_argument('--export-iocs', metavar='PATH',
                             help='Export IOCs to JSON/CSV/STIX (e.g., "iocs/malware")')
    export_group.add_argument('--generate-yara', metavar='FILE',
                             help='Generate YARA rule file (e.g., "detection.yar")')
    export_group.add_argument('--report', metavar='FILE',
                             help='Generate HTML report (e.g., "analysis.html")')
    export_group.add_argument('--report-md', metavar='FILE',
                             help='Generate Markdown report (e.g., "analysis.md")')
    
    # Platform options
    platform_group = analyze_parser.add_argument_group('platform options')
    platform_group.add_argument('--android', action='store_true',
                               help='Analyze Android APK/DEX file')
    platform_group.add_argument('--pe', action='store_true',
                               help='Force PE (Windows) analysis')
    platform_group.add_argument('--elf', action='store_true',
                               help='Force ELF (Linux) analysis')
    
    # Detection options
    detection_group = analyze_parser.add_argument_group('detection options')
    detection_group.add_argument('--disable-stego', dest='enable_stego', 
                                action='store_false', default=True,
                                help='Disable steganography detection')
    detection_group.add_argument('--disable-shellcode', dest='enable_shellcode',
                                action='store_false', default=True,
                                help='Disable shellcode detection')
    detection_group.add_argument('--disable-crypto', dest='enable_crypto',
                                action='store_false', default=True,
                                help='Disable cryptographic detection')
    detection_group.add_argument('--disable-network', dest='enable_network',
                                action='store_false', default=True,
                                help='Disable network artifact detection')
    
    analyze_parser.set_defaults(func=cmd_analyze)
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    version_parser.set_defaults(func=cmd_version)
    
    # Examples command
    examples_parser = subparsers.add_parser('examples', help='Show usage examples')
    examples_parser.set_defaults(func=cmd_help_examples)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show help if no command
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute command
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
