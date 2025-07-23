#!/usr/bin/env python3
"""
Example script demonstrating pyghidra integration with reD2 shared library analyzer.

This script shows how to use the enhanced SharedLibraryAnalyzer with Ghidra
integration for advanced static analysis of Android shared libraries.
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from utils.shared_library_analyzer import SharedLibraryAnalyzer
from utils.pyghidra_integration import check_pyghidra_availability


def print_section(title: str, content: str = None):
    """Print a formatted section header."""
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print('=' * 60)
    if content:
        print(content)


def analyze_library_example(library_path: str):
    """
    Demonstrate comprehensive library analysis with optional Ghidra integration.
    
    Args:
        library_path: Path to the shared library (.so file) to analyze
    """
    print_section("PyGhidra Integration Example")
    print(f"Analyzing: {library_path}")
    
    # Check if the file exists
    if not os.path.exists(library_path):
        print(f"Error: File not found: {library_path}")
        return
    
    # Initialize the analyzer
    print_section("Initializing Analyzer")
    analyzer = SharedLibraryAnalyzer()
    
    # Check Ghidra availability
    print_section("Checking Ghidra Availability")
    is_available, status = check_pyghidra_availability()
    print(f"PyGhidra Available: {is_available}")
    print(f"Status: {status}")
    
    analyzer_ghidra_info = analyzer.get_ghidra_info()
    print(f"Analyzer Ghidra Info: {analyzer_ghidra_info}")
    
    # Perform standard analysis
    print_section("Standard Analysis")
    print("Running standard shared library analysis...")
    standard_results = analyzer.analyze_shared_library(library_path)
    
    # Print key results from standard analysis
    file_info = standard_results.get('file_info', {})
    print(f"File: {file_info.get('filename', 'N/A')}")
    print(f"Size: {file_info.get('size_human', 'N/A')}")
    print(f"Architecture: {standard_results.get('architecture', {}).get('detected_abi', 'N/A')}")
    print(f"Symbols: {standard_results.get('symbols', {}).get('count', 0)}")
    print(f"Strings: {standard_results.get('strings', {}).get('count', 0)}")
    print(f"Risk Score: {standard_results.get('summary', {}).get('risk_score', 0)}")
    
    # Perform enhanced analysis with Ghidra integration
    print_section("Enhanced Analysis with Ghidra Integration")
    print("Running enhanced analysis with Ghidra integration...")
    
    # Example with all features enabled
    ghidra_options = {
        'extract_functions': True,
        'extract_xrefs': True,
        'extract_strings': True,
        'custom_scripts': None  # Could include paths to custom Ghidra scripts
    }
    
    enhanced_results = analyzer.analyze_with_ghidra(
        library_path,
        merge_with_standard=True,
        ghidra_options=ghidra_options
    )
    
    # Print Ghidra-specific results
    ghidra_section = enhanced_results.get('ghidra_analysis', {})
    if ghidra_section.get('available', False):
        print("✓ Ghidra analysis successful!")
        
        # Function analysis
        functions = ghidra_section.get('functions', {})
        print(f"Functions analyzed: {functions.get('total_functions', 0)}")
        
        # Symbol analysis
        symbols = ghidra_section.get('symbols', {})
        symbol_stats = symbols.get('symbol_statistics', {})
        print(f"Symbols found: {symbol_stats.get('total_symbols', 0)}")
        print(f"  - Global: {symbol_stats.get('global_count', 0)}")
        print(f"  - External: {symbol_stats.get('external_count', 0)}")
        
        # Cross-references
        xrefs = ghidra_section.get('cross_references', {})
        print(f"Function calls: {len(xrefs.get('function_calls', []))}")
        print(f"External references: {len(xrefs.get('external_references', []))}")
        
        # Memory layout
        memory = ghidra_section.get('memory_layout', {})
        print(f"Memory blocks: {len(memory.get('memory_blocks', []))}")
        print(f"Total memory: {memory.get('total_memory', 0)} bytes")
        
        # Enhanced features from merging
        if 'enhanced_functions' in enhanced_results:
            enhanced_funcs = enhanced_results['enhanced_functions']
            print(f"Enhanced function analysis available with {enhanced_funcs.get('function_count', 0)} functions")
        
        if 'cross_references' in enhanced_results:
            print("Cross-reference analysis available in main results")
    
    else:
        print("⚠ Ghidra analysis not available")
        print(f"Reason: {ghidra_section.get('error', 'Unknown')}")
        print("Falling back to standard analysis results only")
    
    # Example: Ghidra-only analysis
    print_section("Ghidra-Only Analysis Example")
    print("Running Ghidra-only analysis (no standard tools)...")
    
    ghidra_only_results = analyzer.analyze_with_ghidra(
        library_path,
        merge_with_standard=False
    )
    
    print(f"Ghidra-only mode: {ghidra_only_results.get('ghidra_only', False)}")
    if 'error' in ghidra_only_results:
        print(f"Error: {ghidra_only_results['error']}")
    else:
        ghidra_data = ghidra_only_results.get('ghidra_analysis', {})
        if ghidra_data.get('available', False):
            print("✓ Ghidra-only analysis completed")
        else:
            print("⚠ Ghidra not available for analysis")
    
    # Summary
    print_section("Analysis Summary")
    summary = enhanced_results.get('summary', {})
    print(f"File: {summary.get('file_name', 'N/A')}")
    print(f"Risk Level: {summary.get('risk_level', 'unknown')}")
    print(f"Total Symbols: {summary.get('symbol_count', 0)}")
    print(f"Total Strings: {summary.get('string_count', 0)}")
    
    ghidra_summary = summary.get('ghidra_analysis', {})
    if ghidra_summary.get('enabled', False):
        print(f"Ghidra Functions: {ghidra_summary.get('function_count', 0)}")
        print(f"Ghidra External Refs: {ghidra_summary.get('external_ref_count', 0)}")
    
    print_section("Integration Notes")
    print("""
The pyghidra integration provides several advantages over standard tools:

1. **Function Analysis**: Ghidra can identify function boundaries, calling
   conventions, and parameters more accurately than tools like nm or objdump.

2. **Cross-Reference Analysis**: Ghidra tracks all references between functions,
   data, and strings, providing better insight into program flow.

3. **Advanced String Analysis**: Ghidra can identify strings embedded in data
   structures and provides better Unicode support.

4. **Memory Layout**: Detailed memory segment analysis with permissions and
   initialization status.

5. **Custom Scripts**: Ability to run custom Ghidra scripts for specialized
   analysis tasks.

To enable Ghidra integration:
1. Install Ghidra: https://ghidra-sre.org/
2. Install pyghidra: pip install pyghidra
3. Set GHIDRA_INSTALL_DIR environment variable
4. Ensure Java 17+ is available

The integration gracefully falls back to standard analysis if Ghidra is not
available, ensuring the tool remains functional in all environments.
    """)


def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python example_pyghidra_integration.py <path_to_shared_library.so>")
        print()
        print("Example:")
        print("  python example_pyghidra_integration.py /path/to/lib/arm64-v8a/libnative.so")
        print()
        print("This script demonstrates the enhanced shared library analysis")
        print("capabilities with optional Ghidra integration.")
        sys.exit(1)
    
    library_path = sys.argv[1]
    analyze_library_example(library_path)


if __name__ == '__main__':
    main()
