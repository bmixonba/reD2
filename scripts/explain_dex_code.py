#!/usr/bin/env python3
"""
Explain Decompiled DEX Code

This script analyzes decompiled DEX code from APKs and provides human-readable
explanations of what the code does, including obfuscation detection and security analysis.

Usage:
    python explain_dex_code.py --file path/to/code.java
    python explain_dex_code.py --file path/to/code.java --package com.example.app
    python explain_dex_code.py --stdin < code.java
    cat code.java | python explain_dex_code.py --stdin
"""

import sys
import argparse
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import directly without going through utils.__init__.py which has heavy dependencies
import importlib.util
spec = importlib.util.spec_from_file_location("dex_code_explainer", 
    str(Path(__file__).parent.parent / "utils" / "dex_code_explainer.py"))
dex_explainer_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dex_explainer_module)
DexCodeExplainer = dex_explainer_module.DexCodeExplainer


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(levelname)s: %(message)s'
    )


def read_code_from_file(file_path: str) -> str:
    """Read code from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Error reading file: {e}")
        sys.exit(1)


def read_code_from_stdin() -> str:
    """Read code from stdin."""
    try:
        return sys.stdin.read()
    except Exception as e:
        logging.error(f"Error reading from stdin: {e}")
        sys.exit(1)


def main():
    """Main entry point for the DEX code explainer script."""
    parser = argparse.ArgumentParser(
        description='Explain decompiled DEX code from APKs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Explain code from a file
  python explain_dex_code.py --file DrmInitData.java
  
  # Explain code with package context
  python explain_dex_code.py --file DrmInitData.java --package com.facebook.ads.internal.exoplayer2.drm
  
  # Read from stdin
  cat DrmInitData.java | python explain_dex_code.py --stdin
  
  # Save output to file
  python explain_dex_code.py --file DrmInitData.java --output explanation.txt
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '--file', '-f',
        help='Path to Java/DEX code file to analyze'
    )
    input_group.add_argument(
        '--stdin',
        action='store_true',
        help='Read code from stdin'
    )
    
    # Context options
    parser.add_argument(
        '--package', '-p',
        help='Package name for additional context (e.g., com.facebook.ads)'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        help='Output file path (default: print to stdout)'
    )
    
    parser.add_argument(
        '--no-technical-details',
        action='store_true',
        help='Omit technical details from the explanation'
    )
    
    # Other options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Read code
    if args.file:
        logging.info(f"Reading code from file: {args.file}")
        code = read_code_from_file(args.file)
    else:
        logging.info("Reading code from stdin...")
        code = read_code_from_stdin()
    
    if not code.strip():
        logging.error("No code provided or file is empty")
        sys.exit(1)
    
    logging.info(f"Analyzing {len(code)} characters of code...")
    
    # Analyze code
    explainer = DexCodeExplainer()
    explanation = explainer.explain_code(code, args.package)
    
    # Format output
    formatted_output = explainer.format_explanation(
        explanation, 
        include_technical_details=not args.no_technical_details
    )
    
    # Output results
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            logging.info(f"Explanation written to: {args.output}")
        except Exception as e:
            logging.error(f"Error writing output file: {e}")
            sys.exit(1)
    else:
        print(formatted_output)
    
    logging.info("Analysis complete!")


if __name__ == '__main__':
    main()
