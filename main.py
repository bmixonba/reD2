#!/usr/bin/env python3
"""
MobileGPT: Automated APK analysis with LLM integration.

This tool processes APKs from the apks/ directory, extracts and decompiles them,
analyzes the code using LLMs, and generates insights and Frida hook suggestions.
"""

import sys
import os
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Optional

# Import local modules
from utils.apk import analyze_apk
from utils.llm import get_model_analyzer, ModelType


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def find_apk_files(apk_directory: str) -> List[str]:
    """
    Find all APK files in the specified directory.
    
    Args:
        apk_directory: Directory to search for APK files
        
    Returns:
        List of APK file paths
    """
    apk_dir = Path(apk_directory)
    if not apk_dir.exists():
        logging.warning(f"APK directory {apk_directory} does not exist")
        return []
    
    apk_files = list(apk_dir.glob("*.apk"))
    logging.info(f"Found {len(apk_files)} APK files in {apk_directory}")
    
    return [str(apk_file) for apk_file in apk_files]


def process_single_apk(apk_path: str, llm_analyzer, output_dir: Optional[str] = None) -> Dict:
    """
    Process a single APK file through the complete analysis pipeline.
    
    Args:
        apk_path: Path to the APK file
        llm_analyzer: Configured LLM analyzer instance
        output_dir: Optional output directory for results
        
    Returns:
        Dictionary containing complete analysis results
    """
    logging.info(f"Processing APK: {apk_path}")
    
    # Step 1: Extract APK information and decompile
    apk_info, decompiled_dir, interesting_files, dependencies = analyze_apk(apk_path)
    
    if not apk_info:
        logging.error(f"Failed to analyze APK: {apk_path}")
        return {'error': 'APK analysis failed'}
    
    logging.info(f"APK Info - Package: {apk_info.get('package_name')}, "
                f"Version: {apk_info.get('version_name')}")
    logging.info(f"Found {len(interesting_files)} interesting files")
    logging.info(f"Extracted {len(dependencies)} dependencies")
    
    # Step 2: Analyze interesting files with LLM
    file_analyses = []
    
    for file_path in interesting_files[:5]:  # Limit to top 5 files to avoid overwhelming
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                file_content = f.read(5000)  # Read first 5KB of each file
                
            analysis = llm_analyzer.analyze_code_file(file_path, file_content)
            file_analyses.append(analysis)
            
            logging.info(f"Analyzed file: {os.path.basename(file_path)}")
            
        except Exception as e:
            logging.error(f"Failed to analyze file {file_path}: {e}")
            continue
    
    # Step 3: Generate summary analysis
    summary_analysis = llm_analyzer.analyze_multiple_files(file_analyses)
    
    # Compile complete results
    results = {
        'apk_path': apk_path,
        'apk_info': apk_info,
        'decompiled_directory': decompiled_dir,
        'dependencies': dependencies[:20],  # Top 20 dependencies
        'interesting_files': interesting_files,
        'file_analyses': file_analyses,
        'summary_analysis': summary_analysis,
        'recommendations': summary_analysis.get('recommendations', [])
    }
    
    logging.info(f"Completed analysis for {apk_path}")
    return results


def save_results(results: Dict, output_file: str):
    """
    Save analysis results to a file.
    
    Args:
        results: Analysis results dictionary
        output_file: Path to output file
    """
    import json
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        logging.info(f"Results saved to {output_file}")
    except Exception as e:
        logging.error(f"Failed to save results: {e}")


def print_summary(results: Dict):
    """
    Print a summary of analysis results to console.
    
    Args:
        results: Analysis results dictionary
    """
    apk_info = results.get('apk_info', {})
    summary = results.get('summary_analysis', {})
    
    print(f"\n{'='*60}")
    print(f"MobileGPT Analysis Summary")
    print(f"{'='*60}")
    print(f"APK: {os.path.basename(results.get('apk_path', 'Unknown'))}")
    print(f"Package: {apk_info.get('package_name', 'Unknown')}")
    print(f"Version: {apk_info.get('version_name', 'Unknown')}")
    print(f"Target SDK: {apk_info.get('target_sdk', 'Unknown')}")
    
    print(f"\nFiles Analyzed: {summary.get('files_analyzed', 0)}")
    print(f"Model Used: {summary.get('model_used', 'Unknown')}")
    
    # Security Issues
    security_issues = summary.get('security_issues', [])
    if security_issues:
        print(f"\nSecurity Issues ({len(security_issues)}):")
        for issue in security_issues[:5]:  # Top 5
            print(f"  • {issue}")
    
    # Hook Suggestions
    hook_suggestions = summary.get('hook_suggestions', [])
    if hook_suggestions:
        print(f"\nFrida Hook Suggestions ({len(hook_suggestions)}):")
        for suggestion in hook_suggestions[:5]:  # Top 5
            print(f"  • {suggestion}")
    
    # Recommendations
    recommendations = results.get('recommendations', [])
    if recommendations:
        print(f"\nRecommendations:")
        for rec in recommendations[:5]:  # Top 5
            print(f"  • {rec}")
    
    print(f"\n{'='*60}")


def main():
    """Main entry point for MobileGPT."""
    parser = argparse.ArgumentParser(
        description="MobileGPT: Automated APK analysis with LLM integration"
    )
    
    parser.add_argument(
        '--apk-dir', 
        default='apks',
        help='Directory containing APK files (default: apks)'
    )
    
    parser.add_argument(
        '--model-type',
        choices=['codellama', 'gpt4', 'opensource'],
        default='opensource',
        help='LLM model type to use (default: opensource)'
    )
    
    parser.add_argument(
        '--model-name',
        help='Specific model name (optional)'
    )
    
    parser.add_argument(
        '--output-dir',
        help='Output directory for analysis results (optional)'
    )
    
    parser.add_argument(
        '--single-apk',
        help='Process a single APK file instead of directory'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    print("MobileGPT - Automated APK Analysis Tool")
    print("=" * 50)
    
    # Initialize LLM analyzer
    try:
        logging.info(f"Initializing {args.model_type} model...")
        llm_analyzer = get_model_analyzer(args.model_type, args.model_name)
        print(f"Model: {args.model_type}")
        if args.model_name:
            print(f"Model Name: {args.model_name}")
    except Exception as e:
        logging.error(f"Failed to initialize LLM model: {e}")
        print("Warning: LLM model initialization failed, using fallback analysis")
        llm_analyzer = get_model_analyzer('opensource')
    
    # Determine APK files to process
    if args.single_apk:
        apk_files = [args.single_apk] if os.path.exists(args.single_apk) else []
    else:
        # Create apks directory if it doesn't exist
        os.makedirs(args.apk_dir, exist_ok=True)
        apk_files = find_apk_files(args.apk_dir)
    
    if not apk_files:
        print(f"No APK files found in {args.apk_dir}")
        print("Please place APK files in the apks/ directory or specify --single-apk")
        return 1
    
    print(f"Found {len(apk_files)} APK file(s) to process")
    print("-" * 50)
    
    # Process each APK
    all_results = []
    
    for i, apk_path in enumerate(apk_files, 1):
        print(f"\nProcessing APK {i}/{len(apk_files)}: {os.path.basename(apk_path)}")
        
        try:
            results = process_single_apk(apk_path, llm_analyzer, args.output_dir)
            
            if 'error' not in results:
                all_results.append(results)
                print_summary(results)
                
                # Save individual results if output directory specified
                if args.output_dir:
                    os.makedirs(args.output_dir, exist_ok=True)
                    output_file = os.path.join(
                        args.output_dir, 
                        f"{Path(apk_path).stem}_analysis.json"
                    )
                    save_results(results, output_file)
            else:
                print(f"Failed to process {apk_path}: {results.get('error')}")
                
        except Exception as e:
            logging.error(f"Unexpected error processing {apk_path}: {e}")
            print(f"Error: {e}")
            continue
    
    # Summary
    print(f"\n{'='*60}")
    print(f"MobileGPT Analysis Complete")
    print(f"Successfully processed: {len(all_results)}/{len(apk_files)} APKs")
    
    if args.output_dir and all_results:
        print(f"Results saved to: {args.output_dir}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
