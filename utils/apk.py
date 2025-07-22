"""
APK analysis utilities for MobileGPT.
Handles APK extraction, decompilation, and manifest parsing.
"""

import os
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from androguard.core import apk
from androguard.pentest import Pentest
from androguard.decompiler import graph, dataflow 


try:
    import androguard as ag
    import subprocess
except ImportError as e:
    logging.warning(f"Import error: {e}. Please install dependencies: pip install -r requirements.txt")


class APKAnalyzer:
    """Handle APK extraction, decompilation, and analysis."""
    
    def __init__(self, jadx_path: Optional[str] = None):
        """
        Initialize APK analyzer.
        
        Args:
            jadx_path: Path to jadx executable. If None, assumes jadx is in PATH.
        """
        self.jadx_path = jadx_path or "jadx"
        self.logger = logging.getLogger(__name__)
    
    def extract_apk_info(self, apk_path: str) -> Dict:
        """
        Extract basic APK information using apkutils.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary containing APK metadata
        """
        try:
            app = apk.APK(apk_path)
            print(app)
            
            info = {
                'package_name': app.get_package(),
                'version_name': app.get_androidversion_name(),
                'version_code': app.get_androidversion_code(),
                'app_name': app.get_app_name(),
                'min_sdk': app.get_min_sdk_version(),
                'target_sdk': app.get_target_sdk_version(),
                'permissions': app.get_permissions(),
                'activities': app.get_activities(),
                'services': app.get_services(),
                'receivers': app.get_receivers(),
                'providers': app.get_providers(),
                'file_list': app.get_files(),
            }
            
            self.logger.info(f"Extracted info for {info.get('package_name', 'Unknown')}")
            return info
            
        except Exception as e:
            self.logger.error(f"Error extracting APK info: {e}")
            return {}
    
    def decompile_apk(self, apk_path: str, output_dir: Optional[str] = None) -> str:
        """
        Decompile APK using jadx.
        
        Args:
            apk_path: Path to the APK file
            output_dir: Directory to save decompiled code. If None, uses temp directory.
            
        Returns:
            Path to decompiled output directory
        """
        print(f"decompile_apk({apk_path}, {output_dir})")
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="mobilegpt_decompiled_")
        
        try:
            # Construct jadx command
            cmd = [
                self.jadx_path,
                "-d", output_dir,  # output directory
                "--show-bad-code",  # show inconsistent code
                "--no-res",  # do not decode resources
                "--no-imports",  # disable imports processing
                apk_path
            ]
            
            self.logger.info(f"Decompiling {apk_path} to {output_dir}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                self.logger.error(f"Jadx decompilation failed: {result.stderr}")
                return ""
            
            self.logger.info(f"Decompilation completed: {output_dir}")
            return output_dir
            
        except subprocess.TimeoutExpired:
            self.logger.error("Jadx decompilation timed out")
            return ""
        except FileNotFoundError:
            self.logger.error(f"Jadx not found at {self.jadx_path}")
            return ""
        except Exception as e:
            self.logger.error(f"Error during decompilation: {e}")
            return ""
    
    def find_interesting_files(self, decompiled_dir: str) -> List[str]:
        """
        Find interesting files in decompiled APK for analysis.
        
        Args:
            decompiled_dir: Path to decompiled APK directory
            
        Returns:
            List of interesting file paths
        """
        print(f"find_interesting_files({decompiled_dir})")
        if not os.path.exists(decompiled_dir):
            return []
        
        interesting_files = []
        interesting_patterns = [
            'MainActivity.java',
            'LoginActivity.java',
            'AuthActivity.java',
            'NetworkService.java',
            'ApiService.java',
            'CryptoUtil.java',
            'SecurityUtil.java',
            'Constants.java',
            'Config.java',
        ]
        
        # Walk through decompiled directory
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    
                    # Add files matching interesting patterns
                    if any(pattern in file for pattern in interesting_patterns):
                        interesting_files.append(file_path)
                    
                    # Add files containing potential security-related keywords
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1000)  # Read first 1KB for quick check
                            security_keywords = [
                                'encrypt', 'decrypt', 'password', 'token', 'api_key',
                                'secret', 'auth', 'login', 'certificate', 'ssl', 'tls'
                            ]
                            if any(keyword.lower() in content.lower() for keyword in security_keywords):
                                if file_path not in interesting_files:
                                    interesting_files.append(file_path)
                    except:
                        continue  # Skip files that can't be read
        
        self.logger.info(f"Found {len(interesting_files)} interesting files")
        return interesting_files[:20]  # Limit to top 20 files to avoid overwhelming analysis
    
    def get_dependencies(self, decompiled_dir: str) -> List[str]:
        """
        Extract dependencies and imports from decompiled code.
        
        Args:
            decompiled_dir: Path to decompiled APK directory
            
        Returns:
            List of unique dependencies/imports
        """
        if not os.path.exists(decompiled_dir):
            return []
        
        dependencies = set()
        
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.java'):
                    try:
                        file_path = os.path.join(root, file)
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith('import '):
                                    # Extract import statement
                                    import_statement = line.replace('import ', '').rstrip(';')
                                    dependencies.add(import_statement)
                    except:
                        continue
        
        self.logger.info(f"Found {len(dependencies)} dependencies")
        return sorted(list(dependencies))


def analyze_apk(apk_path: str, output_dir: str) -> Tuple[Dict, str, List[str], List[str]]:
    """
    Convenience function to perform complete APK analysis.
    
    Args:
        apk_path: Path to APK file
        
    Returns:
        Tuple of (apk_info, decompiled_dir, interesting_files, dependencies)
    """
    analyzer = APKAnalyzer()
    
    # Extract APK metadata
    apk_info = analyzer.extract_apk_info(apk_path)
    
    # Decompile APK
    decompiled_dir = analyzer.decompile_apk(apk_path, output_dir)
    
    if decompiled_dir:
        # Find interesting files
        interesting_files = analyzer.find_interesting_files(decompiled_dir)
        
        # Get dependencies
        dependencies = analyzer.get_dependencies(decompiled_dir)
    else:
        interesting_files = []
        dependencies = []
    
    return apk_info, decompiled_dir, interesting_files, dependencies
