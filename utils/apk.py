"""
APK analysis utilities for MobileGPT.
Handles APK extraction, decompilation, and manifest parsing.
"""

import os
import tempfile
import logging
import re
import base64
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from androguard.core import apk
from androguard.pentest import Pentest
from androguard.decompiler import graph, dataflow 


try:
    import androguard as ag
    import subprocess
    import magic
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
    
    def extract_file_metadata(self, apk_path: str) -> Dict:
        """
        Extract comprehensive file-level metadata from APK.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary containing file metadata for each file in APK
        """
        try:
            app = apk.APK(apk_path)
            file_metadata = {}
            
            for filename in app.get_files():
                try:
                    # Get file data
                    file_data = app.get_file(filename)
                    
                    metadata = {
                        'filename': filename,
                        'size': len(file_data) if file_data else 0,
                        'mime_type': self._detect_mime_type(file_data, filename),
                        'magic_type': self._detect_magic_type(file_data),
                        'has_base64': self._detect_base64_content(file_data),
                        'file_extension': Path(filename).suffix.lower(),
                        'is_binary': self._is_binary_file(file_data),
                    }
                    
                    # Add additional analysis for specific file types
                    if filename.endswith(('.xml', '.json', '.txt', '.properties')):
                        metadata['text_content_preview'] = self._get_text_preview(file_data)
                    
                    file_metadata[filename] = metadata
                    
                except Exception as e:
                    self.logger.warning(f"Error processing file {filename}: {e}")
                    file_metadata[filename] = {'error': str(e)}
            
            self.logger.info(f"Extracted metadata for {len(file_metadata)} files")
            return file_metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting file metadata: {e}")
            return {}
    
    def _detect_mime_type(self, file_data: bytes, filename: str) -> str:
        """Detect MIME type of file data."""
        if not file_data:
            return 'application/octet-stream'
        
        try:
            # Use python-magic if available
            import magic
            mime = magic.Magic(mime=True)
            return mime.from_buffer(file_data)
        except (ImportError, Exception):
            # Fallback to extension-based detection
            extension_map = {
                '.xml': 'application/xml',
                '.json': 'application/json',
                '.txt': 'text/plain',
                '.html': 'text/html',
                '.css': 'text/css',
                '.js': 'application/javascript',
                '.png': 'image/png',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.gif': 'image/gif',
                '.pdf': 'application/pdf',
                '.zip': 'application/zip',
                '.dex': 'application/octet-stream',
                '.so': 'application/x-sharedlib',
            }
            ext = Path(filename).suffix.lower()
            return extension_map.get(ext, 'application/octet-stream')
    
    def _detect_magic_type(self, file_data: bytes) -> str:
        """Detect file type using magic number/header."""
        if not file_data:
            return 'empty'
        
        try:
            import magic
            return magic.from_buffer(file_data)
        except (ImportError, Exception):
            # Fallback magic number detection
            if file_data.startswith(b'\x89PNG'):
                return 'PNG image'
            elif file_data.startswith(b'\xFF\xD8\xFF'):
                return 'JPEG image'
            elif file_data.startswith(b'GIF8'):
                return 'GIF image'
            elif file_data.startswith(b'PK'):
                return 'ZIP archive'
            elif file_data.startswith(b'\x7FELF'):
                return 'ELF executable'
            elif file_data.startswith(b'dex\n'):
                return 'Android DEX file'
            elif file_data.startswith(b'<?xml'):
                return 'XML document'
            elif file_data.startswith(b'{'):
                return 'JSON data'
            else:
                return 'data'
    
    def _detect_base64_content(self, file_data: bytes) -> Dict:
        """
        Detect base64 encoded content in file data.
        
        Returns:
            Dictionary with base64 detection results
        """
        if not file_data:
            return {'has_base64': False, 'base64_strings': []}
        
        try:
            # Convert to text if it's not already
            if isinstance(file_data, bytes):
                try:
                    text_content = file_data.decode('utf-8', errors='ignore')
                except:
                    return {'has_base64': False, 'base64_strings': []}
            else:
                text_content = str(file_data)
            
            # Find potential base64 strings (at least 20 chars, alphanumeric + /+=)
            base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
            potential_base64 = base64_pattern.findall(text_content)
            
            verified_base64 = []
            for candidate in potential_base64:
                if self._is_valid_base64(candidate):
                    verified_base64.append({
                        'string': candidate[:50] + '...' if len(candidate) > 50 else candidate,
                        'length': len(candidate),
                        'decoded_preview': self._get_base64_preview(candidate)
                    })
            
            return {
                'has_base64': len(verified_base64) > 0,
                'base64_strings': verified_base64[:10]  # Limit to first 10 findings
            }
            
        except Exception as e:
            self.logger.warning(f"Error detecting base64 content: {e}")
            return {'has_base64': False, 'base64_strings': []}
    
    def _is_valid_base64(self, s: str) -> bool:
        """Check if string is valid base64."""
        try:
            if len(s) % 4 != 0:
                return False
            base64.b64decode(s, validate=True)
            return True
        except:
            return False
    
    def _get_base64_preview(self, base64_string: str) -> str:
        """Get a preview of decoded base64 content."""
        try:
            decoded = base64.b64decode(base64_string)
            if all(32 <= byte <= 126 for byte in decoded[:20]):  # Printable ASCII
                return decoded[:20].decode('utf-8', errors='ignore')
            else:
                return f"Binary data ({len(decoded)} bytes)"
        except:
            return "Decode failed"
    
    def _is_binary_file(self, file_data: bytes) -> bool:
        """Determine if file is binary based on content."""
        if not file_data:
            return False
        
        # Check for null bytes or high ratio of non-printable characters
        null_bytes = file_data.count(b'\x00')
        if null_bytes > 0:
            return True
        
        # Sample first 1KB for analysis
        sample = file_data[:1024]
        try:
            sample.decode('utf-8')
            return False  # Successfully decoded as UTF-8, likely text
        except UnicodeDecodeError:
            return True  # Failed to decode, likely binary
    
    def _get_text_preview(self, file_data: bytes) -> str:
        """Get a preview of text file content."""
        try:
            text = file_data.decode('utf-8', errors='ignore')
            # Return first 200 characters
            return text[:200] + '...' if len(text) > 200 else text
        except:
            return "Unable to decode text"
    
    def get_file_cross_references(self, apk_path: str, decompiled_dir: str = None) -> Dict:
        """
        Analyze cross-references between files in APK and decompiled code.
        
        Args:
            apk_path: Path to the APK file
            decompiled_dir: Path to decompiled code directory
            
        Returns:
            Dictionary mapping files to their usage references
        """
        try:
            app = apk.APK(apk_path)
            cross_refs = {}
            
            # Get all files in APK
            apk_files = app.get_files()
            
            # If we have decompiled code, search for file references
            if decompiled_dir and os.path.exists(decompiled_dir):
                cross_refs = self._find_code_references(apk_files, decompiled_dir)
            
            # Add asset/resource references from manifest and resources
            resource_refs = self._find_resource_references(app, apk_files)
            
            # Merge results
            for filename, refs in resource_refs.items():
                if filename in cross_refs:
                    cross_refs[filename].extend(refs)
                else:
                    cross_refs[filename] = refs
            
            self.logger.info(f"Found cross-references for {len(cross_refs)} files")
            return cross_refs
            
        except Exception as e:
            self.logger.error(f"Error finding cross-references: {e}")
            return {}
    
    def _find_code_references(self, apk_files: List[str], decompiled_dir: str) -> Dict:
        """Find references to APK files in decompiled code."""
        references = {}
        
        # Common asset/resource directories to look for
        interesting_paths = [
            'assets/', 'res/', 'resources/', 'lib/', 'META-INF/',
            'classes.dex', 'AndroidManifest.xml'
        ]
        
        for apk_file in apk_files:
            # Only check files in interesting directories
            if any(apk_file.startswith(path) for path in interesting_paths):
                file_refs = []
                filename_only = os.path.basename(apk_file)
                
                # Search for references in decompiled Java files
                for root, dirs, files in os.walk(decompiled_dir):
                    for java_file in files:
                        if java_file.endswith('.java'):
                            java_path = os.path.join(root, java_file)
                            try:
                                with open(java_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                    
                                # Look for filename or path references
                                if (filename_only in content or 
                                    apk_file.replace('/', '') in content or
                                    apk_file in content):
                                    file_refs.append({
                                        'referenced_in': java_path,
                                        'reference_type': 'code'
                                    })
                                    
                            except Exception:
                                continue
                
                if file_refs:
                    references[apk_file] = file_refs
        
        return references
    
    def _find_resource_references(self, app: apk.APK, apk_files: List[str]) -> Dict:
        """Find resource references in manifest and resource files."""
        references = {}
        
        try:
            # Check manifest for file references
            manifest = app.get_android_manifest_xml()
            if manifest:
                manifest_str = str(manifest)
                for apk_file in apk_files:
                    filename = os.path.basename(apk_file)
                    if filename in manifest_str or apk_file in manifest_str:
                        if apk_file not in references:
                            references[apk_file] = []
                        references[apk_file].append({
                            'referenced_in': 'AndroidManifest.xml',
                            'reference_type': 'manifest'
                        })
            
            # TODO: Add more sophisticated resource reference analysis
            # This could include XML resource files, string resources, etc.
            
        except Exception as e:
            self.logger.warning(f"Error analyzing resource references: {e}")
        
        return references
    
    def analyze_file_types(self, apk_path: str) -> Dict:
        """
        Perform comprehensive file type analysis of APK contents.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary with file type analysis results
        """
        try:
            file_metadata = self.extract_file_metadata(apk_path)
            
            # Categorize files by type
            type_categories = {
                'code': [],
                'resources': [],
                'assets': [],
                'libraries': [],
                'manifests': [],
                'certificates': [],
                'other': []
            }
            
            # Size statistics
            total_size = 0
            size_by_type = {}
            
            for filename, metadata in file_metadata.items():
                if 'error' in metadata:
                    continue
                    
                file_size = metadata.get('size', 0)
                total_size += file_size
                
                # Categorize file
                category = self._categorize_file(filename, metadata)
                type_categories[category].append({
                    'filename': filename,
                    'size': file_size,
                    'mime_type': metadata.get('mime_type'),
                    'has_base64': metadata.get('has_base64', {}).get('has_base64', False)
                })
                
                # Track size by category
                if category not in size_by_type:
                    size_by_type[category] = 0
                size_by_type[category] += file_size
            
            # Generate summary statistics
            file_count_by_type = {cat: len(files) for cat, files in type_categories.items()}
            
            return {
                'total_files': len(file_metadata),
                'total_size': total_size,
                'file_count_by_type': file_count_by_type,
                'size_by_type': size_by_type,
                'files_by_category': type_categories,
                'largest_files': self._get_largest_files(file_metadata, 10),
                'suspicious_files': self._identify_suspicious_files(file_metadata)
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing file types: {e}")
            return {}
    
    def _categorize_file(self, filename: str, metadata: Dict) -> str:
        """Categorize a file based on its path and metadata."""
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.dex') or filename_lower.startswith('classes'):
            return 'code'
        elif filename_lower.startswith('res/'):
            return 'resources'
        elif filename_lower.startswith('assets/'):
            return 'assets'
        elif filename_lower.startswith('lib/') or filename_lower.endswith('.so'):
            return 'libraries'
        elif 'manifest' in filename_lower or filename_lower.endswith('.xml'):
            return 'manifests'
        elif filename_lower.startswith('meta-inf/'):
            return 'certificates'
        else:
            return 'other'
    
    def _get_largest_files(self, file_metadata: Dict, count: int) -> List[Dict]:
        """Get the largest files by size."""
        files_with_size = []
        
        for filename, metadata in file_metadata.items():
            if 'error' not in metadata and 'size' in metadata:
                files_with_size.append({
                    'filename': filename,
                    'size': metadata['size'],
                    'mime_type': metadata.get('mime_type', 'unknown')
                })
        
        # Sort by size descending
        files_with_size.sort(key=lambda x: x['size'], reverse=True)
        return files_with_size[:count]
    
    def _identify_suspicious_files(self, file_metadata: Dict) -> List[Dict]:
        """Identify potentially suspicious files."""
        suspicious = []
        
        for filename, metadata in file_metadata.items():
            if 'error' in metadata:
                continue
                
            suspicion_reasons = []
            
            # Check for suspicious characteristics
            if metadata.get('has_base64', {}).get('has_base64', False):
                suspicion_reasons.append('Contains base64 encoded data')
            
            if filename.lower().startswith('assets/') and metadata.get('size', 0) > 1024*1024:  # > 1MB
                suspicion_reasons.append('Large asset file')
            
            if filename.lower().endswith('.so') and 'lib/' not in filename.lower():
                suspicion_reasons.append('Native library in unexpected location')
            
            if any(keyword in filename.lower() for keyword in ['hidden', 'temp', 'cache', 'tmp']):
                suspicion_reasons.append('Suspicious filename pattern')
            
            if suspicion_reasons:
                suspicious.append({
                    'filename': filename,
                    'reasons': suspicion_reasons,
                    'size': metadata.get('size', 0),
                    'mime_type': metadata.get('mime_type', 'unknown')
                })
        
        return suspicious


def analyze_apk(apk_path: str, output_dir: str) -> Tuple[Dict, str, List[str], List[str]]:
    """
    Convenience function to perform complete APK analysis.
    
    Args:
        apk_path: Path to APK file
        output_dir: Output directory for decompiled code
        
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


def analyze_apk_comprehensive(apk_path: str, output_dir: str = None) -> Dict:
    """
    Perform comprehensive APK analysis including file metadata extraction.
    
    Args:
        apk_path: Path to APK file
        output_dir: Optional output directory for decompiled code
        
    Returns:
        Dictionary containing complete analysis results including file metadata
    """
    analyzer = APKAnalyzer()
    
    # Basic APK analysis
    apk_info, decompiled_dir, interesting_files, dependencies = analyze_apk(apk_path, output_dir)
    
    # Enhanced file-level analysis
    file_metadata = analyzer.extract_file_metadata(apk_path)
    file_type_analysis = analyzer.analyze_file_types(apk_path)
    cross_references = analyzer.get_file_cross_references(apk_path, decompiled_dir)
    
    return {
        'apk_info': apk_info,
        'decompiled_dir': decompiled_dir,
        'interesting_files': interesting_files,
        'dependencies': dependencies,
        'file_metadata': file_metadata,
        'file_type_analysis': file_type_analysis,
        'cross_references': cross_references,
        'analysis_summary': {
            'total_files': len(file_metadata),
            'files_with_base64': len([f for f in file_metadata.values() 
                                    if f.get('has_base64', {}).get('has_base64', False)]),
            'suspicious_files': len(file_type_analysis.get('suspicious_files', [])),
            'largest_files': file_type_analysis.get('largest_files', [])[:5]
        }
    }
