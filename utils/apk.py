"""
APK analysis utilities for extracting file-level metadata and cross-references.

This module provides utilities for analyzing APK files and extracting comprehensive
metadata about all files contained within the APK, including file type detection,
base64 content analysis, size information, and cross-reference analysis.
"""

import os
import re
import base64
import binascii
from typing import Dict, List, Any, Optional, Set
from pathlib import Path

try:
    import magic
except ImportError:
    magic = None

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
except ImportError:
    APK = None
    DEX = None


class APKUtils:
    """
    Utility class for APK file analysis and metadata extraction.
    
    This class provides methods to extract comprehensive metadata from APK files,
    including file type detection, content analysis, and cross-reference mapping.
    """
    
    def __init__(self, apk_path: str):
        """
        Initialize APKUtils with an APK file.
        
        Args:
            apk_path (str): Path to the APK file to analyze
            
        Raises:
            FileNotFoundError: If the APK file doesn't exist
            ImportError: If required dependencies are not installed
            ValueError: If the APK file is invalid
        """
        if not APK:
            raise ImportError("androguard is required. Install with: pip install androguard")
        
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        self.apk_path = apk_path
        try:
            self.apk = APK(apk_path)
        except Exception as e:
            raise ValueError(f"Invalid APK file: {e}")
        
        self._file_metadata_cache = None
        
    def _detect_file_type(self, file_content: bytes, filename: str) -> Dict[str, str]:
        """
        Detect file type using multiple methods.
        
        Args:
            file_content (bytes): File content bytes
            filename (str): Original filename
            
        Returns:
            Dict[str, str]: Dictionary containing file type information
        """
        result = {
            'extension': os.path.splitext(filename)[1].lower(),
            'mime_type': 'application/octet-stream',
            'magic_type': 'unknown'
        }
        
        # Use python-magic if available
        if magic:
            try:
                result['mime_type'] = magic.from_buffer(file_content, mime=True)
                result['magic_type'] = magic.from_buffer(file_content)
            except Exception:
                pass
        
        # Fallback to basic detection based on file content
        if not magic or result['mime_type'] == 'application/octet-stream':
            result.update(self._basic_file_type_detection(file_content, filename))
        
        return result
    
    def _basic_file_type_detection(self, content: bytes, filename: str) -> Dict[str, str]:
        """
        Basic file type detection based on magic bytes and filename.
        
        Args:
            content (bytes): File content
            filename (str): Filename
            
        Returns:
            Dict[str, str]: Basic type information
        """
        result = {}
        
        # Check common magic bytes
        if content.startswith(b'\x89PNG'):
            result['mime_type'] = 'image/png'
            result['magic_type'] = 'PNG image'
        elif content.startswith(b'\xFF\xD8\xFF'):
            result['mime_type'] = 'image/jpeg'
            result['magic_type'] = 'JPEG image'
        elif content.startswith(b'GIF8'):
            result['mime_type'] = 'image/gif'
            result['magic_type'] = 'GIF image'
        elif content.startswith(b'PK\x03\x04'):
            result['mime_type'] = 'application/zip'
            result['magic_type'] = 'ZIP archive'
        elif content.startswith(b'dex\n'):
            result['mime_type'] = 'application/vnd.android.dex'
            result['magic_type'] = 'Android DEX file'
        elif filename.endswith('.xml') and b'<?xml' in content[:100]:
            result['mime_type'] = 'application/xml'
            result['magic_type'] = 'XML document'
        elif filename.endswith('.json'):
            result['mime_type'] = 'application/json'
            result['magic_type'] = 'JSON document'
        
        return result
    
    def _detect_base64_content(self, content: bytes) -> Dict[str, Any]:
        """
        Detect if content contains base64 encoded data.
        
        Args:
            content (bytes): File content to analyze
            
        Returns:
            Dict[str, Any]: Base64 detection information
        """
        result = {
            'has_base64': False,
            'base64_strings': [],
            'base64_percentage': 0.0
        }
        
        try:
            # Convert to string for regex analysis
            text_content = content.decode('utf-8', errors='ignore')
            
            # Look for base64 patterns (at least 16 characters, proper base64 format)
            # This pattern matches valid base64 strings that are properly padded
            base64_pattern = r'[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/=])'
            matches = re.findall(base64_pattern, text_content)
            
            valid_base64 = []
            for match in matches:
                try:
                    # Check if it looks like valid base64
                    # Must be divisible by 4 or end with padding
                    if len(match) >= 16 and (len(match) % 4 == 0 or '=' in match):
                        # Try to decode to validate it's actually base64
                        decoded = base64.b64decode(match, validate=True)
                        if len(decoded) > 0:
                            valid_base64.append({
                                'string': match,
                                'decoded_size': len(decoded),
                                'position': text_content.find(match)
                            })
                except (binascii.Error, ValueError):
                    continue
            
            if valid_base64:
                result['has_base64'] = True
                result['base64_strings'] = valid_base64
                
                # Calculate percentage of content that is base64
                total_base64_chars = sum(len(b64['string']) for b64 in valid_base64)
                result['base64_percentage'] = (total_base64_chars / len(text_content)) * 100 if text_content else 0
                
        except Exception:
            pass
        
        return result
    
    def _find_file_references(self, filename: str) -> Dict[str, List[str]]:
        """
        Find references to the file in code and other assets.
        
        Args:
            filename (str): File to search references for
            
        Returns:
            Dict[str, List[str]]: References found in different contexts
        """
        references = {
            'code_references': [],
            'asset_references': [],
            'manifest_references': []
        }
        
        # Search in all files for references to this filename
        search_terms = [
            filename,
            os.path.basename(filename),
            os.path.splitext(os.path.basename(filename))[0]  # filename without extension
        ]
        
        for file_path in self.apk.get_files():
            try:
                file_content = self.apk.get_file(file_path)
                if not file_content:
                    continue
                
                # Try to decode as text
                try:
                    text_content = file_content.decode('utf-8', errors='ignore')
                except:
                    continue
                
                # Check for references
                for term in search_terms:
                    if term in text_content:
                        if file_path.endswith('.dex') or 'classes' in file_path:
                            if file_path not in references['code_references']:
                                references['code_references'].append(file_path)
                        elif file_path == 'AndroidManifest.xml':
                            if file_path not in references['manifest_references']:
                                references['manifest_references'].append(file_path)
                        else:
                            if file_path not in references['asset_references']:
                                references['asset_references'].append(file_path)
                                
            except Exception:
                continue
        
        return references
    
    def get_file_metadata(self) -> Dict[str, Dict[str, Any]]:
        """
        Extract comprehensive metadata for all files in the APK.
        
        This method analyzes all files within the APK and extracts detailed metadata
        including file type detection, base64 content analysis, size information,
        and cross-reference mapping.
        
        Returns:
            Dict[str, Dict[str, Any]]: Dictionary mapping file paths to their metadata.
            Each file's metadata contains:
            - size: File size in bytes
            - type_info: File type detection results (MIME type, magic type, extension)
            - base64_analysis: Base64 content detection results
            - references: Cross-references from other files
            - checksum: Basic checksum of the file content
            
        Example:
            >>> apk_utils = APKUtils('app.apk')
            >>> metadata = apk_utils.get_file_metadata()
            >>> print(metadata['assets/config.json']['type_info']['mime_type'])
            'application/json'
        """
        if self._file_metadata_cache:
            return self._file_metadata_cache
        
        metadata = {}
        
        # Get all files in the APK
        all_files = self.apk.get_files()
        
        for file_path in all_files:
            try:
                # Get file content
                file_content = self.apk.get_file(file_path)
                if file_content is None:
                    continue
                
                # Calculate basic metrics
                file_size = len(file_content)
                
                # Generate a simple checksum
                import hashlib
                checksum = hashlib.md5(file_content).hexdigest()
                
                # Detect file type
                type_info = self._detect_file_type(file_content, file_path)
                
                # Analyze base64 content
                base64_analysis = self._detect_base64_content(file_content)
                
                # Find cross-references (limit this for performance)
                references = self._find_file_references(file_path)
                
                # Compile metadata
                metadata[file_path] = {
                    'size': file_size,
                    'type_info': type_info,
                    'base64_analysis': base64_analysis,
                    'references': references,
                    'checksum': checksum
                }
                
            except Exception as e:
                # Log error but continue processing other files
                metadata[file_path] = {
                    'error': str(e),
                    'size': 0,
                    'type_info': {'mime_type': 'unknown', 'magic_type': 'error'},
                    'base64_analysis': {'has_base64': False},
                    'references': {'code_references': [], 'asset_references': [], 'manifest_references': []},
                    'checksum': 'unknown'
                }
        
        # Cache the results
        self._file_metadata_cache = metadata
        return metadata
    
    def get_files_by_type(self, mime_type: str) -> List[str]:
        """
        Get all files of a specific MIME type.
        
        Args:
            mime_type (str): MIME type to filter by
            
        Returns:
            List[str]: List of file paths matching the MIME type
        """
        metadata = self.get_file_metadata()
        return [
            file_path for file_path, data in metadata.items()
            if data.get('type_info', {}).get('mime_type') == mime_type
        ]
    
    def get_files_with_base64(self) -> List[str]:
        """
        Get all files containing base64 encoded content.
        
        Returns:
            List[str]: List of file paths containing base64 content
        """
        metadata = self.get_file_metadata()
        return [
            file_path for file_path, data in metadata.items()
            if data.get('base64_analysis', {}).get('has_base64', False)
        ]
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """
        Get summary statistics about the APK file contents.
        
        Returns:
            Dict[str, Any]: Summary statistics including file counts, total size, etc.
        """
        metadata = self.get_file_metadata()
        
        total_files = len(metadata)
        total_size = sum(data.get('size', 0) for data in metadata.values())
        
        # Count files by type
        type_counts = {}
        base64_count = 0
        
        for data in metadata.values():
            mime_type = data.get('type_info', {}).get('mime_type', 'unknown')
            type_counts[mime_type] = type_counts.get(mime_type, 0) + 1
            
            if data.get('base64_analysis', {}).get('has_base64', False):
                base64_count += 1
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'files_by_type': type_counts,
            'files_with_base64': base64_count,
            'average_file_size': total_size / total_files if total_files > 0 else 0
        }