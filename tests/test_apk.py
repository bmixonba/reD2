"""
Test suite for APK metadata extraction functionality.

This module contains comprehensive tests for the APKUtils class and its
file metadata extraction capabilities.
"""

import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock
import zipfile
import sys

# Add the parent directory to the path to import utils
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from utils.apk import APKUtils
except ImportError as e:
    # Skip tests if dependencies are not available
    APKUtils = None
    print(f"Warning: APKUtils not available for testing: {e}")


class TestAPKUtils(unittest.TestCase):
    """Test cases for APKUtils class."""
    
    def setUp(self):
        """Set up test fixtures."""
        if APKUtils is None:
            self.skipTest("APKUtils not available - missing dependencies")
        
        # Create a mock APK file for testing
        self.test_apk_content = self._create_mock_apk()
        
    def _create_mock_apk(self):
        """Create a mock APK file structure for testing."""
        # Create a temporary APK-like zip file
        temp_fd, temp_path = tempfile.mkstemp(suffix='.apk')
        os.close(temp_fd)
        
        with zipfile.ZipFile(temp_path, 'w') as zf:
            # Add AndroidManifest.xml
            manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.test">
    <application android:icon="@drawable/icon"/>
</manifest>'''
            zf.writestr('AndroidManifest.xml', manifest_content)
            
            # Add a file with base64 content
            base64_content = '''
{
    "config": "SGVsbG8gV29ybGQ=",
    "data": "VGhpcyBpcyBhIHRlc3QgZmlsZSB3aXRoIGJhc2U2NCBjb250ZW50"
}'''
            zf.writestr('assets/config.json', base64_content)
            
            # Add a PNG image (mock)
            png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
            zf.writestr('res/drawable/icon.png', png_header + b'\x00' * 100)
            
            # Add a DEX file (mock)
            dex_content = b'dex\n035\x00' + b'\x00' * 100
            zf.writestr('classes.dex', dex_content)
            
            # Add a text file that references other files
            ref_content = 'This file references icon.png and config.json in the code'
            zf.writestr('assets/references.txt', ref_content)
        
        return temp_path
    
    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, 'test_apk_content') and os.path.exists(self.test_apk_content):
            os.unlink(self.test_apk_content)
    
    @patch('utils.apk.APK')
    def test_apk_utils_initialization(self, mock_apk_class):
        """Test APKUtils initialization."""
        mock_apk_instance = Mock()
        mock_apk_class.return_value = mock_apk_instance
        
        apk_utils = APKUtils(self.test_apk_content)
        
        self.assertEqual(apk_utils.apk_path, self.test_apk_content)
        mock_apk_class.assert_called_once_with(self.test_apk_content)
    
    def test_apk_utils_file_not_found(self):
        """Test APKUtils with non-existent file."""
        if APKUtils is None:
            self.skipTest("APKUtils not available - missing dependencies")
        
        with patch('utils.apk.APK') as mock_apk_class:
            # Mock androguard being available
            with self.assertRaises(FileNotFoundError):
                APKUtils('/non/existent/file.apk')
    
    def test_basic_file_type_detection(self):
        """Test basic file type detection method."""
        with patch('utils.apk.APK') as mock_apk_class:
            mock_apk_instance = Mock()
            mock_apk_class.return_value = mock_apk_instance
            
            apk_utils = APKUtils(self.test_apk_content)
            
            # Test PNG detection
            png_content = b'\x89PNG\r\n\x1a\n'
            result = apk_utils._basic_file_type_detection(png_content, 'test.png')
            self.assertEqual(result['mime_type'], 'image/png')
            
            # Test JPEG detection
            jpeg_content = b'\xFF\xD8\xFF'
            result = apk_utils._basic_file_type_detection(jpeg_content, 'test.jpg')
            self.assertEqual(result['mime_type'], 'image/jpeg')
            
            # Test DEX detection
            dex_content = b'dex\n035'
            result = apk_utils._basic_file_type_detection(dex_content, 'classes.dex')
            self.assertEqual(result['mime_type'], 'application/vnd.android.dex')
    
    def test_base64_content_detection(self):
        """Test base64 content detection."""
        with patch('utils.apk.APK') as mock_apk_class:
            mock_apk_instance = Mock()
            mock_apk_class.return_value = mock_apk_instance
            
            apk_utils = APKUtils(self.test_apk_content)
            
            # Test content with base64
            content_with_base64 = b'{"key": "SGVsbG8gV29ybGQ=", "other": "data"}'
            result = apk_utils._detect_base64_content(content_with_base64)
            
            self.assertTrue(result['has_base64'])
            self.assertGreater(len(result['base64_strings']), 0)
            self.assertGreater(result['base64_percentage'], 0)
            
            # Test content without base64
            content_without_base64 = b'{"key": "normal_string", "other": "data"}'
            result = apk_utils._detect_base64_content(content_without_base64)
            
            self.assertFalse(result['has_base64'])
            self.assertEqual(len(result['base64_strings']), 0)
            self.assertEqual(result['base64_percentage'], 0.0)
    
    @patch('utils.apk.APK')
    def test_get_file_metadata(self, mock_apk_class):
        """Test comprehensive file metadata extraction."""
        # Set up mock APK
        mock_apk_instance = Mock()
        mock_apk_class.return_value = mock_apk_instance
        
        # Mock file list and content
        mock_files = ['AndroidManifest.xml', 'assets/config.json', 'res/drawable/icon.png']
        mock_apk_instance.get_files.return_value = mock_files
        
        # Mock file contents
        def mock_get_file(path):
            if path == 'AndroidManifest.xml':
                return b'<?xml version="1.0"?><manifest/>'
            elif path == 'assets/config.json':
                return b'{"data": "SGVsbG8gV29ybGQ="}'
            elif path == 'res/drawable/icon.png':
                return b'\x89PNG\r\n\x1a\n' + b'\x00' * 50
            return None
        
        mock_apk_instance.get_file.side_effect = mock_get_file
        
        apk_utils = APKUtils(self.test_apk_content)
        metadata = apk_utils.get_file_metadata()
        
        # Verify metadata structure
        self.assertIn('AndroidManifest.xml', metadata)
        self.assertIn('assets/config.json', metadata)
        self.assertIn('res/drawable/icon.png', metadata)
        
        # Check that each file has required metadata fields
        for file_path, file_metadata in metadata.items():
            self.assertIn('size', file_metadata)
            self.assertIn('type_info', file_metadata)
            self.assertIn('base64_analysis', file_metadata)
            self.assertIn('references', file_metadata)
            self.assertIn('checksum', file_metadata)
            
            # Verify type_info structure
            type_info = file_metadata['type_info']
            self.assertIn('mime_type', type_info)
            self.assertIn('magic_type', type_info)
            self.assertIn('extension', type_info)
            
            # Verify base64_analysis structure
            base64_analysis = file_metadata['base64_analysis']
            self.assertIn('has_base64', base64_analysis)
            self.assertIn('base64_strings', base64_analysis)
            self.assertIn('base64_percentage', base64_analysis)
    
    @patch('utils.apk.APK')
    def test_get_files_by_type(self, mock_apk_class):
        """Test filtering files by MIME type."""
        mock_apk_instance = Mock()
        mock_apk_class.return_value = mock_apk_instance
        
        apk_utils = APKUtils(self.test_apk_content)
        
        # Mock the metadata
        apk_utils._file_metadata_cache = {
            'file1.png': {'type_info': {'mime_type': 'image/png'}},
            'file2.jpg': {'type_info': {'mime_type': 'image/jpeg'}},
            'file3.png': {'type_info': {'mime_type': 'image/png'}},
            'file4.json': {'type_info': {'mime_type': 'application/json'}}
        }
        
        png_files = apk_utils.get_files_by_type('image/png')
        self.assertEqual(len(png_files), 2)
        self.assertIn('file1.png', png_files)
        self.assertIn('file3.png', png_files)
    
    @patch('utils.apk.APK')
    def test_get_files_with_base64(self, mock_apk_class):
        """Test filtering files with base64 content."""
        mock_apk_instance = Mock()
        mock_apk_class.return_value = mock_apk_instance
        
        apk_utils = APKUtils(self.test_apk_content)
        
        # Mock the metadata
        apk_utils._file_metadata_cache = {
            'file1.json': {'base64_analysis': {'has_base64': True}},
            'file2.txt': {'base64_analysis': {'has_base64': False}},
            'file3.config': {'base64_analysis': {'has_base64': True}},
            'file4.xml': {'base64_analysis': {'has_base64': False}}
        }
        
        base64_files = apk_utils.get_files_with_base64()
        self.assertEqual(len(base64_files), 2)
        self.assertIn('file1.json', base64_files)
        self.assertIn('file3.config', base64_files)
    
    @patch('utils.apk.APK')
    def test_get_summary_statistics(self, mock_apk_class):
        """Test summary statistics generation."""
        mock_apk_instance = Mock()
        mock_apk_class.return_value = mock_apk_instance
        
        apk_utils = APKUtils(self.test_apk_content)
        
        # Mock the metadata
        apk_utils._file_metadata_cache = {
            'file1.png': {
                'size': 1000,
                'type_info': {'mime_type': 'image/png'},
                'base64_analysis': {'has_base64': False}
            },
            'file2.json': {
                'size': 500,
                'type_info': {'mime_type': 'application/json'},
                'base64_analysis': {'has_base64': True}
            },
            'file3.png': {
                'size': 1500,
                'type_info': {'mime_type': 'image/png'},
                'base64_analysis': {'has_base64': False}
            }
        }
        
        stats = apk_utils.get_summary_statistics()
        
        self.assertEqual(stats['total_files'], 3)
        self.assertEqual(stats['total_size_bytes'], 3000)
        self.assertEqual(stats['files_with_base64'], 1)
        self.assertEqual(stats['average_file_size'], 1000.0)
        self.assertEqual(stats['files_by_type']['image/png'], 2)
        self.assertEqual(stats['files_by_type']['application/json'], 1)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)