#!/usr/bin/env python3
"""
Test cases for SharedLibraryAnalyzer functionality in MobileGPT.

Tests the comprehensive shared library analysis capabilities.
"""

import unittest
import tempfile
import os
import struct
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to path for imports
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from utils.shared_library_analyzer import SharedLibraryAnalyzer
    ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import SharedLibraryAnalyzer: {e}")
    ANALYZER_AVAILABLE = False


class TestSharedLibraryAnalyzer(unittest.TestCase):
    """Test cases for SharedLibraryAnalyzer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        if ANALYZER_AVAILABLE:
            self.analyzer = SharedLibraryAnalyzer()
        else:
            self.skipTest("SharedLibraryAnalyzer not available")
    
    def test_initialization(self):
        """Test analyzer initialization."""
        self.assertIsInstance(self.analyzer, SharedLibraryAnalyzer)
        self.assertIsNotNone(self.analyzer.android_abis)
        self.assertIsNotNone(self.analyzer.suspicious_patterns)
        self.assertIsNotNone(self.analyzer.known_packers)
    
    def test_map_machine_to_abi(self):
        """Test machine type to ABI mapping."""
        test_cases = [
            ('ARM', 'armeabi-v7a'),
            ('AArch64', 'arm64-v8a'),
            ('x86-64', 'x86_64'),
            ('Intel 80386', 'x86'),
            ('unknown_arch', 'unknown')
        ]
        
        for machine, expected_abi in test_cases:
            with self.subTest(machine=machine):
                result = self.analyzer._map_machine_to_abi(machine)
                self.assertEqual(result, expected_abi)
    
    def test_detect_abi_from_path(self):
        """Test ABI detection from file path."""
        test_cases = [
            ('/lib/arm64-v8a/libtest.so', 'arm64-v8a'),
            ('/lib/armeabi-v7a/libexample.so', 'armeabi-v7a'),
            ('/lib/x86/libfoo.so', 'x86'),
            ('/lib/x86_64/libbar.so', 'x86_64'),
            ('/some/other/path/lib.so', None)
        ]
        
        for path, expected_abi in test_cases:
            with self.subTest(path=path):
                result = self.analyzer._detect_abi_from_path(path)
                self.assertEqual(result, expected_abi)
    
    def test_human_readable_size(self):
        """Test human readable size formatting."""
        test_cases = [
            (512, '512.0 B'),
            (1024, '1.0 KB'),
            (1536, '1.5 KB'),
            (1048576, '1.0 MB'),
            (1073741824, '1.0 GB')
        ]
        
        for size, expected in test_cases:
            with self.subTest(size=size):
                result = self.analyzer._human_readable_size(size)
                self.assertEqual(result, expected)
    
    def test_categorize_suspicious_string(self):
        """Test suspicious string categorization."""
        test_cases = [
            (r'https?://.*', 'network'),
            (r'AES|encrypt', 'crypto'),
            (r'root|sudo', 'system'),
            (r'debug|anti', 'anti-analysis'),
            (r'payload|exploit', 'malware'),
            (r'other_pattern', 'other')
        ]
        
        for pattern, expected_category in test_cases:
            with self.subTest(pattern=pattern):
                result = self.analyzer._categorize_suspicious_string(pattern)
                self.assertEqual(result, expected_category)
    
    def test_find_urls(self):
        """Test URL extraction from strings."""
        test_strings = [
            'Visit https://example.com for more info',
            'Check http://test.org/page',
            'No URLs here',
            'Multiple: https://site1.com and http://site2.net'
        ]
        
        result = self.analyzer._find_urls(test_strings)
        expected_urls = ['https://example.com', 'http://test.org/page', 'https://site1.com', 'http://site2.net']
        
        for url in expected_urls:
            self.assertIn(url, result)
    
    def test_find_crypto_strings(self):
        """Test cryptography string detection."""
        test_strings = [
            'AES encryption enabled',
            'RSA key pair generation',
            'MD5 hash calculation',
            'No crypto here',
            'encrypt the data',
            'decrypt function'
        ]
        
        result = self.analyzer._find_crypto_strings(test_strings)
        
        # Should find crypto-related strings
        crypto_found = [s for s in result if any(crypto in s.lower() for crypto in ['aes', 'rsa', 'md5', 'encrypt', 'decrypt'])]
        self.assertGreater(len(crypto_found), 0)
    
    def test_find_file_paths(self):
        """Test file path extraction."""
        test_strings = [
            '/system/bin/sh',
            '/data/data/com.example',
            'C:\\Windows\\System32',
            'Regular text without paths',
            '/sdcard/download/file.txt'
        ]
        
        result = self.analyzer._find_file_paths(test_strings)
        
        expected_paths = ['/system/bin/sh', '/data/data/com.example', '/sdcard/download/file.txt']
        for path in expected_paths:
            self.assertIn(path, result)
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        # Create a temporary file with known content
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            # Write repetitive data (low entropy)
            tmp_file.write(b'A' * 1000)
            tmp_path = tmp_file.name
        
        try:
            entropy = self.analyzer._calculate_entropy(tmp_path)
            # Repetitive data should have low entropy
            self.assertLess(entropy, 2.0)
        finally:
            os.unlink(tmp_path)
        
        # Test with more random data
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            # Write more varied data - use a repeating pattern that still has some entropy
            import random
            random.seed(42)  # Deterministic for testing
            # Create data with some randomness but not completely random
            data = bytearray()
            for i in range(1000):
                if i % 10 == 0:
                    data.append(random.randint(0, 255))
                else:
                    data.append(ord('A') + (i % 26))
            tmp_file.write(data)
            tmp_path = tmp_file.name
        
        try:
            entropy = self.analyzer._calculate_entropy(tmp_path)
            # More varied data should have higher entropy than repetitive data
            self.assertGreater(entropy, 1.0)
        finally:
            os.unlink(tmp_path)
    
    def test_analyze_sections(self):
        """Test suspicious section analysis."""
        mock_readelf_output = """
        There are 30 section headers, starting at offset 0x123456:
        
        Section Headers:
          [Nr] Name              Type             Address           Offset
          [ 0]                   NULL             0000000000000000  00000000
          [ 1] .text             PROGBITS         0000000000400000  00001000
          [ 2] .data             PROGBITS         0000000000600000  00002000
          [ 3] .upx              PROGBITS         0000000000700000  00003000
          [ 4] .packed           PROGBITS         0000000000800000  00004000
        """
        
        result = self.analyzer._analyze_sections(mock_readelf_output)
        
        # Should detect suspicious sections
        suspicious_found = any('.upx' in section or '.packed' in section for section in result)
        self.assertTrue(suspicious_found)
    
    def test_parse_dynamic_section(self):
        """Test dynamic section parsing."""
        mock_readelf_output = """
        Dynamic section at offset 0x123 contains 10 entries:
          Tag        Type                         Name/Value
         0x00000001 (NEEDED)                     Shared library: [libc.so.6]
         0x00000001 (NEEDED)                     Shared library: [libssl.so.1.1]
         0x0000000e (SONAME)                     Library soname: [libexample.so.1]
         0x0000000f (RPATH)                      Library rpath: [/usr/lib]
         0x0000001d (RUNPATH)                    Library runpath: [/usr/local/lib]
        """
        
        result = self.analyzer._parse_dynamic_section(mock_readelf_output)
        
        self.assertIn('libc.so.6', result['needed_libraries'])
        self.assertIn('libssl.so.1.1', result['needed_libraries'])
        self.assertEqual(result['soname'], 'libexample.so.1')
        self.assertIn('/usr/lib', result['rpath'])
        self.assertIn('/usr/local/lib', result['runpath'])
    
    def test_parse_nm_output(self):
        """Test nm output parsing for symbols."""
        mock_nm_output = """
        0000000000001000 T main
        0000000000002000 T function1
                         U printf
                         U malloc
        0000000000003000 t local_function
        0000000000004000 W weak_symbol
        """
        
        result = self.analyzer._parse_nm_output(mock_nm_output)
        
        # Check that symbols are categorized correctly
        exported_names = [s['name'] for s in result['exported']]
        undefined_names = [s['name'] for s in result['undefined']]
        
        self.assertIn('main', exported_names)
        self.assertIn('function1', exported_names)
        self.assertIn('printf', undefined_names)
        self.assertIn('malloc', undefined_names)
        self.assertGreater(result['count'], 0)
    
    def test_parse_elf_header(self):
        """Test ELF header parsing."""
        mock_header_output = """
        ELF Header:
          Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
          Class:                             ELF64
          Data:                              2's complement, little endian
          Version:                           1 (current)
          OS/ABI:                            UNIX - System V
          ABI Version:                       0
          Type:                              DYN (Shared object file)
          Machine:                           AArch64
          Version:                           0x1
          Entry point address:               0x1000
        """
        
        result = self.analyzer._parse_elf_header(mock_header_output)
        
        self.assertEqual(result.get('class'), 'ELF64')
        self.assertEqual(result.get('machine'), 'AArch64')
        self.assertEqual(result.get('type'), 'DYN (Shared object file)')
    
    def test_convert_to_jni_name(self):
        """Test JNI name conversion."""
        test_method = {
            'class_name': 'com.example.MyClass',
            'method_name': 'nativeMethod'
        }
        
        result = self.analyzer._convert_to_jni_name(test_method)
        expected = 'Java_com_example_MyClass_nativeMethod'
        
        self.assertEqual(result, expected)
    
    @patch('subprocess.run')
    def test_detect_architecture_with_readelf(self, mock_run):
        """Test architecture detection using readelf."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
        ELF Header:
          Machine:                           AArch64
          Class:                             ELF64
          Data:                              2's complement, little endian
          Type:                              DYN (Shared object file)
        """
        mock_run.return_value = mock_result
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._detect_architecture(tmp_file.name)
        
        self.assertEqual(result.get('machine'), 'AArch64')
        self.assertEqual(result.get('detected_abi'), 'arm64-v8a')
        self.assertEqual(result.get('class'), 'ELF64')
    
    @patch('subprocess.run')
    def test_extract_symbols_with_nm(self, mock_run):
        """Test symbol extraction using nm."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
        0000000000001000 T main
        0000000000002000 T exported_function
                         U imported_function
        """
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._extract_symbols(tmp_file.name)
        
        self.assertGreater(result['count'], 0)
        self.assertTrue(any(s['name'] == 'main' for s in result['exported']))
    
    @patch('subprocess.run')
    def test_extract_strings(self, mock_run):
        """Test string extraction."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = """
        /system/bin/sh
        https://example.com
        AES encryption
        normal string
        """
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._extract_strings(tmp_file.name)
        
        self.assertGreater(result['count'], 0)
        self.assertIn('/system/bin/sh', result['all_strings'])
        self.assertGreater(len(result['suspicious_strings']), 0)
    
    def test_analyze_nonexistent_file(self):
        """Test behavior with non-existent file."""
        result = self.analyzer.analyze_shared_library('/nonexistent/path/file.so')
        self.assertIn('error', result)
    
    def test_file_info_extraction(self):
        """Test basic file info extraction."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as tmp_file:
            tmp_file.write(b'test data')
            tmp_path = tmp_file.name
        
        try:
            file_info = self.analyzer._get_file_info(tmp_path)
            
            self.assertEqual(file_info['filename'], os.path.basename(tmp_path))
            self.assertEqual(file_info['full_path'], tmp_path)
            self.assertEqual(file_info['size'], 9)  # len(b'test data')
            self.assertIn('B', file_info['size_human'])
        finally:
            os.unlink(tmp_path)


class TestSharedLibraryAnalyzerIntegration(unittest.TestCase):
    """Integration tests for SharedLibraryAnalyzer."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        if not ANALYZER_AVAILABLE:
            self.skipTest("SharedLibraryAnalyzer not available")
        
        self.analyzer = SharedLibraryAnalyzer()
        
        # Create a mock ELF file for testing
        self.test_elf = self._create_mock_elf_file()
    
    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, 'test_elf') and os.path.exists(self.test_elf):
            os.unlink(self.test_elf)
    
    def _create_mock_elf_file(self):
        """Create a minimal ELF file for testing."""
        with tempfile.NamedTemporaryFile(suffix='.so', delete=False) as tmp_file:
            # Write ELF magic number and minimal header
            elf_header = bytearray(64)  # ELF64 header size
            
            # ELF magic
            elf_header[0:4] = b'\x7fELF'
            # Class: ELF64
            elf_header[4] = 2
            # Data: little endian
            elf_header[5] = 1
            # Version: current
            elf_header[6] = 1
            # OS/ABI: UNIX System V
            elf_header[7] = 0
            
            # e_type: shared object (ET_DYN = 3)
            elf_header[16:18] = struct.pack('<H', 3)
            # e_machine: AArch64 (EM_AARCH64 = 183)
            elf_header[18:20] = struct.pack('<H', 183)
            
            tmp_file.write(elf_header)
            return tmp_file.name
    
    def test_detect_architecture_fallback(self):
        """Test fallback architecture detection."""
        result = self.analyzer._detect_architecture_fallback(self.test_elf)
        
        self.assertEqual(result.get('class'), 'ELF64')
        self.assertEqual(result.get('endianness'), 'little')
        self.assertEqual(result.get('machine'), 'AArch64')
        self.assertEqual(result.get('detected_abi'), 'arm64-v8a')
    
    def test_detect_file_type_fallback(self):
        """Test fallback file type detection."""
        result = self.analyzer._detect_file_type_fallback(self.test_elf)
        
        self.assertIn('mime_type', result)
        self.assertIn('description', result)
    
    def test_full_analysis_structure(self):
        """Test that full analysis returns expected structure."""
        # This test uses the mock ELF file which may not work with all tools
        # but should at least test the error handling and structure
        result = self.analyzer.analyze_shared_library(self.test_elf)
        
        # Check that the main structure is present
        expected_keys = [
            'file_info', 'architecture', 'file_type', 'hashes',
            'symbols', 'strings', 'dependencies', 'security_analysis',
            'packer_detection', 'suspicious_indicators', 'elf_analysis',
            'summary'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # Check file_info structure
        self.assertIn('filename', result['file_info'])
        self.assertIn('size', result['file_info'])
        
        # Check that summary is generated
        self.assertIn('file_name', result['summary'])
        self.assertIn('risk_level', result['summary'])


class TestSharedLibraryAnalyzerMocked(unittest.TestCase):
    """Tests using mocked external dependencies."""
    
    def setUp(self):
        """Set up mocked test fixtures."""
        if not ANALYZER_AVAILABLE:
            self.skipTest("SharedLibraryAnalyzer not available")
        
        self.analyzer = SharedLibraryAnalyzer()
    
    @patch('utils.shared_library_analyzer.subprocess.run')
    def test_mocked_readelf_failure(self, mock_run):
        """Test handling of readelf command failure."""
        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stderr = "readelf: Error reading file"
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._detect_architecture(tmp_file.name)
        
        # Should fall back to manual detection
        self.assertIsInstance(result, dict)
    
    @patch('utils.shared_library_analyzer.subprocess.run')
    def test_mocked_nm_success(self, mock_run):
        """Test successful nm execution."""
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "0000000000001000 T test_function\n                 U printf"
        mock_run.return_value = mock_result
        
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._extract_symbols(tmp_file.name)
        
        self.assertGreater(result['count'], 0)
        self.assertTrue(any(s['name'] == 'test_function' for s in result['exported']))
        self.assertTrue(any(s['name'] == 'printf' for s in result['undefined']))
    
    @patch('utils.shared_library_analyzer.subprocess.run')
    def test_command_timeout_handling(self, mock_run):
        """Test handling of command timeouts."""
        from subprocess import TimeoutExpired
        mock_run.side_effect = TimeoutExpired('readelf', 30)
        
        with tempfile.NamedTemporaryFile(suffix='.so') as tmp_file:
            result = self.analyzer._detect_architecture(tmp_file.name)
        
        # Should handle timeout gracefully
        self.assertIsInstance(result, dict)


if __name__ == '__main__':
    unittest.main()