"""
Advanced Shared Library Analyzer for MobileGPT.
Analyzes shared libraries (.so files) found in APKs with comprehensive feature detection.
"""

import os
import re
import hashlib
import subprocess
import logging
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False
    logging.warning("ssdeep not available - fuzzy hashing will be disabled")

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False
    logging.warning("python-magic not available - using fallback file type detection")

try:
    from .pyghidra_integration import PyGhidraAnalyzer, check_pyghidra_availability
    PYGHIDRA_INTEGRATION_AVAILABLE = True
except ImportError:
    PYGHIDRA_INTEGRATION_AVAILABLE = False
    logging.info("pyghidra integration not available - advanced Ghidra analysis will be disabled")


class SharedLibraryAnalyzer:
    """
    Advanced analyzer for shared libraries (.so files) in Android APKs.
    
    Provides comprehensive analysis including:
    - Architecture/ABI detection
    - Symbol extraction and analysis
    - String extraction and pattern matching
    - Dependency mapping
    - Hash calculation (including fuzzy hashing)
    - Packer/obfuscator detection
    - Cross-referencing with Java native methods
    """
    
    def __init__(self):
        """Initialize the SharedLibraryAnalyzer."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize PyGhidra analyzer if available
        self.ghidra_analyzer = None
        if PYGHIDRA_INTEGRATION_AVAILABLE:
            try:
                self.ghidra_analyzer = PyGhidraAnalyzer()
                if self.ghidra_analyzer.is_available():
                    self.logger.info("PyGhidra integration enabled")
                else:
                    self.logger.info("PyGhidra not properly configured - falling back to standard analysis")
                    self.ghidra_analyzer = None
            except Exception as e:
                self.logger.warning(f"Failed to initialize PyGhidra: {e}")
                self.ghidra_analyzer = None
        
        # Common Android architectures
        self.android_abis = {
            'arm64-v8a': ['aarch64', 'arm64'],
            'armeabi-v7a': ['arm'],
            'x86': ['i386', 'i686'],
            'x86_64': ['x86-64', 'x86_64']
        }
        
        # Suspicious string patterns
        self.suspicious_patterns = [
            # Network/URL patterns
            r'https?://[^\s]+',
            r'ftp://[^\s]+',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP addresses
            
            # Crypto/encryption patterns
            r'AES|DES|RSA|SHA|MD5',
            r'encrypt|decrypt|cipher|key',
            r'base64|encode|decode',
            
            # System/privilege patterns
            r'root|sudo|su\b',
            r'/system/|/data/|/sdcard/',
            r'chmod|chown|mount',
            
            # Anti-analysis patterns
            r'debug|trace|hook|frida',
            r'emulator|virtual|vm',
            r'anti|detect|bypass',
            
            # Common malware strings
            r'payload|shell|exploit',
            r'backdoor|trojan|virus',
            r'steal|exfil|upload'
        ]
        
        # Known packers/obfuscators
        self.known_packers = [
            'UPX', 'Themida', 'VMProtect', 'Armadillo', 'ASProtect',
            'Enigma', 'ExeCryptor', 'Molebox', 'MPRESS', 'PESpin',
            'Petite', 'tElock', 'WinUpack', 'Yoda\'s Protector'
        ]
    
    def analyze_shared_library(self, library_path: str) -> Dict:
        """
        Perform comprehensive analysis of a shared library file.
        
        Args:
            library_path: Path to the .so file
            
        Returns:
            Dictionary containing complete analysis results
        """
        if not os.path.exists(library_path):
            return {'error': f'File not found: {library_path}'}
        
        try:
            analysis = {
                'file_info': self._get_file_info(library_path),
                'architecture': self._detect_architecture(library_path),
                'file_type': self._detect_file_type(library_path),
                'hashes': self._calculate_hashes(library_path),
                'symbols': self._extract_symbols(library_path),
                'strings': self._extract_strings(library_path),
                'dependencies': self._extract_dependencies(library_path),
                'security_analysis': self._analyze_security_features(library_path),
                'packer_detection': self._detect_packers(library_path),
                'suspicious_indicators': self._analyze_suspicious_patterns(library_path),
                'elf_analysis': self._analyze_elf_structure(library_path)
            }
            
            # Generate summary
            analysis['summary'] = self._generate_summary(analysis)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing {library_path}: {e}")
            return {'error': str(e)}
    
    def _get_file_info(self, library_path: str) -> Dict:
        """Get basic file information."""
        stat = os.stat(library_path)
        return {
            'filename': os.path.basename(library_path),
            'full_path': library_path,
            'size': stat.st_size,
            'size_human': self._human_readable_size(stat.st_size),
            'modified': stat.st_mtime
        }
    
    def _detect_architecture(self, library_path: str) -> Dict:
        """
        Detect the architecture/ABI of the shared library.
        
        Returns:
            Dictionary with architecture detection results
        """
        try:
            # Use readelf to get ELF header information
            result = subprocess.run(
                ['readelf', '-h', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode != 0:
                return self._detect_architecture_fallback(library_path)
            
            output = result.stdout
            arch_info = {}
            
            # Parse readelf output
            for line in output.split('\n'):
                if 'Machine:' in line:
                    machine = line.split('Machine:')[1].strip()
                    arch_info['machine'] = machine
                    arch_info['detected_abi'] = self._map_machine_to_abi(machine)
                elif 'Class:' in line:
                    arch_info['class'] = line.split('Class:')[1].strip()
                elif 'Data:' in line:
                    arch_info['endianness'] = line.split('Data:')[1].strip()
                elif 'Type:' in line:
                    arch_info['type'] = line.split('Type:')[1].strip()
            
            # Determine Android ABI from path if available
            path_abi = self._detect_abi_from_path(library_path)
            if path_abi:
                arch_info['path_abi'] = path_abi
            
            return arch_info
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.warning(f"readelf failed for {library_path}: {e}")
            return self._detect_architecture_fallback(library_path)
    
    def _detect_architecture_fallback(self, library_path: str) -> Dict:
        """Fallback architecture detection using file magic numbers."""
        try:
            with open(library_path, 'rb') as f:
                header = f.read(20)
            
            if len(header) < 20:
                return {'error': 'File too small'}
            
            # Check ELF magic
            if header[:4] != b'\x7fELF':
                return {'error': 'Not an ELF file'}
            
            # Parse ELF header
            ei_class = header[4]  # 32-bit or 64-bit
            ei_data = header[5]   # Endianness
            e_machine = struct.unpack('<H' if ei_data == 1 else '>H', header[18:20])[0]
            
            arch_info = {
                'class': 'ELF64' if ei_class == 2 else 'ELF32',
                'endianness': 'little' if ei_data == 1 else 'big',
                'machine_code': e_machine
            }
            
            # Map machine code to architecture
            machine_map = {
                0x28: 'ARM',
                0xB7: 'AArch64',
                0x03: 'x86',
                0x3E: 'x86-64'
            }
            
            if e_machine in machine_map:
                arch_info['machine'] = machine_map[e_machine]
                arch_info['detected_abi'] = self._map_machine_to_abi(machine_map[e_machine])
            
            path_abi = self._detect_abi_from_path(library_path)
            if path_abi:
                arch_info['path_abi'] = path_abi
            
            return arch_info
            
        except Exception as e:
            self.logger.error(f"Fallback architecture detection failed: {e}")
            return {'error': str(e)}
    
    def _map_machine_to_abi(self, machine: str) -> str:
        """Map machine type to Android ABI."""
        machine_lower = machine.lower()
        
        if 'aarch64' in machine_lower or 'arm64' in machine_lower:
            return 'arm64-v8a'
        elif 'arm' in machine_lower:
            return 'armeabi-v7a'
        elif 'x86-64' in machine_lower or 'x86_64' in machine_lower:
            return 'x86_64'
        elif 'i386' in machine_lower or 'i686' in machine_lower or machine_lower == 'intel 80386':
            return 'x86'
        else:
            return 'unknown'
    
    def _detect_abi_from_path(self, library_path: str) -> Optional[str]:
        """Detect ABI from file path (e.g., lib/arm64-v8a/libtest.so)."""
        path_parts = Path(library_path).parts
        
        for part in path_parts:
            if part in self.android_abis:
                return part
        
        return None
    
    def _detect_file_type(self, library_path: str) -> Dict:
        """Detect detailed file type information."""
        file_type_info = {}
        
        if MAGIC_AVAILABLE:
            try:
                # Get MIME type
                mime = magic.Magic(mime=True)
                file_type_info['mime_type'] = mime.from_file(library_path)
                
                # Get detailed description
                desc = magic.Magic()
                file_type_info['description'] = desc.from_file(library_path)
                
            except Exception as e:
                self.logger.warning(f"Magic detection failed: {e}")
                file_type_info = self._detect_file_type_fallback(library_path)
        else:
            file_type_info = self._detect_file_type_fallback(library_path)
        
        # Additional checks
        file_type_info['is_stripped'] = self._is_stripped(library_path)
        file_type_info['is_debug'] = self._has_debug_info(library_path)
        
        return file_type_info
    
    def _detect_file_type_fallback(self, library_path: str) -> Dict:
        """Fallback file type detection."""
        try:
            # Use file command if available
            result = subprocess.run(
                ['file', library_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                description = result.stdout.strip()
                return {
                    'description': description,
                    'mime_type': 'application/x-sharedlib' if 'shared object' in description else 'application/octet-stream'
                }
                
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Basic fallback
        return {
            'description': 'Shared library (fallback detection)',
            'mime_type': 'application/x-sharedlib'
        }
    
    def _calculate_hashes(self, library_path: str) -> Dict:
        """Calculate various hashes of the library file."""
        hashes = {}
        
        try:
            with open(library_path, 'rb') as f:
                data = f.read()
            
            # Standard hashes
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
            
            # Fuzzy hash if available
            if SSDEEP_AVAILABLE:
                try:
                    hashes['ssdeep'] = ssdeep.hash(data)
                except Exception as e:
                    self.logger.warning(f"ssdeep hashing failed: {e}")
                    hashes['ssdeep'] = None
            else:
                hashes['ssdeep'] = None
                
        except Exception as e:
            self.logger.error(f"Hash calculation failed: {e}")
            hashes['error'] = str(e)
        
        return hashes
    
    def _extract_symbols(self, library_path: str) -> Dict:
        """Extract symbols from the shared library."""
        symbols = {
            'exported': [],
            'imported': [],
            'undefined': [],
            'local': [],
            'count': 0
        }
        
        try:
            # Use nm to extract symbols
            result = subprocess.run(
                ['nm', '-D', library_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                symbols = self._parse_nm_output(result.stdout)
            
            # Also try objdump for additional symbol information
            objdump_result = subprocess.run(
                ['objdump', '-T', library_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if objdump_result.returncode == 0:
                objdump_symbols = self._parse_objdump_output(objdump_result.stdout)
                symbols.update(objdump_symbols)
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.warning(f"Symbol extraction failed: {e}")
            symbols['error'] = str(e)
        
        return symbols
    
    def _parse_nm_output(self, nm_output: str) -> Dict:
        """Parse nm command output to extract symbols."""
        symbols = {
            'exported': [],
            'imported': [],
            'undefined': [],
            'local': [],
            'count': 0
        }
        
        for line in nm_output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                symbol_type = parts[1] if len(parts) >= 3 else parts[0]
                symbol_name = parts[-1]
                
                symbol_info = {
                    'name': symbol_name,
                    'type': symbol_type,
                    'full_line': line
                }
                
                # Categorize symbols
                if symbol_type == 'U':
                    symbols['undefined'].append(symbol_info)
                elif symbol_type in 'Tt':
                    symbols['exported'].append(symbol_info)
                elif symbol_type.lower() in 'wv':
                    symbols['imported'].append(symbol_info)
                else:
                    symbols['local'].append(symbol_info)
                
                symbols['count'] += 1
        
        return symbols
    
    def _parse_objdump_output(self, objdump_output: str) -> Dict:
        """Parse objdump output for additional symbol information."""
        dynamic_symbols = []
        
        in_dynamic_section = False
        for line in objdump_output.split('\n'):
            line = line.strip()
            
            if 'DYNAMIC SYMBOL TABLE' in line:
                in_dynamic_section = True
                continue
            elif in_dynamic_section and line.startswith('0'):
                # Parse dynamic symbol entry
                parts = line.split()
                if len(parts) >= 6:
                    dynamic_symbols.append({
                        'address': parts[0],
                        'flags': parts[1],
                        'section': parts[2],
                        'size': parts[3],
                        'version': parts[4],
                        'name': ' '.join(parts[5:])
                    })
        
        return {'dynamic_symbols': dynamic_symbols}
    
    def _extract_strings(self, library_path: str) -> Dict:
        """Extract strings from the shared library."""
        strings_info = {
            'all_strings': [],
            'suspicious_strings': [],
            'count': 0,
            'min_length': 4
        }
        
        try:
            # Use strings command to extract printable strings
            result = subprocess.run(
                ['strings', '-n', '4', library_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                all_strings = result.stdout.split('\n')
                all_strings = [s.strip() for s in all_strings if s.strip()]
                
                strings_info['all_strings'] = all_strings[:1000]  # Limit to first 1000
                strings_info['count'] = len(all_strings)
                
                # Analyze for suspicious patterns
                strings_info['suspicious_strings'] = self._find_suspicious_strings(all_strings)
                
                # Additional string analysis
                strings_info['url_strings'] = self._find_urls(all_strings)
                strings_info['crypto_strings'] = self._find_crypto_strings(all_strings)
                strings_info['file_path_strings'] = self._find_file_paths(all_strings)
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.warning(f"String extraction failed: {e}")
            strings_info['error'] = str(e)
        
        return strings_info
    
    def _find_suspicious_strings(self, strings: List[str]) -> List[Dict]:
        """Find strings matching suspicious patterns."""
        suspicious = []
        
        for string in strings:
            for pattern in self.suspicious_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    suspicious.append({
                        'string': string,
                        'pattern': pattern,
                        'category': self._categorize_suspicious_string(pattern)
                    })
                    break  # One match per string
        
        return suspicious[:100]  # Limit results
    
    def _categorize_suspicious_string(self, pattern: str) -> str:
        """Categorize suspicious string patterns."""
        if 'http' in pattern or 'ftp' in pattern or r'\d.*\d.*\d.*\d' in pattern:
            return 'network'
        elif any(crypto in pattern.lower() for crypto in ['aes', 'des', 'rsa', 'sha', 'md5', 'encrypt', 'decrypt']):
            return 'crypto'
        elif any(sys in pattern.lower() for sys in ['root', 'sudo', 'chmod', 'mount']):
            return 'system'
        elif any(anti in pattern.lower() for anti in ['debug', 'trace', 'hook', 'emulator', 'anti']):
            return 'anti-analysis'
        elif any(mal in pattern.lower() for mal in ['payload', 'shell', 'exploit', 'backdoor']):
            return 'malware'
        else:
            return 'other'
    
    def _find_urls(self, strings: List[str]) -> List[str]:
        """Find URL strings."""
        url_pattern = re.compile(r'https?://[^\s]+', re.IGNORECASE)
        urls = []
        
        for string in strings:
            matches = url_pattern.findall(string)
            urls.extend(matches)
        
        return list(set(urls))[:50]  # Unique URLs, limited
    
    def _find_crypto_strings(self, strings: List[str]) -> List[str]:
        """Find cryptography-related strings."""
        crypto_patterns = [
            r'\b(AES|DES|RSA|SHA|MD5|HMAC)\b',
            r'\b(encrypt|decrypt|cipher|hash|sign|verify)\b',
            r'\b(certificate|private.*key|public.*key)\b'
        ]
        
        crypto_strings = []
        for string in strings:
            for pattern in crypto_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    crypto_strings.append(string)
                    break
        
        return list(set(crypto_strings))[:30]
    
    def _find_file_paths(self, strings: List[str]) -> List[str]:
        """Find file path strings."""
        path_pattern = re.compile(r'(/[a-zA-Z0-9_/.-]+)|([A-Z]:\\[a-zA-Z0-9_\\.-]+)')
        paths = []
        
        for string in strings:
            matches = path_pattern.findall(string)
            for match in matches:
                path = match[0] or match[1]
                if len(path) > 3:  # Filter out very short paths
                    paths.append(path)
        
        return list(set(paths))[:50]
    
    def _extract_dependencies(self, library_path: str) -> Dict:
        """Extract library dependencies."""
        dependencies = {
            'needed_libraries': [],
            'soname': None,
            'rpath': [],
            'runpath': []
        }
        
        try:
            # Use readelf to get dynamic section
            result = subprocess.run(
                ['readelf', '-d', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                dependencies = self._parse_dynamic_section(result.stdout)
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.warning(f"Dependency extraction failed: {e}")
            dependencies['error'] = str(e)
        
        return dependencies
    
    def _parse_dynamic_section(self, readelf_output: str) -> Dict:
        """Parse readelf dynamic section output."""
        dependencies = {
            'needed_libraries': [],
            'soname': None,
            'rpath': [],
            'runpath': []
        }
        
        for line in readelf_output.split('\n'):
            line = line.strip()
            
            if 'NEEDED' in line and 'Shared library:' in line:
                # Extract library name from [libname.so]
                match = re.search(r'\[([^\]]+)\]', line)
                if match:
                    dependencies['needed_libraries'].append(match.group(1))
            
            elif 'SONAME' in line and 'Library soname:' in line:
                match = re.search(r'\[([^\]]+)\]', line)
                if match:
                    dependencies['soname'] = match.group(1)
            
            elif 'RPATH' in line:
                match = re.search(r'\[([^\]]+)\]', line)
                if match:
                    dependencies['rpath'].append(match.group(1))
            
            elif 'RUNPATH' in line:
                match = re.search(r'\[([^\]]+)\]', line)
                if match:
                    dependencies['runpath'].append(match.group(1))
        
        return dependencies
    
    def _analyze_security_features(self, library_path: str) -> Dict:
        """Analyze security features and mitigations."""
        security = {
            'nx_bit': False,
            'stack_canary': False,
            'pic_pie': False,
            'relro': False,
            'fortified': False
        }
        
        try:
            # Check for security features using checksec-like analysis
            result = subprocess.run(
                ['readelf', '-l', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Check for NX bit (GNU_STACK)
                if 'GNU_STACK' in output and 'RWE' not in output:
                    security['nx_bit'] = True
                
                # Check for PIE
                if 'DYN' in output:
                    security['pic_pie'] = True
                
                # Check for RELRO
                if 'GNU_RELRO' in output:
                    security['relro'] = True
            
            # Check for stack canary and fortification in symbols
            symbols_result = subprocess.run(
                ['nm', '-D', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if symbols_result.returncode == 0:
                symbols_output = symbols_result.stdout
                
                if '__stack_chk_fail' in symbols_output:
                    security['stack_canary'] = True
                
                if any(func in symbols_output for func in ['__sprintf_chk', '__strcpy_chk', '__memcpy_chk']):
                    security['fortified'] = True
                    
        except Exception as e:
            self.logger.warning(f"Security analysis failed: {e}")
            security['error'] = str(e)
        
        return security
    
    def _detect_packers(self, library_path: str) -> Dict:
        """Detect common packers and obfuscators."""
        packer_info = {
            'detected_packers': [],
            'entropy': 0.0,
            'compressed_sections': [],
            'suspicious_sections': []
        }
        
        try:
            # Check entropy (high entropy might indicate packing)
            packer_info['entropy'] = self._calculate_entropy(library_path)
            
            # Check for known packer signatures in strings
            strings_result = subprocess.run(
                ['strings', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if strings_result.returncode == 0:
                strings_content = strings_result.stdout
                
                for packer in self.known_packers:
                    if packer.lower() in strings_content.lower():
                        packer_info['detected_packers'].append(packer)
            
            # Analyze section names for suspicious patterns
            sections_result = subprocess.run(
                ['readelf', '-S', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if sections_result.returncode == 0:
                suspicious_sections = self._analyze_sections(sections_result.stdout)
                packer_info['suspicious_sections'] = suspicious_sections
                
        except Exception as e:
            self.logger.warning(f"Packer detection failed: {e}")
            packer_info['error'] = str(e)
        
        return packer_info
    
    def _calculate_entropy(self, library_path: str) -> float:
        """Calculate Shannon entropy of the file."""
        try:
            with open(library_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            frequencies = [0] * 256
            for byte in data:
                frequencies[byte] += 1
            
            # Calculate entropy
            import math
            entropy = 0.0
            data_len = len(data)
            
            for freq in frequencies:
                if freq > 0:
                    p = freq / data_len
                    entropy -= p * math.log2(p)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _analyze_sections(self, readelf_output: str) -> List[str]:
        """Analyze ELF sections for suspicious patterns."""
        suspicious = []
        
        suspicious_section_names = [
            '.upx', '.upack', '.aspack', '.petite',
            '.packed', '.compress', '.protect'
        ]
        
        for line in readelf_output.split('\n'):
            for sus_name in suspicious_section_names:
                if sus_name in line.lower():
                    suspicious.append(line.strip())
        
        return suspicious
    
    def _analyze_suspicious_patterns(self, library_path: str) -> Dict:
        """Analyze file for various suspicious patterns and indicators."""
        indicators = {
            'high_entropy_sections': [],
            'unusual_entry_point': False,
            'suspicious_imports': [],
            'anti_debug_strings': [],
            'vm_detection_strings': [],
            'risk_score': 0
        }
        
        try:
            # Check for anti-debugging and VM detection strings
            strings_result = subprocess.run(
                ['strings', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if strings_result.returncode == 0:
                all_strings = strings_result.stdout.split('\n')
                
                anti_debug_patterns = [
                    'ptrace', 'debugger', 'gdb', 'strace', 'ltrace',
                    'debug', 'trace', 'hook', 'inject'
                ]
                
                vm_patterns = [
                    'vmware', 'virtualbox', 'vbox', 'qemu', 'xen',
                    'virtual', 'emulator', 'simulator'
                ]
                
                for string in all_strings:
                    string_lower = string.lower()
                    
                    for pattern in anti_debug_patterns:
                        if pattern in string_lower:
                            indicators['anti_debug_strings'].append(string)
                            indicators['risk_score'] += 1
                            break
                    
                    for pattern in vm_patterns:
                        if pattern in string_lower:
                            indicators['vm_detection_strings'].append(string)
                            indicators['risk_score'] += 1
                            break
            
            # Check for suspicious imports
            nm_result = subprocess.run(
                ['nm', '-D', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if nm_result.returncode == 0:
                suspicious_funcs = [
                    'ptrace', 'dlopen', 'dlsym', 'mprotect',
                    'mmap', 'execve', 'system', 'fork'
                ]
                
                for line in nm_result.stdout.split('\n'):
                    for func in suspicious_funcs:
                        if func in line:
                            indicators['suspicious_imports'].append(line.strip())
                            indicators['risk_score'] += 2
                            break
                            
        except Exception as e:
            self.logger.warning(f"Suspicious pattern analysis failed: {e}")
            indicators['error'] = str(e)
        
        return indicators
    
    def _analyze_elf_structure(self, library_path: str) -> Dict:
        """Analyze ELF file structure details."""
        elf_info = {
            'header': {},
            'sections': [],
            'program_headers': [],
            'entry_point': None
        }
        
        try:
            # Get ELF header
            header_result = subprocess.run(
                ['readelf', '-h', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if header_result.returncode == 0:
                elf_info['header'] = self._parse_elf_header(header_result.stdout)
            
            # Get sections
            sections_result = subprocess.run(
                ['readelf', '-S', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if sections_result.returncode == 0:
                elf_info['sections'] = self._parse_sections(sections_result.stdout)
            
            # Get program headers
            program_result = subprocess.run(
                ['readelf', '-l', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if program_result.returncode == 0:
                elf_info['program_headers'] = self._parse_program_headers(program_result.stdout)
                
        except Exception as e:
            self.logger.warning(f"ELF structure analysis failed: {e}")
            elf_info['error'] = str(e)
        
        return elf_info
    
    def _parse_elf_header(self, header_output: str) -> Dict:
        """Parse ELF header information."""
        header = {}
        
        for line in header_output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower().replace(' ', '_')
                value = value.strip()
                header[key] = value
        
        return header
    
    def _parse_sections(self, sections_output: str) -> List[Dict]:
        """Parse ELF sections information."""
        sections = []
        
        # Skip header lines and parse section entries
        lines = sections_output.split('\n')
        for line in lines:
            if line.strip().startswith('[') and ']' in line:
                parts = line.split()
                if len(parts) >= 7:
                    try:
                        section = {
                            'index': parts[0].strip('[]'),
                            'name': parts[1],
                            'type': parts[2],
                            'address': parts[3],
                            'offset': parts[4],
                            'size': parts[5],
                            'flags': parts[6] if len(parts) > 6 else ''
                        }
                        sections.append(section)
                    except (IndexError, ValueError):
                        continue
        
        return sections
    
    def _parse_program_headers(self, program_output: str) -> List[Dict]:
        """Parse ELF program headers."""
        headers = []
        
        lines = program_output.split('\n')
        for line in lines:
            parts = line.split()
            if len(parts) >= 6 and parts[0] not in ['Type', 'PHDR']:
                try:
                    header = {
                        'type': parts[0],
                        'offset': parts[1],
                        'virt_addr': parts[2],
                        'phys_addr': parts[3],
                        'file_size': parts[4],
                        'mem_size': parts[5],
                        'flags': parts[6] if len(parts) > 6 else '',
                        'align': parts[7] if len(parts) > 7 else ''
                    }
                    headers.append(header)
                except (IndexError, ValueError):
                    continue
        
        return headers
    
    def _is_stripped(self, library_path: str) -> bool:
        """Check if the library is stripped of symbols."""
        try:
            result = subprocess.run(
                ['file', library_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return 'stripped' in result.stdout.lower()
                
        except Exception:
            pass
        
        return False
    
    def _has_debug_info(self, library_path: str) -> bool:
        """Check if the library has debug information."""
        try:
            result = subprocess.run(
                ['readelf', '-S', library_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                debug_sections = ['.debug_info', '.debug_line', '.debug_frame']
                return any(section in output for section in debug_sections)
                
        except Exception:
            pass
        
        return False
    
    def _generate_summary(self, analysis: Dict) -> Dict:
        """Generate a summary of the analysis results."""
        summary = {
            'file_name': analysis.get('file_info', {}).get('filename', 'unknown'),
            'file_size': analysis.get('file_info', {}).get('size', 0),
            'architecture': analysis.get('architecture', {}).get('detected_abi', 'unknown'),
            'is_stripped': analysis.get('file_type', {}).get('is_stripped', False),
            'has_debug': analysis.get('file_type', {}).get('is_debug', False),
            'symbol_count': analysis.get('symbols', {}).get('count', 0),
            'string_count': analysis.get('strings', {}).get('count', 0),
            'dependency_count': len(analysis.get('dependencies', {}).get('needed_libraries', [])),
            'suspicious_string_count': len(analysis.get('strings', {}).get('suspicious_strings', [])),
            'risk_score': analysis.get('suspicious_indicators', {}).get('risk_score', 0),
            'entropy': analysis.get('packer_detection', {}).get('entropy', 0.0),
            'detected_packers': analysis.get('packer_detection', {}).get('detected_packers', [])
        }
        
        # Risk assessment
        if summary['risk_score'] > 10:
            summary['risk_level'] = 'high'
        elif summary['risk_score'] > 5:
            summary['risk_level'] = 'medium'
        else:
            summary['risk_level'] = 'low'
        
        return summary
    
    def analyze_with_ghidra(self, library_path: str, 
                           merge_with_standard: bool = True,
                           ghidra_options: Optional[Dict] = None) -> Dict:
        """
        Perform advanced analysis using Ghidra integration.
        
        This method leverages pyghidra for deeper static analysis capabilities
        beyond what standard tools like nm, readelf, and strings can provide.
        Ghidra excels at function analysis, cross-reference detection, and
        control flow analysis.
        
        Args:
            library_path: Path to the shared library file
            merge_with_standard: Whether to merge Ghidra results with standard analysis
            ghidra_options: Optional dictionary of Ghidra analysis options
                          - extract_functions: bool (default True)
                          - extract_xrefs: bool (default True) 
                          - extract_strings: bool (default True)
                          - custom_scripts: List[str] (default None)
                          
        Returns:
            Dictionary containing analysis results. If merge_with_standard is True,
            includes both standard and Ghidra analysis. If False, only Ghidra results.
            
        Example:
            analyzer = SharedLibraryAnalyzer()
            
            # Basic Ghidra analysis
            results = analyzer.analyze_with_ghidra('/path/to/lib.so')
            
            # Advanced with custom options
            options = {
                'extract_functions': True,
                'extract_xrefs': True,
                'custom_scripts': ['/path/to/script.py']
            }
            results = analyzer.analyze_with_ghidra('/path/to/lib.so', 
                                                  ghidra_options=options)
            
            # Access Ghidra-specific results
            if 'ghidra_analysis' in results:
                functions = results['ghidra_analysis']['functions']
                xrefs = results['ghidra_analysis']['cross_references']
        """
        if not os.path.exists(library_path):
            return {'error': f'File not found: {library_path}'}
        
        # Prepare default options
        default_options = {
            'extract_functions': True,
            'extract_xrefs': True,
            'extract_strings': True,
            'custom_scripts': None
        }
        
        if ghidra_options:
            default_options.update(ghidra_options)
        
        # Initialize results structure
        if merge_with_standard:
            # Start with standard analysis
            results = self.analyze_shared_library(library_path)
        else:
            # Only basic file info for Ghidra-only analysis
            results = {
                'file_info': self._get_file_info(library_path),
                'ghidra_only': True
            }
        
        # Check if Ghidra is available
        if not self.ghidra_analyzer or not self.ghidra_analyzer.is_available():
            ghidra_status = self._get_ghidra_status()
            results['ghidra_analysis'] = {
                'available': False,
                'status': ghidra_status,
                'error': 'PyGhidra not available or not properly configured'
            }
            
            if not merge_with_standard:
                # For Ghidra-only analysis, this is a critical failure
                results['error'] = 'Ghidra analysis requested but not available'
            
            return results
        
        try:
            # Perform Ghidra analysis
            self.logger.info(f"Starting Ghidra analysis for {library_path}")
            ghidra_results = self.ghidra_analyzer.analyze_library(
                library_path,
                extract_functions=default_options['extract_functions'],
                extract_xrefs=default_options['extract_xrefs'],
                extract_strings=default_options['extract_strings'],
                custom_scripts=default_options['custom_scripts']
            )
            
            # Add Ghidra results to the main analysis
            results['ghidra_analysis'] = ghidra_results
            
            # Enhance standard analysis with Ghidra insights if merging
            if merge_with_standard and ghidra_results.get('available', False):
                results = self._merge_ghidra_insights(results, ghidra_results)
            
            self.logger.info("Ghidra analysis completed successfully")
            
        except Exception as e:
            self.logger.error(f"Ghidra analysis failed for {library_path}: {e}")
            results['ghidra_analysis'] = {
                'available': True,
                'error': str(e),
                'analysis_failed': True
            }
        
        return results
    
    def _get_ghidra_status(self) -> str:
        """Get status of Ghidra availability."""
        if not PYGHIDRA_INTEGRATION_AVAILABLE:
            return "PyGhidra integration module not available"
        
        try:
            is_available, message = check_pyghidra_availability()
            return message
        except Exception as e:
            return f"Error checking Ghidra status: {e}"
    
    def _merge_ghidra_insights(self, standard_results: Dict, ghidra_results: Dict) -> Dict:
        """
        Merge Ghidra analysis insights into standard analysis results.
        
        This method enhances the standard analysis with additional insights
        from Ghidra, creating a comprehensive analysis report.
        """
        try:
            # Enhance symbol analysis with Ghidra symbols
            if 'symbols' in ghidra_results and 'symbols' in standard_results:
                self._enhance_symbol_analysis(standard_results['symbols'], 
                                            ghidra_results['symbols'])
            
            # Enhance function analysis
            if 'functions' in ghidra_results:
                standard_results['enhanced_functions'] = self._create_enhanced_function_analysis(
                    standard_results.get('symbols', {}), 
                    ghidra_results['functions']
                )
            
            # Add cross-reference analysis
            if 'cross_references' in ghidra_results:
                standard_results['cross_references'] = ghidra_results['cross_references']
            
            # Enhance string analysis with Ghidra findings
            if ('strings' in ghidra_results and 
                'strings' in standard_results and 
                ghidra_results['strings'].get('defined_strings')):
                self._enhance_string_analysis(standard_results['strings'], 
                                            ghidra_results['strings'])
            
            # Add memory layout information
            if 'memory_layout' in ghidra_results:
                standard_results['memory_layout'] = ghidra_results['memory_layout']
            
            # Update summary with Ghidra insights
            if 'summary' in standard_results and 'analysis_summary' in ghidra_results:
                self._enhance_analysis_summary(standard_results['summary'], 
                                             ghidra_results['analysis_summary'])
            
        except Exception as e:
            self.logger.warning(f"Failed to merge Ghidra insights: {e}")
        
        return standard_results
    
    def _enhance_symbol_analysis(self, standard_symbols: Dict, ghidra_symbols: Dict) -> None:
        """Enhance standard symbol analysis with Ghidra symbol information."""
        try:
            # Add Ghidra symbol counts to comparison
            ghidra_stats = ghidra_symbols.get('symbol_statistics', {})
            if ghidra_stats:
                standard_symbols['ghidra_comparison'] = {
                    'total_symbols': ghidra_stats.get('total_symbols', 0),
                    'global_symbols': ghidra_stats.get('global_count', 0),
                    'external_symbols': ghidra_stats.get('external_count', 0),
                    'analysis_method': 'ghidra_advanced'
                }
            
            # Add detailed symbol categories from Ghidra
            if 'global_symbols' in ghidra_symbols:
                standard_symbols['ghidra_global_symbols'] = ghidra_symbols['global_symbols'][:50]  # Limit for size
            
            if 'external_symbols' in ghidra_symbols:
                standard_symbols['ghidra_external_symbols'] = ghidra_symbols['external_symbols'][:50]
        
        except Exception as e:
            self.logger.warning(f"Symbol enhancement failed: {e}")
    
    def _create_enhanced_function_analysis(self, standard_symbols: Dict, 
                                         ghidra_functions: Dict) -> Dict:
        """Create enhanced function analysis combining standard and Ghidra data."""
        enhanced = {
            'source': 'ghidra_analysis',
            'function_count': ghidra_functions.get('total_functions', 0),
            'entry_points': ghidra_functions.get('entry_points', []),
            'function_statistics': ghidra_functions.get('function_statistics', {}),
            'top_functions_by_size': [],
            'external_calls': []
        }
        
        try:
            # Get top functions by size
            function_details = ghidra_functions.get('function_details', [])
            if function_details:
                # Sort by size and get top 10
                sorted_functions = sorted(function_details, 
                                        key=lambda x: x.get('size', 0), 
                                        reverse=True)
                enhanced['top_functions_by_size'] = sorted_functions[:10]
                
                # Extract external function calls
                external_funcs = [f for f in function_details if f.get('is_external', False)]
                enhanced['external_calls'] = external_funcs[:20]  # Limit for size
        
        except Exception as e:
            self.logger.warning(f"Function analysis enhancement failed: {e}")
        
        return enhanced
    
    def _enhance_string_analysis(self, standard_strings: Dict, ghidra_strings: Dict) -> None:
        """Enhance string analysis with Ghidra string findings."""
        try:
            ghidra_stats = ghidra_strings.get('string_statistics', {})
            if ghidra_stats:
                standard_strings['ghidra_comparison'] = {
                    'total_strings': ghidra_stats.get('total_strings', 0),
                    'unicode_strings': ghidra_stats.get('unicode_count', 0),
                    'avg_string_length': ghidra_stats.get('avg_length', 0),
                    'analysis_method': 'ghidra_defined_data'
                }
            
            # Add unicode strings if found
            if ghidra_strings.get('unicode_strings'):
                standard_strings['unicode_strings'] = ghidra_strings['unicode_strings'][:20]
        
        except Exception as e:
            self.logger.warning(f"String analysis enhancement failed: {e}")
    
    def _enhance_analysis_summary(self, standard_summary: Dict, ghidra_summary: Dict) -> None:
        """Enhance analysis summary with Ghidra insights."""
        try:
            standard_summary['ghidra_analysis'] = {
                'enabled': True,
                'success': ghidra_summary.get('success', False),
                'features_analyzed': ghidra_summary.get('features_analyzed', []),
                'function_count': ghidra_summary.get('function_count', 0),
                'symbol_count': ghidra_summary.get('symbol_count', 0),
                'call_count': ghidra_summary.get('call_count', 0),
                'external_ref_count': ghidra_summary.get('external_ref_count', 0)
            }
            
            # Update risk assessment based on Ghidra findings
            if ghidra_summary.get('external_ref_count', 0) > 20:
                standard_summary['risk_score'] = standard_summary.get('risk_score', 0) + 1
                
            if ghidra_summary.get('function_count', 0) > 1000:
                standard_summary['risk_score'] = standard_summary.get('risk_score', 0) + 1
        
        except Exception as e:
            self.logger.warning(f"Summary enhancement failed: {e}")
    
    def is_ghidra_available(self) -> bool:
        """
        Check if Ghidra analysis is available.
        
        Returns:
            True if PyGhidra is properly configured and available
        """
        return (self.ghidra_analyzer is not None and 
                self.ghidra_analyzer.is_available())
    
    def get_ghidra_info(self) -> Dict[str, Any]:
        """
        Get information about Ghidra availability and configuration.
        
        Returns:
            Dictionary with Ghidra status information
        """
        info = {
            'integration_available': PYGHIDRA_INTEGRATION_AVAILABLE,
            'analyzer_initialized': self.ghidra_analyzer is not None,
            'ghidra_available': self.is_ghidra_available(),
            'status_message': self._get_ghidra_status()
        }
        
        if self.ghidra_analyzer:
            info['ghidra_install_dir'] = getattr(self.ghidra_analyzer, 'ghidra_install_dir', None)
        
        return info
    
    def _human_readable_size(self, size: int) -> str:
        """Convert size in bytes to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def analyze_apk_libraries(self, apk_path: str) -> Dict:
        """
        Analyze all shared libraries found in an APK.
        
        Args:
            apk_path: Path to the APK file
            
        Returns:
            Dictionary containing analysis of all .so files
        """
        try:
            from androguard.core import apk
            
            app = apk.APK(apk_path)
            results = {
                'apk_name': os.path.basename(apk_path),
                'libraries': {},
                'summary': {
                    'total_libraries': 0,
                    'architectures': set(),
                    'total_size': 0,
                    'risk_scores': []
                }
            }
            
            # Find all .so files
            for filename in app.get_files():
                if filename.endswith('.so'):
                    try:
                        # Extract library data
                        lib_data = app.get_file(filename)
                        if lib_data:
                            # Save to temporary file for analysis
                            import tempfile
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.so') as tmp_file:
                                tmp_file.write(lib_data)
                                tmp_path = tmp_file.name
                            
                            # Analyze the library
                            analysis = self.analyze_shared_library(tmp_path)
                            analysis['original_path'] = filename
                            
                            results['libraries'][filename] = analysis
                            
                            # Update summary
                            results['summary']['total_libraries'] += 1
                            if 'architecture' in analysis and 'detected_abi' in analysis['architecture']:
                                results['summary']['architectures'].add(analysis['architecture']['detected_abi'])
                            if 'file_info' in analysis:
                                results['summary']['total_size'] += analysis['file_info'].get('size', 0)
                            if 'summary' in analysis:
                                results['summary']['risk_scores'].append(analysis['summary'].get('risk_score', 0))
                            
                            # Clean up temporary file
                            os.unlink(tmp_path)
                            
                    except Exception as e:
                        self.logger.error(f"Error analyzing library {filename}: {e}")
                        results['libraries'][filename] = {'error': str(e)}
            
            # Finalize summary
            results['summary']['architectures'] = list(results['summary']['architectures'])
            if results['summary']['risk_scores']:
                results['summary']['max_risk_score'] = max(results['summary']['risk_scores'])
                results['summary']['avg_risk_score'] = sum(results['summary']['risk_scores']) / len(results['summary']['risk_scores'])
            else:
                results['summary']['max_risk_score'] = 0
                results['summary']['avg_risk_score'] = 0
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing APK libraries: {e}")
            return {'error': str(e)}
    
    def cross_reference_java_natives(self, apk_path: str, decompiled_dir: str = None) -> Dict:
        """
        Cross-reference native library symbols with Java native method declarations.
        
        Args:
            apk_path: Path to the APK file
            decompiled_dir: Path to decompiled Java code directory
            
        Returns:
            Dictionary mapping native methods to library symbols
        """
        cross_refs = {
            'native_methods': [],
            'matched_symbols': {},
            'unmatched_methods': [],
            'unmatched_symbols': []
        }
        
        try:
            # First, analyze libraries to get available symbols
            lib_analysis = self.analyze_apk_libraries(apk_path)
            all_symbols = {}
            
            for lib_name, analysis in lib_analysis.get('libraries', {}).items():
                if 'symbols' in analysis and 'exported' in analysis['symbols']:
                    for symbol in analysis['symbols']['exported']:
                        symbol_name = symbol.get('name', '')
                        if symbol_name not in all_symbols:
                            all_symbols[symbol_name] = []
                        all_symbols[symbol_name].append(lib_name)
            
            # If decompiled directory is provided, scan for native method declarations
            if decompiled_dir and os.path.exists(decompiled_dir):
                native_methods = self._find_native_methods(decompiled_dir)
                cross_refs['native_methods'] = native_methods
                
                # Try to match methods with symbols
                for method in native_methods:
                    jni_name = self._convert_to_jni_name(method)
                    
                    # Look for exact matches first
                    if jni_name in all_symbols:
                        cross_refs['matched_symbols'][method['signature']] = {
                            'jni_name': jni_name,
                            'libraries': all_symbols[jni_name]
                        }
                    else:
                        # Look for partial matches
                        partial_matches = [sym for sym in all_symbols.keys() if method['method_name'] in sym]
                        if partial_matches:
                            cross_refs['matched_symbols'][method['signature']] = {
                                'jni_name': jni_name,
                                'partial_matches': partial_matches
                            }
                        else:
                            cross_refs['unmatched_methods'].append(method)
                
                # Find unmatched symbols (potential undeclared native functions)
                matched_symbol_names = set()
                for match in cross_refs['matched_symbols'].values():
                    if 'libraries' in match:
                        matched_symbol_names.update(match['libraries'])
                
                cross_refs['unmatched_symbols'] = [
                    sym for sym in all_symbols.keys() 
                    if sym not in matched_symbol_names and 'Java_' in sym
                ]
            
        except Exception as e:
            self.logger.error(f"Cross-reference analysis failed: {e}")
            cross_refs['error'] = str(e)
        
        return cross_refs
    
    def _find_native_methods(self, decompiled_dir: str) -> List[Dict]:
        """Find native method declarations in decompiled Java code."""
        native_methods = []
        
        for root, dirs, files in os.walk(decompiled_dir):
            for file in files:
                if file.endswith('.java'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Find native method declarations
                        native_pattern = re.compile(
                            r'(public|private|protected)?\s*(?:static\s+)?native\s+(\w+)\s+(\w+)\s*\([^)]*\)\s*;',
                            re.MULTILINE
                        )
                        
                        for match in native_pattern.finditer(content):
                            visibility = match.group(1) or 'package'
                            return_type = match.group(2)
                            method_name = match.group(3)
                            
                            # Extract class name from file path
                            rel_path = os.path.relpath(file_path, decompiled_dir)
                            class_path = rel_path.replace('/', '.').replace('.java', '')
                            
                            native_methods.append({
                                'class_name': class_path,
                                'method_name': method_name,
                                'return_type': return_type,
                                'visibility': visibility,
                                'signature': f"{class_path}.{method_name}",
                                'file_path': file_path
                            })
                            
                    except Exception as e:
                        self.logger.warning(f"Error reading {file_path}: {e}")
                        continue
        
        return native_methods
    
    def _convert_to_jni_name(self, method: Dict) -> str:
        """Convert Java method signature to JNI function name."""
        class_name = method['class_name'].replace('.', '_')
        method_name = method['method_name']
        
        # JNI naming convention: Java_<package>_<class>_<method>
        jni_name = f"Java_{class_name}_{method_name}"
        
        return jni_name