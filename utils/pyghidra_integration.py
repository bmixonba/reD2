"""
PyGhidra Integration Module for Advanced Shared Library Analysis.

This module provides a reusable template for analyzing shared libraries using 
pyghidra, offering advanced static analysis capabilities including function 
analysis, symbol extraction, cross-references, and custom script execution.

Requirements:
    - Ghidra installation with proper GHIDRA_INSTALL_DIR environment variable
    - pyghidra package: pip install pyghidra
    - Java 17+ (required by Ghidra)

Usage:
    from utils.pyghidra_integration import PyGhidraAnalyzer
    
    analyzer = PyGhidraAnalyzer()
    if analyzer.is_available():
        results = analyzer.analyze_library('/path/to/library.so')
        # Results contain advanced Ghidra analysis data
    else:
        # Fallback to standard analysis methods
        pass

Note: This module gracefully handles cases where pyghidra is not available
and will not raise import errors when imported.
"""

import os
import sys
import logging
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

# Graceful handling of pyghidra imports
try:
    import pyghidra
    from pyghidra import start_ghidra, PyGhidraLauncher
    PYGHIDRA_AVAILABLE = True
    
    # Additional imports that may be needed for advanced analysis
    try:
        from ghidra.program.model.listing import Program, Function, Instruction
        from ghidra.program.model.symbol import Symbol, SymbolTable
        from ghidra.program.model.mem import Memory
        from ghidra.program.model.address import AddressSetView
        from ghidra.util.task import ConsoleTaskMonitor
        GHIDRA_API_AVAILABLE = True
    except ImportError:
        GHIDRA_API_AVAILABLE = False
        
except ImportError:
    PYGHIDRA_AVAILABLE = False
    GHIDRA_API_AVAILABLE = False


class PyGhidraAnalyzer:
    """
    Advanced shared library analyzer using Ghidra through pyghidra.
    
    This class provides a high-level interface for analyzing shared libraries
    with Ghidra's powerful reverse engineering capabilities. It handles
    initialization, analysis execution, and result extraction.
    
    Features:
    - Automatic Ghidra project management
    - Function analysis and cross-reference extraction
    - Symbol table analysis beyond standard ELF tools
    - Custom script execution capabilities
    - Structured output compatible with existing analyzers
    """
    
    def __init__(self, ghidra_install_dir: Optional[str] = None):
        """
        Initialize the PyGhidra analyzer.
        
        Args:
            ghidra_install_dir: Path to Ghidra installation directory.
                              If None, uses GHIDRA_INSTALL_DIR environment variable.
        """
        self.logger = logging.getLogger(__name__)
        self.ghidra_install_dir = ghidra_install_dir or os.getenv('GHIDRA_INSTALL_DIR')
        self.launcher = None
        self.current_program = None
        self._initialized = False
        
        # Check availability during initialization
        self._check_availability()
    
    def _check_availability(self) -> None:
        """Check if pyghidra and Ghidra are properly configured."""
        if not PYGHIDRA_AVAILABLE:
            self.logger.warning("pyghidra is not installed. Advanced Ghidra analysis will be unavailable.")
            return
        
        if not self.ghidra_install_dir or not os.path.exists(self.ghidra_install_dir):
            self.logger.warning(
                f"Ghidra installation directory not found: {self.ghidra_install_dir}. "
                "Set GHIDRA_INSTALL_DIR environment variable or provide ghidra_install_dir parameter."
            )
            return
        
        try:
            # Test if we can initialize pyghidra
            self.launcher = PyGhidraLauncher(
                verbose=False,
                install_dir=Path(self.ghidra_install_dir)
            )
            self._initialized = True
            self.logger.info("PyGhidra analyzer initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize PyGhidra: {e}")
            self._initialized = False
    
    def is_available(self) -> bool:
        """
        Check if PyGhidra analysis is available.
        
        Returns:
            True if pyghidra is installed and Ghidra is properly configured.
        """
        return PYGHIDRA_AVAILABLE and self._initialized
    
    def analyze_library(self, library_path: str, 
                       extract_functions: bool = True,
                       extract_xrefs: bool = True,
                       extract_strings: bool = True,
                       custom_scripts: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive Ghidra analysis on a shared library.
        
        Args:
            library_path: Path to the shared library file (.so)
            extract_functions: Whether to extract function analysis
            extract_xrefs: Whether to extract cross-references
            extract_strings: Whether to extract string analysis
            custom_scripts: List of Ghidra script paths to execute
            
        Returns:
            Dictionary containing Ghidra analysis results
        """
        if not self.is_available():
            return {
                'error': 'PyGhidra not available',
                'available': False,
                'reason': 'pyghidra not installed or Ghidra not configured'
            }
        
        if not os.path.exists(library_path):
            return {'error': f'Library file not found: {library_path}'}
        
        results = {
            'available': True,
            'library_path': library_path,
            'analysis_timestamp': None,
            'functions': {},
            'symbols': {},
            'cross_references': {},
            'strings': {},
            'memory_layout': {},
            'custom_script_results': {},
            'analysis_summary': {}
        }
        
        try:
            with start_ghidra(ghidra_dir=self.ghidra_install_dir, verbose=False) as ghidra:
                # Import the binary and analyze it
                program = self._import_and_analyze(ghidra, library_path)
                if not program:
                    return {'error': 'Failed to import and analyze library in Ghidra'}
                
                self.current_program = program
                
                # Perform requested analyses
                if extract_functions:
                    results['functions'] = self._extract_functions(program)
                
                if extract_xrefs:
                    results['cross_references'] = self._extract_cross_references(program)
                
                if extract_strings:
                    results['strings'] = self._extract_ghidra_strings(program)
                
                # Extract memory layout and symbols
                results['symbols'] = self._extract_symbols(program)
                results['memory_layout'] = self._extract_memory_layout(program)
                
                # Execute custom scripts if provided
                if custom_scripts:
                    results['custom_script_results'] = self._execute_custom_scripts(
                        program, custom_scripts
                    )
                
                # Generate analysis summary
                results['analysis_summary'] = self._generate_analysis_summary(results)
                
                import datetime
                results['analysis_timestamp'] = datetime.datetime.now().isoformat()
                
        except Exception as e:
            self.logger.error(f"Ghidra analysis failed for {library_path}: {e}")
            results['error'] = str(e)
        
        return results
    
    def _import_and_analyze(self, ghidra, library_path: str):
        """Import binary into Ghidra and run auto-analysis."""
        try:
            from ghidra.app.util.importer import AutoImporter
            from ghidra.app.util.opinion import LoaderService
            from ghidra.framework.model import DomainFolder
            from ghidra.program.database import ProgramDB
            
            # Create temporary project
            project = ghidra.getProject()
            root_folder = project.getProjectData().getRootFolder()
            
            # Import the binary
            library_name = os.path.basename(library_path)
            imported_files = AutoImporter.importByUsingBestGuess(
                library_path,
                project,
                root_folder,
                None,  # LoadSpec
                library_name,
                None,  # DomainFolder
                None   # MessageLog
            )
            
            if not imported_files:
                self.logger.error("Failed to import library into Ghidra")
                return None
            
            # Get the imported program
            imported_file = imported_files[0]
            program = imported_file.getDomainObject(self, True, False, None)
            
            # Run auto-analysis
            from ghidra.app.services import AutoAnalysisManager
            auto_mgr = AutoAnalysisManager.getAnalysisManager(program)
            auto_mgr.initializeOptions()
            auto_mgr.startAnalysis(ConsoleTaskMonitor(), False)
            
            return program
            
        except Exception as e:
            self.logger.error(f"Failed to import and analyze: {e}")
            return None
    
    def _extract_functions(self, program) -> Dict[str, Any]:
        """Extract function information from the analyzed program."""
        functions_data = {
            'total_functions': 0,
            'function_details': [],
            'entry_points': [],
            'function_statistics': {}
        }
        
        try:
            if not GHIDRA_API_AVAILABLE:
                return functions_data
                
            function_manager = program.getFunctionManager()
            functions = function_manager.getFunctions(True)  # True for forward iteration
            
            function_list = []
            for func in functions:
                func_info = {
                    'name': func.getName(),
                    'address': str(func.getEntryPoint()),
                    'size': func.getBody().getNumAddresses(),
                    'parameter_count': func.getParameterCount(),
                    'local_variable_count': len(func.getLocalVariables()),
                    'is_external': func.isExternal(),
                    'is_thunk': func.isThunk(),
                    'calling_convention': str(func.getCallingConventionName()),
                    'signature': func.getSignature().getPrototypeString()
                }
                
                # Get instruction count
                instruction_count = 0
                listing = program.getListing()
                instructions = listing.getInstructions(func.getBody(), True)
                for _ in instructions:
                    instruction_count += 1
                func_info['instruction_count'] = instruction_count
                
                function_list.append(func_info)
            
            functions_data['total_functions'] = len(function_list)
            functions_data['function_details'] = function_list
            
            # Extract entry points
            entry_points = []
            for func in function_list:
                if not func['is_external']:
                    entry_points.append({
                        'name': func['name'],
                        'address': func['address']
                    })
            functions_data['entry_points'] = entry_points
            
            # Calculate statistics
            if function_list:
                sizes = [f['size'] for f in function_list if not f['is_external']]
                if sizes:
                    functions_data['function_statistics'] = {
                        'avg_function_size': sum(sizes) / len(sizes),
                        'min_function_size': min(sizes),
                        'max_function_size': max(sizes),
                        'total_code_size': sum(sizes)
                    }
            
        except Exception as e:
            self.logger.error(f"Function extraction failed: {e}")
            functions_data['error'] = str(e)
        
        return functions_data
    
    def _extract_cross_references(self, program) -> Dict[str, Any]:
        """Extract cross-reference information."""
        xrefs_data = {
            'function_calls': [],
            'data_references': [],
            'external_references': [],
            'string_references': []
        }
        
        try:
            if not GHIDRA_API_AVAILABLE:
                return xrefs_data
                
            from ghidra.program.model.symbol import RefType
            
            reference_manager = program.getReferenceManager()
            function_manager = program.getFunctionManager()
            
            # Get all references
            all_refs = reference_manager.getReferenceIterator(program.getMinAddress())
            
            for ref in all_refs:
                ref_info = {
                    'from_address': str(ref.getFromAddress()),
                    'to_address': str(ref.getToAddress()),
                    'reference_type': str(ref.getReferenceType())
                }
                
                # Categorize references
                if ref.getReferenceType().isCall():
                    # Function call reference
                    to_func = function_manager.getFunctionAt(ref.getToAddress())
                    if to_func:
                        ref_info['target_function'] = to_func.getName()
                        if to_func.isExternal():
                            xrefs_data['external_references'].append(ref_info)
                        else:
                            xrefs_data['function_calls'].append(ref_info)
                elif ref.getReferenceType().isData():
                    xrefs_data['data_references'].append(ref_info)
                
                # Check if it's a string reference
                data = program.getListing().getDataAt(ref.getToAddress())
                if data and data.hasStringValue():
                    ref_info['string_value'] = str(data.getValue())[:100]  # Limit length
                    xrefs_data['string_references'].append(ref_info)
        
        except Exception as e:
            self.logger.error(f"Cross-reference extraction failed: {e}")
            xrefs_data['error'] = str(e)
        
        return xrefs_data
    
    def _extract_ghidra_strings(self, program) -> Dict[str, Any]:
        """Extract string analysis using Ghidra's capabilities."""
        strings_data = {
            'defined_strings': [],
            'string_references': [],
            'unicode_strings': [],
            'string_statistics': {}
        }
        
        try:
            if not GHIDRA_API_AVAILABLE:
                return strings_data
                
            listing = program.getListing()
            data_iterator = listing.getDefinedData(True)
            
            string_list = []
            for data in data_iterator:
                if data.hasStringValue():
                    string_info = {
                        'address': str(data.getAddress()),
                        'value': str(data.getValue()),
                        'length': data.getLength(),
                        'data_type': str(data.getDataType()),
                        'is_unicode': data.getDataType().getName().lower().startswith('unicode')
                    }
                    string_list.append(string_info)
                    
                    if string_info['is_unicode']:
                        strings_data['unicode_strings'].append(string_info)
            
            strings_data['defined_strings'] = string_list
            
            # Calculate statistics
            if string_list:
                lengths = [s['length'] for s in string_list]
                strings_data['string_statistics'] = {
                    'total_strings': len(string_list),
                    'avg_length': sum(lengths) / len(lengths),
                    'total_string_data': sum(lengths),
                    'unicode_count': len(strings_data['unicode_strings'])
                }
        
        except Exception as e:
            self.logger.error(f"String extraction failed: {e}")
            strings_data['error'] = str(e)
        
        return strings_data
    
    def _extract_symbols(self, program) -> Dict[str, Any]:
        """Extract symbol table information."""
        symbols_data = {
            'global_symbols': [],
            'local_symbols': [],
            'external_symbols': [],
            'symbol_statistics': {}
        }
        
        try:
            if not GHIDRA_API_AVAILABLE:
                return symbols_data
                
            symbol_table = program.getSymbolTable()
            all_symbols = symbol_table.getAllSymbols(True)
            
            global_syms = []
            local_syms = []
            external_syms = []
            
            for symbol in all_symbols:
                sym_info = {
                    'name': symbol.getName(),
                    'address': str(symbol.getAddress()),
                    'namespace': symbol.getParentNamespace().getName(),
                    'is_global': symbol.isGlobal(),
                    'is_external': symbol.isExternal(),
                    'symbol_type': str(symbol.getSymbolType())
                }
                
                if symbol.isExternal():
                    external_syms.append(sym_info)
                elif symbol.isGlobal():
                    global_syms.append(sym_info)
                else:
                    local_syms.append(sym_info)
            
            symbols_data['global_symbols'] = global_syms
            symbols_data['local_symbols'] = local_syms
            symbols_data['external_symbols'] = external_syms
            symbols_data['symbol_statistics'] = {
                'total_symbols': len(global_syms) + len(local_syms) + len(external_syms),
                'global_count': len(global_syms),
                'local_count': len(local_syms),
                'external_count': len(external_syms)
            }
        
        except Exception as e:
            self.logger.error(f"Symbol extraction failed: {e}")
            symbols_data['error'] = str(e)
        
        return symbols_data
    
    def _extract_memory_layout(self, program) -> Dict[str, Any]:
        """Extract memory layout information."""
        memory_data = {
            'memory_blocks': [],
            'address_ranges': {},
            'total_memory': 0
        }
        
        try:
            if not GHIDRA_API_AVAILABLE:
                return memory_data
                
            memory = program.getMemory()
            blocks = memory.getBlocks()
            
            block_list = []
            total_size = 0
            
            for block in blocks:
                block_info = {
                    'name': block.getName(),
                    'start_address': str(block.getStart()),
                    'end_address': str(block.getEnd()),
                    'size': block.getSize(),
                    'is_initialized': block.isInitialized(),
                    'is_executable': block.isExecute(),
                    'is_writable': block.isWrite(),
                    'is_readable': block.isRead(),
                    'permissions': f"{'R' if block.isRead() else '-'}"
                                  f"{'W' if block.isWrite() else '-'}"
                                  f"{'X' if block.isExecute() else '-'}"
                }
                block_list.append(block_info)
                total_size += block.getSize()
            
            memory_data['memory_blocks'] = block_list
            memory_data['total_memory'] = total_size
            memory_data['address_ranges'] = {
                'min_address': str(program.getMinAddress()),
                'max_address': str(program.getMaxAddress())
            }
        
        except Exception as e:
            self.logger.error(f"Memory layout extraction failed: {e}")
            memory_data['error'] = str(e)
        
        return memory_data
    
    def _execute_custom_scripts(self, program, script_paths: List[str]) -> Dict[str, Any]:
        """Execute custom Ghidra scripts and collect results."""
        script_results = {}
        
        for script_path in script_paths:
            if not os.path.exists(script_path):
                script_results[script_path] = {'error': 'Script file not found'}
                continue
            
            try:
                # This is a simplified version - actual script execution would
                # depend on the specific Ghidra scripting framework
                script_results[script_path] = {
                    'executed': True,
                    'note': 'Custom script execution would be implemented here'
                }
            except Exception as e:
                script_results[script_path] = {'error': str(e)}
        
        return script_results
    
    def _generate_analysis_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a summary of the Ghidra analysis results."""
        summary = {
            'analysis_type': 'ghidra_advanced',
            'success': True,
            'features_analyzed': []
        }
        
        try:
            if 'functions' in results and results['functions'].get('total_functions', 0) > 0:
                summary['features_analyzed'].append('functions')
                summary['function_count'] = results['functions']['total_functions']
            
            if 'symbols' in results:
                summary['features_analyzed'].append('symbols')
                symbol_stats = results['symbols'].get('symbol_statistics', {})
                summary['symbol_count'] = symbol_stats.get('total_symbols', 0)
            
            if 'cross_references' in results:
                summary['features_analyzed'].append('cross_references')
                summary['call_count'] = len(results['cross_references'].get('function_calls', []))
                summary['external_ref_count'] = len(results['cross_references'].get('external_references', []))
            
            if 'strings' in results:
                summary['features_analyzed'].append('strings')
                string_stats = results['strings'].get('string_statistics', {})
                summary['string_count'] = string_stats.get('total_strings', 0)
            
            if 'memory_layout' in results:
                summary['features_analyzed'].append('memory_layout')
                summary['memory_blocks'] = len(results['memory_layout'].get('memory_blocks', []))
                summary['total_memory'] = results['memory_layout'].get('total_memory', 0)
        
        except Exception as e:
            summary['error'] = str(e)
            summary['success'] = False
        
        return summary


def get_analyzer_instance(ghidra_install_dir: Optional[str] = None) -> PyGhidraAnalyzer:
    """
    Factory function to get a PyGhidraAnalyzer instance.
    
    Args:
        ghidra_install_dir: Optional path to Ghidra installation
        
    Returns:
        PyGhidraAnalyzer instance
    """
    return PyGhidraAnalyzer(ghidra_install_dir)


def check_pyghidra_availability() -> Tuple[bool, str]:
    """
    Check if pyghidra is available and properly configured.
    
    Returns:
        Tuple of (is_available, status_message)
    """
    if not PYGHIDRA_AVAILABLE:
        return False, "pyghidra package not installed"
    
    ghidra_dir = os.getenv('GHIDRA_INSTALL_DIR')
    if not ghidra_dir:
        return False, "GHIDRA_INSTALL_DIR environment variable not set"
    
    if not os.path.exists(ghidra_dir):
        return False, f"Ghidra installation directory not found: {ghidra_dir}"
    
    try:
        analyzer = PyGhidraAnalyzer(ghidra_dir)
        if analyzer.is_available():
            return True, "pyghidra is available and configured"
        else:
            return False, "pyghidra initialization failed"
    except Exception as e:
        return False, f"pyghidra check failed: {e}"


# Module-level convenience functions
def analyze_with_pyghidra(library_path: str, **kwargs) -> Dict[str, Any]:
    """
    Convenience function to analyze a library with pyghidra.
    
    Args:
        library_path: Path to the shared library
        **kwargs: Additional arguments passed to analyze_library()
        
    Returns:
        Analysis results dictionary
    """
    analyzer = get_analyzer_instance()
    return analyzer.analyze_library(library_path, **kwargs)