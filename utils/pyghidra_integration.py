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
import binascii
import sys
import json
import pathlib
import logging
import tempfile
import shutil
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

PYGHIDRA_AVAILABLE=False
GHIDRA_API_AVAILABLE = False


# Graceful handling of pyghidra imports

try:
    import pyghidra
    from pyghidra import start, HeadlessPyGhidraLauncher
    PYGHIDRA_AVAILABLE = True
    print(f"pyghidra_integration. import pyghidra PYGHIDRA_AVAILABLE={PYGHIDRA_AVAILABLE}")
    
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
        print(f"GHIDRA_API_AVAILABLE={GHIDRA_API_AVAILABLE}")
        
except ImportError:
    PYGHIDRA_AVAILABLE = False
    GHIDRA_API_AVAILABLE = False
    print(f"PYGHIDRA_AVAILABLE={PYGHIDRA_AVAILABLE}, GHIDRA_API_AVAILABLE={GHIDRA_API_AVAILABLE}")


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
    
    def __init__(self, ghidra_install_dir: Optional[str] = None, library_path: Optional[str] = None):
        """
        Initialize the PyGhidra analyzer.
        
        Args:
            ghidra_install_dir: Path to Ghidra installation directory.
                              If None, uses GHIDRA_INSTALL_DIR environment variable.
        """
        self.logger = logging.getLogger(__name__)
        self.ghidra_install_dir = None
        self.ghidra_install_dir = ghidra_install_dir or os.getenv('GHIDRA_INSTALL_DIR')
        print(f"pyghidra_integration.PyGhidraAnalyzer.__init__.self.ghidra_install_dir={self.ghidra_install_dir}, PYGHIDRA_AVAILABLE={PYGHIDRA_AVAILABLE}, library_path={library_path}")
        self.launcher = None
        self.current_program = None
        self._initialized = False
        self.library_path = library_path
        self.program_context = None
        self.flat_api = None
        self.program = None
        self.decompiler = None
        self.program_info = {}

        
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
            self.launcher = HeadlessPyGhidraLauncher(
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
                       custom_scripts: Optional[List[str]] = None,
                       output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive Ghidra analysis on a shared library.
        
        Args:
            library_path: Path to the shared library file (.so)
            extract_functions: Whether to extract function analysis
            extract_xrefs: Whether to extract cross-references
            extract_strings: Whether to extract string analysis
            custom_scripts: List of Ghidra script paths to execute
            output_path: String to the output directroy.
            
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
            'symbols': [],
            'cross_references': {},
            'strings': {},
            'memory_layout': {},
            'custom_script_results': {},
            'analysis_summary': {}
        }
        
        pyghidra.start()
        cleanup = False

        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        print(f"analyze_library - BEFORE - library_path={library_path}")

        library_path = Path(library_path).resolve()
        print(f"analyze_library - AFTER - library_path={library_path}")
        analyze=True
        verbose=True

        print(f"analyze_library. self.program_context={library_path}")
        

        if not output_path:
            output_path = library_path.with_suffix('.c')

        else:
            output_path = Path(output_path).resolve()
            if output_path.is_dir():
                library_path = library_path.name
                output_path = output_path / f"{library_path}.c"

        output_path.parent.mkdir(parents=True, exist_ok=True)


        if cleanup:
            temp_dir = tempfile.mkdtemp(prefix="ghidra_")
            project_location = temp_dir
            project_name = "temp_project"
        else:
            project_location = None
            project_name = None
        try:

            with pyghidra.open_program(library_path, project_name=project_name, 
                                              project_location=project_location, analyze=analyze) as flat_api:
                        monitor = ConsoleTaskMonitor()
                        program = flat_api.getCurrentProgram()
                        self.current_program = program
                        
                        if extract_functions:
                            results['functions'] = self._extract_functions(program)

                        if extract_xrefs:
                            results['cross_references'] = self._extract_cross_references(program)
                        
                        if extract_strings:
                            results['strings'] = self._extract_ghidra_strings(program)
                        
                        # Extract memory layout and symbols
                        results['symbols'] = self._extract_symbols(program)
                        results['memory_layout'] = self._extract_memory_layout(program)
                        """ 
                        program.getSymbolTable()
                        for s in symbols.getAllSymbols(True):
                            if s.isGlobal():
                                results['symbols'].append(s)

                                print(f"symbols={s}")
                        """ 

                        
                        if verbose:
                            print(f"Program loaded: {program.getName()}")
                            print(f"Architecture: {program.getLanguage().getProcessor().toString()}")
                        
                        decompiler = DecompInterface()
                        decompiler.openProgram(program)
                        
                        function_manager = program.getFunctionManager()
                        functions = list(function_manager.getFunctions(True))

                        # Execute custom scripts if provided
                        if custom_scripts:
                            results['custom_script_results'] = self._execute_custom_scripts(
                                program, custom_scripts
                            )
                        
                        # Generate analysis summary
                        results['analysis_summary'] = self._generate_analysis_summary(results)
                        
                        import datetime
                        results['analysis_timestamp'] = datetime.datetime.now().isoformat()

                        
                        if verbose:
                            print(f"Found {len(functions)} functions")
                        """ 
                        
                        with open(output_path, 'w') as f:
                            f.write(f"// Decompiled using PyGhidra\n")
                            f.write(f"// Program: {program.getName()}\n")
                            f.write(f"// Architecture: {program.getLanguage().getProcessor().toString()}\n\n")
                            
                            successful = 0
                            for function in functions:
                                if function.isExternal():
                                    continue
                                
                                if verbose:
                                    print(f"Decompiling: {function.getName()} @ {function.getEntryPoint()}")
                                
                                results = decompiler.decompileFunction(function, 60, monitor)
                                
                                if results.decompileCompleted():
                                    f.write(f"// Function: {function.getName()}\n")
                                    f.write(f"// Address: {function.getEntryPoint()}\n")
                                    f.write(f"{results.getDecompiledFunction().getC()}\n\n")
                                    successful += 1
                                else:
                                    f.write(f"// Failed to decompile: {function.getName()}\n\n")
                            
                            if verbose:
                                print(f"Successfully decompiled {successful} out of {len(functions)} functions")
                        """ 
                
        finally:
            if cleanup and temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                    if verbose:
                        print(f"Removed temporary project directory: {temp_dir}")
                except Exception as e:
                    if verbose:
                        print(f"Warning: failed to clean up temp directory: {e}")


            """
                

        except Exception as e:
            self.logger.error(f"Ghidra analysis failed for {library_path}: {e}")
            results['error'] = str(e)
        
            """
                
        return results
    
    # def _import_and_analyze(self, library_path: str):
    def _import_and_analyze(self, ghidra, library_path: str):
        """Import binary into Ghidra and run auto-analysis."""
        try:

            self.program_context = pyghidra.open_program(self.library_path, analyze=True)
            print(f"_import_and_analyze. self.program_context={self.program_context}")
            self.flat_api = self.program_context # .__enter__()
            self.program = flat_api.getCurrentProgram()
            from ghidra.app.decompiler import DecompInterface

            self.decompiler = DecompInterface()
            self.decompiler.openProgram(program)
            self.program_info['programName'] = program.getName()
            self.program_info['minAddr'] = program.minAddress
            self.program_info['maxAddr'] = program.maxAddress
            self.program_info['lang'] = program.language

            func_mgr = program.getFunctionManager()
            func_cnt = func_mgr.getFunctionCount()

            ## BEGIN: AI Generated 
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
        
        print(f"extract_function - ENTER")
        try:
            # if not GHIDRA_API_AVAILABLE:
            #    return functions_data
                
            function_manager = program.getFunctionManager()
            functions = function_manager.getFunctions(True)  # True for forward iteration
            
            function_list = []

            print(f"extract_function - ENTER LOOP")
            for func in functions:
                print(f"extract_function - func.getName()={func.getName()}")
                func_info = {
                    'name': func.getName(),
                    'address': str(func.getEntryPoint()),
                    'size': func.getBody().getNumAddresses(),
                    'parameter_count': func.getParameterCount(),
                    'local_variable_count': len(func.getLocalVariables()),
                    'is_external': func.isExternal(),
                    'is_thunk': func.isThunk(),
                    'calling_convention': str(func.getCallingConventionName()),
                    'instructions' : [],
                    'signature': func.getSignature().getPrototypeString()
                }
                
                # Get instruction count
                instruction_count = 0
                listing = program.getListing()
                instructions = listing.getInstructions(func.getBody(), True)
                """
                code_units = listing.getInstructions(func.getBody(), True)
                for code_unit in code_units:
                    if isinstance(code_unit, ghidra.program.model.listing.Instruction):
                        instruction_count += 1
                        assembly_string = code_unit.toString()
                        instruction_bytes = code_unit.getBytes()
                        binary_rep = binascii.hexlify(instruction_bytes).decode('ascii')
                        func_info['instructions'].append((assembly_string, instruction_bytes, binary_rep))
                """

                instruction_count = 0
                for i in instructions:
                    assembly_string = i.toString()
                    instruction_bytes = i.getBytes()
                    binary_rep = binascii.hexlify(instruction_bytes).decode('ascii')
                    func_info['instructions'].append((assembly_string, binary_rep))
                    instruction_count += 1
                #    if isinstance(code_unit, Instruction):
                func_info['instruction_count'] = instruction_count
                print(f"extract_function.instruction_count={instruction_count}")
                
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
            # if not GHIDRA_API_AVAILABLE:
            #    return xrefs_data
                
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
            # if not GHIDRA_API_AVAILABLE:
            #    return strings_data
                
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
        print(f"_extract_symbols - ENTER")
        symbols_data = {
            'global_symbols': [],
            'local_symbols': [],
            'external_symbols': [],
            'symbol_statistics': {}
        }
        
        try:
            # if not GHIDRA_API_AVAILABLE:
            #   print(f"_extract_symbols - EARLY EXIT - GHIDRA_API_AVAILABLE={GHIDRA_API_AVAILABLE}!!!")
            #    return symbols_data
                
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
            # if not GHIDRA_API_AVAILABLE:
            #    return memory_data
                
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


def get_analyzer_instance(ghidra_install_dir: Optional[str] = None, library_path: Optional[str] = None) -> PyGhidraAnalyzer:
    """
    Factory function to get a PyGhidraAnalyzer instance.
    
    Args:
        ghidra_install_dir: Optional path to Ghidra installation
        
    Returns:
        PyGhidraAnalyzer instance
    """
    return PyGhidraAnalyzer(ghidra_install_dir=ghidra_install_dir, library_path=library_path)


def check_pyghidra_availability() -> Tuple[bool, str]:
    """
    Check if pyghidra is available and properly configured.
    
    Returns:
        Tuple of (is_available, status_message)
    """
    if not PYGHIDRA_AVAILABLE:
        return False, "pyghidra package not installed"
    
    install_dir = os.getenv('GHIDRA_INSTALL_DIR')
    print(f"check_pyghidra_availability - install_dir: {install_dir}")
    if not install_dir:
        return False, "GHIDRA_INSTALL_DIR environment variable not set"
    
    if not os.path.exists(install_dir):
        return False, f"Ghidra installation directory not found: {install_dir}"
    
    try:
        analyzer = PyGhidraAnalyzer(install_dir)
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

    print(f"analyze_with_pyghidra. library_path={library_path}")
    analyzer = get_analyzer_instance(library_path=library_path)
    results = analyzer.analyze_library(library_path=library_path, **kwargs)
    with open("libopvpnutil.analysis.json" ,"w") as f:
        json.dump(results, f)
    # print(f"analyze_with_pyghidra. results={results}")
    return results

def test_pyghidra():
    """ """
    # lib_path = "/media/conntrack/Seagate1/git/vpn-osint2/VPNSuperUnlimitedProxy/SourceArm/lib/arm64-v8a/libtnccs.so"
    lib_path = "/media/conntrack/Seagate1/git/reD2/utils/TurboVPN/lib/libopvpnutil.so"
    print(f"test_pyghidra. lib_path={lib_path}")
    pyghidra_analyzer = analyze_with_pyghidra(lib_path)
    # pyghidra_analyzer.analyze_library(lib_path)

def main():
    """"""
    test_pyghidra()

if __name__ == '__main__':
    main()
