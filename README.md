# MobileGPT
A tool for automated analysis of APKs to identify dependencies, de-obfuscate gross code, identify interesting files and their semantics, and generate suggestions for frida hooks.

## Features

### File-Level APK Metadata Extraction
MobileGPT now includes comprehensive file-level metadata extraction capabilities that analyze all files within an APK and provide detailed information about:

- **File Type Detection**: Uses MIME type detection and magic value analysis to identify file types
- **Base64 Content Analysis**: Detects and analyzes base64 encoded content within files
- **File Size Collection**: Provides size information for all files
- **Cross-Reference Analysis**: Maps usage relationships between files in code and assets
- **Comprehensive Metadata**: Includes checksums, file extensions, and detailed type information

## Installation

1. Clone the repository:
```bash
git clone https://github.com/bmixonba/MobileGPT.git
cd MobileGPT
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic APK Analysis

```python
from utils.apk import APKUtils

# Initialize with an APK file
apk_utils = APKUtils('path/to/your/app.apk')

# Extract comprehensive file metadata
metadata = apk_utils.get_file_metadata()

# Print metadata for a specific file
print(metadata['assets/config.json'])
```

### File Type Filtering

```python
# Get all PNG images
png_files = apk_utils.get_files_by_type('image/png')
print(f"Found {len(png_files)} PNG files")

# Get all files with base64 content
base64_files = apk_utils.get_files_with_base64()
print(f"Found {len(base64_files)} files containing base64 data")
```

### Summary Statistics

```python
# Get overall statistics about the APK contents
stats = apk_utils.get_summary_statistics()
print(f"Total files: {stats['total_files']}")
print(f"Total size: {stats['total_size_bytes']} bytes")
print(f"Files with base64: {stats['files_with_base64']}")
print(f"File types: {stats['files_by_type']}")
```

### Metadata Structure

Each file's metadata includes:

```python
{
    'size': 1024,  # File size in bytes
    'type_info': {
        'mime_type': 'application/json',
        'magic_type': 'JSON document',
        'extension': '.json'
    },
    'base64_analysis': {
        'has_base64': True,
        'base64_strings': [
            {
                'string': 'SGVsbG8gV29ybGQ=',
                'decoded_size': 11,
                'position': 45
            }
        ],
        'base64_percentage': 15.2
    },
    'references': {
        'code_references': ['classes.dex'],
        'asset_references': ['assets/other_file.txt'],
        'manifest_references': []
    },
    'checksum': 'a1b2c3d4e5f6...'
}
```

## Dependencies

- `androguard`: APK analysis and DEX file parsing
- `python-magic`: File type detection using libmagic
- Standard Python libraries for base64 detection and file analysis

## Testing

Run the test suite to verify functionality:

```bash
python -m pytest tests/
# or
python tests/test_apk.py
```

## Contributing

Contributions are welcome! Please ensure that new features include appropriate tests and documentation.
