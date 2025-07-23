# Dataset Schema Documentation

This document describes the data formats and schemas used throughout the Security LLM Training Framework.

## Raw Metasploit Module Schema

The output from `harvest_metasploit_pocs.py` follows this schema:

```json
{
  "filepath": "string - Full path to the module file",
  "filename": "string - Base filename of the module",
  "relative_path": "string - Path relative to Metasploit root",
  "category": "string - Module category (exploits, auxiliary, post, etc.)",
  "size_bytes": "integer - File size in bytes",
  "line_count": "integer - Number of lines in the file",
  "extracted_at": "string - ISO timestamp of extraction",
  
  "name": "string - Module name",
  "description": "string - Module description", 
  "authors": ["string - List of author names"],
  "license": "string - Module license",
  "platform": "string - Target platform",
  
  "cves": ["string - List of CVE identifiers"],
  "references": ["string - List of reference URLs/papers"],
  "targets": "string - Target information",
  "rank": "string - Exploit rank (low/normal/good/great/excellent)",
  
  "requires_admin": "boolean - Whether admin privileges required",
  "network_required": "boolean - Whether network access required",
  "default_payload": "string - Default payload used",
  "method_count": "integer - Number of Ruby methods defined",
  "security_patterns": ["string - List of detected security patterns"],
  
  "code": "string - Full cleaned module code",
  "code_preview": "string - First 500 characters of code",
  
  "intent": "string - Classified intent (exploitation, reconnaissance, etc.)",
  "complexity": "string - Assessed complexity (low/medium/high)",
  "risk_level": "string - Risk assessment (low/medium/high)",
  "educational_value": "string - Educational value (low/medium/high)",
  "tags": ["string - Generated tags for categorization"],
  
  "training_pairs": [
    {
      "prompt": "string - Training prompt",
      "completion": "string - Expected completion",
      "type": "string - Type of training pair"
    }
  ]
}
```

## Training Corpus Schema

The output from `prepare_security_corpus.py` follows this schema:

```json
{
  "id": "string - Unique sample identifier (sec_[hash])",
  "created_at": "string - ISO timestamp of creation",
  "template_type": "string - Type of prompt template used",
  
  "prompt": "string - Training prompt text",
  "completion": "string - Training completion text",
  "prompt_length": "integer - Character length of prompt",
  "completion_length": "integer - Character length of completion",
  
  "source_metadata": {
    "category": "string - Original module category",
    "complexity": "string - Complexity level",
    "risk_level": "string - Risk assessment",
    "tags": ["string - List of tags"]
  },
  
  "ethical_context": {
    "intended_use": "string - Intended use description",
    "restrictions": ["string - List of usage restrictions"],
    "risk_level": "string - Risk level",
    "educational_value": "string - Educational value assessment"
  },
  
  "code_included": "boolean - Whether code is included in prompt",
  "vulnerability_focused": "boolean - Whether focused on vulnerability analysis",
  "ethical_guidance": "boolean - Whether includes ethical guidance",
  "technical_focused": "boolean - Whether focused on technical details",
  "mitigation_focused": "boolean - Whether focused on mitigation",
  
  "validated": "boolean - Whether sample passed validation",
  "source_dataset": "string - Original dataset filename"
}
```

## Fine-tuning Input Format

The fine-tuning script expects training samples in this format:

```json
{
  "input_ids": [123, 456, 789, ...],
  "attention_mask": [1, 1, 1, ...],
  "labels": [123, 456, 789, ...]
}
```

This is automatically generated from the training corpus format.

## Template Types

The following template types are used for generating training pairs:

### 1. Code Explanation (`code_explanation`)
- **Purpose**: Teach the model to explain security code
- **Prompt Templates**:
  - "Explain what this security code does:"
  - "Analyze the following security module:"
  - "Describe the functionality of this exploit code:"

### 2. Vulnerability Analysis (`vulnerability_analysis`)
- **Purpose**: Teach vulnerability assessment and impact analysis
- **Prompt Templates**:
  - "Analyze the security implications of this vulnerability:"
  - "What are the risks associated with this security issue?"
  - "Explain the impact of this exploit:"

### 3. Usage Guidance (`usage_guidance`)
- **Purpose**: Teach appropriate and ethical use of security tools
- **Prompt Templates**:
  - "When would you use this security tool?"
  - "What are the appropriate use cases for this module?"
  - "How should this exploit be used responsibly?"

### 4. Technical Details (`technical_details`)
- **Purpose**: Teach technical implementation details
- **Prompt Templates**:
  - "Explain the technical approach used in this exploit:"
  - "What are the prerequisites for this attack?"
  - "How does this vulnerability work technically?"

### 5. Mitigation (`mitigation`)
- **Purpose**: Teach defensive measures and countermeasures
- **Prompt Templates**:
  - "How can this vulnerability be mitigated?"
  - "What patches or fixes address this security issue?"
  - "How can systems be protected against this exploit?"

## Category Mappings

### Module Categories
- `exploits` - Direct exploitation modules
- `auxiliary` - Auxiliary and scanning modules
- `post` - Post-exploitation modules
- `payloads` - Payload modules
- `encoders` - Encoder modules
- `nops` - NOP sled modules

### Intent Classifications
- `exploitation` - Direct exploitation of vulnerabilities
- `reconnaissance` - Information gathering and scanning
- `auxiliary_attack` - Supporting attack functions
- `post_exploitation` - Post-compromise activities
- `payload_delivery` - Payload generation and delivery
- `other` - Other/miscellaneous purposes

### Complexity Levels
- `low` - Simple modules (<50 lines, <3 methods)
- `medium` - Moderate complexity (<200 lines, <8 methods)
- `high` - Complex modules (>=200 lines or >=8 methods)

### Risk Levels
- `low` - Low risk, basic functionality
- `medium` - Medium risk, requires privileges or has some security patterns
- `high` - High risk, excellent/great rank or dangerous patterns

### Educational Value
- `low` - Basic educational value
- `medium` - Good educational value with some documentation
- `high` - High educational value with CVEs and references

## Security Patterns

The following security patterns are automatically detected:

- `buffer_overflow` - Buffer overflow vulnerabilities
- `sql_injection` - SQL injection attacks
- `xss` - Cross-site scripting vulnerabilities
- `rce` - Remote code execution vulnerabilities
- `privilege_escalation` - Privilege escalation techniques
- `authentication_bypass` - Authentication bypass methods

## Validation Rules

### Content Validation
- Minimum prompt length: 10 characters
- Minimum completion length: 20 characters
- Maximum prompt length: 2000 characters (configurable)
- Maximum completion length: 4000 characters (configurable)
- No empty content allowed

### Content Filtering
Prohibited content includes:
- Actual malware code
- Zero-day exploits
- Personal information
- Illegal activities
- Harmful instructions

### Ethical Requirements
All training samples must include:
- Educational purpose disclaimer
- Authorization requirements
- Legal compliance notices
- Ethical usage guidelines

## File Formats

### JSONL Format (Recommended)
```
{"field1": "value1", "field2": "value2"}
{"field1": "value3", "field2": "value4"}
```

### JSON Format
```json
[
  {"field1": "value1", "field2": "value2"},
  {"field1": "value3", "field2": "value4"}
]
```

## Example Data Samples

### Raw Module Sample
```json
{
  "filepath": "/tmp/metasploit/modules/exploits/windows/smb/ms08_067_netapi.rb",
  "filename": "ms08_067_netapi.rb",
  "category": "exploits",
  "name": "MS08-067 Microsoft Server Service Relative Path Stack Corruption",
  "description": "This module exploits a parsing flaw in the path canonicalization code...",
  "cves": ["CVE-2008-4250"],
  "rank": "great",
  "security_patterns": ["buffer_overflow", "rce"],
  "complexity": "high",
  "risk_level": "high",
  "educational_value": "high"
}
```

### Training Sample
```json
{
  "id": "sec_a1b2c3d4e5f6g7h8",
  "template_type": "vulnerability_analysis",
  "prompt": "Analyze the security implications of the module 'MS08-067 Microsoft Server Service Relative Path Stack Corruption'",
  "completion": "This vulnerability involves a parsing flaw in the path canonicalization code... Risk level: high. Security patterns involved: buffer_overflow, rce.",
  "ethical_context": {
    "intended_use": "Educational and authorized security testing only",
    "restrictions": ["No malicious use", "Requires proper authorization"]
  }
}
```