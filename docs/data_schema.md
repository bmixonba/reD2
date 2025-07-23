# Security Corpus Data Schema

## Overview

This document describes the standardized data schema used throughout the Security Corpus Harvesting Pipeline. All data sources are normalized to this common format to enable consistent processing, deduplication, and corpus preparation.

## Core Data Structure

### Root Entry Schema

```json
{
  "source": "string",           // Harvester identifier
  "harvested_at": "ISO8601",    // Timestamp of data collection
  "data_type": "string",        // Type classification
  "identifiers": {},            // Unique identifiers object
  "content": {},               // Main content object
  "metadata": {},              // Additional metadata object
  "enrichment": {},            // Added by enrichment process
  "raw_data": {}              // Original source data (optional)
}
```

## Data Types

### Supported Data Types

| Data Type | Description | Primary Sources |
|-----------|-------------|-----------------|
| `cve` | Common Vulnerabilities and Exposures | NVD, MITRE |
| `cwe` | Common Weakness Enumeration | MITRE CWE |
| `mitre_attack` | MITRE ATT&CK Framework | MITRE CTI |
| `metasploit` | Metasploit Framework modules | Rapid7 GitHub |
| `security_report` | Security advisories and reports | Various vendors |
| `security_whitepaper` | Research papers and whitepapers | Academic/Industry |

## Detailed Schemas by Data Type

### CVE (Common Vulnerabilities and Exposures)

```json
{
  "source": "NVD_CVE",
  "data_type": "cve",
  "identifiers": {
    "cve_id": "CVE-YYYY-NNNN",
    "source_identifier": "string",
    "published": "ISO8601",
    "last_modified": "ISO8601"
  },
  "content": {
    "descriptions": {
      "en": "English description",
      "lang_code": "Localized description"
    },
    "problem_types": [
      {
        "cwe_id": "CWE-XXX",
        "description": "Problem type description",
        "lang": "en"
      }
    ],
    "references": [
      {
        "url": "https://example.com/advisory",
        "source": "vendor.com",
        "tags": ["Vendor Advisory", "Third Party Advisory"]
      }
    ]
  },
  "metadata": {
    "cvss_scores": {
      "v3.1": {
        "baseScore": 9.8,
        "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "impactScore": 5.9,
        "exploitabilityScore": 3.9
      }
    },
    "vendor_comments": [],
    "vuln_status": "Published",
    "evaluator_comment": "string",
    "evaluator_solution": "string",
    "evaluator_impact": "string"
  }
}
```

### CWE (Common Weakness Enumeration)

```json
{
  "source": "MITRE_CWE",
  "data_type": "cwe",
  "identifiers": {
    "cwe_id": "CWE-XXX",
    "name": "Weakness name",
    "abstraction": "Base|Variant|Class|Category",
    "status": "Stable|Draft|Deprecated"
  },
  "content": {
    "description": "Primary description",
    "extended_description": "Detailed explanation",
    "relationships": [
      {
        "type": "ChildOf|ParentOf|CanPrecede|CanFollow",
        "target": "CWE-XXX"
      }
    ],
    "applicable_platforms": ["Web", "Database", "Windows", "Linux"],
    "common_consequences": [
      {
        "scope": "Confidentiality|Integrity|Availability",
        "impact": "Impact description"
      }
    ],
    "mitigations": ["Mitigation strategy 1", "Mitigation strategy 2"]
  },
  "metadata": {
    "structure": "Simple|Composite",
    "abstraction_level": "Base|Variant|Class|Category",
    "status": "Stable|Draft|Deprecated",
    "weakness_ordinalities": ["Primary", "Resultant"],
    "detection_methods": ["Static Analysis", "Dynamic Analysis"],
    "taxonomy_mappings": []
  }
}
```

### MITRE ATT&CK

```json
{
  "source": "MITRE_ATTACK",
  "data_type": "mitre_attack",
  "identifiers": {
    "attack_id": "attack-pattern--uuid",
    "name": "Technique name",
    "type": "attack-pattern|intrusion-set|course-of-action",
    "technique_id": "T1234.001",
    "tactic": "initial-access|execution|persistence"
  },
  "content": {
    "description": "Technique description",
    "references": ["https://attack.mitre.org/techniques/T1234/"],
    "platforms": ["Windows", "Linux", "macOS"],
    "kill_chain_phases": [
      {
        "kill_chain_name": "mitre-attack",
        "phase_name": "initial-access"
      }
    ],
    "mitigations": ["Mitigation 1", "Mitigation 2"],
    "detection": "Detection guidance"
  },
  "metadata": {
    "object_type": "attack-pattern|intrusion-set|course-of-action",
    "last_modified": "ISO8601",
    "created": "ISO8601",
    "version": "1.0",
    "deprecated": false,
    "data_sources": ["Process monitoring", "File monitoring"],
    "defense_bypassed": ["Anti-virus", "Host intrusion prevention systems"],
    "permissions_required": ["User", "Administrator"],
    "system_requirements": ["Requirement description"]
  }
}
```

### Metasploit Modules

```json
{
  "source": "METASPLOIT",
  "data_type": "metasploit",
  "identifiers": {
    "relative_path": "modules/exploits/category/module.rb",
    "filename": "module.rb",
    "category": "exploits|auxiliary|post|payloads",
    "extracted_at": "ISO8601"
  },
  "content": {
    "name": "Module name",
    "description": "Module description",
    "authors": ["Author 1", "Author 2"],
    "license": "License type",
    "platform": "Target platform",
    "cves": ["CVE-2024-1234"],
    "references": ["https://example.com/advisory"],
    "code": "Full module code",
    "code_preview": "First 500 characters..."
  },
  "metadata": {
    "size_bytes": 12345,
    "line_count": 250,
    "method_count": 8,
    "rank": "Excellent|Great|Good|Normal|Average|Low|Manual",
    "requires_admin": true,
    "network_required": true,
    "default_payload": "windows/meterpreter/reverse_tcp",
    "security_patterns": ["buffer_overflow", "rce"],
    "complexity": "low|medium|high",
    "risk_level": "low|medium|high",
    "educational_value": "low|medium|high"
  }
}
```

### Security Reports

```json
{
  "source": "BUGTRAQ_SECURITY",
  "data_type": "security_report",
  "identifiers": {
    "report_id": "SR-2024-001",
    "title": "Report title",
    "source": "SecurityFocus|Full Disclosure|OSS-Security",
    "date": "YYYY-MM-DD",
    "author": "Author name"
  },
  "content": {
    "description": "Vulnerability description",
    "vulnerability_type": "RCE|SQL Injection|XSS|Buffer Overflow",
    "affected_systems": ["System 1", "System 2"],
    "cve_references": ["CVE-2024-1234"],
    "mitigation": "Mitigation guidance",
    "references": ["https://example.com/advisory"],
    "disclosure_timeline": {
      "discovered": "YYYY-MM-DD",
      "vendor_notified": "YYYY-MM-DD",
      "patch_released": "YYYY-MM-DD",
      "public_disclosure": "YYYY-MM-DD"
    },
    "technical_details": "Technical explanation",
    "proof_of_concept": "PoC code or description"
  },
  "metadata": {
    "severity": "Critical|High|Medium|Low",
    "exploit_available": true,
    "patch_available": true,
    "public_disclosure": "YYYY-MM-DD",
    "vendor_response": {},
    "impact_assessment": {},
    "researcher_credit": "Researcher name"
  }
}
```

### Security Whitepapers

```json
{
  "source": "SECURITY_WHITEPAPERS",
  "data_type": "security_whitepaper",
  "identifiers": {
    "paper_id": "WP-2024-001",
    "title": "Paper title",
    "authors": ["Author 1", "Author 2"],
    "organization": "Organization name",
    "publication_date": "YYYY-MM-DD",
    "url": "https://example.com/paper.pdf"
  },
  "content": {
    "abstract": "Paper abstract",
    "content_summary": "Summary of content",
    "key_findings": ["Finding 1", "Finding 2"],
    "keywords": ["keyword1", "keyword2"],
    "topics": ["Topic 1", "Topic 2"],
    "related_frameworks": ["NIST", "MITRE ATT&CK"],
    "full_text": "Extracted full text (if available)",
    "sections": [
      {
        "page": 1,
        "content": "Section content",
        "tables": [],
        "figures": []
      }
    ]
  },
  "metadata": {
    "document_type": "Research Paper|Technical Guide|White Paper",
    "pages": 45,
    "language": "English",
    "access_level": "Public|Restricted|Internal",
    "citations": 156,
    "file_format": "PDF",
    "file_size": 2048000,
    "checksum": "sha256_hash",
    "download_date": "ISO8601"
  }
}
```

## Enrichment Schema

### Cross-References

```json
{
  "enrichment": {
    "cross_references": [
      {
        "type": "cve_reference|cwe_reference|attack_technique_reference",
        "target_id": "CVE-2024-1234|CWE-79|T1566.002",
        "source_field": "description|references|mitigations"
      }
    ],
    "related_entries": [
      {
        "type": "shared_platform|content_similarity|technique_similarity",
        "target_id": "entry_identifier",
        "target_type": "cve|cwe|mitre_attack",
        "relationship": "Relationship description"
      }
    ],
    "extracted_entities": {
      "cve_ids": ["CVE-2024-1234"],
      "cwe_ids": ["CWE-79"],
      "attack_techniques": ["T1566.002"],
      "vendors": ["microsoft", "google"],
      "products": ["windows", "chrome"]
    },
    "enriched_at": "ISO8601"
  }
}
```

## Training Sample Schema

### Prompt/Completion Format

```json
{
  "id": "sec_unique_identifier",
  "created_at": "ISO8601",
  "template_type": "code_explanation|vulnerability_analysis|usage_guidance|technical_details|mitigation",
  "source_metadata": {
    "category": "exploits|auxiliary|cve|cwe",
    "complexity": "low|medium|high",
    "risk_level": "low|medium|high",
    "tags": ["tag1", "tag2"]
  },
  "prompt": "Training prompt text",
  "completion": "Expected completion text",
  "code_included": true,
  "vulnerability_focused": true,
  "ethical_guidance": true,
  "technical_focused": true,
  "mitigation_focused": true,
  "ethical_context": {
    "intended_use": "Educational and authorized security testing only",
    "restrictions": [
      "No malicious use",
      "Requires proper authorization",
      "Legal compliance mandatory",
      "Responsible disclosure principles"
    ],
    "risk_level": "low|medium|high",
    "educational_value": "low|medium|high"
  },
  "validated": true,
  "prompt_length": 150,
  "completion_length": 300
}
```

### Template Types

#### Code Explanation
- **Purpose**: Explain what security code does
- **Focus**: Educational understanding of security tools
- **Example Prompt**: "Explain what this security module does:"

#### Vulnerability Analysis
- **Purpose**: Analyze security implications and risks
- **Focus**: Risk assessment and impact analysis
- **Example Prompt**: "Analyze the security implications of this vulnerability:"

#### Usage Guidance
- **Purpose**: Provide ethical usage guidelines
- **Focus**: Appropriate and responsible use
- **Example Prompt**: "When would you use this security tool?"

#### Technical Details
- **Purpose**: Explain technical implementation
- **Focus**: Prerequisites, complexity, and technical approach
- **Example Prompt**: "Explain the technical approach used in this exploit:"

#### Mitigation
- **Purpose**: Provide defense and mitigation strategies
- **Focus**: Protective measures and best practices
- **Example Prompt**: "How can this vulnerability be mitigated?"

## Data Quality Standards

### Required Fields

| Field | CVE | CWE | ATT&CK | Metasploit | Report | Whitepaper |
|-------|-----|-----|--------|------------|--------|------------|
| identifiers.primary_id | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| content.description | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| metadata.risk_level | ✓ | ○ | ○ | ✓ | ✓ | ○ |

Legend: ✓ Required, ○ Optional

### Validation Rules

1. **Identifier Uniqueness**: All primary identifiers must be unique within data type
2. **Content Completeness**: Description field must be non-empty
3. **Date Formats**: All dates must be ISO8601 format
4. **URL Validity**: All reference URLs must be valid
5. **Enum Validation**: All enumerated fields must use valid values

### Quality Metrics

- **Completeness**: Percentage of required fields populated
- **Uniqueness**: Percentage of entries with unique identifiers
- **Reference Validity**: Percentage of valid reference URLs
- **Cross-Reference Accuracy**: Percentage of valid cross-references

## Schema Evolution

### Versioning Strategy

- Schema version included in pipeline configuration
- Backward compatibility maintained for one major version
- Migration scripts provided for breaking changes

### Extension Points

- Additional metadata fields can be added without breaking changes
- New data types can be registered with custom schemas
- Enrichment plugins can add custom enrichment fields

### Future Enhancements

1. **Semantic Tagging**: AI-generated semantic tags and categories
2. **Quality Scoring**: Automated quality assessment scores
3. **Relationship Confidence**: Confidence scores for detected relationships
4. **Multi-language Support**: Enhanced localization and translation fields