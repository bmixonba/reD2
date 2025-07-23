# Prompt Templates and Instructions

This document provides examples of prompt templates and training instructions used in the Security LLM Training Framework.

## Template Categories

The framework uses five main categories of prompt templates to create diverse training samples:

1. **Code Explanation** - Understanding and explaining security code
2. **Vulnerability Analysis** - Analyzing security implications and risks
3. **Usage Guidance** - Appropriate and ethical use of security tools
4. **Technical Details** - Implementation details and prerequisites
5. **Mitigation** - Defensive measures and countermeasures

## Code Explanation Templates

### Template Variations
```
"Explain what this security code does:"
"Analyze the following security module:"
"Describe the functionality of this exploit code:"
"What is the purpose of this security script?"
"Break down this security tool for educational purposes:"
```

### Example Training Pair
```json
{
  "prompt": "Explain what this security code does:\n\n```ruby\nclass MetasploitModule < Msf::Exploit::Remote\n  def initialize(info = {})\n    super(update_info(info,\n      'Name' => 'MS08-067 Microsoft Server Service Relative Path Stack Corruption',\n      'Description' => 'This module exploits a parsing flaw in the path canonicalization code...',\n      'Author' => ['hdm', 'Brett Moore <brett.moore@insomniasec.com>'],\n      'License' => MSF_LICENSE,\n      'References' => [\n        ['CVE', '2008-4250'],\n        ['OSVDB', '49243'],\n        ['MSB', 'MS08-067']\n      ],\n      'DefaultOptions' => {\n        'EXITFUNC' => 'thread'\n      },\n      'Payload' => {\n        'Space' => 400,\n        'BadChars' => \"\\x00\\x0a\\x0d\\x5c\\x5f\\x2f\\x2e\",\n        'StackAdjustment' => -3500\n      }\n    ))\n  end\nend\n```",
  "completion": "This is an exploit module named 'MS08-067 Microsoft Server Service Relative Path Stack Corruption'. This module exploits a parsing flaw in the path canonicalization code of the Microsoft Server Service, targeting a critical vulnerability (CVE-2008-4250) that allows remote code execution. The module is designed to work with payloads up to 400 bytes while avoiding specific bad characters that would break the exploit. This is a well-documented and historically significant vulnerability that was used in the Conficker worm.",
  "type": "code_explanation"
}
```

## Vulnerability Analysis Templates

### Template Variations
```
"Analyze the security implications of this vulnerability:"
"What are the risks associated with this security issue?"
"Explain the impact of this exploit:"
"Describe the attack vector used in this module:"
"What defensive measures should be taken against this threat?"
```

### Example Training Pair
```json
{
  "prompt": "Analyze the security implications of the module 'MS08-067 Microsoft Server Service Relative Path Stack Corruption'",
  "completion": "This vulnerability involves a parsing flaw in the path canonicalization code that allows remote attackers to execute arbitrary code without authentication. Risk level: high. Security patterns involved: buffer_overflow, rce. The vulnerability affects the Server service in Microsoft Windows and can be exploited remotely over SMB. Impact factors: requires network access. This vulnerability was critical because it affected multiple Windows versions and allowed wormable attacks, as demonstrated by Conficker. Associated CVEs: CVE-2008-4250.",
  "type": "vulnerability_analysis"
}
```

## Usage Guidance Templates

### Template Variations
```
"When would you use this security tool?"
"What are the appropriate use cases for this module?"
"How should this exploit be used responsibly?"
"What are the ethical considerations for this tool?"
"In what scenarios is this security technique applicable?"
```

### Example Training Pair
```json
{
  "prompt": "When would you use the exploits module \"MS08-067 Microsoft Server Service Relative Path Stack Corruption\"?",
  "completion": "This module would be used for exploitation purposes, particularly when conducting authorized penetration testing against legacy Windows systems. Educational value: high. This tool should only be used for:\n- Authorized penetration testing\n- Security research and education\n- Vulnerability assessment with proper authorization\n- Legal security auditing activities\n\n⚠️ This is a high-risk tool that requires careful handling and appropriate authorization. It should never be used for malicious purposes or without explicit permission from system owners.",
  "type": "usage_guidance"
}
```

## Technical Details Templates

### Template Variations
```
"Explain the technical approach used in this exploit:"
"What are the prerequisites for this attack?"
"How does this vulnerability work technically?"
"Describe the exploit development process for this issue:"
"What are the technical requirements for this module?"
```

### Example Training Pair
```json
{
  "prompt": "Explain the technical approach used in MS08-067 Microsoft Server Service Relative Path Stack Corruption",
  "completion": "Technical approach: This module exploits a parsing flaw in the path canonicalization code of the Microsoft Server Service, targeting a critical vulnerability that allows remote code execution. Prerequisites: network connectivity, target platform: Windows. Complexity: high (156 lines, 8 methods). Implements: buffer_overflow, rce. The exploit works by sending a specially crafted SMB request that triggers a stack-based buffer overflow in the NetpwPathCanonicalize function. The vulnerability occurs when processing malformed path names in SMB requests, allowing attackers to overwrite the stack and gain control of the instruction pointer.",
  "type": "technical_details"
}
```

## Mitigation Templates

### Template Variations
```
"How can this vulnerability be mitigated?"
"What patches or fixes address this security issue?"
"How can systems be protected against this exploit?"
"What are the best practices to prevent this attack?"
"How should organizations defend against this threat?"
```

### Example Training Pair
```json
{
  "prompt": "How can the MS08-067 vulnerability be mitigated?",
  "completion": "To mitigate MS08-067:\n- Implement proper input validation and bounds checking\n- Use memory-safe programming languages where possible\n- Enable stack canaries and ASLR\n- Keep systems updated with latest security patches\n- Implement network segmentation\n- Use intrusion detection and monitoring\n- Regular security assessments and penetration testing\n\nSpecific to this vulnerability:\n- Apply Microsoft Security Bulletin MS08-067 patch immediately\n- Disable Server service if not required\n- Implement firewall rules to block SMB traffic from untrusted networks\n- Monitor for unusual SMB activity and exploit attempts\n\nReferences available: Multiple sources including Microsoft advisory and CVE database.",
  "type": "mitigation"
}
```

## Ethical Context Templates

All training samples include ethical context to ensure responsible AI development:

### Standard Ethical Preamble
```
"The following is for educational and authorized security research only. This information should only be used for legitimate security testing with proper authorization and legal compliance."
```

### Ethical Context Structure
```json
{
  "ethical_context": {
    "intended_use": "Educational and authorized security testing only",
    "restrictions": [
      "No malicious use",
      "Requires proper authorization", 
      "Legal compliance mandatory",
      "Responsible disclosure principles"
    ],
    "risk_level": "high",
    "educational_value": "high"
  }
}
```

## Instruction Following Format

The fine-tuning script formats training data using instruction-following templates:

### Training Text Format
```
The following is for educational and authorized security research only. This information should only be used for legitimate security testing with proper authorization and legal compliance.

### Instruction:
[PROMPT TEXT]

### Response:
[COMPLETION TEXT]
```

### Example Formatted Training Text
```
The following is for educational and authorized security research only. This information should only be used for legitimate security testing with proper authorization and legal compliance.

### Instruction:
Explain what this security code does:

```ruby
class MetasploitModule < Msf::Exploit::Remote
  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Example Exploit',
      'Description' => 'Educational example...'
    ))
  end
end
```

### Response:
This is an exploit module that demonstrates basic Metasploit module structure for educational purposes. The module inherits from the Remote exploit class and defines metadata including name, description, and other configuration parameters...
```

## Template Distribution

The default distribution for generating training samples:

- **Code Explanation**: 30% - Understanding security code
- **Vulnerability Analysis**: 25% - Risk assessment and impact
- **Usage Guidance**: 20% - Ethical use and appropriate scenarios  
- **Technical Details**: 15% - Implementation specifics
- **Mitigation**: 10% - Defensive measures

This distribution can be customized using the `prepare_security_corpus.py` script.

## Customization Guidelines

### Adding New Templates

1. **Define Template Category**: Create a new category in the template dictionary
2. **Add Variations**: Provide multiple prompt variations for diversity
3. **Implement Generator**: Create a generation function for the template type
4. **Update Distribution**: Adjust the template distribution as needed

### Template Quality Guidelines

- **Clear Instructions**: Prompts should be unambiguous and specific
- **Educational Focus**: Emphasize learning and understanding
- **Ethical Context**: Include appropriate disclaimers and restrictions
- **Technical Accuracy**: Ensure completions are technically correct
- **Appropriate Scope**: Keep responses focused and relevant

### Security Considerations

- **No Actual Exploits**: Avoid including working exploit code
- **Educational Disclaimers**: Always include ethical usage guidance
- **Risk Awareness**: Clearly communicate risk levels
- **Authorization Emphasis**: Stress the need for proper authorization
- **Legal Compliance**: Ensure all content promotes legal use

## Example Complete Training Sample

```json
{
  "id": "sec_a1b2c3d4e5f6g7h8",
  "created_at": "2024-01-15T10:30:00Z",
  "template_type": "code_explanation",
  "prompt": "Explain what this security code does:\n\n```ruby\nclass MetasploitModule < Msf::Exploit::Remote\n  def initialize(info = {})\n    super(update_info(info,\n      'Name' => 'HTTP Header Injection',\n      'Description' => 'Educational example of header injection vulnerability',\n      'Author' => ['Educational Example'],\n      'License' => 'Educational Use Only'\n    ))\n  end\nend\n```",
  "completion": "This is an exploit module named 'HTTP Header Injection' designed for educational purposes. The module demonstrates how header injection vulnerabilities can be structured in the Metasploit framework. This type of vulnerability occurs when user input is improperly validated before being included in HTTP response headers, potentially allowing attackers to manipulate response headers or inject additional headers. The module inherits from Msf::Exploit::Remote, indicating it targets remote services over a network connection.",
  "prompt_length": 345,
  "completion_length": 512,
  "source_metadata": {
    "category": "exploits",
    "complexity": "low", 
    "risk_level": "medium",
    "tags": ["exploits", "http", "injection", "educational"]
  },
  "ethical_context": {
    "intended_use": "Educational and authorized security testing only",
    "restrictions": [
      "No malicious use",
      "Requires proper authorization",
      "Legal compliance mandatory",
      "Responsible disclosure principles"
    ],
    "risk_level": "medium",
    "educational_value": "high"
  },
  "code_included": true,
  "vulnerability_focused": false,
  "ethical_guidance": false,
  "technical_focused": false,
  "mitigation_focused": false,
  "validated": true,
  "source_dataset": "metasploit_dataset.jsonl"
}
```