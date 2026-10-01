# AI Security Incident Tracker

A curated, MITRE ATLAS-mapped catalog of publicly documented AI/ML security incidents, maintained by [CyberGemChick](https://github.com/cybergemchick).

**Purpose:** Give AI red teams, defenders, and researchers a structured reference of real-world AI attacks to inform threat modeling, red team scenario planning, and AI risk assessments.

---

## Coverage

**27 documented incidents (2016 to 2025)**: 8 critical, 16 high, 3 medium. Every incident is mapped to [MITRE ATLAS v5.6.0](https://atlas.mitre.org/) and, where it applies, the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/). Every entry links to at least one public source.

| Category | Count | Incidents | OWASP LLM IDs |
|----------|-------|-----------|---------------|
| Prompt Injection and Jailbreaks (direct, indirect, system prompt extraction) | 6 | INC-002, INC-005, INC-014, INC-017, INC-020, INC-023 | LLM01, LLM02, LLM05, LLM07 |
| Agentic AI Exploitation | 3 | INC-011, INC-015, INC-027 | LLM01, LLM02, LLM06 |
| AI Supply Chain Compromise | 4 | INC-021, INC-022, INC-024, INC-025 | LLM01, LLM03, LLM06 |
| Training Data Poisoning and Backdoors | 2 | INC-012, INC-026 | LLM04 |
| Data Leakage and Model Extraction | 4 | INC-001, INC-003, INC-006, INC-008 | LLM02, LLM10 |
| Adversarial Evasion | 1 | INC-004 | None |
| AI-Enabled Fraud and Abuse (deepfakes, influence ops, criminal LLMs, LLMjacking) | 5 | INC-007, INC-009, INC-013, INC-016, INC-018 | None |
| Bias and Hallucination | 2 | INC-010, INC-019 | LLM09 |

`None` means the incident is outside the scope of the OWASP LLM list: misuse of AI by attackers, deepfakes, or non-LLM machine learning systems.

## Quick Start

```bash
# View all incidents
python view_incidents.py

# Filter by severity
python view_incidents.py --severity CRITICAL

# Filter by ATLAS technique
python view_incidents.py --atlas AML.T0051

# Filter by OWASP category
python view_incidents.py --owasp LLM01

# Search by keyword
python view_incidents.py --search "injection"

# Export as markdown table
python view_incidents.py --format markdown > incident_report.md

# ATLAS coverage table with official technique names
python view_incidents.py --format atlas

# Validate the dataset
pip install pytest && python -m pytest -q
```

## Incident Schema

Each entry in `incidents.json` includes:

```json
{
  "id": "INC-001",
  "date": "2023-03",
  "title": "Incident title",
  "vendor": "Affected vendor",
  "product": "Specific product",
  "summary": "Description of what happened",
  "attack_type": "Attack classification",
  "atlas_techniques": ["AML.T0051"],
  "owasp_llm": ["LLM01", "LLM06"],
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "impact": "Business/technical impact",
  "references": ["URLs to public reporting"],
  "disclosed_by": "Who disclosed it",
  "patch_status": "Current remediation status"
}
```

## How to Use This for Threat Modeling

1. **Scenario planning:** Use incidents as the basis for red team scenarios ("what if INC-007 happened to us?")
2. **Risk assessment:** Map incidents to your own AI surface area using the ATLAS technique column
3. **Defense gap analysis:** Cross-reference `owasp_llm` columns with your current controls
4. **Stakeholder briefings:** Use real incidents to justify AI security investment

## MITRE ATLAS Techniques Referenced

Generated with `python view_incidents.py --format atlas`.

| Technique | Name | Incidents |
|-----------|------|-----------|
| AML.T0005.001 | Create Proxy AI Model: Train Proxy via Replication | INC-004 |
| AML.T0010.001 | AI Supply Chain Compromise: AI Software | INC-021, INC-024 |
| AML.T0010.005 | AI Supply Chain Compromise: AI Agent Tool | INC-022 |
| AML.T0011.001 | User Execution: Malicious Package | INC-025 |
| AML.T0012 | Valid Accounts | INC-009 |
| AML.T0015 | Evade AI Model | INC-004 |
| AML.T0016 | Obtain Capabilities | INC-016 |
| AML.T0018.000 | Manipulate AI Model: Poison AI Model | INC-012, INC-026 |
| AML.T0020 | Poison Training Data | INC-012, INC-026 |
| AML.T0024 | Exfiltration via AI Inference API | INC-008 |
| AML.T0024.002 | Exfiltration via AI Inference API: Extract AI Model | INC-006 |
| AML.T0043 | Craft Adversarial Data | INC-014 |
| AML.T0043.002 | Craft Adversarial Data: Black-Box Transfer | INC-004 |
| AML.T0043.004 | Craft Adversarial Data: Insert Backdoor Trigger | INC-012, INC-026 |
| AML.T0048 | External Harms | INC-001, INC-003, INC-007, INC-010, INC-013, INC-016, INC-018, INC-019 |
| AML.T0048.000 | External Harms: Financial Harm | INC-009 |
| AML.T0049 | Exploit Public-Facing Application | INC-009 |
| AML.T0051.000 | LLM Prompt Injection: Direct | INC-002 |
| AML.T0051.001 | LLM Prompt Injection: Indirect | INC-005, INC-011, INC-015, INC-017, INC-020, INC-023 |
| AML.T0052.000 | Phishing: Spearphishing via Social Engineering LLM | INC-016, INC-018 |
| AML.T0052.001 | Phishing: Deepfake-Assisted Phishing | INC-007 |
| AML.T0053 | AI Agent Tool Invocation | INC-011, INC-025, INC-027 |
| AML.T0054 | LLM Jailbreak | INC-002, INC-011, INC-014, INC-027 |
| AML.T0055 | Unsecured Credentials | INC-025 |
| AML.T0056 | Extract LLM System Prompt | INC-002 |
| AML.T0057 | LLM Data Leakage | INC-003, INC-008, INC-015, INC-020, INC-023 |
| AML.T0061 | LLM Prompt Self-Replication | INC-015 |
| AML.T0066 | Retrieval Content Crafting | INC-005 |
| AML.T0068 | LLM Prompt Obfuscation | INC-011, INC-021 |
| AML.T0077 | LLM Response Rendering | INC-020, INC-023 |
| AML.T0080.000 | AI Agent Context Poisoning: Memory | INC-017 |
| AML.T0081 | Modify AI Agent Configuration | INC-021 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | INC-022 |
| AML.T0088 | Generate Deepfakes | INC-007 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | INC-011, INC-024 |
| AML.T0102 | Generate Malicious Commands | INC-027 |
| AML.T0103 | Deploy AI Agent | INC-024, INC-027 |
| AML.T0104 | Publish Poisoned AI Agent Tool | INC-022 |
| AML.T0112.000 | Machine Compromise: Local AI Agent | INC-025 |

## Contributing

To add an incident:
1. Ensure it is **publicly reported** (news, academic paper, vendor disclosure, or CVE)
2. Follow the schema above
3. Include at least one reference URL
4. Map to ATLAS techniques (use IDs from the official [atlas-data](https://github.com/mitre-atlas/atlas-data) release and add new ones to `atlas_techniques.json`) and OWASP LLM Top 10 (2025 IDs, only where the incident is a vulnerability in an LLM application)
5. Run `python -m pytest -q` before opening a PR

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [AI Incident Database](https://incidentdatabase.ai/)
- [AVID: AI Vulnerability Database](https://avidml.org/)
