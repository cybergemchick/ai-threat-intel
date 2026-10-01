# AI Security Incident Tracker

A curated, MITRE ATLAS-mapped catalog of publicly documented AI/ML security incidents — maintained by [CyberGemChick](https://github.com/cybergemchick).

**Purpose:** Give AI red teams, defenders, and researchers a structured reference of real-world AI attacks to inform threat modeling, red team scenario planning, and AI risk assessments.

---

## Coverage

**27 documented incidents (2023–2025)**: 10 CRITICAL · 14 HIGH · 3 MEDIUM. Each one is mapped to [MITRE ATLAS v5.6.0](https://atlas.mitre.org/) and the [OWASP Top 10 for LLM Applications v1.1](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

| Category | Count | Incidents | OWASP LLM IDs |
|----------|-------|-----------|---------------|
| Prompt Injection & Jailbreak (direct, indirect, system prompt extraction) | 8 | INC-002, 005, 009, 014, 015, 017, 020, 023 | LLM01, LLM02, LLM06 |
| Agentic AI Exploitation & Misuse | 4 | INC-011, 021, 022, 027 | LLM01, LLM08 |
| AI Supply Chain Compromise | 2 | INC-024, 025 | LLM05, LLM08 |
| Training Data Poisoning & Backdoors | 2 | INC-012, 026 | LLM03 |
| Data Leakage & Model Extraction | 4 | INC-001, 003, 006, 008 | LLM03, LLM06, LLM10 |
| Adversarial Evasion | 1 | INC-004 | — |
| AI-Enabled Fraud, Influence Ops & Criminal LLMs | 4 | INC-007, 013, 016, 018 | LLM02 |
| Bias & Hallucination | 2 | INC-010, 019 | LLM09 |

### What's new in v2.1.0

- **5 new 2025 incidents:** EchoLeak zero-click Copilot exfiltration (CVE-2025-32711), the Amazon Q Developer wiper-prompt supply chain compromise, the s1ngularity Nx attack that used victims' own AI CLIs to hunt for secrets, the 250-document pretraining-poisoning result, and GTG-1002, the first reported AI-orchestrated espionage campaign.
- **ATLAS mappings audited:** all 27 incidents were checked against the official [`mitre-atlas/atlas-data`](https://github.com/mitre-atlas/atlas-data) release and moved to current technique and sub-technique IDs. Official names now live in `atlas_techniques.json`.
- **Data-quality test suite:** `pytest` checks the schema, ID order, ATLAS/OWASP ID validity and reference URLs, so a bad mapping fails the tests instead of shipping.

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

Generated with `python view_incidents.py --format atlas`. Names come from MITRE ATLAS v5.6.0.

| Technique | Name | Incidents |
|-----------|------|-----------|
| AML.T0010.001 | AI Supply Chain Compromise: AI Software | INC-024 |
| AML.T0011.001 | User Execution: Malicious Package | INC-025 |
| AML.T0015 | Evade AI Model | INC-004 |
| AML.T0016 | Obtain Capabilities | INC-016 |
| AML.T0018.000 | Manipulate AI Model: Poison AI Model | INC-012, INC-026 |
| AML.T0020 | Poison Training Data | INC-012, INC-026 |
| AML.T0024 | Exfiltration via AI Inference API | INC-008 |
| AML.T0024.002 | Exfiltration via AI Inference API: Extract AI Model | INC-006 |
| AML.T0043 | Craft Adversarial Data | INC-004, INC-014 |
| AML.T0043.004 | Craft Adversarial Data: Insert Backdoor Trigger | INC-012, INC-026 |
| AML.T0048 | External Harms | INC-001, INC-003, INC-007, INC-010, INC-013, INC-016, INC-018, INC-019 |
| AML.T0051 | LLM Prompt Injection | INC-014 |
| AML.T0051.000 | LLM Prompt Injection: Direct | INC-002, INC-009 |
| AML.T0051.001 | LLM Prompt Injection: Indirect | INC-005, INC-011, INC-015, INC-017, INC-020, INC-021, INC-022, INC-023 |
| AML.T0052.000 | Phishing: Spearphishing via Social Engineering LLM | INC-016, INC-018 |
| AML.T0052.001 | Phishing: Deepfake-Assisted Phishing | INC-007 |
| AML.T0053 | AI Agent Tool Invocation | INC-011, INC-021, INC-022, INC-024, INC-025, INC-027 |
| AML.T0054 | LLM Jailbreak | INC-002, INC-009, INC-014, INC-027 |
| AML.T0055 | Unsecured Credentials | INC-025 |
| AML.T0056 | Extract LLM System Prompt | INC-002, INC-009 |
| AML.T0057 | LLM Data Leakage | INC-003, INC-008, INC-020, INC-023 |
| AML.T0066 | Retrieval Content Crafting | INC-005, INC-015 |
| AML.T0077 | LLM Response Rendering | INC-020, INC-023 |
| AML.T0080.000 | AI Agent Context Poisoning: Memory | INC-017 |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | INC-022 |
| AML.T0088 | Generate Deepfakes | INC-007, INC-013 |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | INC-024 |
| AML.T0102 | Generate Malicious Commands | INC-027 |
| AML.T0103 | Deploy AI Agent | INC-027 |
| AML.T0112.000 | Machine Compromise: Local AI Agent | INC-025 |

## Contributing

To add an incident:
1. Ensure it is **publicly reported** (news, academic paper, vendor disclosure, or CVE)
2. Follow the schema above
3. Include at least one reference URL
4. Map to ATLAS techniques (use IDs from the official [atlas-data](https://github.com/mitre-atlas/atlas-data) release and add new ones to `atlas_techniques.json`) and OWASP LLM Top 10
5. Run `python -m pytest -q` before opening a PR

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AI Incident Database](https://incidentdatabase.ai/)
- [AVID — AI Vulnerability Database](https://avidml.org/)
