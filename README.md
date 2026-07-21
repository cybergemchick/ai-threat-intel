# AI Security Incident Tracker

A curated, MITRE ATLAS-mapped catalog of publicly documented AI/ML security incidents — maintained by [CyberGemChick](https://github.com/cybergemchick).

**Purpose:** Give AI red teams, defenders, and researchers a structured reference of real-world AI attacks to inform threat modeling, red team scenario planning, and AI risk assessments.

---

## Coverage

14 documented incidents across categories:

| Category | Count | OWASP LLM IDs |
|----------|-------|--------------|
| Prompt Injection / System Prompt Extraction | 4 | LLM01, LLM06 |
| Data Leakage & Privacy Breach | 3 | LLM03, LLM06 |
| Adversarial Evasion Attacks | 3 | LLM01 |
| Model Theft / Extraction | 1 | LLM10 |
| AI-Enabled Fraud / Social Engineering | 2 | LLM02 |
| Algorithmic Bias | 1 | LLM09 |

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

| Technique | Name | Incident IDs |
|-----------|------|-------------|
| AML.T0019 | Backdoor ML Model | INC-012 |
| AML.T0020 | Poison Training Data | INC-012 |
| AML.T0024 | Exfiltrate Training Data | INC-008 |
| AML.T0031 | Adversarial Patch | INC-004, INC-014 |
| AML.T0048 | Societal Harm | INC-001–005, INC-010–011, INC-013–014 |
| AML.T0051 | LLM Prompt Injection | INC-002, INC-005, INC-009, INC-011, INC-014 |
| AML.T0056 | Steal ML Model | INC-006 |
| AML.T0057 | Exfiltrate Via Cyber | INC-003, INC-008 |
| AML.T0058 | Manipulate ML System | INC-007, INC-013 |

## Contributing

To add an incident:
1. Ensure it is **publicly reported** (news, academic paper, vendor disclosure, or CVE)
2. Follow the schema above
3. Include at least one reference URL
4. Map to ATLAS techniques and OWASP LLM Top 10

## References

- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [AI Incident Database](https://incidentdatabase.ai/)
- [AVID — AI Vulnerability Database](https://avidml.org/)
