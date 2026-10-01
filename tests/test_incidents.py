"""
Data-quality tests for incidents.json.

Run:  python -m pytest -q
"""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(ROOT, "incidents.json")) as f:
    DATA = json.load(f)
with open(os.path.join(ROOT, "atlas_techniques.json")) as f:
    ATLAS = json.load(f)["techniques"]

INCIDENTS = DATA["incidents"]
REQUIRED = [
    "id", "date", "title", "vendor", "product", "summary", "attack_type",
    "atlas_techniques", "owasp_llm", "severity", "impact", "references",
    "disclosed_by", "patch_status",
]
OWASP_V1_1 = {f"LLM{n:02d}" for n in range(1, 11)}
IDS = [i["id"] for i in INCIDENTS]


def test_ids_unique_and_sequential():
    assert len(IDS) == len(set(IDS)), "duplicate incident IDs"
    assert IDS == [f"INC-{n:03d}" for n in range(1, len(IDS) + 1)]


@pytest.mark.parametrize("inc", INCIDENTS, ids=IDS)
def test_schema(inc):
    missing = [k for k in REQUIRED if k not in inc]
    assert not missing, f"{inc['id']} missing {missing}"
    assert re.fullmatch(r"20\d\d-(0[1-9]|1[0-2])", inc["date"])
    assert inc["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


@pytest.mark.parametrize("inc", INCIDENTS, ids=IDS)
def test_atlas_ids_are_real(inc):
    """Every ATLAS ID must exist in the official MITRE ATLAS lookup."""
    assert inc["atlas_techniques"], f"{inc['id']} has no ATLAS mapping"
    for t in inc["atlas_techniques"]:
        assert t in ATLAS, f"{inc['id']}: {t} not in atlas_techniques.json"


@pytest.mark.parametrize("inc", INCIDENTS, ids=IDS)
def test_owasp_ids_valid(inc):
    assert set(inc["owasp_llm"]) <= OWASP_V1_1


@pytest.mark.parametrize("inc", INCIDENTS, ids=IDS)
def test_has_public_reference(inc):
    assert inc["references"], f"{inc['id']} needs at least one reference"
    for ref in inc["references"]:
        assert ref.startswith("https://"), ref


def test_no_duplicate_titles():
    titles = [i["title"].lower() for i in INCIDENTS]
    assert len(titles) == len(set(titles))
