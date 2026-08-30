"""
NetSage AI - Utility Helper Functions
Dataset validation, data loading, and formatting utilities.
"""

import os
import re
import csv
import json
from typing import Dict, List, Any, Optional

def load_cases(csv_path: str) -> List[Dict[str, Any]]:
    """Loads and validates the cases.csv dataset."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Cases file not found at: {csv_path}")
    
    cases = []
    required_fields = [
        "case_id", "issue_type", "symptom", "topology_note",
        "show_output", "expected_fault", "osi_layer", "concept", "severity"
    ]
    
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row_idx, row in enumerate(reader, start=1):
            # Check required fields
            for field in required_fields:
                if field not in row or row[field] is None or row[field].strip() == "":
                    raise ValueError(f"Missing required field '{field}' at row {row_idx}")
            
            clean_row = {k.strip(): v.strip() for k, v in row.items()}
            cases.append(clean_row)
            
    return cases

def validate_dataset(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Computes summary statistics and verifies coverage of required domains."""
    total_cases = len(cases)
    domains = set(c["concept"] for c in cases)
    osi_layers = set(c["osi_layer"] for c in cases)
    severities = set(c["severity"] for c in cases)
    
    expected_concepts = {"VLAN", "Gateway", "DHCP", "DNS", "Routing", "ACL", "NAT", "Wireless"}
    missing_concepts = expected_concepts - domains
    
    return {
        "total_cases": total_cases,
        "domains_found": sorted(list(domains)),
        "missing_required_domains": sorted(list(missing_concepts)),
        "osi_layers": sorted(list(osi_layers)),
        "severities": sorted(list(severities)),
        "is_valid": total_cases >= 30 and len(missing_concepts) == 0
    }

def format_json_response(data: Any) -> str:
    """Pretty prints JSON string."""
    return json.dumps(data, indent=2)
