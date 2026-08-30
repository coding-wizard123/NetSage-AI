"""
Test Suite for NetSage AI Rule Checker & Dataset Integrity
"""

import os
import sys
import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from utils import load_cases, validate_dataset
from checker import RuleChecker, run_checker_on_dataset
from pipeline import NetSagePipeline

DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "cases.csv"))

def test_dataset_integrity():
    """Verify cases.csv contains 30 valid cases and covers all 8 domains."""
    cases = load_cases(DATA_PATH)
    assert len(cases) >= 30, f"Expected at least 30 cases, found {len(cases)}"
    
    validation = validate_dataset(cases)
    assert validation["is_valid"], f"Dataset validation failed: {validation}"
    assert len(validation["missing_required_domains"]) == 0, f"Missing domains: {validation['missing_required_domains']}"

def test_rule_checker_accuracy():
    """Verify that deterministic rule checker matches all 30 benchmark cases."""
    cases = load_cases(DATA_PATH)
    results = run_checker_on_dataset(cases)
    
    unmatched = [r for r in results if not r["rule_matched"]]
    assert len(unmatched) == 0, f"Unmatched cases in rule engine: {[u['case_id'] for u in unmatched]}"
    
    # Verify each case has valid fix steps and confidence >= 0.90
    for r in results:
        assert r["confidence"] >= 0.90
        assert len(r["fix_steps"]) > 0
        assert len(r["evidence"]) > 0

def test_pipeline_execution():
    """Verify that full pipeline executes and computes metrics properly."""
    pipeline = NetSagePipeline(DATA_PATH)
    eval_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "test_eval_output.json"))
    
    summary = pipeline.run_all(eval_file)
    assert summary["total_cases"] == 30
    assert summary["rule_engine_match_rate_pct"] == 100.0
    assert summary["human_corrected_count"] == 5
    assert summary["human_agreement_rate_pct"] > 80.0
    
    if os.path.exists(eval_file):
        os.remove(eval_file)
