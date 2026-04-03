#!/usr/bin/env python3
"""Quick test to verify model-aware template handling."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# Import after path setup
from sbl_audit_gui_v_2000 import (
    _model_to_filename_slug,
    _get_sbl_model_from_workbook,
    get_sbl_template_baseline_path,
    get_master_json_template_latest_path,
)

def test_model_slug():
    """Test model name to filename slug conversion."""
    model = "Geospatial Intelligence Foundation"
    slug = _model_to_filename_slug(model)
    print(f"Model: {model}")
    print(f"Slug: {slug}")
    assert slug == "GEOINT_FD", f"Expected 'GEOINT_FD' but got '{slug}'"
    print("✓ Slug conversion OK")

def test_template_paths():
    """Test template path generation."""
    model = "Geospatial Intelligence Foundation"
    baseline = get_sbl_template_baseline_path(model)
    latest_json = get_master_json_template_latest_path(model)
    
    print(f"Baseline SBL: {baseline}")
    print(f"Latest JSON: {latest_json}")
    
    assert "GEOINT_FD" in str(baseline), f"Model slug not in baseline path: {baseline}"
    assert "GEOINT_FD" in str(latest_json), f"Model slug not in JSON path: {latest_json}"
    print("✓ Template paths OK")

def test_model_extraction():
    """Test extracting model from testing_sbl.xlsx."""
    sbl_path = "tests/testing_sbl.xlsx"
    if Path(sbl_path).exists():
        model = _get_sbl_model_from_workbook(sbl_path)
        print(f"Extracted model from {sbl_path}: {model}")
        assert model == "Geospatial Intelligence Foundation", f"Expected 'Geospatial Intelligence Foundation' but got '{model}'"
        print("✓ Model extraction OK")
    else:
        print(f"⚠ {sbl_path} not found, skipping extraction test")

if __name__ == "__main__":
    try:
        test_model_slug()
        test_template_paths()
        test_model_extraction()
        print("\n✅ All tests passed!")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
