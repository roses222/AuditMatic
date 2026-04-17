"""
AuditMatic Utility Module

Utility functions for text processing, version comparison, workbook detection, and common operations.
"""

import re
import json
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd

from config import SYSTEM_COLUMNS, MASTER_SOFTWARE_LIST_PATH, TEMPLATES_DIR
from models import AuditRow, ScanResult, WorkbookSchema

try:
    from openpyxl import load_workbook
    from openpyxl.cell.cell import MergedCell
except ImportError:
    load_workbook = None
    MergedCell = None


# =====================================================================
# Text Normalization Functions
# =====================================================================
def normalize_text(value: Any) -> str:
    """Normalize text: clean whitespace, convert to string."""
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def normalize_header(value: Any) -> str:
    """Normalize header: uppercase normalized text."""
    return normalize_text(value).upper()


def is_x_mark(value: Any) -> bool:
    """Check if value is an X mark indicator."""
    return normalize_text(value).upper() == "X"


# =====================================================================
# Time Functions
# =====================================================================
def today_str() -> str:
    """Return today's date as uppercase string (e.g., '17APR2026')."""
    return datetime.now().strftime("%d%b%Y").upper()


def timestamp_str() -> str:
    """Return ISO timestamp for file naming (e.g., '20260417_143200')."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


# =====================================================================
# Version Comparison Functions
# =====================================================================
def normalize_version(value: str) -> str:
    """Extract semantic version from text (e.g., '3.9.8' from 'Python 3.9.8')."""
    text = normalize_text(value)
    if not text:
        return ""
    match = re.search(r"\d+(?:\.\d+){1,}", text)
    if match:
        return match.group(0)
    return text.lower()


def parse_version_tuple(value: str) -> Tuple[int, ...]:
    """Parse version string into tuple of integers (e.g., (3, 9, 8))."""
    normalized = normalize_version(value)
    if not normalized:
        return tuple()
    parts = [part for part in re.split(r"[^0-9]+", normalized) if part]
    if not parts:
        return tuple()
    return tuple(int(part) for part in parts)


def compare_versions(expected: str, found: str, scan_status: str) -> Tuple[str, str]:
    """
    Compare expected vs found versions and return (status, audit_text).
    
    Args:
        expected: Expected version string
        found: Found/detected version string
        scan_status: Scan result status (PASS, FAIL, WARN)
    
    Returns:
        Tuple of (status, audit_text) for audit result cell
    """
    expected_n = normalize_version(expected)
    found_n = normalize_version(found)
    expected_tuple = parse_version_tuple(expected)
    found_tuple = parse_version_tuple(found)

    if scan_status == "WARN":
        return "WARN", f"WARN | result=NOT_SCANNED | expected={expected_n or 'UNKNOWN'} | found={found or 'NOT_FOUND'}"
    if not found_n:
        return "FAIL", f"FAIL | result=NOT_FOUND | expected={expected_n or 'UNKNOWN'} | found=NOT_FOUND"
    if expected_n and expected_n == found_n:
        return "PASS", f"PASS | result=MATCH | expected={expected_n} | found={found_n}"

    if expected_tuple and found_tuple:
        width = max(len(expected_tuple), len(found_tuple))
        expected_padded = expected_tuple + (0,) * (width - len(expected_tuple))
        found_padded = found_tuple + (0,) * (width - len(found_tuple))
        if found_padded < expected_padded:
            relation = "LOWER_THAN_EXPECTED"
        elif found_padded > expected_padded:
            relation = "HIGHER_THAN_EXPECTED"
        else:
            relation = "MISMATCH"
        return "FAIL", f"FAIL | result={relation} | expected={expected_n or expected} | found={found_n or found}"

    return "FAIL", f"FAIL | result=DIFFERENT | expected={expected_n or expected} | found={found_n or found}"


# =====================================================================
# File Path Extraction
# =====================================================================
def extract_path_from_version_location(version_location: Any) -> str:
    """Extract a filesystem path prefix from a VERSION LOCATIONS string."""
    text = normalize_text(version_location)
    if not text:
        return ""
    match = re.match(r"([A-Za-z]:[\\/].*?)(?=\s*>)", text)
    if match:
        return match.group(1)
    return text


# =====================================================================
# Workbook Format Detection
# =====================================================================
def detect_workbook_format(path: str) -> str:
    """
    Detect if file is Excel, JSON, or CSV format.
    
    Returns:
        One of: 'excel', 'json', 'csv'
    """
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix in ['.xlsx', '.xls']:
        return 'excel'
    elif suffix == '.json':
        return 'json'
    elif suffix == '.csv':
        return 'csv'
    else:
        # Try to infer by content
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(100)
                if content.strip().startswith('{') or content.strip().startswith('['):
                    return 'json'
                elif ',' in content or '\t' in content:
                    return 'csv'
        except:
            pass
    return 'excel'  # default assumption


def detect_header_row_index(path: str, format_type: str) -> int:
    """
    Find the header row index (0-based) by detecting recognizable column names.
    
    Returns:
        0-based row index of header row
    """
    if format_type == 'excel':
        if load_workbook is None:
            return 0
        try:
            wb = load_workbook(path)
            ws = wb.active
            if ws is None:
                return 0
            for idx, row in enumerate(ws.iter_rows(values_only=True), 0):
                headers = [normalize_header(cell) for cell in row if cell]
                # Check if row contains required headers
                if any('SOFTWARE' in h for h in headers) or any('COMPONENT' in h for h in headers):
                    return idx
        except Exception:
            pass
        return 0
    elif format_type == 'json':
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    return 0
        except Exception:
            pass
        return 0
    elif format_type == 'csv':
        try:
            df = pd.read_csv(path, nrows=5)
            return 0
        except Exception:
            pass
        return 0
    return 0


def detect_target_columns(path: str, format_type: str, header_row_idx: int) -> Tuple[List[str], Dict[str, int]]:
    """
    Detect which columns are targets/VMs based on file structure.
    
    Returns:
        Tuple of (target_column_names, column_index_map)
    """
    columns = []
    col_map = {}
    
    if format_type == 'excel':
        if load_workbook is None:
            return [], {}
        try:
            wb = load_workbook(path)
            ws = wb.active
            if ws is None:
                return [], {}
            rows_list = list(ws.iter_rows(values_only=True))
            if not rows_list or header_row_idx >= len(rows_list):
                return [], {}
            
            headers = rows_list[header_row_idx]
            for col_idx, cell in enumerate(headers):
                if cell is None:
                    continue
                col_name = normalize_text(cell)
                if not col_name:
                    continue
                # Target columns are NOT the required headers
                if col_name.upper() not in {'SOFTWARE COMPONENT', 'CURRENT CI VERSION', 'VERSION LOCATIONS', 'SBL BUILD VERSION'}:
                    columns.append(col_name)
                    col_map[col_name] = col_idx
            return columns, col_map
        except Exception:
            pass
    elif format_type == 'json':
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    first_obj = data[0]
                    for key in first_obj.keys():
                        if key.upper() not in {'SOFTWARE COMPONENT', 'CURRENT CI VERSION', 'VERSION LOCATIONS'}:
                            columns.append(key)
                            col_map[key] = len(col_map)
            return columns, col_map
        except Exception:
            pass
    elif format_type == 'csv':
        try:
            df = pd.read_csv(path)
            for col in df.columns:
                if col.upper() not in {'SOFTWARE COMPONENT', 'CURRENT CI VERSION', 'VERSION LOCATIONS'}:
                    columns.append(col)
                    col_map[col] = df.columns.get_loc(col)
            return columns, col_map
        except Exception:
            pass
    
    return columns, col_map


# =====================================================================
# Target Column Resolution
# =====================================================================
def default_target_columns() -> List[str]:
    """Return default/fallback target columns."""
    return list(SYSTEM_COLUMNS)


def resolve_profile_target_columns(payload: Dict[str, Any]) -> List[str]:
    """Resolve target columns from profile payload."""
    schema = payload.get("target_schema", {})
    if isinstance(schema, dict):
        columns = schema.get("target_columns", [])
        if isinstance(columns, list):
            normalized = [normalize_text(item) for item in columns if normalize_text(item)]
            if normalized:
                return normalized

    targets = payload.get("targets", {})
    if isinstance(targets, dict):
        normalized = [normalize_text(item) for item in targets.keys() if normalize_text(item)]
        if normalized:
            return normalized

    return default_target_columns()


def build_target_schema_payload(source_path: str, target_columns: List[str], build_type: str) -> Dict[str, Any]:
    """Build target schema payload for profile storage."""
    return {
        "source_path": source_path,
        "target_columns": [normalize_text(name) for name in target_columns if normalize_text(name)],
        "build_type": infer_build_type(build_type) if build_type else infer_build_type(source_path),
        "legacy_fallback": default_target_columns(),
    }


def infer_build_type(source_text: str) -> str:
    """Infer build type from text (path or filename)."""
    text = normalize_text(source_text).lower()
    if not text:
        return "unknown"
    if "baseline" in text:
        return "baseline"
    if "latest" in text:
        return "latest"
    if "custom" in text or "test" in text:
        return "custom"
    return "unknown"


# =====================================================================
# Header Classification
# =====================================================================
def is_known_non_target_header(header: str) -> bool:
    """Check if header is a known non-target (required) column."""
    normalized = normalize_header(str(header).replace("_", " "))
    if not normalized:
        return True
    known_tokens = (
        "SOFTWARE COMPONENT",
        "CURRENT CI VERSION",
        "VERSION LOCATION",
        "VERSION LOCATIONS",
        "SBL BUILD",
        "AUDIT",
        "DISPLAYED NAME",
        "CM TOOL ID NUMBER",
        "VERSION STATUS",
        "NOTES",
    )
    return any(token in normalized for token in known_tokens)


def pick_record_value(record: Dict[str, Any], candidates: List[str]) -> str:
    """
    Pick first non-empty value from record using candidate field names.
    Tries to match candidate against record keys (normalized).
    """
    normalized = {normalize_header(k): v for k, v in record.items()}
    for candidate in candidates:
        candidate_upper = normalize_header(candidate)
        for key, value in normalized.items():
            if candidate_upper in key:
                return normalize_text(value)
    return ""


def derive_import_target_columns(rows: List[Dict[str, Any]]) -> List[str]:
    """Derive target column names from imported row data."""
    discovered: List[str] = []
    for record in rows:
        target_vms = record.get("target_vms", {})
        if isinstance(target_vms, dict):
            for key in target_vms.keys():
                name = normalize_text(key)
                if name and name not in discovered:
                    discovered.append(name)
        for key in record.keys():
            name = normalize_text(key)
            if not name or is_known_non_target_header(name):
                continue
            if name.lower() == "target_vms":
                continue
            if name not in discovered:
                discovered.append(name)
    return discovered or default_target_columns()


# =====================================================================
# Header Parsing
# =====================================================================
def parse_build_and_audit_headers(headers: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse headers to find SBL Build header and AUDIT header.
    
    Returns:
        Tuple of (sbl_build_header, audit_header)
    """
    sbl_build_col = None
    audit_col = None
    for header in headers:
        n = normalize_header(header)
        if "SBL BUILD" in n and sbl_build_col is None:
            sbl_build_col = header
        if "AUDIT" in n and audit_col is None:
            audit_col = header
    return sbl_build_col, audit_col


# =====================================================================
# Excel Column Auto-fitting
# =====================================================================
def auto_fit_columns(ws, min_width: int = 12, max_width: int = 48) -> None:
    """Auto-fit column widths for readability."""
    from openpyxl.utils import get_column_letter
    for col_idx in range(1, ws.max_column + 1):
        max_len = 0
        for row_idx in range(1, ws.max_row + 1):
            value = ws.cell(row=row_idx, column=col_idx).value
            text = "" if value is None else str(value)
            max_len = max(max_len, len(text))
        ws.column_dimensions[get_column_letter(col_idx)].width = max(min_width, min(max_len + 2, max_width))


# =====================================================================
# Model Key Normalization
# =====================================================================
def normalize_model_key(model_name: Optional[str] = None) -> str:
    """Normalize SBL model name to key format."""
    text = normalize_text(model_name)
    if not text or text.upper() == "UNKNOWN":
        return "GENERAL"
    return text


# =====================================================================
# Path Metadata Derivation (Import Placeholder)
# =====================================================================
def derive_path_metadata(version_location: str) -> Dict[str, str]:
    """
    Derive normalized path metadata for master software list tracking.
    This function is implemented in services/audit_engine.py to avoid circular imports.
    Placeholder here for import statements.
    """
    # This will be imported from services.audit_engine to avoid circular dependencies
    path = normalize_text(version_location)
    return {
        "path": path,
        "coded_path": path,
        "verification_source": "unknown",
    }



# =====================================================================
# Template Path Functions
# =====================================================================
def _model_to_filename_slug(model_name: str) -> str:
    """Convert a model name into the workbook filename slug used by templates."""
    if "Geospatial" in model_name and "Intelligence" in model_name:
        return "GEOINT_FD"
    words = model_name.split()
    if len(words) >= 2:
        return f"{words[0][:6].upper()}_{words[-1][:2].upper()}"
    return model_name[:8].upper()


def get_sbl_template_baseline_path(model_name: Optional[str] = None) -> Path:
    """Get baseline SBL template path for the given model."""
    if model_name is None:
        slug = "GEOINT_FD"  # default fallback
    else:
        slug = _model_to_filename_slug(model_name)
    return TEMPLATES_DIR / f"sbl_template_baseline_{slug}.xlsx"

def get_sbl_template_latest_path(model_name: Optional[str] = None) -> Path:
    """Get latest SBL template path for the given model."""
    if model_name is None:
        slug = "GEOINT_FD"  # default fallback
    else:
        slug = _model_to_filename_slug(model_name)
    return TEMPLATES_DIR / f"sbl_template_latest_{slug}.xlsx"

def get_master_json_template_baseline_path(model_name: Optional[str] = None) -> Path:
    """Get baseline master software list template path."""
    return TEMPLATES_DIR / "master_software_list_template.json"

def get_master_json_template_latest_path(model_name: Optional[str] = None) -> Path:
    """Get latest master software list path."""
    return TEMPLATES_DIR / "master_software_list_latest.json"

# =====================================================================
# Project Structure Initialization
# =====================================================================
def ensure_project_structure() -> None:
    """Create all required project directories if they don't exist."""
    from config import (
        AUDIT_RESULTS_DIR, AUDIT_CHECKLIST_DIR, JSON_DIR, JSON_RESULTS_DIR,
        JSON_CHECKLIST_DIR, JSON_REGISTRY_SNAPSHOTS_DIR, JSON_SCAN_JOBS_DIR,
        PROFILES_DIR, LOGS_DIR, TEMPLATES_DIR, MASTER_SOFTWARE_LIST_PATH,
        MASTER_JSON_TEMPLATE_BASELINE_PATH
    )
    
    for path in [
        AUDIT_RESULTS_DIR,
        AUDIT_CHECKLIST_DIR,
        JSON_DIR,
        JSON_RESULTS_DIR,
        JSON_CHECKLIST_DIR,
        JSON_REGISTRY_SNAPSHOTS_DIR,
        JSON_SCAN_JOBS_DIR,
        PROFILES_DIR,
        LOGS_DIR,
        TEMPLATES_DIR,
    ]:
        path.mkdir(parents=True, exist_ok=True)

    # Initialize master software list if it doesn't exist
    if not MASTER_SOFTWARE_LIST_PATH.exists():
        MASTER_SOFTWARE_LIST_PATH.write_text(
            json.dumps(_empty_master_software_list_payload(), indent=2),
            encoding="utf-8"
        )

    # Initialize master JSON template baseline if it doesn't exist
    if MASTER_JSON_TEMPLATE_BASELINE_PATH and not MASTER_JSON_TEMPLATE_BASELINE_PATH.exists():
        MASTER_JSON_TEMPLATE_BASELINE_PATH.write_text(
            json.dumps(_empty_master_software_list_payload(), indent=2),
            encoding="utf-8"
        )


def _empty_master_software_list_payload() -> Dict[str, Any]:
    """Generate an empty master software list payload."""
    return {
        "SBL_models": {
            "GENERAL": _new_model_bucket(),
        },
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


def _new_model_bucket() -> Dict[str, Any]:
    """Generate a new model bucket template."""
    return {
        "software_components": {},
        "vm_components": {
            vm_name: {
                "vm_name": "",
                "os_type": "windows",
                "tracked_software": [],
            }
            for vm_name in default_target_columns()
        },
    }


def _create_example_registry_snapshot() -> Dict[str, Any]:
    """Generate an example registry snapshot payload."""
    return {
        "_file_purpose": "Registry snapshot template. Captures raw installed software inventory from the machine being scanned.",
        "_how_to_use": "Keep this structure when generating or validating registry snapshot data. Each item in software_inventory represents one uninstall registry record.",
        "status": "success",
        "timestamp": "2026-04-17T14:32:00",
        "entry_count": 3,
        "captured_from": "LOCAL_MACHINE",
        "software_inventory": [
            {
                "display_name": "ArcGIS Enterprise Portal 11.3",
                "display_version": "11.3.0",
                "publisher": "Esri",
                "install_date": "20240315",
                "install_location": "C:\\Program Files\\ArcGIS\\Portal",
                "registry_hive": "HKEY_LOCAL_MACHINE",
                "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\ArcGIS_Enterprise_Portal_113",
            },
            {
                "display_name": "Python 3.9.8",
                "display_version": "3.9.8",
                "publisher": "Python Software Foundation",
                "install_date": "20260401",
                "install_location": "C:\\Python39",
                "registry_hive": "HKEY_LOCAL_MACHINE",
                "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Python39",
            },
            {
                "display_name": "PostgreSQL 12.5",
                "display_version": "12.5",
                "publisher": "PostgreSQL Global Development Group",
                "install_date": "20240101",
                "install_location": "C:\\Program Files\\PostgreSQL\\12",
                "registry_hive": "HKEY_LOCAL_MACHINE",
                "registry_path": "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PostgreSQL_12",
            },
        ],
    }


def _create_example_checklist_json() -> Dict[str, Any]:
    """Generate an example checklist payload."""
    return {
        "_file_purpose": "Checklist template. Represents parsed SBL rows and target applicability before scans run.",
        "_how_to_use": "Use this structure for checklist exports. checklist_items should align to workbook rows used for auditing.",
        "checklist_name": "example_checklist",
        "generated_at": "2026-04-17T14:32:00",
        "baseline_version": "BASELINE_EXAMPLE_v3.2",
        "target_systems": ["ArcGIS_Portal", "GIS_Server"],
        "total_items": 3,
        "checklist_items": [
            {
                "row_number": 2,
                "software_component": "ArcGIS Enterprise Portal",
                "sbl_version": "11.3.0",
                "version_locations": "Programs and Features",
                "detection_rule": "programs_and_features",
                "targeted_systems": ["LOCAL_MACHINE"],
            },
            {
                "row_number": 3,
                "software_component": "Python",
                "sbl_version": "3.9.7",
                "version_locations": "File Version",
                "detection_rule": "file_version",
                "targeted_systems": ["GIS_Server"],
            },
            {
                "row_number": 4,
                "software_component": "PostgreSQL",
                "sbl_version": "12.5",
                "version_locations": "File Version",
                "detection_rule": "file_version",
                "targeted_systems": ["ArcGIS_Portal"],
            },
        ],
    }


def _create_example_result_json() -> Dict[str, Any]:
    """Generate an example audit result payload."""
    return {
        "_file_purpose": "Audit result template. Stores pass/fail/warn outcomes after version comparisons are complete.",
        "_how_to_use": "Use one results entry per evaluated component/target check. results_summary should match counts in results.",
        "audit_workbook": "C:\\path\\to\\example_audit_workbook.xlsx",
        "saved_workbook": "C:\\path\\to\\audit_results\\audit_results.xlsx",
        "profile_name": "example_profile",
        "generated_at": "2026-04-17T14:35:30",
        "total_audits": 3,
        "results_summary": {"pass": 1, "fail": 1, "warn": 1},
        "results": [
            {
                "worksheet_row": 2,
                "software_component": "ArcGIS Enterprise Portal",
                "expected_version": "11.3.0",
                "found_version": "11.3.0",
                "status": "PASS",
                "audit_text": "PASS | result=MATCH | expected=11.3.0 | found=11.3.0",
                "target_name": "LOCAL_MACHINE",
                "details": "Verified via Programs and Features registry",
            },
            {
                "worksheet_row": 3,
                "software_component": "Python",
                "expected_version": "3.9.7",
                "found_version": "3.9.8",
                "status": "WARN",
                "audit_text": "WARN | result=HIGHER_THAN_EXPECTED | expected=3.9.7 | found=3.9.8",
                "target_name": "LOCAL_MACHINE",
                "details": "Newer patch version detected than expected",
            },
            {
                "worksheet_row": 4,
                "software_component": "PostgreSQL",
                "expected_version": "12.5",
                "found_version": "NOT_FOUND",
                "status": "FAIL",
                "audit_text": "FAIL | result=NOT_FOUND | expected=12.5 | found=NOT_FOUND",
                "target_name": "LOCAL_MACHINE",
                "details": "Software not installed or not found at specified path",
            },
        ],
    }


def _create_example_scan_job_payload() -> Dict[str, Any]:
    """Generate an example scan job payload."""
    example_time = "2026-04-17T14:32:00"
    return {
        "_file_purpose": "Scan job template. Full execution record for one audit run, including settings, parsed rows, and scan outcomes.",
        "_how_to_use": "Use this as the authoritative run envelope when troubleshooting or replaying audits.",
        "status": "completed",
        "started_at": example_time,
        "completed_at": "2026-04-17T14:35:30",
        "error": "",
        "sbl_file": {
            "name": "example_audit_workbook.xlsx",
            "path": "C:\\path\\to\\example_audit_workbook.xlsx",
            "baseline_name": "BASELINE_EXAMPLE_v3.2",
            "timestamp": example_time,
            "sbl_model": "GEOINT_FD",
        },
        "output": {
            "workbook_path": "C:\\path\\to\\audit_results\\audit_results.xlsx",
            "result_base_name": "audit_results",
        },
        "settings": {
            "profile_name": "example_profile",
            "build_type": "PRODUCTION",
            "connection_mode": "LOCAL",
            "local_only": True,
            "fallback_enabled": False,
            "vcenter_server": "",
            "ssh_gateway_host": "",
            "ssh_gateway_port": 22,
            "ssh_target_port": 22,
        },
    }


def _create_example_files() -> None:
    """Create example artifacts used by the GUI on first launch."""
    from config import (
        AUDIT_CHECKLIST_DIR,
        AUDIT_RESULTS_DIR,
        JSON_CHECKLIST_DIR,
        JSON_REGISTRY_SNAPSHOTS_DIR,
        JSON_RESULTS_DIR,
        JSON_SCAN_JOBS_DIR,
    )
    from services.workbook_service import (
        _create_example_audit_checklist_workbook,
        _create_example_audit_results_workbook,
    )

    ensure_project_structure()

    snapshot_path = JSON_REGISTRY_SNAPSHOTS_DIR / "example_registry_snapshot.json"
    if not snapshot_path.exists():
        snapshot_path.write_text(json.dumps(_create_example_registry_snapshot(), indent=2), encoding="utf-8")

    checklist_path = JSON_CHECKLIST_DIR / "example_checklist.json"
    if not checklist_path.exists():
        checklist_path.write_text(json.dumps(_create_example_checklist_json(), indent=2), encoding="utf-8")

    result_path = JSON_RESULTS_DIR / "example_result.json"
    if not result_path.exists():
        result_path.write_text(json.dumps(_create_example_result_json(), indent=2), encoding="utf-8")

    scan_job_path = JSON_SCAN_JOBS_DIR / "example_scan_job.json"
    if not scan_job_path.exists():
        scan_job_path.write_text(json.dumps(_create_example_scan_job_payload(), indent=2), encoding="utf-8")

    checklist_workbook = AUDIT_CHECKLIST_DIR / "example_audit_checklist.xlsx"
    if not checklist_workbook.exists():
        _create_example_audit_checklist_workbook(checklist_workbook)

    results_workbook = AUDIT_RESULTS_DIR / "example_audit_results.xlsx"
    if not results_workbook.exists():
        _create_example_audit_results_workbook(results_workbook)
