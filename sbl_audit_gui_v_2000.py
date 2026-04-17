# Abreviations:
# In Reference to:
# _GENERAL_
# SBL - Software Build List

# _FILE NAMES_
# TG - Tool Generated
# UP - User Provided

import copy
import base64
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import traceback
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import pandas as pd
import sys
import re


import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.cell.cell import MergedCell
    from openpyxl.styles import PatternFill
except ImportError as exc:
    raise SystemExit("This app requires openpyxl. Install it with: pip install openpyxl") from exc

try:
    import winreg  # type: ignore
except Exception:
    winreg = None

try:
    import ssl
    import requests
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim
    PYVMOMI_AVAILABLE = True
except Exception:
    ssl = None
    requests = None
    Disconnect = None
    SmartConnect = None
    vim = None
    PYVMOMI_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except Exception:
    paramiko = None
    PARAMIKO_AVAILABLE = False

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:
    Fernet = None
    InvalidToken = Exception
    CRYPTO_AVAILABLE = False

APP_TITLE = "Audit Tool v2"
APP_GEOMETRY = "1020x760"
LOCAL_SENTINEL = "__LOCAL__"

APP_DIR = Path(__file__).resolve().parent
PROJECT_DIR = APP_DIR
AUDIT_RESULTS_DIR = PROJECT_DIR / "Audit Results"
AUDIT_CHECKLIST_DIR = PROJECT_DIR / "Audit Checklist"
JSON_DIR = PROJECT_DIR / "JSON"
JSON_RESULTS_DIR = JSON_DIR / "json_result"
JSON_CHECKLIST_DIR = JSON_DIR / "json_checklist"
JSON_REGISTRY_SNAPSHOTS_DIR = JSON_DIR / "registry_snapshots"
JSON_SCAN_JOBS_DIR = JSON_DIR / "scan_jobs"
PROFILES_DIR = PROJECT_DIR / "profiles" / "vm_profiles"
LOGS_DIR = PROJECT_DIR / "logs"
TESTS_DIR = PROJECT_DIR / "tests"
MASTER_SOFTWARE_LIST_PATH = JSON_DIR / "master_software_list.json"
TEMPLATES_DIR = PROJECT_DIR / "templates"

def _get_sbl_model_from_workbook(sbl_path: str) -> str:
    """Extract SBL model name (first component in workbook, e.g., 'Geospatial Intelligence Foundation')."""
    try:
        service = AuditWorkbookService(sbl_path)
        service.detect_header_row()
        service.build_column_map()
        for row in service.iter_audit_rows():
            if row.software_component:
                return row.software_component
    except Exception:
        pass
    return "UNKNOWN"

def _model_to_filename_slug(model_name: str) -> str:
    """Convert model name to filename slug.
    E.g., 'Geospatial Intelligence Foundation' -> 'GEOINT_FD' (acronym from key words).
    """
    if "Geospatial" in model_name and "Intelligence" in model_name:
        return "GEOINT_FD"  # Special case for this known model
    
    # Generic fallback: first word first 6 chars + last word first 2 chars
    words = model_name.split()
    if len(words) >= 2:
        return f"{words[0][:6].upper()}_{words[-1][:2].upper()}"
    return model_name[:8].upper()

def get_sbl_template_baseline_path(model_name: str = None) -> Path:
    """Get baseline SBL template path for the given model."""
    if model_name is None:
        slug = "GEOINT_FD"  # default fallback
    else:
        slug = _model_to_filename_slug(model_name)
    return TEMPLATES_DIR / f"sbl_template_baseline_{slug}.xlsx"

def get_sbl_template_latest_path(model_name: str = None) -> Path:
    """Get latest SBL template path for the given model."""
    if model_name is None:
        slug = "GEOINT_FD"  # default fallback
    else:
        slug = _model_to_filename_slug(model_name)
    return TEMPLATES_DIR / f"sbl_template_latest_{slug}.xlsx"

def get_master_json_template_baseline_path(model_name: str = None) -> Path:
    """Get baseline master software list template path."""
    return TEMPLATES_DIR / "master_software_list_template.json"

def get_master_json_template_latest_path(model_name: str = None) -> Path:
    """Get latest master software list path."""
    return TEMPLATES_DIR / "master_software_list_latest.json"

# Keep defaults for backward compatibility
SBL_TEMPLATE_BASELINE_PATH = get_sbl_template_baseline_path()
SBL_TEMPLATE_LATEST_PATH = get_sbl_template_latest_path()
MASTER_JSON_TEMPLATE_BASELINE_PATH = get_master_json_template_baseline_path()
MASTER_JSON_TEMPLATE_LATEST_PATH = get_master_json_template_latest_path()

REQ_HEADERS = {"SOFTWARE COMPONENT", "CURRENT CI VERSION", "VERSION LOCATIONS"}
SYSTEM_COLUMNS = [
    "ArcGIS_WebAdaptor",
    "ArcGIS_Portal",
    "ArcGIS_HostingServer",
    "ArcGIS_DS1",
    "ArcGIS_DS2",
    "GCS_Management",
]
BUILD_TYPE_OPTIONS = ["unknown", "baseline", "latest", "custom"]

PASS_FILL = PatternFill(fill_type="solid", fgColor="C6EFCE")
FAIL_FILL = PatternFill(fill_type="solid", fgColor="FFC7CE")
WARN_FILL = PatternFill(fill_type="solid", fgColor="FFEB9C")


@dataclass
class AuditRow:
    row_index: int
    software_component: str
    current_ci_version: str
    sbl_build_version: str
    audit_value: str
    target_vms: Dict[str, str]
    version_locations: str


@dataclass
class ScanResult:
    software_component: str
    target_name: str
    expected_version: str
    found_version: str
    status: str
    details: str
    worksheet_row: int
    audit_text: str


def default_target_columns() -> List[str]:
    """Default target columns."""
    return list(SYSTEM_COLUMNS)


def infer_build_type(source_text: str) -> str:
    """Infer build type."""
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


def resolve_profile_target_columns(payload: Dict[str, Any]) -> List[str]:
    """Resolve profile target columns."""
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
    """Build target schema payload."""
    return {
        "source_path": source_path,
        "target_columns": [normalize_text(name) for name in target_columns if normalize_text(name)],
        "build_type": infer_build_type(build_type) if build_type else infer_build_type(source_path),
        "legacy_fallback": default_target_columns(),
    }


def confirm_target_column_mapping(
    parent: tk.Widget,
    source_path: str,
    detected_columns: List[str],
    build_type: str,
    current_columns: Optional[List[str]] = None,
) -> Optional[List[str]]:
    """Confirm target column mapping."""
    detected = [normalize_text(item) for item in detected_columns if normalize_text(item)]
    fallback = default_target_columns()
    if not detected:
        return fallback

    preview = "\n".join(f"- {name}" for name in detected)
    message = (
        f"Detected VM target columns from source:\n{source_path or 'N/A'}\n"
        f"Build type: {infer_build_type(build_type)}\n\n"
        f"Detected columns:\n{preview}\n\n"
        "Choose Yes to use detected columns, No to use legacy fallback columns, or Cancel to keep current selection."
    )
    choice = messagebox.askyesnocancel("Confirm Target Column Mapping", message, parent=parent)
    if choice is True:
        return detected
    if choice is False:
        return fallback
    if current_columns:
        return list(current_columns)
    return None


def pick_record_value(record: Dict[str, Any], candidates: List[str]) -> str:
    """Pick record value."""
    normalized = {normalize_header(k): v for k, v in record.items()}
    for candidate in candidates:
        candidate_upper = normalize_header(candidate)
        for key, value in normalized.items():
            if candidate_upper in key:
                return normalize_text(value)
    return ""


def derive_import_target_columns(rows: List[Dict[str, Any]]) -> List[str]:
    """Derive import target columns."""
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


def extract_path_from_version_location(version_location: Any) -> str:
    """Extract a filesystem path prefix from a VERSION LOCATIONS-style string when possible."""
    text = normalize_text(version_location)
    if not text:
        return ""
    match = re.match(r"([A-Za-z]:[\\/].*?)(?=\s*>)", text)
    if match:
        return match.group(1)
    return text


def read_software_list_universal_rows(
    file_path: str,
    debug_logger: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Read heterogeneous SBL-like sources and normalize rows for import/checklist pipelines.

    This keeps the strict parser as the primary path and acts as a tolerant fallback when
    incoming workbooks vary in header row or naming conventions.
    """
    format_type = detect_workbook_format(file_path)

    def _dbg(message: str) -> None:
        """Emit parser debug messages when a logger callback is provided."""
        if debug_logger is not None:
            debug_logger(f"[universal-parser] {message}")

    _dbg(f"source={file_path}")
    _dbg(f"detected_format={format_type}")

    def _select_column(columns: List[str], patterns: List[str]) -> str:
        normalized = [normalize_text(col).lower() for col in columns]
        for pattern in patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            for index, col_name in enumerate(normalized):
                if regex.search(col_name):
                    return columns[index]
        return ""

    def _normalize_records(raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized_rows: List[Dict[str, Any]] = []
        for record in raw_records:
            if not isinstance(record, dict):
                continue
            software_component = pick_record_value(record, ["SOFTWARE COMPONENT", "COMPONENT", "SOFTWARE", "NAME"])
            if not software_component:
                continue
            displayed_name = pick_record_value(record, ["DISPLAYED NAME", "DISPLAY NAME", "SOFTWARE COMPONENT", "NAME"]) or software_component
            expected_version = pick_record_value(record, ["CURRENT CI VERSION", "CURRENT VERSION", "EXPECTED VERSION", "VERSION"])
            version_locations = extract_path_from_version_location(
                pick_record_value(record, ["VERSION LOCATIONS", "VERSION LOCATION", "LOCATION", "PATH", "RULE"])
            )
            cm_id = pick_record_value(record, ["CM TOOL ID NUMBER", "TOOL ID", "ID"])

            target_vms: Dict[str, str] = {}
            for key, value in record.items():
                key_name = normalize_text(key)
                if not key_name or is_known_non_target_header(key_name) or key_name.lower() == "target_vms":
                    continue
                if normalize_text(value).upper() == "X":
                    target_vms[key_name] = "X"

            normalized_entry: Dict[str, Any] = {
                "SOFTWARE COMPONENT": software_component,
                "DISPLAYED NAME": displayed_name,
                "CURRENT CI VERSION": expected_version,
                "VERSION LOCATIONS": version_locations,
            }
            if cm_id:
                normalized_entry["CM TOOL ID NUMBER"] = cm_id
            if target_vms:
                normalized_entry["target_vms"] = target_vms
            normalized_rows.append(normalized_entry)
        _dbg(f"json_rows_in={len(raw_records)} json_rows_out={len(normalized_rows)}")
        return normalized_rows

    def _from_dataframe(df: pd.DataFrame) -> List[Dict[str, Any]]:
        if df.empty:
            return []
        columns = [normalize_text(col) for col in list(df.columns)]
        source_columns = list(df.columns)

        software_col = _select_column(columns, [r"software\s*component", r"\bcomponent\b", r"\bsoftware\b", r"\bname\b"])
        current_col = _select_column(columns, [r"current\s*ci\s*version", r"current\s*version", r"expected\s*version", r"\bci\s*version\b"])
        version_col = _select_column(columns, [r"version\s*locations?", r"\bversion\s*location\b", r"\blocation\b", r"\bpath\b", r"\brule\b"])
        displayed_col = _select_column(columns, [r"displayed\s*name", r"display\s*name"])
        id_col = _select_column(columns, [r"cm\s*tool\s*id\s*number", r"\btool\s*id\b", r"\bid\b"])

        if not software_col:
            _dbg("software_component column not found in dataframe candidate")
            return []

        _dbg(
            "matched_columns="
            f"software={software_col or 'N/A'}, "
            f"current={current_col or 'N/A'}, "
            f"version_locations={version_col or 'N/A'}, "
            f"displayed={displayed_col or 'N/A'}, "
            f"id={id_col or 'N/A'}"
        )

        # Map selected normalized labels back to original column names.
        col_lookup = {normalize_text(original): original for original in source_columns}
        software_src = col_lookup.get(software_col, software_col)
        current_src = col_lookup.get(current_col, current_col) if current_col else ""
        version_src = col_lookup.get(version_col, version_col) if version_col else ""
        displayed_src = col_lookup.get(displayed_col, displayed_col) if displayed_col else ""
        id_src = col_lookup.get(id_col, id_col) if id_col else ""

        output_rows: List[Dict[str, Any]] = []
        for _, row in df.iterrows():
            software_component = normalize_text(row.get(software_src, ""))
            if not software_component:
                continue
            displayed_name = normalize_text(row.get(displayed_src, "")) if displayed_src else software_component
            expected_version = normalize_text(row.get(current_src, "")) if current_src else ""
            version_locations = extract_path_from_version_location(row.get(version_src, "")) if version_src else ""
            cm_id = normalize_text(row.get(id_src, "")) if id_src else ""

            selected_cols = {software_src, current_src, version_src, displayed_src, id_src}
            target_vms: Dict[str, str] = {}
            for col_name in source_columns:
                if col_name in selected_cols:
                    continue
                if is_known_non_target_header(normalize_text(col_name)):
                    continue
                if normalize_text(row.get(col_name, "")).upper() == "X":
                    target_vms[normalize_text(col_name)] = "X"

            normalized_entry: Dict[str, Any] = {
                "SOFTWARE COMPONENT": software_component,
                "DISPLAYED NAME": displayed_name,
                "CURRENT CI VERSION": expected_version,
                "VERSION LOCATIONS": version_locations,
            }
            if cm_id:
                normalized_entry["CM TOOL ID NUMBER"] = cm_id
            if target_vms:
                normalized_entry["target_vms"] = target_vms
            output_rows.append(normalized_entry)
        _dbg(f"dataframe_rows_in={len(df)} dataframe_rows_out={len(output_rows)}")
        return output_rows

    if format_type == "excel":
        primary_header = detect_header_row_index(file_path, format_type)
        header_candidates: List[int] = [primary_header, 0, 1, 2, 3, 4, 5]
        _dbg(f"excel_header_candidates={header_candidates}")
        seen: set = set()
        for header_index in header_candidates:
            if header_index in seen or header_index < 0:
                continue
            seen.add(header_index)
            try:
                df = pd.read_excel(file_path, header=header_index)
            except Exception:
                _dbg(f"header_index={header_index} read_failed")
                continue
            _dbg(f"header_index={header_index} read_ok columns={list(df.columns)}")
            normalized_rows = _from_dataframe(df)
            if normalized_rows:
                _dbg(f"selected_header_index={header_index}")
                return normalized_rows
        raise ValueError("Unable to detect required columns in workbook using universal parser")

    if format_type == "csv":
        df = pd.read_csv(file_path)
        _dbg(f"csv_columns={list(df.columns)}")
        normalized_rows = _from_dataframe(df)
        if normalized_rows:
            return normalized_rows
        raise ValueError("CSV parse did not produce usable software rows")

    if format_type == "json":
        payload = json.loads(Path(file_path).read_text(encoding="utf-8"))
        _dbg(f"json_payload_type={type(payload).__name__}")
        if isinstance(payload, list):
            normalized_rows = _normalize_records(payload)
        elif isinstance(payload, dict):
            candidate_rows = payload.get("rows", [])
            normalized_rows = _normalize_records(candidate_rows if isinstance(candidate_rows, list) else [])
        else:
            normalized_rows = []
        if normalized_rows:
            return normalized_rows
        raise ValueError("JSON parse did not produce usable software rows")

    raise ValueError(f"Unsupported format for universal row reader: {format_type}")


def is_known_non_target_header(header: str) -> bool:
    """Is known non target header."""
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


@dataclass
class WorkbookSchema:
    """
    Dynamically discovered workbook structure.
    Replaces hardcoded SYSTEM_COLUMNS by detecting actual columns in the workbook.
    """
    source_path: str
    source_format: str  # 'excel', 'json', 'csv'
    header_row_index: int
    software_column: str  # e.g., "SOFTWARE COMPONENT"
    current_version_column: str  # e.g., "CURRENT CI VERSION"
    sbl_version_column: str  # e.g., "VERSION LOCATIONS" or "SBL BUILD VERSION"
    target_columns: List[str]  # e.g., ["Target_1", "Target_2", "vm-prod-01", ...] instead of hardcoded SYSTEM_COLUMNS
    other_columns: List[str]  # non-target columns
    
    def get_all_columns(self) -> List[str]:
        """Return all columns in order: required + targets + others."""
        return [self.software_column, self.current_version_column, self.sbl_version_column] + self.target_columns + self.other_columns
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage in profiles."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "WorkbookSchema":
        """Deserialize from profile storage."""
        return WorkbookSchema(**data)


def detect_workbook_format(path: str) -> str:
    """Detect if the file is Excel, JSON, or CSV."""
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
    """Find the header row index (0-based) by detecting the first row with recognizable column names."""
    if format_type == 'excel':
        try:
            wb = load_workbook(path)
            ws = wb.active
            for idx, row in enumerate(ws.iter_rows(values_only=True), 0):
                headers = [normalize_header(cell) for cell in row if cell]
                # Check if row contains required headers
                if any('SOFTWARE' in h for h in headers) or any('COMPONENT' in h for h in headers):
                    return idx
        except Exception:
            pass
        return 0  # default to first row
    elif format_type == 'json':
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                # JSON with list of objects; first item is the "header"
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    return 0
        except Exception:
            pass
        return 0
    elif format_type == 'csv':
        try:
            df = pd.read_csv(path, nrows=5)
            return 0  # CSV headers are always first row
        except Exception:
            pass
        return 0
    return 0


def detect_target_columns(path: str, format_type: str, header_row_idx: int) -> Tuple[List[str], Dict[str, int]]:
    """
    Detect which columns are targets/VMs and return their names.
    Strategy: Find columns that have VM-like names (dns names, IP patterns) or
    contain consistent values in rows (not sparse).
    Returns: (target_column_names, column_index_map)
    """
    columns = []
    col_map = {}
    
    if format_type == 'excel':
        try:
            wb = load_workbook(path)
            ws = wb.active
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
                # Heuristic: target columns are NOT the required headers
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


def normalize_text(value: Any) -> str:
    """Normalize text."""
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def normalize_header(value: Any) -> str:
    """Normalize header."""
    return normalize_text(value).upper()


def is_x_mark(value: Any) -> bool:
    """Is x mark."""
    return normalize_text(value).upper() == "X"


def today_str() -> str:
    """Today str."""
    return datetime.now().strftime("%d%b%Y").upper()


def timestamp_str() -> str:
    """Timestamp str."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def normalize_version(value: str) -> str:
    """Normalize version."""
    text = normalize_text(value)
    if not text:
        return ""
    match = re.search(r"\d+(?:\.\d+){1,}", text)
    if match:
        return match.group(0)
    return text.lower()


def parse_version_tuple(value: str) -> Tuple[int, ...]:
    """Parse version tuple."""
    normalized = normalize_version(value)
    if not normalized:
        return tuple()
    parts = [part for part in re.split(r"[^0-9]+", normalized) if part]
    if not parts:
        return tuple()
    return tuple(int(part) for part in parts)


def compare_versions(expected: str, found: str, scan_status: str) -> Tuple[str, str]:
    """Compare versions."""
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


def _create_example_registry_snapshot() -> Dict[str, Any]:
    """Generate an example registry snapshot (raw installed software inventory)."""
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
    """Generate an example checklist JSON (parsed checklist rows)."""
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
    """Generate an example audit result JSON (comparison results)."""
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
    """Generate an example scan job to demonstrate the full structure."""
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
        "sbl_parse": {
            "target_columns": [],
            "row_count": 3,
            "rows": [
                {
                    "worksheet_row": 2,
                    "software_component": "ArcGIS Enterprise Portal",
                    "current_ci_version": "11.3.0",
                    "sbl_build_version": "11.3.0",
                    "version_locations": "Programs and Features",
                    "rule": "programs_and_features",
                    "marked_targets": [],
                    "local_detection_commands": [
                        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName -like '*ArcGIS Enterprise Portal*'} | Select-Object DisplayVersion"
                    ],
                },
                {
                    "worksheet_row": 3,
                    "software_component": "Python",
                    "current_ci_version": "3.9.7",
                    "sbl_build_version": "3.9.7",
                    "version_locations": "File Version",
                    "rule": "file_version",
                    "marked_targets": [],
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Python39\\python.exe').VersionInfo.ProductVersion"
                    ],
                },
                {
                    "worksheet_row": 4,
                    "software_component": "PostgreSQL",
                    "current_ci_version": "12.5",
                    "sbl_build_version": "12.5",
                    "version_locations": "File Version",
                    "rule": "file_version",
                    "marked_targets": [],
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe').VersionInfo.ProductVersion"
                    ],
                },
            ],
            "special_path_scan_list": [
                {
                    "worksheet_row": 3,
                    "software_component": "Python",
                    "current_ci_version": "3.9.7",
                    "sbl_build_version": "3.9.7",
                    "version_locations": "File Version",
                    "rule": "file_version",
                    "marked_targets": [],
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Python39\\python.exe').VersionInfo.ProductVersion"
                    ],
                },
                {
                    "worksheet_row": 4,
                    "software_component": "PostgreSQL",
                    "current_ci_version": "12.5",
                    "sbl_build_version": "12.5",
                    "version_locations": "File Version",
                    "rule": "file_version",
                    "marked_targets": [],
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe').VersionInfo.ProductVersion"
                    ],
                },
            ],
        },
        "local_machine_scan": {
            "results": [
                {
                    "worksheet_row": 2,
                    "software_component": "ArcGIS Enterprise Portal",
                    "expected_version": "11.3.0",
                    "found_version": "11.3.0",
                    "status": "PASS",
                    "audit_text": "PASS | result=MATCH | expected=11.3.0 | found=11.3.0",
                    "details": "Verified via Programs and Features registry",
                    "version_locations": "Programs and Features",
                    "local_detection_commands": [
                        "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName -like '*ArcGIS Enterprise Portal*'} | Select-Object DisplayVersion"
                    ],
                },
                {
                    "worksheet_row": 3,
                    "software_component": "Python",
                    "expected_version": "3.9.7",
                    "found_version": "3.9.8",
                    "status": "WARN",
                    "audit_text": "WARN | result=HIGHER_THAN_EXPECTED | expected=3.9.7 | found=3.9.8",
                    "details": "Newer patch version detected than expected",
                    "version_locations": "File Version",
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Python39\\python.exe').VersionInfo.ProductVersion"
                    ],
                },
                {
                    "worksheet_row": 4,
                    "software_component": "PostgreSQL",
                    "expected_version": "12.5",
                    "found_version": "NOT_FOUND",
                    "status": "FAIL",
                    "audit_text": "FAIL | result=NOT_FOUND | expected=12.5 | found=NOT_FOUND",
                    "details": "Software not installed or not found at specified path",
                    "version_locations": "File Version",
                    "local_detection_commands": [
                        "(Get-Item 'C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe').VersionInfo.ProductVersion"
                    ],
                },
            ],
            "comparison_summary": {
                "total": 3,
                "pass": 1,
                "fail": 1,
                "warn": 1,
            },
        },
    }


def _create_example_audit_checklist_workbook(file_path: Path) -> None:
    """Create an example audit checklist workbook."""
    wb = Workbook()
    ws = wb.active
    ws.title = "Checklist"

    notes_ws = wb.create_sheet(title="README")
    notes_ws.append(["File Purpose", "Template checklist workbook used to define expected software versions and target scope."])
    notes_ws.append(["How To Use", "Populate checklist rows, keep header names unchanged, and mark targets with X where component applies."])
    notes_ws.append(["Key Columns", "SOFTWARE COMPONENT, CURRENT CI VERSION, VERSION LOCATIONS, then one column per target system."])
    
    # Headers
    headers = ["SOFTWARE COMPONENT", "CURRENT CI VERSION", "VERSION LOCATIONS", "ArcGIS_Portal", "GIS_Server"]
    ws.append(headers)
    
    # Sample data
    rows = [
        ["ArcGIS Enterprise Portal", "11.3.0", "Programs and Features", "X", "X"],
        ["Python", "3.9.7", "File Version", "", "X"],
        ["PostgreSQL", "12.5", "File Version", "X", ""],
    ]
    for row in rows:
        ws.append(row)
    
    # Auto-adjust column widths
    for col in ws.columns:
        max_length = max(len(str(cell.value or "")) for cell in col)
        ws.column_dimensions[col[0].column_letter].width = max_length + 2
    
    wb.save(file_path)


def _create_example_audit_results_workbook(file_path: Path) -> None:
    """Create an example audit results workbook."""
    baseline_template = get_sbl_template_baseline_path()
    if baseline_template.exists():
        shutil.copy2(baseline_template, file_path)
        wb = load_workbook(file_path)
        ws = wb.active

        proxy = AuditWorkbookServiceProxy(ws)
        col_map, sbl_header, audit_header = proxy.build_column_map()
        header_row = proxy.header_row_index or 1

        software_col = col_map.get("SOFTWARE COMPONENT")
        current_ci_header = next((name for name in col_map.keys() if name.startswith("CURRENT CI VERSION")), "")
        current_ci_col = col_map.get(current_ci_header)
        sbl_col = col_map.get(sbl_header)
        audit_col = col_map.get(audit_header)
        version_locations_col = col_map.get("VERSION LOCATIONS")
        target_columns = [name for name in col_map.keys() if not is_known_non_target_header(name)]

        data_start_row = header_row + 1
        if software_col:
            for row_idx in range(header_row + 1, ws.max_row + 1):
                software_value = normalize_text(ws.cell(row_idx, software_col).value)
                if not software_value:
                    continue
                if "geospatial intelligence foundation" in software_value.lower():
                    data_start_row = row_idx + 3
                    break
                data_start_row = row_idx
                break

        for row_idx in range(data_start_row, ws.max_row + 1):
            for col_idx in col_map.values():
                cell = ws.cell(row_idx, col_idx)
                if not isinstance(cell, MergedCell):
                    cell.value = None

        sample_rows = [
            {
                "software_component": "ArcGIS Enterprise Portal",
                "current_ci_version": "11.3.0",
                "sbl_build_version": "11.3.0",
                "version_locations": "Programs and Features",
                "targets": {"ArcGIS_Portal": "X", "ArcGIS_HostingServer": "X"},
                "audit_text": "PASS | expected=11.3.0\nfound=11.3.0\nsource=Programs and Features registry (DisplayVersion)",
                "status": "PASS",
            },
            {
                "software_component": "Python",
                "current_ci_version": "3.9.7",
                "sbl_build_version": "3.9.7",
                "version_locations": "C:\\Python39\\python.exe",
                "targets": {"ArcGIS_DS1": "X"},
                "audit_text": "WARN | expected=3.9.7\nfound=3.9.8\nsource=C:\\Python39\\python.exe (ProductVersion)",
                "status": "WARN",
            },
            {
                "software_component": "PostgreSQL",
                "current_ci_version": "12.5",
                "sbl_build_version": "12.5",
                "version_locations": "C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe",
                "targets": {"ArcGIS_DS2": "X"},
                "audit_text": "FAIL | expected=12.5\nfound=NOT_FOUND\nsource=C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe",
                "status": "FAIL",
            },
        ]

        pass_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
        fail_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
        warn_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")

        for offset, row_data in enumerate(sample_rows):
            row_idx = data_start_row + offset
            if software_col:
                ws.cell(row_idx, software_col).value = row_data["software_component"]
            if current_ci_col:
                ws.cell(row_idx, current_ci_col).value = row_data["current_ci_version"]
            if sbl_col:
                ws.cell(row_idx, sbl_col).value = row_data["sbl_build_version"]
            if version_locations_col:
                ws.cell(row_idx, version_locations_col).value = row_data["version_locations"]
            if audit_col:
                audit_cell = ws.cell(row_idx, audit_col)
                audit_cell.value = row_data["audit_text"]
                audit_cell.alignment = copy.copy(audit_cell.alignment)
                audit_cell.alignment = audit_cell.alignment.copy(wrapText=True)
                if row_data["status"] == "PASS":
                    audit_cell.fill = pass_fill
                elif row_data["status"] == "WARN":
                    audit_cell.fill = warn_fill
                else:
                    audit_cell.fill = fail_fill

            for target_name in target_columns:
                target_col = col_map.get(target_name)
                if not target_col:
                    continue
                ws.cell(row_idx, target_col).value = row_data["targets"].get(target_name, "")

        if audit_col:
            audit_col_letter = ws.cell(header_row, audit_col).column_letter
            ws.column_dimensions[audit_col_letter].width = max(48, ws.column_dimensions[audit_col_letter].width or 0)

        wb.save(file_path)
        return

    wb = Workbook()
    ws = wb.active
    ws.title = "Results"
    ws.append(["SOFTWARE COMPONENT", "CURRENT CI VERSION", "VERSION LOCATIONS", "AUDIT RESULT"])
    ws.append([
        "ArcGIS Enterprise Portal",
        "11.3.0",
        "Programs and Features",
        "PASS | expected=11.3.0\nfound=11.3.0\nsource=Programs and Features registry (DisplayVersion)",
    ])
    ws.append([
        "Python",
        "3.9.7",
        "C:\\Python39\\python.exe",
        "WARN | expected=3.9.7\nfound=3.9.8\nsource=C:\\Python39\\python.exe (ProductVersion)",
    ])
    ws.append([
        "PostgreSQL",
        "12.5",
        "C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe",
        "FAIL | expected=12.5\nfound=NOT_FOUND\nsource=C:\\Program Files\\PostgreSQL\\12\\bin\\postgres.exe",
    ])
    ws.column_dimensions["D"].width = 56
    for row_idx in range(2, ws.max_row + 1):
        ws.cell(row_idx, 4).alignment = ws.cell(row_idx, 4).alignment.copy(wrapText=True)
    wb.save(file_path)


def _create_example_files() -> None:
    """Create all example files in their respective directories."""
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


def ensure_project_structure() -> None:
    """Ensure project structure."""
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

    if not MASTER_SOFTWARE_LIST_PATH.exists():
        MASTER_SOFTWARE_LIST_PATH.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")

    if not MASTER_JSON_TEMPLATE_BASELINE_PATH.exists():
        MASTER_JSON_TEMPLATE_BASELINE_PATH.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")


def normalize_model_key(model_name: str = None) -> str:
    """Normalize model key."""
    text = normalize_text(model_name)
    if not text or text.upper() == "UNKNOWN":
        return "GENERAL"
    return text


def _new_model_bucket() -> Dict[str, Any]:
    """Internal helper for new model bucket."""
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


def _empty_master_software_list_payload() -> Dict[str, Any]:
    """Internal helper for empty master software list payload."""
    return {
        "SBL_models": {
            "GENERAL": _new_model_bucket(),
        },
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


def _max_workbook_style_index(file_path: str) -> Optional[int]:
    """Internal helper for max workbook style index."""
    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            styles_xml = archive.read("xl/styles.xml")
    except Exception:
        return None

    try:
        root = ET.fromstring(styles_xml)
    except ET.ParseError:
        return None

    namespace = {"main": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    cell_xfs = root.find("main:cellXfs", namespace)
    if cell_xfs is None:
        return None
    style_count = len(list(cell_xfs))
    if style_count <= 0:
        return None
    return style_count - 1


def _repair_invalid_style_indexes(file_path: str) -> Optional[str]:
    """Internal helper for repair invalid style indexes."""
    max_style_index = _max_workbook_style_index(file_path)
    if max_style_index is None:
        return None

    changed_files: Dict[str, bytes] = {}
    worksheet_namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    sheet_glob_prefix = "xl/worksheets/"
    style_file_name = "xl/styles.xml"

    with zipfile.ZipFile(file_path, "r") as archive:
        try:
            styles_root = ET.fromstring(archive.read(style_file_name))
        except ET.ParseError:
            styles_root = None

        if styles_root is not None:
            fonts = styles_root.find(f"{{{worksheet_namespace}}}fonts")
            fills = styles_root.find(f"{{{worksheet_namespace}}}fills")
            borders = styles_root.find(f"{{{worksheet_namespace}}}borders")
            cell_xfs = styles_root.find(f"{{{worksheet_namespace}}}cellXfs")
            font_count = len(list(fonts)) if fonts is not None else 0
            fill_count = len(list(fills)) if fills is not None else 0
            border_count = len(list(borders)) if borders is not None else 0
            styles_changed = False

            for xf in list(cell_xfs) if cell_xfs is not None else []:
                font_id = xf.get("fontId")
                if font_id and font_id.isdigit() and int(font_id) >= font_count:
                    xf.set("fontId", "0")
                    styles_changed = True

                fill_id = xf.get("fillId")
                if fill_id and fill_id.isdigit() and int(fill_id) >= fill_count:
                    xf.set("fillId", "0")
                    styles_changed = True

                border_id = xf.get("borderId")
                if border_id and border_id.isdigit() and int(border_id) >= border_count:
                    xf.set("borderId", "0")
                    styles_changed = True

            if styles_changed:
                changed_files[style_file_name] = ET.tostring(styles_root, encoding="utf-8", xml_declaration=True)

        worksheet_names = [name for name in archive.namelist() if name.startswith(sheet_glob_prefix) and name.endswith(".xml")]
        for name in worksheet_names:
            try:
                root = ET.fromstring(archive.read(name))
            except ET.ParseError:
                continue

            changed = False
            for cell in root.iter(f"{{{worksheet_namespace}}}c"):
                style_value = cell.get("s")
                if style_value and style_value.isdigit() and int(style_value) > max_style_index:
                    cell.set("s", "0")
                    changed = True

            for row in root.iter(f"{{{worksheet_namespace}}}row"):
                style_value = row.get("s")
                if style_value and style_value.isdigit() and int(style_value) > max_style_index:
                    row.set("s", "0")
                    row.set("customFormat", "0")
                    changed = True

            for col in root.iter(f"{{{worksheet_namespace}}}col"):
                style_value = col.get("style")
                if style_value and style_value.isdigit() and int(style_value) > max_style_index:
                    col.set("style", "0")
                    changed = True

            if changed:
                changed_files[name] = ET.tostring(root, encoding="utf-8", xml_declaration=True)

        if not changed_files:
            return None

        ensure_project_structure()
        with tempfile.NamedTemporaryFile(prefix="audit_repaired_", suffix=".xlsx", delete=False) as tmp_file:
            repaired_path = tmp_file.name

        with zipfile.ZipFile(file_path, "r") as source_archive, zipfile.ZipFile(repaired_path, "w", compression=zipfile.ZIP_DEFLATED) as repaired_archive:
            for item in source_archive.infolist():
                data = changed_files.get(item.filename, source_archive.read(item.filename))
                repaired_archive.writestr(item, data)

    return repaired_path


def auto_fit_columns(ws, min_width: int = 12, max_width: int = 48) -> None:
    """Auto fit columns."""
    from openpyxl.utils import get_column_letter
    for col_idx in range(1, ws.max_column + 1):
        max_len = 0
        for row_idx in range(1, ws.max_row + 1):
            value = ws.cell(row=row_idx, column=col_idx).value
            text = "" if value is None else str(value)
            max_len = max(max_len, len(text))
        ws.column_dimensions[get_column_letter(col_idx)].width = max(min_width, min(max_len + 2, max_width))


def parse_build_and_audit_headers(headers: List[str]) -> Tuple[Optional[str], Optional[str]]:
    """Parse build and audit headers."""
    sbl_build_col = None
    audit_col = None
    for header in headers:
        n = normalize_header(header)
        if "SBL BUILD" in n and sbl_build_col is None:
            sbl_build_col = header
        if "AUDIT" in n and audit_col is None:
            audit_col = header
    return sbl_build_col, audit_col


class FileLogger:
    def __init__(self, log_dir: Path, prefix: str):
        """Initialize the FileLogger instance."""
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"{prefix}_{timestamp_str()}.log"
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        """Write."""
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def write_exception(self, exc: Exception) -> None:
        """Write exception."""
        self.write(f"ERROR: {exc}")
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(tb + "\n")

    def get_path(self) -> str:
        """Get path."""
        return str(self.log_file)


class MasterSoftwarePathService:
    def __init__(self, path: Path = MASTER_SOFTWARE_LIST_PATH):
        """Initialize the MasterSoftwarePathService instance."""
        self.path = path
        ensure_project_structure()

    def load(self) -> Dict[str, Any]:
        """Load."""
        if not self.path.exists():
            self.path.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        changed = False

        if "SBL_models" not in payload or not isinstance(payload.get("SBL_models"), dict):
            legacy_model = normalize_model_key(payload.get("sbl_model"))
            payload = {
                "SBL_models": {
                    legacy_model: {
                        "software_components": payload.get("software_components", {}),
                        "vm_components": payload.get("vm_components", {}),
                    }
                },
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
            changed = True

        models = payload.setdefault("SBL_models", {})
        if "GENERAL" not in models:
            models["GENERAL"] = _new_model_bucket()
            changed = True

        for model_name, model_bucket in list(models.items()):
            if not isinstance(model_bucket, dict):
                models[model_name] = _new_model_bucket()
                model_bucket = models[model_name]
                changed = True

            bucket = model_bucket.setdefault("software_components", {})
            vm_bucket = model_bucket.setdefault("vm_components", {})

            if not isinstance(bucket, dict):
                model_bucket["software_components"] = {}
                bucket = model_bucket["software_components"]
                changed = True
            if not isinstance(vm_bucket, dict):
                model_bucket["vm_components"] = {}
                vm_bucket = model_bucket["vm_components"]
                changed = True

            target_columns = list(vm_bucket.keys()) or default_target_columns()
            for vm_name in target_columns:
                vm_entry = vm_bucket.get(vm_name)
                if not isinstance(vm_entry, dict):
                    vm_entry = {}
                    vm_bucket[vm_name] = vm_entry
                    changed = True
                if "vm_name" not in vm_entry:
                    vm_entry["vm_name"] = ""
                    changed = True
                if "os_type" not in vm_entry:
                    vm_entry["os_type"] = "windows"
                    changed = True
                if "tracked_software" not in vm_entry or not isinstance(vm_entry.get("tracked_software"), list):
                    vm_entry["tracked_software"] = []
                    changed = True

            for component, entry in list(bucket.items()):
                if not isinstance(entry, dict):
                    entry = {}
                    bucket[component] = entry
                    changed = True

                path_value = entry.get("path", entry.get("display_path", ""))
                meta = derive_path_metadata(path_value)

                defaults = {
                    "generic_name": entry.get("generic_name", component),
                    "registry_name": entry.get("registry_name", ""),
                    "path": meta["path"],
                    "coded_path": meta["coded_path"],
                    "verification_source": entry.get("verification_source", entry.get("verification_rule", meta["verification_source"])),
                    "path_last_verified_date": entry.get("path_last_verified_date", ""),
                    "notes": entry.get("notes", ""),
                    "tracked_in_vms": entry.get("tracked_in_vms", entry.get("verified_targets", [])),
                }

                for key, value in defaults.items():
                    if key not in entry:
                        entry[key] = value
                        changed = True

                if entry.get("coded_path") == "PROGRAMS_AND_FEATURES":
                    entry["coded_path"] = meta["coded_path"]
                    changed = True

                if not isinstance(entry.get("tracked_in_vms", []), list):
                    entry["tracked_in_vms"] = []
                    changed = True

                if not entry.get("tracked_in_vms"):
                    note_text = normalize_text(entry.get("notes", ""))
                    legacy_match = re.match(r"^Verified via\s+(.+)$", note_text, flags=re.IGNORECASE)
                    if legacy_match:
                        target = legacy_match.group(1).strip()
                        if target:
                            entry["tracked_in_vms"] = [target]
                            entry["notes"] = f"Tracked in VMs: {target}"
                            changed = True

                note_text = normalize_text(entry.get("notes", ""))
                if note_text.upper().startswith("VERIFIED VIA TARGETS:"):
                    vm_text = note_text.split(":", 1)[1].strip()
                    entry["notes"] = f"Tracked in VMs: {vm_text}"
                    changed = True

                for legacy_key in ("verified_targets", "verification_rule", "display_path", "last_verified_target", "last_scan_status"):
                    if legacy_key in entry:
                        del entry[legacy_key]
                        changed = True

                tracked_vms = entry.get("tracked_in_vms", [])
                if isinstance(tracked_vms, list):
                    for vm_name in tracked_vms:
                        if vm_name not in SYSTEM_COLUMNS:
                            continue
                        vm_entry = vm_bucket.setdefault(vm_name, {"vm_name": "", "os_type": "windows", "tracked_software": []})
                        tracked_software = vm_entry.get("tracked_software", [])
                        if not isinstance(tracked_software, list):
                            tracked_software = []
                        if component not in tracked_software:
                            tracked_software.append(component)
                            vm_entry["tracked_software"] = tracked_software
                            changed = True

        if "updated_at" not in payload:
            payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
            changed = True

        if changed:
            self.save(payload)
        return payload

    def save(self, payload: Dict[str, Any]) -> None:
        """Save."""
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def update_component(
        self,
        software_component: str,
        path_value: str,
        target_name: str = "",
        scan_status: str = "",
        notes: str = "",
        model_name: str = "",
    ) -> None:
        """Update component."""
        payload = self.load()
        model_key = normalize_model_key(model_name)
        models = payload.setdefault("SBL_models", {})
        model_bucket = models.setdefault(model_key, _new_model_bucket())
        bucket = model_bucket.setdefault("software_components", {})
        vm_bucket = model_bucket.setdefault("vm_components", {})
        existing_entry = bucket.get(software_component)
        path_meta = derive_path_metadata(path_value)
        is_new_component = not isinstance(existing_entry, dict)

        if is_new_component:
            tracked_vms: List[str] = []
            is_vm_target = target_name in SYSTEM_COLUMNS
            if is_vm_target:
                tracked_vms.append(target_name)
                vm_entry = vm_bucket.get(target_name)
                if not isinstance(vm_entry, dict):
                    vm_entry = {"vm_name": "", "os_type": "windows", "tracked_software": []}
                tracked_software = vm_entry.get("tracked_software", [])
                if not isinstance(tracked_software, list):
                    tracked_software = []
                if software_component and software_component not in tracked_software:
                    tracked_software.append(software_component)
                vm_entry["tracked_software"] = tracked_software
                vm_entry.setdefault("vm_name", "")
                vm_entry.setdefault("os_type", "windows")
                vm_bucket[target_name] = vm_entry

            entry = {
                "generic_name": software_component,
                "registry_name": "",
                "path": path_meta["path"],
                "coded_path": path_meta["coded_path"],
                "verification_source": path_meta["verification_source"],
                "path_last_verified_date": datetime.now().isoformat(timespec="seconds"),
                "notes": notes or (f"Tracked in VMs: {', '.join(tracked_vms)}" if tracked_vms else ""),
                "tracked_in_vms": tracked_vms,
            }
            bucket[software_component] = entry
            payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
            self.save(payload)
            return

        old_path = normalize_text(existing_entry.get("path", ""))
        old_coded = normalize_text(existing_entry.get("coded_path", ""))
        old_source = normalize_text(existing_entry.get("verification_source", ""))
        new_path = normalize_text(path_meta["path"])
        new_coded = normalize_text(path_meta["coded_path"])
        new_source = normalize_text(path_meta["verification_source"])

        location_changed = old_path != new_path or old_coded != new_coded or old_source != new_source
        if not location_changed:
            return

        existing_entry["path"] = path_meta["path"]
        existing_entry["coded_path"] = path_meta["coded_path"]
        existing_entry["verification_source"] = path_meta["verification_source"]
        existing_entry["path_last_verified_date"] = datetime.now().isoformat(timespec="seconds")
        bucket[software_component] = existing_entry
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        self.save(payload)


class TemplateAssetService:
    def __init__(self):
        """Initialize the TemplateAssetService instance."""
        ensure_project_structure()

    @staticmethod
    def _find_first_existing(paths: List[Path]) -> Optional[Path]:
        """Internal helper for find first existing."""
        for candidate in paths:
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _blank_master_payload(components: Dict[str, str], sbl_model: str = None) -> Dict[str, Any]:
        """Internal helper for blank master payload."""
        model_key = normalize_model_key(sbl_model)
        software_components = {}
        for name, version_location in components.items():
            meta = derive_path_metadata(version_location)
            software_components[name] = {
                "generic_name": name,
                "registry_name": "",
                "path": meta["path"],
                "coded_path": meta["coded_path"],
                "verification_source": meta["verification_source"],
                "path_last_verified_date": "",
                "notes": "",
                "tracked_in_vms": [],
            }

        payload = {
            "SBL_models": {
                "GENERAL": _new_model_bucket(),
                model_key: {
                    "software_components": software_components,
                    "vm_components": {
                        vm_name: {
                            "vm_name": "",
                            "os_type": "windows",
                            "tracked_software": [],
                        }
                        for vm_name in SYSTEM_COLUMNS
                    },
                },
            },
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        return payload

    def _extract_components_from_sbl(self, sbl_path: str) -> Dict[str, str]:
        """Internal helper for extract components from sbl."""
        service = AuditWorkbookService(sbl_path)
        service.detect_header_row()
        service.build_column_map()
        components: Dict[str, str] = {}
        for row in service.iter_audit_rows():
            if row.software_component and row.software_component not in components:
                components[row.software_component] = row.version_locations
        return components

    def _write_blank_master_from_sbl(self, sbl_path: str, output_json_path: Path, sbl_model: str = None) -> str:
        """Internal helper for write blank master from sbl."""
        components = self._extract_components_from_sbl(sbl_path)
        model_key = normalize_model_key(sbl_model)
        if output_json_path.exists():
            payload = json.loads(output_json_path.read_text(encoding="utf-8"))
            if "SBL_models" not in payload or not isinstance(payload.get("SBL_models"), dict):
                payload = self._blank_master_payload({}, sbl_model="GENERAL")
        else:
            payload = self._blank_master_payload({}, sbl_model="GENERAL")

        model_bucket = payload.setdefault("SBL_models", {}).setdefault(model_key, _new_model_bucket())
        model_bucket["software_components"] = self._blank_master_payload(components, sbl_model=model_key)["SBL_models"][model_key]["software_components"]
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        output_json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output_json_path)

    def update_baseline_from_sbl(self, sbl_path: str) -> Dict[str, str]:
        """Update baseline templates from SBL and upsert model in master software list template."""
        sbl_model = _get_sbl_model_from_workbook(sbl_path)
        baseline_sbl = get_sbl_template_baseline_path(sbl_model)
        baseline_json = get_master_json_template_baseline_path(sbl_model)
        
        shutil.copy2(sbl_path, baseline_sbl)
        json_path = self._write_blank_master_from_sbl(sbl_path, baseline_json, sbl_model=sbl_model)
        return {
            "sbl_template": str(baseline_sbl),
            "json_template": json_path,
        }

    def update_latest_sbl(self, sbl_path: str) -> str:
        """Latest SBL snapshots are disabled; baseline template remains the source of truth."""
        return "disabled (latest SBL template snapshots are not used)"

    def snapshot_current_master_to_latest(self, sbl_model: str = None) -> str:
        """Keep the canonical master software list in JSON folder only."""
        if not MASTER_SOFTWARE_LIST_PATH.exists():
            payload = _empty_master_software_list_payload()
            MASTER_SOFTWARE_LIST_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(MASTER_SOFTWARE_LIST_PATH)

    def get_baseline_sbl_path(self, sbl_model: str = None) -> str:
        """Get baseline SBL path (model-specific if provided)."""
        return str(get_sbl_template_baseline_path(sbl_model))

    def resolve_existing_baseline_sbl_path(self, sbl_model: str = None) -> Optional[str]:
        """Return an existing baseline template path, trying model-specific then fallbacks."""
        preferred = get_sbl_template_baseline_path(sbl_model)
        default_path = get_sbl_template_baseline_path()
        candidates = [preferred, default_path]
        fallback = self._find_first_existing(candidates)
        if fallback is not None:
            return str(fallback)

        # Final fallback: any baseline template in templates folder.
        any_baseline = sorted(TEMPLATES_DIR.glob("sbl_template_baseline_*.xlsx"))
        if any_baseline:
            return str(any_baseline[0])
        return None

    @staticmethod
    def _format_mtime(path: Path) -> str:
        """Internal helper for format mtime."""
        if not path.exists():
            return "Missing"
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    def get_template_status(self, sbl_model: str = None) -> Dict[str, Dict[str, str]]:
        """Get template status (model-specific if provided)."""
        if sbl_model is None:
            sbl_model = "Geospatial Intelligence Foundation"  # default
        
        targets = {
            "baseline_sbl": get_sbl_template_baseline_path(sbl_model),
            "baseline_master_list": get_master_json_template_baseline_path(sbl_model),
        }
        status: Dict[str, Dict[str, str]] = {}
        for key, path in targets.items():
            status[key] = {
                "path": str(path),
                "exists": "Yes" if path.exists() else "No",
                "updated": self._format_mtime(path),
            }
        status["latest_sbl"] = {
            "path": "(disabled)",
            "exists": "No",
            "updated": "Disabled",
        }
        status["latest_master_list"] = {
            "path": str(MASTER_SOFTWARE_LIST_PATH),
            "exists": "Yes" if MASTER_SOFTWARE_LIST_PATH.exists() else "No",
            "updated": self._format_mtime(MASTER_SOFTWARE_LIST_PATH),
        }
        return status

    def import_list_to_sbl_workbook(self, input_path: str, output_path: str) -> str:
        """Import list to sbl workbook."""
        ext = Path(input_path).suffix.lower()
        if ext in (".xlsx", ".xlsm"):
            shutil.copy2(input_path, output_path)
            return output_path

        rows: List[Dict[str, Any]] = []
        if ext == ".csv":
            df = pd.read_csv(input_path)
            rows = df.fillna("").to_dict(orient="records")
        elif ext == ".json":
            payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                candidate_rows = payload.get("rows", [])
                if isinstance(candidate_rows, list):
                    rows = [item for item in candidate_rows if isinstance(item, dict)]
            elif isinstance(payload, list):
                rows = [item for item in payload if isinstance(item, dict)]
        else:
            raise ValueError("Unsupported import format. Use .xlsx, .xlsm, .csv, or .json")

        baseline_template = get_sbl_template_baseline_path()
        if baseline_template.exists():
            # Preserve baseline sheet structure (merged headers, styles, and banner rows)
            # by seeding imports from the canonical template instead of a blank workbook.
            shutil.copy2(baseline_template, output_path)
            wb = load_workbook(output_path)
            ws = wb.active

            proxy = AuditWorkbookServiceProxy(ws)
            col_map, sbl_header, audit_header = proxy.build_column_map()
            header_row = proxy.header_row_index or 1

            software_col = col_map.get("SOFTWARE COMPONENT")
            current_ci_header = next((name for name in col_map.keys() if name.startswith("CURRENT CI VERSION")), "")
            current_ci_col = col_map.get(current_ci_header)
            version_locations_col = col_map.get("VERSION LOCATIONS")
            sbl_col = col_map.get(sbl_header)
            audit_col = col_map.get(audit_header)

            template_target_columns = [name for name in col_map.keys() if not is_known_non_target_header(name)]

            data_start_row = header_row + 1
            if software_col:
                for row_idx in range(header_row + 1, ws.max_row + 1):
                    cell_value = normalize_text(ws.cell(row_idx, software_col).value)
                    if not cell_value:
                        continue
                    if "geospatial intelligence foundation" in cell_value.lower():
                        data_start_row = row_idx + 3
                        break
                    data_start_row = row_idx
                    break

            # Clear existing data rows while preserving template styles and merges.
            for row_idx in range(data_start_row, ws.max_row + 1):
                for col_idx in col_map.values():
                    cell = ws.cell(row_idx, col_idx)
                    if not isinstance(cell, MergedCell):
                        cell.value = None

            for offset, record in enumerate(rows):
                row_idx = data_start_row + offset
                software_component = pick_record_value(record, ["SOFTWARE COMPONENT", "NAME", "COMPONENT"])
                current_ci = pick_record_value(record, ["CURRENT CI VERSION", "CURRENT VERSION", "EXPECTED VERSION", "VERSION"])
                sbl_build = pick_record_value(record, ["SBL BUILD", "SBL BUILD VERSION", "BUILD VERSION", "BASELINE"])
                audit_value = pick_record_value(record, ["AUDIT", "AUDIT VALUE"])
                version_locations = pick_record_value(record, ["VERSION LOCATIONS", "VERSION LOCATION", "PATH", "LOCATION", "RULE"])
                target_vms = record.get("target_vms", {}) if isinstance(record.get("target_vms", {}), dict) else {}

                if software_col:
                    ws.cell(row_idx, software_col).value = software_component
                if current_ci_col:
                    ws.cell(row_idx, current_ci_col).value = current_ci
                if sbl_col:
                    ws.cell(row_idx, sbl_col).value = sbl_build
                if audit_col:
                    ws.cell(row_idx, audit_col).value = audit_value
                if version_locations_col:
                    ws.cell(row_idx, version_locations_col).value = version_locations

                for target_name in template_target_columns:
                    target_col = col_map.get(target_name)
                    if not target_col:
                        continue
                    if target_name in target_vms:
                        target_value = normalize_text(target_vms.get(target_name, ""))
                    else:
                        target_value = pick_record_value(record, [target_name])
                    ws.cell(row_idx, target_col).value = target_value

            wb.save(output_path)
            return output_path

        wb = Workbook()
        ws = wb.active
        ws.title = "Imported SBL"
        target_columns = derive_import_target_columns(rows)
        headers = [
            "SOFTWARE COMPONENT",
            "CURRENT CI VERSION",
            "VERSION LOCATIONS",
            *target_columns,
            "SBL BUILD TEMPLATE",
            "AUDIT TEMPLATE",
        ]
        ws.append(headers)

        for record in rows:
            software_component = pick_record_value(record, ["SOFTWARE COMPONENT", "NAME", "COMPONENT"])
            current_ci = pick_record_value(record, ["CURRENT CI VERSION", "CURRENT VERSION", "EXPECTED VERSION", "VERSION"])
            sbl_build = pick_record_value(record, ["SBL BUILD", "SBL BUILD VERSION", "BUILD VERSION", "BASELINE"])
            audit_value = pick_record_value(record, ["AUDIT", "AUDIT VALUE"])
            version_locations = pick_record_value(record, ["VERSION LOCATIONS", "VERSION LOCATION", "PATH", "LOCATION", "RULE"])
            target_vms = record.get("target_vms", {}) if isinstance(record.get("target_vms", {}), dict) else {}
            row_values = [
                software_component,
                current_ci,
                version_locations,
            ]
            for target_name in target_columns:
                if target_name in target_vms:
                    row_values.append(normalize_text(target_vms.get(target_name, "")))
                else:
                    row_values.append(pick_record_value(record, [target_name]))
            row_values.extend([
                sbl_build,
                audit_value,
            ])
            ws.append(row_values)

        auto_fit_columns(ws)
        wb.save(output_path)
        return output_path


class JsonExportService:
    @staticmethod
    def write_checklist_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write checklist json."""
        ensure_project_structure()
        output = JSON_CHECKLIST_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_result_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write result json."""
        ensure_project_structure()
        output = JSON_RESULTS_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_registry_snapshot_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write registry snapshot json."""
        ensure_project_structure()
        output = JSON_REGISTRY_SNAPSHOTS_DIR / f"{base_name}_registry_snapshot_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_scan_job_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write scan job json."""
        ensure_project_structure()
        output = JSON_SCAN_JOBS_DIR / f"{base_name}_scan_job_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)


class VMProfileService:
    def __init__(self, profiles_dir: Path = PROFILES_DIR):
        """Initialize the VMProfileService instance."""
        self.profiles_dir = profiles_dir
        ensure_project_structure()

    @staticmethod
    def _key_path() -> Path:
        """Internal helper for key path."""
        return Path.home() / ".auditmatic" / "profile_credentials.key"

    def _get_fernet(self):
        """Internal helper for get fernet."""
        if not CRYPTO_AVAILABLE or Fernet is None:
            return None
        key_path = self._key_path()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
        return Fernet(key)

    @staticmethod
    def encryption_supported() -> bool:
        """Encryption supported."""
        return bool(CRYPTO_AVAILABLE and Fernet is not None)

    def profile_credential_storage_mode(self, profile_name: str) -> str:
        """Profile credential storage mode."""
        path = self.profile_path(profile_name)
        if not path.exists():
            return "no-profile"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return "unknown"
        if bool(payload.get("credentials_encrypted", False)):
            return "encrypted"
        return "legacy-plain"

    @staticmethod
    def _encrypt_value(fernet, value: str) -> str:
        """Internal helper for encrypt value."""
        if not fernet or not value:
            return value
        return fernet.encrypt(value.encode("utf-8")).decode("ascii")

    @staticmethod
    def _decrypt_value(fernet, value: str) -> str:
        """Internal helper for decrypt value."""
        if not fernet or not value:
            return value
        try:
            return fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except Exception:
            return ""

    def _encrypt_profile_credentials(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Internal helper for encrypt profile credentials."""
        fernet = self._get_fernet()
        encrypted_payload = copy.deepcopy(payload)

        vcenter_user = normalize_text(encrypted_payload.get("vcenter_username", ""))
        vcenter_password = encrypted_payload.get("vcenter_password", "")
        if vcenter_user:
            encrypted_payload["vcenter_username_enc"] = self._encrypt_value(fernet, vcenter_user)
        if vcenter_password:
            encrypted_payload["vcenter_password_enc"] = self._encrypt_value(fernet, vcenter_password)
        encrypted_payload.pop("vcenter_username", None)
        encrypted_payload.pop("vcenter_password", None)

        targets = encrypted_payload.get("targets", {})
        if isinstance(targets, dict):
            for target_name, target_info in targets.items():
                if not isinstance(target_info, dict):
                    continue
                target_user = normalize_text(target_info.get("username", ""))
                target_password = target_info.get("password", "")
                if target_user:
                    target_info["username_enc"] = self._encrypt_value(fernet, target_user)
                if target_password:
                    target_info["password_enc"] = self._encrypt_value(fernet, target_password)
                target_info.pop("username", None)
                target_info.pop("password", None)

        ssh_tunnel = encrypted_payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            gateway_password = ssh_tunnel.get("gateway_password", "")
            if gateway_password:
                ssh_tunnel["gateway_password_enc"] = self._encrypt_value(fernet, gateway_password)
            ssh_tunnel.pop("gateway_password", None)

        encrypted_payload["credentials_encrypted"] = bool(fernet)
        encrypted_payload["credentials_scheme"] = "fernet-v1" if fernet else "none"
        return encrypted_payload

    def _decrypt_profile_credentials(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Internal helper for decrypt profile credentials."""
        fernet = self._get_fernet()
        decrypted_payload = copy.deepcopy(payload)

        if decrypted_payload.get("vcenter_username_enc"):
            decrypted_payload["vcenter_username"] = self._decrypt_value(fernet, decrypted_payload.get("vcenter_username_enc", ""))
        else:
            decrypted_payload["vcenter_username"] = normalize_text(decrypted_payload.get("vcenter_username", ""))

        if decrypted_payload.get("vcenter_password_enc"):
            decrypted_payload["vcenter_password"] = self._decrypt_value(fernet, decrypted_payload.get("vcenter_password_enc", ""))
        else:
            decrypted_payload["vcenter_password"] = decrypted_payload.get("vcenter_password", "")

        targets = decrypted_payload.get("targets", {})
        if isinstance(targets, dict):
            for target_name, target_info in targets.items():
                if not isinstance(target_info, dict):
                    continue
                if target_info.get("username_enc"):
                    target_info["username"] = self._decrypt_value(fernet, target_info.get("username_enc", ""))
                else:
                    target_info["username"] = normalize_text(target_info.get("username", ""))

                if target_info.get("password_enc"):
                    target_info["password"] = self._decrypt_value(fernet, target_info.get("password_enc", ""))
                else:
                    target_info["password"] = target_info.get("password", "")

        ssh_tunnel = decrypted_payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            if ssh_tunnel.get("gateway_password_enc"):
                ssh_tunnel["gateway_password"] = self._decrypt_value(fernet, ssh_tunnel.get("gateway_password_enc", ""))
            else:
                ssh_tunnel["gateway_password"] = ssh_tunnel.get("gateway_password", "")

        return decrypted_payload

    def profile_path(self, profile_name: str) -> Path:
        """Profile path."""
        return self.profiles_dir / f"{profile_name}.json"

    def save_profile(self, profile_name: str, payload: Dict[str, Any]) -> str:
        """Save profile."""
        payload = self._encrypt_profile_credentials(payload)
        payload["profile_name"] = profile_name
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        path = self.profile_path(profile_name)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(path)

    def load_profile(self, profile_name: str) -> Dict[str, Any]:
        """Load profile."""
        payload = json.loads(self.profile_path(profile_name).read_text(encoding="utf-8"))
        return self._decrypt_profile_credentials(payload)


class VSphereService:
    def __init__(self, server: str, username: str, password: str, ignore_ssl: bool = True):
        """Initialize the VSphereService instance."""
        self.server = server.strip()
        self.username = username.strip()
        self.password = password
        self.ignore_ssl = ignore_ssl
        self.si = None

    def connect(self):
        """Connect."""
        if not PYVMOMI_AVAILABLE:
            raise RuntimeError("pyVmomi is not installed. Install it with: pip install pyvmomi requests")
        context = ssl._create_unverified_context() if self.ignore_ssl else None
        self.si = SmartConnect(host=self.server, user=self.username, pwd=self.password, sslContext=context)
        return self.si

    def disconnect(self):
        """Disconnect."""
        if self.si is not None:
            Disconnect(self.si)
            self.si = None

    def _all_vms(self):
        """Internal helper for all vms."""
        if self.si is None:
            self.connect()
        content = self.si.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def find_vm(self, vm_name: str):
        """Find vm."""
        for vm_obj in self._all_vms():
            if vm_obj.name == vm_name:
                return vm_obj
        return None

    def list_windows_vms(self) -> List[str]:
        """List windows vms."""
        names = [LOCAL_SENTINEL]
        for vm_obj in self._all_vms():
            guest_name = normalize_text(getattr(getattr(vm_obj, "guest", None), "guestFullName", ""))
            if not guest_name or "WINDOWS" in guest_name.upper():
                names.append(vm_obj.name)
        return sorted(set(names), key=lambda x: (x != LOCAL_SENTINEL, x.lower()))

    def verify_vm_names(self, vm_names: List[str]) -> Dict[str, Dict[str, str]]:
        """Verify vm names."""
        inventory: Dict[str, Dict[str, str]] = {}
        for vm_obj in self._all_vms():
            inventory[vm_obj.name] = {
                "power_state": normalize_text(getattr(getattr(vm_obj, "runtime", None), "powerState", "")),
                "tools_status": normalize_text(getattr(getattr(vm_obj, "guest", None), "toolsRunningStatus", "")),
                "guest_os": normalize_text(getattr(getattr(vm_obj, "guest", None), "guestFullName", "")),
            }
        inventory[LOCAL_SENTINEL] = {"power_state": "LOCAL", "tools_status": "LOCAL", "guest_os": platform.platform()}
        return {name: inventory.get(name, {"power_state": "NOT_FOUND", "tools_status": "NOT_FOUND", "guest_os": "NOT_FOUND"}) for name in vm_names}

    def run_powershell_in_guest(self, vm_name: str, guest_username: str, guest_password: str, script: str, timeout_seconds: int = 90) -> Tuple[str, str, str]:
        """Run powershell in guest."""
        if requests is None:
            return "WARN", "ERROR", "requests is not installed. Install with: pip install requests"
        vm_obj = self.find_vm(vm_name)
        if vm_obj is None:
            return "WARN", "NOT_FOUND", f"VM '{vm_name}' not found"
        power_state = normalize_text(getattr(getattr(vm_obj, "runtime", None), "powerState", ""))
        if power_state.lower() != "poweredon":
            return "WARN", "VM_OFF", f"VM '{vm_name}' is not powered on"
        tools_status = normalize_text(getattr(getattr(vm_obj, "guest", None), "toolsRunningStatus", ""))
        if "guestToolsRunning" not in tools_status and "running" not in tools_status.lower():
            return "WARN", "TOOLS_NOT_READY", f"VMware Tools not ready on '{vm_name}'"

        content = self.si.RetrieveContent()
        guest_ops = content.guestOperationsManager
        creds = vim.vm.guest.NamePasswordAuthentication(username=guest_username, password=guest_password, interactiveSession=False)
        marker = timestamp_str()
        remote_out = fr"C:\Windows\Temp\sbl_audit_{marker}.txt"
        remote_err = fr"C:\Windows\Temp\sbl_audit_{marker}_err.txt"
        wrapped = (
            "$ErrorActionPreference='Stop';"
            f"try {{ {script} | Out-File -FilePath '{remote_out}' -Encoding UTF8 -Force }} "
            f"catch {{ $_ | Out-File -FilePath '{remote_err}' -Encoding UTF8 -Force; exit 1 }}"
        )
        spec = vim.vm.guest.ProcessManager.ProgramSpec(
            programPath=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            arguments=f"-NoProfile -ExecutionPolicy Bypass -Command \"{wrapped}\"",
        )
        pid = guest_ops.processManager.StartProgramInGuest(vm_obj, creds, spec)
        start = time.time()
        end_code = None
        while time.time() - start < timeout_seconds:
            info = guest_ops.processManager.ListProcessesInGuest(vm_obj, creds, [pid])
            if info and info[0].endTime is not None:
                end_code = info[0].exitCode
                break
            time.sleep(2)
        if end_code is None:
            return "WARN", "TIMEOUT", f"Timed out waiting for guest command on '{vm_name}'"

        def fetch_text(remote_path: str) -> str:
            """Fetch text."""
            try:
                file_info = guest_ops.fileManager.InitiateFileTransferFromGuest(vm_obj, creds, remote_path)
                response = requests.get(file_info.url, verify=not self.ignore_ssl, timeout=30)
                response.raise_for_status()
                return response.text.strip()
            except Exception:
                return ""

        stdout = fetch_text(remote_out)
        stderr = fetch_text(remote_err)
        if end_code == 0:
            return "PASS", stdout or "BLANK_OUTPUT", f"Guest PowerShell completed on '{vm_name}'"
        return "WARN", stderr or stdout or "ERROR", f"Guest PowerShell failed on '{vm_name}' with exit code {end_code}"


class SSHTunnelService:
    def __init__(
        self,
        target_username: str,
        target_password: str,
        target_port: int = 22,
        gateway_host: str = "",
        gateway_username: str = "",
        gateway_password: str = "",
        gateway_port: int = 22,
        timeout_seconds: int = 30,
    ):
        """Initialize the SSHTunnelService instance."""
        self.target_username = target_username.strip()
        self.target_password = target_password
        self.target_port = target_port
        self.gateway_host = gateway_host.strip()
        self.gateway_username = gateway_username.strip()
        self.gateway_password = gateway_password
        self.gateway_port = gateway_port
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _encode_powershell(script: str) -> str:
        """Internal helper for encode powershell."""
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _connect_target(self, target_host: str, target_username: str, target_password: str):
        """Internal helper for connect target."""
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko is not installed. Install it with: pip install paramiko")

        target_client = paramiko.SSHClient()
        target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.gateway_host:
            gateway_client = paramiko.SSHClient()
            gateway_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            gateway_client.connect(
                hostname=self.gateway_host,
                port=self.gateway_port,
                username=self.gateway_username,
                password=self.gateway_password,
                timeout=self.timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = gateway_client.get_transport()
            if transport is None:
                gateway_client.close()
                raise RuntimeError(f"SSH gateway transport is unavailable for {self.gateway_host}")

            sock = transport.open_channel(
                "direct-tcpip",
                (target_host, self.target_port),
                ("127.0.0.1", 0),
            )
            target_client.connect(
                hostname=target_host,
                port=self.target_port,
                username=target_username,
                password=target_password,
                timeout=self.timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
                sock=sock,
            )
            return target_client, gateway_client

        target_client.connect(
            hostname=target_host,
            port=self.target_port,
            username=target_username,
            password=target_password,
            timeout=self.timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        return target_client, None

    def run_powershell(
        self,
        target_host: str,
        script: str,
        timeout_seconds: int = 90,
        target_username: str = "",
        target_password: str = "",
    ) -> Tuple[str, str, str]:
        """Run powershell."""
        resolved_username = normalize_text(target_username) or self.target_username
        resolved_password = target_password or self.target_password
        if not resolved_username or not resolved_password:
            return "WARN", "NO_SSH_CREDS", f"Missing SSH credentials for target {target_host}"
        if not target_host:
            return "WARN", "NO_TARGET", "SSH target host is blank"

        target_client = None
        gateway_client = None
        try:
            target_client, gateway_client = self._connect_target(target_host, resolved_username, resolved_password)
            encoded = self._encode_powershell(script)
            command = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"
            _, stdout, stderr = target_client.exec_command(command, timeout=timeout_seconds)
            out_text = stdout.read().decode(errors="ignore").strip()
            err_text = stderr.read().decode(errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()
            if exit_code == 0:
                return "PASS", out_text or "BLANK_OUTPUT", f"SSH PowerShell completed on '{target_host}'"
            return "WARN", err_text or out_text or "ERROR", f"SSH PowerShell failed on '{target_host}' with exit code {exit_code}"
        except Exception as exc:
            return "WARN", "SSH_ERROR", f"SSH execution failed on '{target_host}': {exc}"
        finally:
            try:
                if target_client is not None:
                    target_client.close()
            except Exception:
                pass
            try:
                if gateway_client is not None:
                    gateway_client.close()
            except Exception:
                pass


class VersionRuleResolver:
    """Resolve VERSION LOCATIONS text into concrete scan rules and payloads."""

    @staticmethod
    def extract_file_paths(version_location: str) -> List[str]:
        """Extract Windows executable/dll paths from a VERSION LOCATIONS string."""
        if not version_location:
            return []
        matches = re.findall(r"[A-Za-z]:\\[^;,\n\r\t]+?\.(?:exe|dll)", version_location, flags=re.IGNORECASE)
        cleaned: List[str] = []
        for match in matches:
            item = match.strip().strip('"').strip("'")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned

    @staticmethod
    def detect_rule(version_location: str) -> Tuple[str, Dict[str, Any]]:
        """Classify VERSION LOCATIONS into programs/features, powershell, file_version, or unknown."""
        upper = normalize_text(version_location).upper()
        if "PROGRAMS AND FEATURES" in upper:
            return "programs_and_features", {}
        if upper.startswith("POWERSHELL:"):
            return "powershell", {"command": version_location.split(":", 1)[1].strip()}
        paths = VersionRuleResolver.extract_file_paths(version_location)
        if paths:
            return "file_version", {"paths": paths}
        return "unknown", {}


def derive_path_metadata(version_location: str) -> Dict[str, str]:
    """Derive normalized path metadata used for master software list tracking."""
    path = normalize_text(version_location)
    rule, payload = VersionRuleResolver.detect_rule(path)

    if rule == "unknown":
        ps_match = re.search(r"type\s+(.+)$", path, flags=re.IGNORECASE)
        if ps_match and "powershell" in path.lower():
            rule = "powershell"
            payload = {"command": ps_match.group(1).strip()}

    if rule == "programs_and_features":
        coded_path = (
            "Get-ItemProperty "
            "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,"
            "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
            "| Select-Object DisplayName,DisplayVersion"
        )
    elif rule == "powershell":
        coded_path = payload.get("command", "")
    elif rule == "file_version":
        coded_path = "; ".join(payload.get("paths", []))
    else:
        coded_path = path

    return {
        "path": path,
        "coded_path": coded_path,
        "verification_source": rule,
    }


class AuditWorkbookService:
    """Parse, read, and write audit data from workbook-based checklist artifacts."""

    def __init__(self, file_path: str):
        """Initialize the AuditWorkbookService instance."""
        self.file_path = file_path
        self.repaired_file_path: Optional[str] = None
        try:
            self.workbook = load_workbook(file_path)
        except IndexError as exc:
            repaired_file_path = _repair_invalid_style_indexes(file_path)
            if not repaired_file_path:
                raise ValueError(
                    "Workbook could not be opened because its merged-cell style data is invalid. "
                    "The audit checklist needs to be repaired or regenerated before scanning."
                ) from exc
            try:
                self.workbook = load_workbook(repaired_file_path)
                self.repaired_file_path = repaired_file_path
            except Exception as repair_exc:
                raise ValueError(
                    "Workbook could not be opened because its merged-cell style data is invalid, "
                    "and automatic repair did not succeed. Regenerate the checklist and rerun the audit."
                ) from repair_exc
        self.worksheet = self.workbook.active
        self.header_row_index: Optional[int] = None
        self.column_map: Dict[str, int] = {}
        self.sbl_build_header: Optional[str] = None
        self.audit_header: Optional[str] = None
        self.current_ci_header: Optional[str] = None
        self.version_location_header: Optional[str] = None
        self.target_columns: List[str] = default_target_columns()
        self.schema: Optional[WorkbookSchema] = None
        self.build_type = infer_build_type(file_path)

    def _detect_target_headers(self, raw_headers: List[str], headers_by_name: Dict[str, int]) -> List[str]:
        """Internal helper for detect target headers."""
        header_positions = {header: idx for idx, header in enumerate(raw_headers)}
        range_candidates: List[str] = []

        if self.version_location_header:
            start_index = header_positions.get(self.version_location_header, -1) + 1
            end_indexes = [
                header_positions.get(self.sbl_build_header, -1),
                header_positions.get(self.audit_header, -1),
            ]
            end_indexes = [idx for idx in end_indexes if idx >= 0]
            if start_index > 0 and end_indexes:
                end_index = min(end_indexes)
                if start_index < end_index:
                    range_candidates = [
                        header for header in raw_headers[start_index:end_index]
                        if not is_known_non_target_header(header)
                    ]

        detected = range_candidates or [header for header in raw_headers if not is_known_non_target_header(header)]
        detected = [header for header in detected if header in headers_by_name]
        if detected:
            return detected

        legacy_present = [header for header in default_target_columns() if header in headers_by_name]
        return legacy_present

    def detect_header_row(self, search_limit: int = 20) -> int:
        """Find the row containing required audit headers within the search window."""
        for row_idx in range(1, min(search_limit, self.worksheet.max_row) + 1):
            normalized = {
                normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value): col_idx
                for col_idx in range(1, self.worksheet.max_column + 1)
                if normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value)
            }
            has_software = "SOFTWARE COMPONENT" in normalized
            has_current_ci = any("CURRENT CI VERSION" in header for header in normalized)
            has_version_loc = "VERSION LOCATION" in normalized or "VERSION LOCATIONS" in normalized
            if has_software and has_current_ci and has_version_loc:
                self.header_row_index = row_idx
                return row_idx
        raise ValueError("Could not find header row with SOFTWARE COMPONENT, CURRENT CI VERSION, and VERSION LOCATION(S).")

    def build_column_map(self) -> Dict[str, int]:
        """Map normalized header text to column indexes and detect target columns."""
        if self.header_row_index is None:
            self.detect_header_row()
        headers_by_name: Dict[str, int] = {}
        raw_headers: List[str] = []
        for col_idx in range(1, self.worksheet.max_column + 1):
            value = self.worksheet.cell(self.header_row_index, col_idx).value
            text = normalize_text(value)
            if text:
                headers_by_name[text] = col_idx
                raw_headers.append(text)
        self.sbl_build_header, self.audit_header = parse_build_and_audit_headers(raw_headers)
        self.current_ci_header = next(
            (header for header in raw_headers if "CURRENT CI VERSION" in normalize_header(header)),
            None,
        )
        self.version_location_header = next(
            (header for header in raw_headers if normalize_header(header) in ("VERSION LOCATION", "VERSION LOCATIONS")),
            None,
        )
        if not self.sbl_build_header or not self.audit_header or not self.current_ci_header or not self.version_location_header:
            raise ValueError("Could not find SBL Build, AUDIT, CURRENT CI VERSION, or VERSION LOCATION column.")
        self.target_columns = self._detect_target_headers(raw_headers, headers_by_name)
        required = ["SOFTWARE COMPONENT", self.current_ci_header, self.sbl_build_header, self.audit_header, self.version_location_header]
        missing = [name for name in required if name not in headers_by_name]
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(missing)}")
        if not self.target_columns:
            raise ValueError("Could not detect any VM target columns from the workbook headers.")
        self.column_map = headers_by_name
        self.schema = WorkbookSchema(
            source_path=self.file_path,
            source_format=detect_workbook_format(self.file_path),
            header_row_index=(self.header_row_index or 1) - 1,
            software_column="SOFTWARE COMPONENT",
            current_version_column=self.current_ci_header,
            sbl_version_column=self.sbl_build_header,
            target_columns=list(self.target_columns),
            other_columns=[
                header for header in raw_headers
                if header not in {"SOFTWARE COMPONENT", self.current_ci_header, self.sbl_build_header, self.audit_header, self.version_location_header}
                and header not in self.target_columns
            ],
        )
        return headers_by_name

    def iter_audit_rows(self) -> List[AuditRow]:
        """Iter audit rows."""
        if not self.column_map:
            self.build_column_map()
        rows: List[AuditRow] = []
        for row_idx in range(self.header_row_index + 1, self.worksheet.max_row + 1):
            software_component = normalize_text(self.worksheet.cell(row_idx, self.column_map["SOFTWARE COMPONENT"]).value)
            current_ci_version = normalize_text(self.worksheet.cell(row_idx, self.column_map[self.current_ci_header]).value)
            sbl_build_version = normalize_text(self.worksheet.cell(row_idx, self.column_map[self.sbl_build_header]).value)
            vl_cell = self.worksheet.cell(row_idx, self.column_map[self.version_location_header])
            if isinstance(vl_cell, MergedCell):
                vl_value = None
                for merged_range in self.worksheet.merged_cells.ranges:
                    if vl_cell.coordinate in merged_range:
                        vl_value = self.worksheet.cell(merged_range.min_row, merged_range.min_col).value
                        break
                version_locations = normalize_text(vl_value)
            else:
                version_locations = normalize_text(vl_cell.value)
            audit_value = normalize_text(self.worksheet.cell(row_idx, self.column_map[self.audit_header]).value)
            marks = {
                name: normalize_text(self.worksheet.cell(row_idx, self.column_map[name]).value)
                for name in self.target_columns
                if name in self.column_map
            }
            if not software_component and not current_ci_version and not sbl_build_version and not version_locations:
                continue
            rows.append(AuditRow(row_idx, software_component, current_ci_version, sbl_build_version, audit_value, marks, version_locations))
        return rows

    def write_audit_result(self, row_index: int, audit_text: str, status: str) -> None:
        """Write audit result."""
        col_index = self.column_map[self.audit_header]
        cell = self.worksheet.cell(row_index, col_index)
        if isinstance(cell, MergedCell):
            for merged_range in self.worksheet.merged_cells.ranges:
                if cell.coordinate in merged_range:
                    cell = self.worksheet.cell(merged_range.min_row, merged_range.min_col)
                    break
        cell.value = audit_text
        cell.fill = PASS_FILL if status == "PASS" else FAIL_FILL if status == "FAIL" else WARN_FILL

    def save_as(self, output_path: str) -> None:
        """Save as."""
        self.workbook.save(output_path)


# class AuditWorkbookServiceProxy:
#     def __init__(self, worksheet):
#         self.worksheet = worksheet
#         self.header_row_index: Optional[int] = None
#         self.sbl_build_header: Optional[str] = None
#         self.audit_header: Optional[str] = None

#     def detect_header_row(self, search_limit: int = 20) -> int:
#         for row_idx in range(1, min(search_limit, self.worksheet.max_row) + 1):
#             normalized = {
#                 normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value): col_idx
#                 for col_idx in range(1, self.worksheet.max_column + 1)
#                 if normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value)
#             }
#             if REQ_HEADERS.issubset(set(normalized.keys())):
#                 self.header_row_index = row_idx
#                 return row_idx
#         raise ValueError("Could not find header row in worksheet.")

#     def build_column_map(self):
#         headers_by_name: Dict[str, int] = {}
#         raw_headers: List[str] = []
#         for col_idx in range(1, self.worksheet.max_column + 1):
#             value = self.worksheet.cell(self.header_row_index, col_idx).value
#             text = normalize_text(value)
#             if text:
#                 headers_by_name[text] = col_idx
#                 raw_headers.append(text)
#         self.sbl_build_header, self.audit_header = parse_build_and_audit_headers(raw_headers)
#         if not self.sbl_build_header or not self.audit_header:
#             raise ValueError("Could not find SBL Build or AUDIT column.")
#         return headers_by_name, self.sbl_build_header, self.audit_header
class AuditWorkbookServiceProxy:
    """Worksheet proxy used by checklist generation for tolerant header and row parsing."""

    def __init__(self, worksheet):
        """Initialize the AuditWorkbookServiceProxy instance."""
        self.worksheet = worksheet
        self.header_row_index: Optional[int] = None
        self.column_map: Dict[str, int] = {}
        self.sbl_build_header: Optional[str] = None
        self.audit_header: Optional[str] = None
        self.current_ci_header: Optional[str] = None
        self.version_location_header: Optional[str] = None
        self.displayed_name_header: Optional[str] = None
        self.id_number_header: Optional[str] = None
        print("Initialized AuditWorkbookServiceProxy.... ready to detect headers and read software list.")

    def reset_header_cache(self) -> None:
        """Reset header cache."""
        self.header_row_index = None
        self.column_map = {}
        self.sbl_build_header = None
        self.audit_header = None
        self.current_ci_header = None
        self.version_location_header = None
        self.displayed_name_header = None
        self.id_number_header = None

    def extract_path(self, version_location: Any) -> str:
        """Extract path."""
        print(f"Extracting path from version_location: {repr(version_location)}")
        if version_location is None:
            return ""
        text = str(version_location).strip()
        match = re.match(r'([A-Za-z]:[\\/].*?)(?=\s*>)', text)
        if match:
            return match.group(1).strip()
        return text
# changed range from 1 to 0 to account for 0-based indexing in openpyxl when using with active worksheet that may have empty first row
    def detect_header_row(self, search_limit: int = 20) -> int:
        """Detect the header row in generated/imported worksheets."""
        print("Detecting header row...")
        if self.header_row_index is not None:
            return self.header_row_index
        # The detect_header_row method iterates through the rows of the worksheet up to a specified search limit (defaulting to 20). For each row, it normalizes the header values and checks for the presence of key headers such as "SOFTWARE COMPONENT" and either "VERSION LOCATION" or "VERSION LOCATIONS". If it finds a row that contains these headers, it sets the header_row_index and returns it. If no suitable header row is found within the search limit, it raises a ValueError.
        for row_idx in range(1, min(search_limit, self.worksheet.max_row) + 1):
            print(f"Checking row {row_idx} for headers...")
            row_headers = [
                normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value)
                for col_idx in range(1, self.worksheet.max_column + 1)
            ]
            # The method checks for the presence of "SOFTWARE COMPONENT" and either "VERSION LOCATION" or "VERSION LOCATIONS" in the normalized headers of the current row. If both conditions are met, it identifies that row as the header row and returns its index.
            has_software_component = "SOFTWARE COMPONENT" in row_headers
            has_version_location = (
                "VERSION LOCATION" in row_headers or
                "VERSION LOCATIONS" in row_headers
            )
            if has_software_component and has_version_location:
                print(f"Found header row at index {row_idx}")

                self.header_row_index = row_idx
                return row_idx
        raise ValueError("Could not find header row in worksheet...")
    
    # The build_column_map method reads the header row and constructs a mapping of header names to their respective column indices. It also identifies the specific headers for SBL Build, AUDIT, CURRENT CI VERSION, VERSION LOCATION(S), DISPLAYED NAME, and CM TOOL ID NUMBER, which are essential for processing the software list and audit results.
    def build_column_map(self, refresh: bool = False):
        """Build and cache worksheet header mappings required for checklist extraction."""
        print("Building column map...")
        if refresh:
            self.reset_header_cache()
        if self.column_map:
            return self.column_map, self.sbl_build_header, self.audit_header
        if self.header_row_index is None:
            print("Header row index not set, attempting to detect header row...")
            self.detect_header_row()

        headers_by_name: Dict[str, int] = {}
        raw_headers: List[str] = []

        for col_idx in range(1, self.worksheet.max_column + 1): # changed range from 0 to 1 to account for 1-based indexing in openpyxl
            print(f"Reading header from column {col_idx}...")
            value = self.worksheet.cell(self.header_row_index, col_idx).value
            text = normalize_text(value)
            print(f"Column {col_idx}: raw header value = {repr(value)}, normalized = {repr(text)}")
            if text:
                headers_by_name[text] = col_idx
                raw_headers.append(text)
                print(f"Added header '{text}' to column map with index {col_idx}.")
        
        # After building the initial mapping of headers, the method uses the parse_build_and_audit_headers function to identify the specific headers for SBL Build and AUDIT. It also looks for headers that match "CURRENT CI VERSION", "VERSION LOCATION(S)", "DISPLAYED NAME", and "CM TOOL ID NUMBER" to set the corresponding attributes in the proxy class. If it cannot find the essential SBL Build or AUDIT columns, it raises a ValueError.
        self.sbl_build_header, self.audit_header = parse_build_and_audit_headers(raw_headers)
        self.current_ci_header = next(
            (header for header in raw_headers if re.match(r".*CURRENT CI VERSION.*", header, re.IGNORECASE)),
            None,
        )
        self.version_location_header = next(
            (
                header for header in raw_headers
                if normalize_header(header) in ("VERSION LOCATION", "VERSION LOCATIONS")
            ),
            None,
        )
        self.displayed_name_header = next(
            (header for header in raw_headers if normalize_header(header) == "DISPLAYED NAME"),
            None,
        )
        self.id_number_header = next(
            (header for header in raw_headers if normalize_header(header) == "CM TOOL ID NUMBER"),
            None,
        )

        if not self.sbl_build_header or not self.audit_header:
            raise ValueError("Could not find SBL Build or AUDIT column.")

        self.column_map = headers_by_name

        return self.column_map, self.sbl_build_header, self.audit_header
    def read_software_list(self) -> List[Dict[str, str]]:
        """Return normalized software rows with expected version and detection location."""
        print("Reading software list from worksheet...")
        #
        column_map, _, _ = self.build_column_map()

        software_component_header = next(
            (header for header in column_map if normalize_header(header) == "SOFTWARE COMPONENT"),
            None,
        )

        if not software_component_header:
            raise ValueError("Missing required column: SOFTWARE COMPONENT")
        if not self.version_location_header:
            raise ValueError("Missing required column: VERSION LOCATION or VERSION LOCATIONS")
        if not self.current_ci_header:
            raise ValueError("No column found with 'CURRENT CI VERSION' in the name.")

        software_list: List[Dict[str, str]] = []

        print(f"Header row index: {self.header_row_index}, column map: {column_map}, version_location_header: {self.version_location_header}, current_ci_header: {self.current_ci_header}")
        for row_idx in range(self.header_row_index + 1, self.worksheet.max_row + 1):
            id_number_value = (
                normalize_text(self.worksheet.cell(row_idx, column_map[self.id_number_header]).value)
                if self.id_number_header else ""
            )
            software_component_value = normalize_text(
                self.worksheet.cell(row_idx, column_map[software_component_header]).value
            )
            displayed_name_value = (
                normalize_text(self.worksheet.cell(row_idx, column_map[self.displayed_name_header]).value)
                if self.displayed_name_header else ""
            )
            vl_cell = self.worksheet.cell(row_idx, column_map[self.version_location_header])
            print(f"Row {row_idx}: raw version_location cell value = {repr(vl_cell.value)} (merged: {isinstance(vl_cell, MergedCell)})")
            if isinstance(vl_cell, MergedCell):
                vl_value = None
                # When dealing with merged cells, we need to find the top-left cell of the merged range to get the actual value. The openpyxl library represents merged cells as MergedCell objects, which do not contain the value directly. Instead, we have to check if the current cell is part of a merged range and then retrieve the value from the starting cell of that range.
                
                for merged_range in self.worksheet.merged_cells.ranges:
                    print(f"Checking if cell {vl_cell.coordinate} is in merged range {merged_range}...")
                    # The coordinate of the current cell is checked against each merged range to see if it falls within that range. If it does, we retrieve the value from the minimum row and minimum column of that merged range, which is where the actual value is stored for merged cells.
                    if vl_cell.coordinate in merged_range:
                        vl_value = self.worksheet.cell(merged_range.min_row, merged_range.min_col).value
                        break
                version_location_value = normalize_text(vl_value)
                if version_location_value is None or pd.isna(version_location_value):
                    version_location_value = ""
            else:
                version_location_value = normalize_text(vl_cell.value)
                if version_location_value is None or pd.isna(version_location_value):
                    version_location_value = ""
            print(f"Row {row_idx}: version_location_value = {repr(version_location_value)}")
            expected_version_value = normalize_text(
                self.worksheet.cell(row_idx, column_map[self.current_ci_header]).value
            )

            if self.id_number_header and not id_number_value:
                continue
            if not software_component_value:
                continue

            software_list.append({
                "name": software_component_value,
                "displayed_name": displayed_name_value,
                "expected_version": expected_version_value,
                "version_location": self.extract_path(version_location_value),
            })
            print(f"Final version_location: {repr(self.extract_path(version_location_value))}")

        return software_list

# This proxy class is designed to work with the active worksheet of the loaded workbook, which may have empty rows at the top. The header detection and column mapping logic has been updated to account for this possibility, allowing for more robust handling of various worksheet formats.
class ChecklistGeneratorService:
    """Generate workbook audit forms from Excel/JSON/CSV checklist sources."""

    def __init__(self, source_path: str):
        """Initialize the ChecklistGeneratorService instance."""
        self.source_path = source_path
        self.template_service = TemplateAssetService()
        self.normalized_source_path = source_path
        source_format = detect_workbook_format(source_path)
        if source_format != "excel":
            with tempfile.NamedTemporaryFile(prefix="auditmatic_import_", suffix=".xlsx", delete=False) as temp_file:
                normalized_path = temp_file.name
            self.template_service.import_list_to_sbl_workbook(source_path, normalized_path)
            self.normalized_source_path = normalized_path
        self.source_workbook = load_workbook(self.normalized_source_path)
        self.source_ws = self.source_workbook.active
        print(f"Initialized ChecklistGeneratorService with source: {source_path} (normalized={self.normalized_source_path})" ) # added print statement to confirm initialization and source path
    
    # The generate_audit_form method creates a new workbook and copies the content and styles from the source worksheet. It then detects the header row and column mapping, clears any existing audit values, updates the audit header with the current date, auto-fits the columns, and saves the new workbook to the specified output path.
    def generate_audit_form(self, output_path: str) -> None:
        """Create an audit workbook by preserving source structure and clearing audit result cells."""
        print(f"Generating audit form from '{self.source_path}' to '{output_path}'")
        src_path = Path(self.normalized_source_path)
        dst_path = Path(output_path)
        if src_path.resolve() != dst_path.resolve():
            # Direct file copy keeps style indexes and merged ranges intact.
            shutil.copy2(src_path, dst_path)

        wb_out = load_workbook(output_path)
        ws_out = wb_out.active

        print("Copied workbook directly. Now detecting headers and clearing audit values...")
        proxy = AuditWorkbookServiceProxy(ws_out)
        col_map, _, audit_header = proxy.build_column_map()
        header_row = proxy.header_row_index
        print(f"Detected header row at index: {header_row}") # added print statement to confirm detected header row
        print(f"Column map: {col_map}, audit header: {audit_header}") # added print statement to show column mapping and audit header   
        audit_col = col_map[audit_header]

        data_start_row = header_row + 1
        software_col = col_map.get("SOFTWARE COMPONENT")
        if software_col:
            for row_idx in range(header_row + 1, ws_out.max_row + 1):
                software_value = normalize_text(ws_out.cell(row_idx, software_col).value)
                if not software_value:
                    continue
                if "geospatial intelligence foundation" in software_value.lower():
                    # Skip template metadata rows and clear only true software data rows.
                    data_start_row = row_idx + 3
                    break
                data_start_row = row_idx
                break

        for row_idx in range(data_start_row, ws_out.max_row + 1):
            cell = ws_out.cell(row_idx, audit_col)
            if not isinstance(cell, MergedCell):
                cell.value = None
                cell.fill = PatternFill(fill_type=None)
        header_cell = ws_out.cell(header_row, audit_col)
        if header_cell.value:
            header_cell.value = re.sub(r"\bXX[A-Z]{3}\d{4}\b", today_str(), str(header_cell.value).upper())
        else:
            print("No audit header found, skipping audit value clearing and header update.")
        wb_out.save(output_path)

    

    def export_json_payload(self) -> Dict[str, Any]:
        """Export normalized checklist rows and schema metadata as a JSON payload."""
        service = AuditWorkbookService(self.normalized_source_path)
        service.detect_header_row()
        service.build_column_map()
        rows = [
            {
                "software_component": row.software_component,
                "current_ci_version": row.current_ci_version,
                "sbl_build_version": row.sbl_build_version,
                "audit_value": row.audit_value,
                "target_vms": row.target_vms,
                "version_locations": row.version_locations,
            }
            for row in service.iter_audit_rows()
        ]
        return {
            "source_workbook": self.source_path,
            "normalized_source_workbook": self.normalized_source_path,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target_columns": list(service.target_columns),
            "build_type": service.build_type,
            "rows": rows,
        }


class LocalWindowsScanner:
    """Run local Windows software detection commands used by the audit engine."""

    @staticmethod
    def describe_local_detection_commands(software_name: str, version_location: str) -> List[str]:
        """Return diagnostic PowerShell commands that correspond to a VERSION LOCATIONS rule."""
        rule, payload = VersionRuleResolver.detect_rule(version_location)
        commands: List[str] = []

        if rule == "programs_and_features":
            safe_name = software_name.replace("'", "''")
            commands.append(
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                "'HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1"
            )
            return commands

        if rule == "powershell":
            command = payload.get("command", "")
            if command:
                commands.append(command)
            return commands

        if rule == "file_version":
            for path_value in payload.get("paths", []):
                safe_path = path_value.replace("'", "''")
                commands.append(
                    f"$p='{safe_path}'; if (Test-Path $p) {{ (Get-Item $p).VersionInfo.ProductVersion }}"
                )
            return commands

        commands.append(
            "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            "Get-ItemProperty $paths -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion"
        )
        for path_value in VersionRuleResolver.extract_file_paths(version_location):
            safe_path = path_value.replace("'", "''")
            commands.append(f"$p='{safe_path}'; if (Test-Path $p) {{ (Get-Item $p).VersionInfo.ProductVersion }}")
        return commands

    def capture_registry_snapshot(self) -> Dict[str, Any]:
        """Capture an inventory snapshot from uninstall registry keys on the local machine."""
        snapshot: Dict[str, Any] = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "status": "ok",
            "entries": [],
            "entry_count": 0,
        }
        if winreg is None or platform.system().lower() != "windows":
            snapshot["status"] = "not_supported"
            snapshot["reason"] = "Registry snapshot requires Windows with winreg support"
            return snapshot

        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        entries: List[Dict[str, str]] = []
        try:
            for hive, root in roots:
                with winreg.OpenKey(hive, root) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        try:
                            sub_name = winreg.EnumKey(base, i)
                            with winreg.OpenKey(base, sub_name) as sub:
                                display_name = normalize_text(winreg.QueryValueEx(sub, "DisplayName")[0])
                                if not display_name:
                                    continue
                                try:
                                    display_version = normalize_text(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                except Exception:
                                    display_version = ""
                                try:
                                    publisher = normalize_text(winreg.QueryValueEx(sub, "Publisher")[0])
                                except Exception:
                                    publisher = ""

                                entries.append(
                                    {
                                        "registry_key": f"{root}\\{sub_name}",
                                        "display_name": display_name,
                                        "display_name_normalized": normalize_header(display_name),
                                        "display_version": display_version,
                                        "display_version_normalized": normalize_version(display_version),
                                        "publisher": publisher,
                                    }
                                )
                        except Exception:
                            continue
            entries.sort(key=lambda item: (item["display_name_normalized"], item["display_version_normalized"], item["registry_key"]))
            snapshot["entries"] = entries
            snapshot["entry_count"] = len(entries)
            return snapshot
        except Exception as exc:
            snapshot["status"] = "error"
            snapshot["reason"] = str(exc)
            snapshot["entries"] = entries
            snapshot["entry_count"] = len(entries)
            return snapshot

    def find_programs_and_features_version(self, software_name: str) -> Tuple[str, str, str]:
        """Find software version by matching DisplayName in Programs and Features registry keys."""
        if winreg is None or platform.system().lower() != "windows":
            return "WARN", "NOT_WINDOWS", "Registry-based scan requires Windows"
        target = software_name.lower()
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        try:
            for hive, root in roots:
                with winreg.OpenKey(hive, root) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        try:
                            sub_name = winreg.EnumKey(base, i)
                            with winreg.OpenKey(base, sub_name) as sub:
                                display_name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                                try:
                                    version = str(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                except Exception:
                                    version = ""
                                if target in display_name.lower():
                                    return "PASS", version or "FOUND_NO_VERSION", f"Matched installed app '{display_name}'"
                        except Exception:
                            continue
        except Exception as exc:
            return "WARN", "ERROR", f"Registry scan failed: {exc}"
        return "FAIL", "NOT_FOUND", "Software not found in Programs and Features"

    def run_powershell(self, command: str) -> Tuple[str, str, str]:
        """Execute a local PowerShell command and normalize status/output semantics."""
        try:
            completed = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], capture_output=True, text=True, timeout=45, check=False)
            output = (completed.stdout or completed.stderr).strip()
            if completed.returncode == 0:
                return "PASS", output or "BLANK_OUTPUT", "Local PowerShell command completed"
            return "WARN", output or "ERROR", f"Local PowerShell returned {completed.returncode}"
        except Exception as exc:
            return "WARN", "ERROR", f"Local PowerShell failed: {exc}"

    def get_file_version(self, path_value: str) -> Tuple[str, str, str]:
        """Read ProductVersion/FileVersion from a local executable or library path."""
        safe_path = path_value.replace("'", "''")
        command = (
            f"$p='{safe_path}';"
            "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
            "$item = Get-Item $p;"
            "$ver = $item.VersionInfo.ProductVersion;"
            "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
            "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
            "Write-Output $ver"
        )
        status, version, details = self.run_powershell(command)
        if status == "PASS" and version == "MISSING_FILE":
            return "FAIL", "MISSING_FILE", f"File not found: {path_value}"
        if status == "PASS":
            return "PASS", version, f"Read file version from {path_value}"
        return status, version, f"File version query failed for {path_value}: {details}"

    def scan_file_versions(self, paths: List[str]) -> Tuple[str, str, str]:
        """Try candidate file paths and return the first successful version lookup."""
        failures: List[str] = []
        for path_value in paths:
            status, version, details = self.get_file_version(path_value)
            if status == "PASS":
                return status, version, details
            failures.append(f"{path_value} -> {version}")
        return "WARN", "NOT_FOUND", "; ".join(failures) if failures else "No candidate file paths found"

    def scan_software_version(self, software_name: str, version_location: str) -> Tuple[str, str, str]:
        """Resolve and execute the appropriate local scan rule for one software component."""
        rule, payload = VersionRuleResolver.detect_rule(version_location)
        if rule == "programs_and_features":
            return self.find_programs_and_features_version(software_name)
        if rule == "powershell":
            return self.run_powershell(payload["command"])
        if rule == "file_version":
            return self.scan_file_versions(payload["paths"])
        return "WARN", "UNKNOWN", f"No implemented scan rule matched VERSION LOCATIONS for {software_name}"


class AuditEngine:
    """Coordinate local/remote scanning and version comparison for parsed audit rows."""

    def __init__(
        self,
        workbook_service: AuditWorkbookService,
        logger,
        vm_profile: Dict[str, Any],
        vcenter_creds: Dict[str, str],
        guest_creds: Dict[str, str],
        connection_mode: str = "vsphere",
        ssh_config: Optional[Dict[str, Any]] = None,
        ssh_fallback_enabled: bool = False,
    ):
        """Initialize the AuditEngine instance."""
        self.workbook_service = workbook_service
        self.logger = logger
        self.vm_profile = vm_profile
        self.vcenter_creds = vcenter_creds
        self.guest_creds = guest_creds
        self.connection_mode = normalize_text(connection_mode).lower() or "vsphere"
        self.ssh_config = ssh_config or {}
        self.ssh_fallback_enabled = bool(ssh_fallback_enabled)
        self.local_scanner = LocalWindowsScanner()
        self.master_paths = MasterSoftwarePathService()
        self.master_model_name = normalize_model_key(_get_sbl_model_from_workbook(self.workbook_service.file_path))
        self.vsphere_service: Optional[VSphereService] = None
        self.ssh_service: Optional[SSHTunnelService] = None

    def _build_result(self, row: AuditRow, target_name: str, found_version: str, scan_status: str, details: str) -> ScanResult:
        """Build a ScanResult and update master path metadata for the scanned component."""
        if row.version_locations:
            self.master_paths.update_component(
                row.software_component,
                row.version_locations,
                target_name=target_name,
                scan_status=scan_status,
                model_name=self.master_model_name,
            )
        status, audit_text = compare_versions(row.sbl_build_version, found_version, scan_status)
        return ScanResult(row.software_component, target_name, row.sbl_build_version, found_version, status, details, row.row_index, audit_text)

    def _scan_local(self, row: AuditRow, target_name: str) -> ScanResult:
        """Scan a row against the local machine and convert output into ScanResult."""
        scan_status, found_version, details = self.local_scanner.scan_software_version(row.software_component, row.version_locations)
        return self._build_result(row, target_name, found_version, scan_status, f"local-machine | {details}")

    def _scan_guest_vm(self, row: AuditRow, target_name: str, vm_name: str, guest_username: str, guest_password: str) -> ScanResult:
        """Scan a target VM through vSphere guest execution using the resolved scan rule."""
        if self.vsphere_service is None:
            return self._build_result(row, target_name, "NO_VSPHERE", "WARN", f"vSphere service is not connected for '{vm_name}'")
        if not guest_username or not guest_password:
            return self._build_result(row, target_name, "NO_GUEST_CREDS", "WARN", f"Missing guest credentials for '{vm_name}'")
        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, payload["command"])
            return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details}")
        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, script)
            if scan_status == "PASS" and found_version == "NOT_FOUND":
                scan_status = "FAIL"
            return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details}")
        if rule == "file_version":
            failures: List[str] = []
            for path_value in payload["paths"]:
                safe_path = path_value.replace("'", "''")
                script = (
                    f"$p='{safe_path}';"
                    "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
                    "$item = Get-Item $p;"
                    "$ver = $item.VersionInfo.ProductVersion;"
                    "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
                    "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
                    "Write-Output $ver"
                )
                scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, script)
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"vm={vm_name} | no candidate file path succeeded | {'; '.join(failures)}")
        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"vm={vm_name} | No implemented scan rule matched VERSION LOCATIONS")

    def _scan_ssh_target(self, row: AuditRow, target_name: str, target_host: str, target_username: str, target_password: str) -> ScanResult:
        """Scan a target host over SSH tunnel mode using the resolved scan rule."""
        if self.ssh_service is None:
            return self._build_result(row, target_name, "NO_SSH_SERVICE", "WARN", f"SSH service is not initialized for '{target_host}'")

        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.ssh_service.run_powershell(
                target_host,
                payload["command"],
                target_username=target_username,
                target_password=target_password,
            )
            return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details}")

        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.ssh_service.run_powershell(
                target_host,
                script,
                target_username=target_username,
                target_password=target_password,
            )
            if scan_status == "PASS" and found_version == "NOT_FOUND":
                scan_status = "FAIL"
            return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details}")

        if rule == "file_version":
            failures: List[str] = []
            for path_value in payload["paths"]:
                safe_path = path_value.replace("'", "''")
                script = (
                    f"$p='{safe_path}';"
                    "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
                    "$item = Get-Item $p;"
                    "$ver = $item.VersionInfo.ProductVersion;"
                    "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
                    "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
                    "Write-Output $ver"
                )
                scan_status, found_version, details = self.ssh_service.run_powershell(
                    target_host,
                    script,
                    target_username=target_username,
                    target_password=target_password,
                )
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"ssh-host={target_host} | no candidate file path succeeded | {'; '.join(failures)}")

        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"ssh-host={target_host} | No implemented scan rule matched VERSION LOCATIONS")

    def scan_target_row(self, row: AuditRow, target_name: str) -> ScanResult:
        """Route a row scan to local, SSH, or vSphere paths based on profile mapping."""
        target_profile = self.vm_profile.get("targets", {}).get(target_name, {})
        vm_name = normalize_text(target_profile.get("vm_name", ""))
        target_username = normalize_text(target_profile.get("username", "")) or normalize_text(self.guest_creds.get("username", ""))
        target_password = target_profile.get("password", "") or self.guest_creds.get("password", "")
        if not vm_name:
            return self._build_result(row, target_name, "PROFILE_NOT_MAPPED", "WARN", f"No VM mapping saved for {target_name}")
        if vm_name.upper() == LOCAL_SENTINEL:
            return self._scan_local(row, target_name)
        if self.connection_mode == "ssh tunnel":
            result = self._scan_ssh_target(row, target_name, vm_name, target_username, target_password)
            if (
                self.ssh_fallback_enabled
                and result.status in ("WARN", "FAIL")
                and self.vsphere_service is not None
            ):
                self.logger(f"SSH scan failed for {target_name}, trying vSphere fallback...")
                vm_result = self._scan_guest_vm(row, target_name, vm_name, target_username, target_password)
                if vm_result.status == "PASS":
                    self.logger(f"vSphere fallback succeeded for {target_name}")
                    return vm_result
                self.logger(f"vSphere fallback also failed for {target_name}")
            return result

        # vSphere mode - try vSphere first
        result = self._scan_guest_vm(row, target_name, vm_name, target_username, target_password)

        # If fallback is enabled and vSphere failed, try SSH
        if (self.ssh_fallback_enabled and
            result.status in ("WARN", "FAIL") and
            self.ssh_service is not None):
            self.logger(f"vSphere scan failed for {target_name}, trying SSH fallback...")
            ssh_result = self._scan_ssh_target(row, target_name, vm_name, target_username, target_password)
            if ssh_result.status == "PASS":
                self.logger(f"SSH fallback succeeded for {target_name}")
                return ssh_result
            else:
                self.logger(f"SSH fallback also failed for {target_name}")

        return result

    @staticmethod
    def choose_best_row_result(row_results: List[ScanResult]) -> ScanResult:
        """Choose best row result."""
        if not row_results:
            return ScanResult("", "", "", "", "WARN", "No targets", 0, "WARN | no targets")
        for result in row_results:
            if result.status == "FAIL":
                return result
        for result in row_results:
            if result.status == "WARN":
                return result
        return row_results[0]

    def run(self) -> List[ScanResult]:
        """Run."""
        rows = self.workbook_service.iter_audit_rows()
        results: List[ScanResult] = []
        self.logger(f"Loaded {len(rows)} audit rows.")
        self.logger("Starting local-machine scan phase...")

        for row in rows:
            if not row.software_component:
                continue
            self.logger(f"Scanning {row.software_component} [LOCAL baseline]...")
            result = self._scan_local(row, "LOCAL_MACHINE")
            results.append(result)
            self.logger(result.audit_text + f" | {result.details}")

        for row in rows:
            if not row.software_component:
                continue
            for target_name, mark in row.target_vms.items():
                if not is_x_mark(mark):
                    continue
                vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                if not vm_name:
                    self.logger(f"Scanning {row.software_component} on {target_name} [UNMAPPED]...")
                    result = self.scan_target_row(row, target_name)
                    results.append(result)
                    self.logger(result.audit_text + f" | {result.details}")
                elif vm_name.upper() == LOCAL_SENTINEL:
                    continue

        needs_remote = any(
            normalize_text(self.vm_profile.get("targets", {}).get(target, {}).get("vm_name", "")).upper() not in ("", LOCAL_SENTINEL)
            for row in rows for target, mark in row.target_vms.items() if is_x_mark(mark)
        )

        if needs_remote:
            self.logger(f"Starting remote scan phase using mode: {self.connection_mode}...")
            if self.connection_mode == "ssh tunnel":
                try:
                    if self.ssh_fallback_enabled:
                        if not PYVMOMI_AVAILABLE:
                            self.logger("vSphere fallback enabled, but pyVmomi is not installed; SSH-only mode will be used.")
                        elif not self.vcenter_creds.get("server", "") or not self.vcenter_creds.get("username", "") or not self.vcenter_creds.get("password", ""):
                            self.logger("vSphere fallback enabled, but vCenter credentials/server are incomplete; SSH-only mode will be used.")
                        else:
                            try:
                                self.vsphere_service = VSphereService(
                                    self.vcenter_creds.get("server", ""),
                                    self.vcenter_creds.get("username", ""),
                                    self.vcenter_creds.get("password", ""),
                                    True,
                                )
                                self.vsphere_service.connect()
                                self.logger("vSphere fallback service initialized for SSH mode.")
                            except Exception as exc:
                                self.vsphere_service = None
                                self.logger(f"Could not initialize vSphere fallback in SSH mode: {exc}")

                    if not PARAMIKO_AVAILABLE:
                        if self.ssh_fallback_enabled and self.vsphere_service is not None:
                            self.logger("paramiko is not installed; attempting vSphere fallback-only scans.")
                            for row in rows:
                                if not row.software_component:
                                    continue
                                for target_name, mark in row.target_vms.items():
                                    if not is_x_mark(mark):
                                        continue
                                    vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                    if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                        self.logger(f"Scanning {row.software_component} on {target_name} [vSphere fallback={vm_name}]...")
                                        result = self._scan_guest_vm(row, target_name, vm_name)
                                        results.append(result)
                                        self.logger(result.audit_text + f" | {result.details}")
                        else:
                            self.logger("paramiko is not installed; SSH targets will be marked WARN.")
                            for row in rows:
                                if not row.software_component:
                                    continue
                                for target_name, mark in row.target_vms.items():
                                    if not is_x_mark(mark):
                                        continue
                                    vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                    if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                        result = self._build_result(
                                            row,
                                            target_name,
                                            "NO_PARAMIKO",
                                            "WARN",
                                            f"ssh-host={vm_name} | paramiko is not installed",
                                        )
                                        results.append(result)
                                        self.logger(result.audit_text + f" | {result.details}")
                    else:
                        self.ssh_service = SSHTunnelService(
                            target_username=self.guest_creds.get("username", ""),
                            target_password=self.guest_creds.get("password", ""),
                            target_port=int(self.ssh_config.get("target_port", 22)),
                            gateway_host=self.ssh_config.get("gateway_host", ""),
                            gateway_username=self.ssh_config.get("gateway_username", ""),
                            gateway_password=self.ssh_config.get("gateway_password", ""),
                            gateway_port=int(self.ssh_config.get("gateway_port", 22)),
                        )
                        self.logger("SSH tunnel mode initialized.")
                        for row in rows:
                            if not row.software_component:
                                continue
                            for target_name, mark in row.target_vms.items():
                                if not is_x_mark(mark):
                                    continue
                                vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                    self.logger(f"Scanning {row.software_component} on {target_name} [SSH={vm_name}]...")
                                    result = self.scan_target_row(row, target_name)
                                    results.append(result)
                                    self.logger(result.audit_text + f" | {result.details}")
                finally:
                    if self.vsphere_service is not None:
                        try:
                            self.vsphere_service.disconnect()
                        except Exception:
                            pass
                        self.vsphere_service = None
            elif not PYVMOMI_AVAILABLE:
                self.logger("pyVmomi is not installed; VM targets will be marked WARN.")
                for row in rows:
                    if not row.software_component:
                        continue
                    for target_name, mark in row.target_vms.items():
                        if not is_x_mark(mark):
                            continue
                        vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                        if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                            result = self._build_result(
                                row,
                                target_name,
                                "NO_PYVMOMI",
                                "WARN",
                                f"vm={vm_name} | pyVmomi is not installed",
                            )
                            results.append(result)
                            self.logger(result.audit_text + f" | {result.details}")
            else:
                self.vsphere_service = VSphereService(
                    self.vcenter_creds.get("server", ""),
                    self.vcenter_creds.get("username", ""),
                    self.vcenter_creds.get("password", ""),
                    True,
                )
                self.logger(f"Connecting to vSphere server {self.vcenter_creds.get('server', '')}...")
                try:
                    self.vsphere_service.connect()
                    self.logger("Connected to vSphere.")

                    # Initialize SSH service for fallback if enabled
                    if self.ssh_fallback_enabled and PARAMIKO_AVAILABLE:
                        self.ssh_service = SSHTunnelService(
                            target_username=self.guest_creds.get("username", ""),
                            target_password=self.guest_creds.get("password", ""),
                            target_port=int(self.ssh_config.get("target_port", 22)),
                            gateway_host=self.ssh_config.get("gateway_host", ""),
                            gateway_username=self.ssh_config.get("gateway_username", ""),
                            gateway_password=self.ssh_config.get("gateway_password", ""),
                            gateway_port=int(self.ssh_config.get("gateway_port", 22)),
                        )
                        self.logger("SSH tunnel service initialized for fallback.")
                    elif self.ssh_fallback_enabled and not PARAMIKO_AVAILABLE:
                        self.logger("SSH fallback enabled but paramiko is not installed; fallback will be skipped.")

                    for row in rows:
                        if not row.software_component:
                            continue
                        for target_name, mark in row.target_vms.items():
                            if not is_x_mark(mark):
                                continue
                            vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                            if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                self.logger(f"Scanning {row.software_component} on {target_name} [VM={vm_name}]...")
                                result = self.scan_target_row(row, target_name)
                                results.append(result)
                                self.logger(result.audit_text + f" | {result.details}")
                except Exception as exc:
                    self.logger(f"vSphere connection failed; VM targets will be marked WARN: {exc}")
                    for row in rows:
                        if not row.software_component:
                            continue
                        for target_name, mark in row.target_vms.items():
                            if not is_x_mark(mark):
                                continue
                            vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                            if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                result = self._build_result(
                                    row,
                                    target_name,
                                    "VSPHERE_CONNECT_FAILED",
                                    "WARN",
                                    f"vm={vm_name} | vSphere connect failed: {exc}",
                                )
                                results.append(result)
                                self.logger(result.audit_text + f" | {result.details}")
                finally:
                    if self.vsphere_service is not None:
                        try:
                            self.vsphere_service.disconnect()
                            self.logger("Disconnected from vSphere.")
                        except Exception:
                            pass
        else:
            self.logger("No VM targets selected.")

        for row in rows:
            row_results = [r for r in results if r.worksheet_row == row.row_index]
            if not row_results:
                continue
            best = self.choose_best_row_result(row_results)
            self.workbook_service.write_audit_result(row.row_index, best.audit_text, best.status)

        return results


class BaseFrame(ttk.Frame):
    def __init__(self, parent, controller):
        """Initialize the BaseFrame instance."""
        super().__init__(parent, padding=16)
        self.controller = controller

    def open_folder(self, folder: Path):
        """Open folder."""
        try:
            if os.name == "nt":
                os.startfile(folder)
            else:
                messagebox.showinfo("Folder", str(folder))
        except Exception as exc:
            messagebox.showerror("Open folder failed", str(exc))


class App(tk.Tk):
    def __init__(self):
        """Initialize the App instance."""
        super().__init__()
        _create_example_files()
        self.title(APP_TITLE)
        self.geometry(APP_GEOMETRY)
        self.resizable(True, True)
        self.minsize(800, 600)
        style = ttk.Style(self)
        try:
            style.theme_use("vista")
        except tk.TclError:
            pass
        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        container.rowconfigure(0, weight=1)
        container.columnconfigure(0, weight=1)
        self.frames = {}
        for frame_cls in (HomeFrame, ProfileFrame, ChecklistFrame, AuditFrame):
            frame = frame_cls(container, self)
            self.frames[frame_cls.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("HomeFrame")

    def show_frame(self, name: str):
        """Show frame."""
        self.frames[name].tkraise()


class HomeFrame(BaseFrame):
    def __init__(self, parent, controller):
        """Initialize the HomeFrame instance."""
        super().__init__(parent, controller)
        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="SBL Checklist & Audit Tool", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(outer, text="Tool purpose: This tool helps in generating audit checklists and running audits against SBL builds.", wraplength=1040).pack(anchor="w", pady=(0, 18))
        cards = ttk.Frame(outer)
        cards.pack(fill="x")
        def card(title: str, body: str, button: str, frame_name: str):
            """Card."""
            box = ttk.LabelFrame(cards, text=title, padding=18)
            box.pack(fill="x", pady=(0, 12))
            ttk.Label(box, text=body, wraplength=980).pack(anchor="w", pady=(0, 10))
            ttk.Button(box, text=button, command=lambda: controller.show_frame(frame_name)).pack(anchor="w")
        card("Configure VM Profile", f"Map worksheet targets to vSphere VMs or to {LOCAL_SENTINEL} for the machine running the tool.", "Open VM Profile Manager", "ProfileFrame")
        card("Create Audit Form", "Generate an audit workbook in the approved format and export additional JSON checklist payload.", "Open Checklist Generator", "ChecklistFrame")
        card("Run Audit", "Scans local targets first, then scans guest VMs through VMware Tools, compares found version against the SBL Build version, and writes PASS/FAIL text to the AUDIT column.", "Open Audit Runner", "AuditFrame")


class ProfileFrame(BaseFrame):
    def __init__(self, parent, controller):
        """Initialize the ProfileFrame instance."""
        super().__init__(parent, controller)
        self.profile_service = VMProfileService()
        self.logger = FileLogger(LOGS_DIR, "vm_profile")
        self.profile_name = tk.StringVar(value="")
        self.saved_profile_name = tk.StringVar(value="")
        self.profile_options = self._get_profile_options()
        self.vcenter_server = tk.StringVar()
        self.vcenter_username = tk.StringVar()
        self.vcenter_password = tk.StringVar()
        self.ignore_ssl = tk.BooleanVar(value=True)
        self.source_sbl_path = tk.StringVar()
        self.build_type = tk.StringVar(value="unknown")
        self.ssh_gateway_host = tk.StringVar()
        self.ssh_gateway_port = tk.StringVar(value="22")
        self.ssh_gateway_username = tk.StringVar()
        self.ssh_gateway_password = tk.StringVar()
        self.ssh_target_port = tk.StringVar(value="22")
        self.target_columns = default_target_columns()
        self.inventory_values = [LOCAL_SENTINEL]
        self.vm_dropdowns: Dict[str, ttk.Combobox] = {}
        self.target_info: Dict[str, Dict[str, str]] = {name: {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"} for name in self.target_columns}
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
        ttk.Label(top, text="VM Profile Manager", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
        settings = ttk.LabelFrame(self, text="vSphere Settings", padding=12)
        settings.pack(fill="x", pady=12)
        self._entry_row(settings, "Profile name", self.profile_name)
        profile_select_row = ttk.Frame(settings)
        profile_select_row.pack(fill="x", pady=4)
        ttk.Label(profile_select_row, text="Saved profiles", width=18).pack(side="left")
        self.profile_selector = ttk.Combobox(
            profile_select_row,
            textvariable=self.saved_profile_name,
            values=self.profile_options,
            state="readonly",
        )
        self.profile_selector.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(profile_select_row, text="Refresh", command=self._refresh_profile_options).pack(side="left")
        ttk.Button(profile_select_row, text="Use Selected", command=self._use_selected_profile).pack(side="left", padx=(8, 0))
        self._entry_row(settings, "Source SBL / checklist", self.source_sbl_path, command=self.pick_profile_source)
        build_row = ttk.Frame(settings)
        build_row.pack(fill="x", pady=4)
        ttk.Label(build_row, text="Build type", width=18).pack(side="left")
        ttk.Combobox(build_row, textvariable=self.build_type, values=BUILD_TYPE_OPTIONS, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(build_row, text="Detect VM Targets", command=self.detect_profile_targets).pack(side="left")
        self._entry_row(settings, "vCenter server", self.vcenter_server)
        self._entry_row(settings, "vCenter username", self.vcenter_username)
        self._entry_row(settings, "vCenter password", self.vcenter_password, show="*")
        ttk.Checkbutton(settings, text="Ignore SSL warnings", variable=self.ignore_ssl).pack(anchor="w", pady=(6, 0))
        self.credential_status_var = tk.StringVar(value="Credentials protection: checking...")
        ttk.Label(settings, textvariable=self.credential_status_var, foreground="#2f6f2f").pack(anchor="w", pady=(6, 0))
        ssh_settings = ttk.LabelFrame(self, text="SSH Tunnel Settings", padding=12)
        ssh_settings.pack(fill="x", pady=(0, 12))
        self._entry_row(ssh_settings, "SSH jump host", self.ssh_gateway_host)
        self._entry_row(ssh_settings, "Jump port", self.ssh_gateway_port)
        self._entry_row(ssh_settings, "Jump username", self.ssh_gateway_username)
        self._entry_row(ssh_settings, "Jump password", self.ssh_gateway_password, show="*")
        self._entry_row(ssh_settings, "Target SSH port", self.ssh_target_port)
        mapping = ttk.LabelFrame(self, text=f"SBL VM Targets → Selected VM Name or {LOCAL_SENTINEL}", padding=12)
        mapping.pack(fill="x")
        self.mapping_rows = ttk.Frame(mapping)
        self.mapping_rows.pack(fill="x")
        self._render_target_rows()
        # Add button to edit target info
        ttk.Button(mapping, text="Edit Target Info", command=self.edit_target_info_dialog).pack(side="right", padx=8)
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=10)
        ttk.Button(controls, text="Load VM Inventory", command=self.load_inventory).pack(side="left")
        self.save_profile_button = ttk.Button(controls, text="Save Profile", command=self.save_profile)
        self.save_profile_button.pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Verify Profile", command=self.verify_profile).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
        self.log = tk.Text(self, wrap="word", height=20)
        self.log.pack(fill="both", expand=True)
        self.profile_name.trace_add("write", self._refresh_profile_save_state)
        self._refresh_profile_save_state()
        self._refresh_profile_options()
        self._refresh_credential_status()

    def pick_profile_source(self):
        """Pick profile source."""
        path = filedialog.askopenfilename(
            title="Select SBL or audit workbook",
            filetypes=[("Supported files", "*.xlsx *.xlsm *.json *.csv"), ("All files", "*.*")],
        )
        if path:
            self.source_sbl_path.set(path)
            if self.build_type.get() == "unknown":
                self.build_type.set(infer_build_type(path))

    def _default_target_info(self) -> Dict[str, str]:
        """Internal helper for default target info."""
        return {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"}

    def _render_target_rows(self):
        """Internal helper for render target rows."""
        for child in self.mapping_rows.winfo_children():
            child.destroy()
        self.vm_dropdowns = {}
        for target_name in self.target_columns:
            info = self.target_info.get(target_name, self._default_target_info())
            row = ttk.Frame(self.mapping_rows)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=f"VM target: {target_name}", width=28).pack(side="left")
            combo = ttk.Combobox(row, state="normal", values=self.inventory_values)
            combo.pack(side="left", fill="x", expand=True)
            combo.set(info.get("vm_name", LOCAL_SENTINEL) or LOCAL_SENTINEL)
            self.vm_dropdowns[target_name] = combo

    def _set_target_columns(self, target_names: List[str]):
        """Internal helper for set target columns."""
        normalized = []
        for item in target_names:
            name = normalize_text(item)
            if name and name not in normalized:
                normalized.append(name)
        self.target_columns = normalized or default_target_columns()
        for target_name in self.target_columns:
            self.target_info.setdefault(target_name, self._default_target_info())
        self._render_target_rows()

    def detect_profile_targets(self):
        """Detect profile targets."""
        source_path = self.source_sbl_path.get().strip()
        if not source_path:
            messagebox.showwarning("Source SBL required", "Select an SBL or audit workbook first.")
            return
        try:
            selected_columns: List[str] = []
            if detect_workbook_format(source_path) == "excel":
                workbook_service = AuditWorkbookService(source_path)
                workbook_service.detect_header_row()
                workbook_service.build_column_map()
                selected_columns = confirm_target_column_mapping(
                    self,
                    source_path,
                    workbook_service.target_columns,
                    workbook_service.build_type,
                    current_columns=self.target_columns,
                ) or self.target_columns
                self.build_type.set(workbook_service.build_type)
            else:
                target_columns, _ = detect_target_columns(source_path, detect_workbook_format(source_path), detect_header_row_index(source_path, detect_workbook_format(source_path)))
                selected_columns = confirm_target_column_mapping(
                    self,
                    source_path,
                    target_columns,
                    infer_build_type(source_path),
                    current_columns=self.target_columns,
                ) or self.target_columns
                self.build_type.set(infer_build_type(source_path))
            self._set_target_columns(selected_columns)
            self.append_log(f"Detected {len(self.target_columns)} VM target columns from source workbook.")
        except Exception as exc:
            self.logger.write_exception(exc)
            self.append_log(f"Target detection fallback in use: {exc}")
            self._set_target_columns(default_target_columns())

    def _get_profile_options(self) -> List[str]:
        """Internal helper for get profile options."""
        if not PROFILES_DIR.exists():
            return []
        return sorted([f.stem for f in PROFILES_DIR.glob("*.json") if f.is_file()])

    def _refresh_profile_options(self, select_name: str = ""):
        """Internal helper for refresh profile options."""
        self.profile_options = self._get_profile_options()
        self.profile_selector.configure(values=self.profile_options)

        candidate = normalize_text(select_name) or normalize_text(self.profile_name.get())
        if candidate and candidate in self.profile_options:
            self.saved_profile_name.set(candidate)
            return

        if self.profile_options:
            self.saved_profile_name.set(self.profile_options[0])
        else:
            self.saved_profile_name.set("")

    def _use_selected_profile(self):
        """Internal helper for use selected profile."""
        selected = normalize_text(self.saved_profile_name.get())
        if not selected:
            messagebox.showwarning("No profile selected", "Select a profile from the dropdown first.")
            return
        self.profile_name.set(selected)
        self.load_saved_profile()

    def _refresh_credential_status(self, profile_name: str = ""):
        """Internal helper for refresh credential status."""
        if not self.profile_service.encryption_supported():
            self.credential_status_var.set("Credentials protection: disabled (install cryptography)")
            return

        key_path = self.profile_service._key_path()
        if key_path.exists():
            base = "Credentials protection: enabled"
        else:
            base = "Credentials protection: enabled (key will be created on first save)"

        selected = normalize_text(profile_name) or normalize_text(self.profile_name.get())
        if not selected:
            self.credential_status_var.set(base)
            return

        mode = self.profile_service.profile_credential_storage_mode(selected)
        if mode == "encrypted":
            self.credential_status_var.set(f"{base} | profile storage: encrypted")
        elif mode == "legacy-plain":
            self.credential_status_var.set(f"{base} | profile storage: legacy/plain")
        elif mode == "no-profile":
            self.credential_status_var.set(f"{base} | profile storage: not saved yet")
        else:
            self.credential_status_var.set(f"{base} | profile storage: unknown")

    def _profile_name_is_valid(self, profile_name: str) -> bool:
        """Internal helper for profile name is valid."""
        return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_name))

    def _get_profile_name_or_warn(self) -> Optional[str]:
        """Internal helper for get profile name or warn."""
        profile_name = normalize_text(self.profile_name.get())
        if not profile_name:
            messagebox.showwarning("Profile name required", "Enter or select a profile name first.")
            return None
        if not self._profile_name_is_valid(profile_name):
            messagebox.showwarning(
                "Invalid profile name",
                "Use 1-64 characters: letters, numbers, underscore, or dash. Must start with a letter or number.",
            )
            return None
        return profile_name

    def _refresh_profile_save_state(self, *_):
        """Internal helper for refresh profile save state."""
        profile_name = normalize_text(self.profile_name.get())
        is_valid = self._profile_name_is_valid(profile_name)
        self.save_profile_button.configure(state="normal" if is_valid else "disabled")
        self._refresh_credential_status(profile_name)

    def edit_target_info_dialog(self):
        """Edit target info dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("Edit Target VM Info")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()
        container = ttk.Frame(dialog, padding=8)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Target", width=30, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(header, text="VM Name", width=24, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
        ttk.Label(header, text="Username", width=18, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
        ttk.Label(header, text="Password", width=18, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
        ttk.Label(header, text="OS", width=10, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")

        rows = {}
        for idx, target_name in enumerate(self.target_columns):
            info = self.target_info.get(target_name, self._default_target_info())
            row = ttk.Frame(container)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=target_name, width=30, anchor="w").pack(side="left")
            vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
            user_var = tk.StringVar(value=info.get("username", ""))
            pass_var = tk.StringVar(value=info.get("password", ""))
            os_var = tk.StringVar(value=info.get("os_type", "windows"))
            ttk.Entry(row, textvariable=vm_var, width=24).pack(side="left", padx=(0, 4))
            ttk.Entry(row, textvariable=user_var, width=18).pack(side="left", padx=(0, 4))
            ttk.Entry(row, textvariable=pass_var, width=18, show="*").pack(side="left", padx=(0, 4))
            ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=10, state="readonly").pack(side="left")
            rows[target_name] = (vm_var, user_var, pass_var, os_var)

        def apply_shared_credentials():
            """Apply shared credentials."""
            shared_user = normalize_text(self.vcenter_username.get())
            shared_password = self.vcenter_password.get()
            if not shared_user or not shared_password:
                messagebox.showwarning(
                    "Shared credentials missing",
                    "Set vCenter username and password first, then apply shared credentials.",
                )
                return
            for _target_name, (_vm_var, user_var, pass_var, _os_var) in rows.items():
                user_var.set(shared_user)
                pass_var.set(shared_password)

        def save_and_close():
            """Save and close."""
            for t, (vm_var, user_var, pass_var, os_var) in rows.items():
                self.target_info[t] = {
                    "vm_name": vm_var.get().strip(),
                    "username": user_var.get().strip(),
                    "password": pass_var.get().strip(),
                    "os_type": os_var.get().strip() or "windows"
                }
                # Update dropdowns to reflect new VM names
                self.vm_dropdowns[t].set(vm_var.get().strip() or LOCAL_SENTINEL)
            dialog.destroy()

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=(8, 0))
        ttk.Button(controls, text="Apply Shared Login To All", command=apply_shared_credentials).pack(side="left")
        ttk.Button(controls, text="Save", command=save_and_close).pack(side="right")

        dialog.wait_window()

    def _entry_row(self, parent, label, var, show=None, command=None):
        """Internal helper for entry row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=18).pack(side="left")
        ttk.Entry(row, textvariable=var, show=show).pack(side="left", fill="x", expand=True, padx=(0, 8))
        if command is not None:
            ttk.Button(row, text="Browse", command=command).pack(side="left")

    def append_log(self, message: str):
        """
        The function `append_log` inserts a message to a log, scrolls to the end of the log, and writes
        the message to a logger.
        
        :param message: The `message` parameter in the `append_log` method is a string that represents
        the log message to be appended to the log
        :type message: str
        """
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.logger.write(message)

    def _service(self) -> VSphereService:
        """Internal helper for service."""
        return VSphereService(self.vcenter_server.get(), self.vcenter_username.get(), self.vcenter_password.get(), self.ignore_ssl.get())

    def load_inventory(self):
        """Load inventory."""
        try:
            self.append_log(f"Connecting to {self.vcenter_server.get().strip()} for VM inventory...")
            service = self._service()
            service.connect()
            names = service.list_windows_vms()
            service.disconnect()
            self.inventory_values = sorted({LOCAL_SENTINEL, *names})
            for combo in self.vm_dropdowns.values():
                combo["values"] = self.inventory_values
                if not combo.get():
                    combo.set(LOCAL_SENTINEL)
            self.append_log(f"Loaded {len(names)} selectable targets, including {LOCAL_SENTINEL}.")
        except Exception as exc:
            self.logger.write_exception(exc)
            self.append_log(f"ERROR: {exc}")

    def save_profile(self):
        """Save profile."""
        profile_name = self._get_profile_name_or_warn()
        if profile_name is None:
            return
        default_user = normalize_text(self.vcenter_username.get())
        default_password = self.vcenter_password.get()
        # Merge dropdowns and target_info for saving
        for name, combo in self.vm_dropdowns.items():
            if name not in self.target_info:
                self.target_info[name] = {"vm_name": combo.get().strip(), "username": "", "password": "", "os_type": "windows"}
            else:
                self.target_info[name]["vm_name"] = combo.get().strip()

            if not normalize_text(self.target_info[name].get("username", "")) and default_user:
                self.target_info[name]["username"] = default_user
            if not self.target_info[name].get("password", "") and default_password:
                self.target_info[name]["password"] = default_password

        profile_path = self.profile_service.profile_path(profile_name)
        if profile_path.exists():
            should_overwrite = messagebox.askyesno(
                "Overwrite existing profile?",
                f"Profile '{profile_name}' already exists. Do you want to overwrite it?",
            )
            if not should_overwrite:
                self.append_log(f"Save canceled for existing profile: {profile_name}")
                return
        payload = {
            "vcenter_server": self.vcenter_server.get().strip(),
            "vcenter_username": default_user,
            "vcenter_password": default_password,
            "ignore_ssl": self.ignore_ssl.get(),
            "source_sbl_path": self.source_sbl_path.get().strip(),
            "build_type": infer_build_type(self.build_type.get() or self.source_sbl_path.get()),
            "target_schema": build_target_schema_payload(self.source_sbl_path.get().strip(), self.target_columns, self.build_type.get()),
            "ssh_tunnel": {
                "gateway_host": self.ssh_gateway_host.get().strip(),
                "gateway_port": normalize_text(self.ssh_gateway_port.get()) or "22",
                "gateway_username": self.ssh_gateway_username.get().strip(),
                "gateway_password": self.ssh_gateway_password.get(),
                "target_port": normalize_text(self.ssh_target_port.get()) or "22",
            },
            "targets": self.target_info,
            "last_verified": ""
        }
        path = self.profile_service.save_profile(profile_name, payload)
        self.append_log(f"Saved profile: {path}")
        self._refresh_profile_options(select_name=profile_name)
        self._refresh_credential_status(profile_name)

    def load_saved_profile(self):
        """Load saved profile."""
        profile_name = self._get_profile_name_or_warn()
        if profile_name is None:
            return
        payload = self.profile_service.load_profile(profile_name)
        self.vcenter_server.set(payload.get("vcenter_server", payload.get("vsphere", {}).get("server", "")))
        self.vcenter_username.set(payload.get("vcenter_username", payload.get("vsphere", {}).get("username", "")))
        self.vcenter_password.set(payload.get("vcenter_password", payload.get("vsphere", {}).get("password", "")))
        self.ignore_ssl.set(bool(payload.get("ignore_ssl", True)))
        self.source_sbl_path.set(payload.get("source_sbl_path", payload.get("target_schema", {}).get("source_path", "")))
        self.build_type.set(infer_build_type(payload.get("build_type", payload.get("target_schema", {}).get("build_type", self.source_sbl_path.get()))))
        ssh_tunnel = payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            self.ssh_gateway_host.set(ssh_tunnel.get("gateway_host", ""))
            self.ssh_gateway_port.set(str(ssh_tunnel.get("gateway_port", "22")))
            self.ssh_gateway_username.set(ssh_tunnel.get("gateway_username", ""))
            self.ssh_gateway_password.set(ssh_tunnel.get("gateway_password", ""))
            self.ssh_target_port.set(str(ssh_tunnel.get("target_port", "22")))
        self._set_target_columns(resolve_profile_target_columns(payload))
        self.target_info = payload.get("targets", {name: self._default_target_info() for name in self.target_columns})
        for name, combo in self.vm_dropdowns.items():
            combo.set(self.target_info.get(name, {}).get("vm_name", LOCAL_SENTINEL))
        self.append_log(f"Loaded profile: {profile_name}")
        self._refresh_profile_options(select_name=profile_name)
        self._refresh_credential_status(profile_name)


    def verify_profile(self):
        """Verify profile."""
        profile_name = self._get_profile_name_or_warn()
        if profile_name is None:
            return
        payload = self.profile_service.load_profile(profile_name)
        service = self._service()
        service.connect()
        target_names = resolve_profile_target_columns(payload)
        vm_names = [payload.get("targets", {}).get(name, {}).get("vm_name", "") for name in target_names if payload.get("targets", {}).get(name, {}).get("vm_name", "")]
        report = service.verify_vm_names(vm_names)
        service.disconnect()
        payload["last_verified"] = datetime.now().isoformat(timespec="seconds")
        self.profile_service.save_profile(profile_name, payload)
        for vm_name, info in report.items():
            self.append_log(f"{vm_name} | power={info['power_state']} | tools={info['tools_status']} | guest={info['guest_os']}")


class ChecklistFrame(BaseFrame):
    def __init__(self, parent, controller):
        """Initialize the ChecklistFrame instance."""
        super().__init__(parent, controller)
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        default_source = TESTS_DIR / "testing_sbl.xlsx"
        default_output = AUDIT_CHECKLIST_DIR / f"TG_SBL_Audit_Checklist_{timestamp}.xlsx" # TG for Tool Generated

        self.source_path = tk.StringVar(value=str(default_source))
        self.output_path = tk.StringVar(value=str(default_output))
        self.status_var = tk.StringVar(value="Status: Ready")
        self.template_baseline_sbl_var = tk.StringVar(value="")
        self.template_latest_sbl_var = tk.StringVar(value="")
        self.template_baseline_json_var = tk.StringVar(value="")
        self.template_latest_json_var = tk.StringVar(value="")
        self.logger = FileLogger(LOGS_DIR, "checklist_generation")
        self.template_service = TemplateAssetService()
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
        ttk.Label(top, text="Create Audit Form", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
        form = ttk.LabelFrame(self, text="Main SBL Source", padding=12)
        form.pack(fill="x", pady=12)
        self._path_row(form, "Source workbook", self.source_path, self.pick_source)
        self._path_row(form, "Output workbook", self.output_path, self.pick_output)
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=(0, 10))
        self.generate_button = ttk.Button(controls, text="Generate Audit Form", command=self.start_generate)#self.start_generate self.read_software_list
        self.generate_button.pack(side="left")
        ttk.Button(controls, text="Load Baseline Template", command=self.load_baseline_template).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Update Baseline From Source", command=self.update_baseline_template).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Import List (CSV/JSON/XLSX)", command=self.import_list_source).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open Templates Folder", command=lambda: self.open_folder(TEMPLATES_DIR)).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Refresh Template Status", command=self.refresh_template_status_panel).pack(side="left", padx=(8, 0))
        ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=(12, 0))

        template_panel = ttk.LabelFrame(self, text="Template Status", padding=10)
        template_panel.pack(fill="x", pady=(0, 10))
        self._template_status_row(template_panel, "Baseline SBL", self.template_baseline_sbl_var)
        self._template_status_row(template_panel, "Latest SBL", self.template_latest_sbl_var)
        self._template_status_row(template_panel, "Baseline Master Software List", self.template_baseline_json_var)
        self._template_status_row(template_panel, "Latest Master Software List", self.template_latest_json_var)

        self.progress_var = tk.DoubleVar(value=0)
        style = ttk.Style()
        style.configure("TProgressbar", troughcolor='lightgreen', background='green')
        style.configure("Red.TProgressbar", troughcolor='lightcoral', background='red')
        self.progress = ttk.Progressbar(self, variable=self.progress_var, maximum=100, style="TProgressbar")
        self.progress.pack(fill="x")
        self.log_widget = tk.Text(self, wrap="word", height=22)
        self.log_widget.pack(fill="both", expand=True)
        self.refresh_template_status_panel()

    def _path_row(self, parent, label, variable, command):
        """Internal helper for path row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text=label, width=16).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse", command=command).pack(side="left")

    def _template_status_row(self, parent, label, variable):
        """Internal helper for template status row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=22).pack(side="left")
        ttk.Label(row, textvariable=variable, anchor="w").pack(side="left", fill="x", expand=True)

    def refresh_template_status_panel(self):
        # Try to infer model from current audit path
        """Refresh template status panel."""
        sbl_model = None
        audit_path = self.audit_path.get().strip() if hasattr(self, 'audit_path') else ""
        if audit_path and Path(audit_path).exists():
            try:
                sbl_model = _get_sbl_model_from_workbook(audit_path)
            except Exception:
                pass
        
        status = self.template_service.get_template_status(sbl_model=sbl_model)
        self.template_baseline_sbl_var.set(
            f"Exists: {status['baseline_sbl']['exists']} | Updated: {status['baseline_sbl']['updated']} | {status['baseline_sbl']['path']}"
        )
        self.template_latest_sbl_var.set(
            f"Exists: {status['latest_sbl']['exists']} | Updated: {status['latest_sbl']['updated']} | {status['latest_sbl']['path']}"
        )
        self.template_baseline_json_var.set(
            f"Exists: {status['baseline_master_list']['exists']} | Updated: {status['baseline_master_list']['updated']} | {status['baseline_master_list']['path']}"
        )
        self.template_latest_json_var.set(
            f"Exists: {status['latest_master_list']['exists']} | Updated: {status['latest_master_list']['updated']} | {status['latest_master_list']['path']}"
        )

    def append_log(self, message: str):
        """Append log."""
        self.log_widget.insert("end", message + "\n")
        self.log_widget.see("end")
        self.logger.write(message)

    def set_status(self, message: str):
        """Set status."""
        self.status_var.set(message)

    def pick_source(self):
        """Pick source."""
        path = filedialog.askopenfilename(title="Select main SBL source", filetypes=[("Supported files", "*.xlsx *.xlsm *.csv *.json"), ("All files", "*.*")])
        if path:
            self.source_path.set(path)

    def pick_output(self):
        """Pick output."""
        path = filedialog.asksaveasfilename(title="Save generated audit form as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if path:
            self.output_path.set(path)

    def load_baseline_template(self):
        """Load baseline template."""
        source = self.source_path.get().strip()
        sbl_model = None
        if source and Path(source).exists():
            try:
                sbl_model = _get_sbl_model_from_workbook(source)
            except Exception:
                sbl_model = None

        baseline_path = self.template_service.resolve_existing_baseline_sbl_path(sbl_model=sbl_model)
        if baseline_path is None and source and Path(source).exists():
            try:
                result = self.template_service.update_baseline_from_sbl(source)
                baseline_path = result.get("sbl_template")
                self.append_log(f"Baseline template was missing and has been created from source: {baseline_path}")
            except Exception as exc:
                self.logger.write_exception(exc)
                messagebox.showerror("Baseline template missing", f"No baseline template found, and auto-create failed: {exc}")
                return

        if not baseline_path or not Path(baseline_path).exists():
            messagebox.showwarning("Baseline template missing", "No baseline template exists yet. Select a source workbook and use 'Update Baseline From Source'.")
            return

        self.source_path.set(baseline_path)
        self.append_log(f"Loaded baseline template as source: {baseline_path}")

    def update_baseline_template(self):
        """Update baseline template."""
        source = self.source_path.get().strip()
        if not source:
            messagebox.showerror("No source selected", "Select a source workbook before updating baseline template.")
            return
        try:
            result = self.template_service.update_baseline_from_sbl(source)
            sbl_model = _get_sbl_model_from_workbook(source)
            self.append_log(f"Updated baseline template for model: {sbl_model}")
            self.append_log(f"Baseline SBL template: {result['sbl_template']}")
            self.append_log(f"Baseline master software list template: {result['json_template']}")
            self.refresh_template_status_panel()
            messagebox.showinfo("Template updated", "Baseline SBL and master software list templates were updated.")
        except Exception as exc:
            self.logger.write_exception(exc)
            messagebox.showerror("Template update failed", str(exc))

    def import_list_source(self):
        """Import list source."""
        in_path = filedialog.askopenfilename(
            title="Import list file",
            filetypes=[("Supported files", "*.xlsx *.xlsm *.csv *.json"), ("All files", "*.*")],
        )
        if not in_path:
            return
        default_name = f"UP_Imported_SBL_{timestamp_str()}.xlsx"
        out_path = filedialog.asksaveasfilename(
            title="Save imported source workbook as",
            defaultextension=".xlsx",
            initialfile=default_name,
            filetypes=[("Excel files", "*.xlsx")],
        )
        if not out_path:
            return
        try:
            imported = self.template_service.import_list_to_sbl_workbook(in_path, out_path)
            self.source_path.set(imported)
            self.append_log(f"Imported list file into SBL workbook: {imported}")
        except Exception as exc:
            self.logger.write_exception(exc)
            messagebox.showerror("Import failed", str(exc))

    def extract_path(self, version_locations):
        # Normalize and handle missing values
        """Extract path."""
        if version_locations is None:
            return ""
        # deference pandas NA values utils
        try:
            if pd.isna(version_locations):
                return ""
        except Exception:
            pass

        raw = str(version_locations).strip()
        if not raw:
            return ""

        # If it is explicitly programs and features marker, keep it
        if re.search(r"programs[_ ]and[_ ]features", raw, re.IGNORECASE):
            return "programs_and_features"

        # Preserve PowerShell command if provided
        if raw.lower().startswith("powershell:"):
            return raw

        # path may include extra data after ' > ' or similar, so extract if present
        match = re.match(r'([A-Za-z]:[\\/][^>\n\r\t]+)', raw)
        if match:
            return match.group(1).strip()

        # fallback to raw value, do not return None
        return raw

    def user_read_software_list(self):
        """User read software list."""
        file_path = self.source_path.get().strip()
        # Columns of interest from SBL
        software_component = 'SOFTWARE COMPONENT'
        version_locations = 'VERSION LOCATIONS'

        print("Reading Software Build List")
        software_list = []
        
        # Read the excel file, drop rows with missing values, trim whitespace, and get the path to the file
        if file_path.endswith('.xlsx'):
            df = pd.read_excel(file_path)
            df = df.dropna(subset=[software_component])
            df[software_component] = df[software_component].str.strip()
            # CC - Different xlsx have different columns names. i.e VERSION LOCATIONS and VERSION LOCATIONS
            df_headers = list(df.columns)
            normalized_headers = [str(h).lower() for h in df_headers]

            ## Find columns of interest by finding headers that contain key words. Location, Version, etc
            keywords = ["location", "component", "name", "id"]

            matching_headers = [og for og, norm in zip(df_headers, normalized_headers) if any(k in norm for k in keywords)]
            print(matching_headers)
            df[version_locations] = df[version_locations].apply(self.extract_path)
            # # CC - Error occurred when xlsx didnt have this header 
            # df[displayed_name] = df[displayed_name].str.strip()
            
        else:
            print(f"Unsupported file format: {file_path}")
            sys.exit(1)
        
        # Match the column that contains the version number
        pattern = r'.*CURRENT CI VERSION.*'
        matching_column = next((col for col in df.columns if re.match(pattern, col, re.IGNORECASE)), None)

        # If the matching column is found, process the rows 
        if matching_column:
            for _, row in df.iterrows():
                print(row.to_dict())
                software_list.append({
                    'name': row[software_component],  
                    'expected_version': row[matching_column],
                    'version_locations': row[version_locations]
                })
        else:
            print("No column found with 'CURRENT CI VERSION' in the name.")
        
        print(software_list)
        return software_list


    def start_generate(self):
        """Start generate."""
        print("Starting checklist generation...")
        self.generate_button.configure(state="disabled")
        if hasattr(self, "progress"):
            self.progress.configure(style="TProgressbar")
        self.progress_var.set(0)
        self.set_status("Status: Generating...")
        self.logger = FileLogger(LOGS_DIR, "checklist_generation")
        self.append_log(f"Starting checklist generation")
        self.append_log(f"Source input: {self.source_path.get()}")
        self.append_log(f"Output workbook: {self.output_path.get()}")
        self.append_log(f"Session log file: {self.logger.get_path()}")
        threading.Thread(target=self._generate_worker, daemon=True).start()

    def _generate_worker(self):
        """Internal helper for generate worker."""
        print("In checklist generation worker thread...")
        try:
            source = self.source_path.get().strip()
            output = self.output_path.get().strip()
            if not source:
                raise ValueError("Select a source workbook first.")
            if not output:
                raise ValueError("Choose an output workbook path first.")

            self.after(0, lambda: self.progress_var.set(10))
            self.after(0, lambda: self.append_log("Loading source input..."))
            generator = ChecklistGeneratorService(source)
            if generator.normalized_source_path != source:
                self.after(0, lambda p=generator.normalized_source_path: self.append_log(f"Normalized non-Excel input to workbook staging file: {p}"))
            #
            # generator.generate_audit_form(output)
            self.after(0, lambda: self.progress_var.set(45))
            self.after(0, lambda: self.append_log("Generating audit workbook from source layout..."))
            generator.generate_audit_form(output)

            self.after(0, lambda: self.progress_var.set(80))
            self.after(0, lambda: self.append_log("Writing checklist JSON export..."))
            json_path = JsonExportService.write_checklist_json(Path(output).stem, generator.export_json_payload())
            sbl_model = _get_sbl_model_from_workbook(output)
            latest_sbl = self.template_service.update_latest_sbl(output)
            latest_master = self.template_service.snapshot_current_master_to_latest(sbl_model=sbl_model)

            self.after(0, lambda: self.progress_var.set(100))
            self.after(0, lambda: self.append_log(f"Generated audit form: {output}"))
            self.after(0, lambda: self.append_log(f"Checklist JSON written: {json_path}"))
            self.after(0, lambda: self.append_log(f"Updated latest SBL snapshot: {latest_sbl}"))
            self.after(0, lambda: self.append_log(f"Updated latest master software list snapshot: {latest_master}"))
            self.after(0, self.refresh_template_status_panel)
            self.after(0, lambda: self.set_status("Status: Complete"))
            self.after(0, lambda: messagebox.showinfo("Checklist generated", f"Audit checklist created.Saved to:{output}"))
        except Exception as exc:
            self.logger.write_exception(exc)
            error_text = str(exc)
            self.after(0, lambda error_text=error_text: self.append_log(f"ERROR: {error_text}"))
            self.after(0, lambda: self.set_status("Status: Failed"))
            if hasattr(self, "progress"):
                self.after(0, lambda: self.progress.configure(style="Red.TProgressbar"))
            self.after(0, lambda error_text=error_text: messagebox.showerror("Checklist generation failed", error_text))
        finally:
            self.after(0, lambda: self.generate_button.configure(state="normal"))


class AuditFrame(BaseFrame):
    def _prompt_quick_audit_vm_details(self, target_columns: List[str]) -> Optional[Dict[str, Any]]:
        """Prompt for quick-audit VM details using a compact modal dialog."""
        dialog = tk.Toplevel(self)
        dialog.title("Quick Audit Scan - VM Details")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)

        container = ttk.Frame(dialog, padding=10)
        container.pack(fill="both", expand=True)

        vcenter_server = tk.StringVar(value=self.vcenter_server.get().strip())
        vcenter_username = tk.StringVar(value=self.vcenter_username.get().strip())
        vcenter_password = tk.StringVar(value=self.vcenter_password.get())
        guest_username = tk.StringVar(value=self.guest_username.get().strip())
        guest_password = tk.StringVar(value=self.guest_password.get())

        ttk.Label(
            container,
            text="Quick Audit Scan: local scan runs first, then VM targets are scanned.",
            wraplength=620,
        ).pack(anchor="w", pady=(0, 8))

        creds = ttk.LabelFrame(container, text="Connection Details", padding=8)
        creds.pack(fill="x", pady=(0, 8))

        def _entry_row(parent: ttk.Widget, label: str, variable: tk.StringVar, show: Optional[str] = None):
            """Render one label/entry row for the quick-audit dialog."""
            row = ttk.Frame(parent)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, width=22).pack(side="left")
            ttk.Entry(row, textvariable=variable, show=show).pack(side="left", fill="x", expand=True)

        _entry_row(creds, "vCenter server", vcenter_server)
        _entry_row(creds, "vCenter username", vcenter_username)
        _entry_row(creds, "vCenter password", vcenter_password, show="*")
        _entry_row(creds, "Guest username", guest_username)
        _entry_row(creds, "Guest password", guest_password, show="*")

        mapping_box = ttk.LabelFrame(container, text="Target -> VM Name Mapping", padding=8)
        mapping_box.pack(fill="both", expand=True)

        target_vars: Dict[str, tk.StringVar] = {}
        for target_name in target_columns:
            row = ttk.Frame(mapping_box)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=target_name, width=26).pack(side="left")
            vm_var = tk.StringVar(value=LOCAL_SENTINEL)
            combo = ttk.Combobox(row, textvariable=vm_var, values=[LOCAL_SENTINEL], state="normal")
            combo.pack(side="left", fill="x", expand=True)
            target_vars[target_name] = vm_var

        result: Dict[str, Any] = {}

        def _apply_guest_to_all():
            """Apply shared guest credentials to all target mappings."""
            user = normalize_text(guest_username.get())
            password = guest_password.get()
            if not user or not password:
                messagebox.showwarning(
                    "Missing guest credentials",
                    "Enter guest username and password first.",
                    parent=dialog,
                )
                return
            for _target, vm_var in target_vars.items():
                if not normalize_text(vm_var.get()):
                    vm_var.set(LOCAL_SENTINEL)

        def _submit():
            """Validate and submit the quick-audit dialog."""
            server = normalize_text(vcenter_server.get())
            user = normalize_text(vcenter_username.get())
            password = vcenter_password.get()
            guest_user = normalize_text(guest_username.get())
            guest_pass = guest_password.get()
            if not server or not user or not password:
                messagebox.showwarning(
                    "vCenter credentials required",
                    "Provide vCenter server, username, and password.",
                    parent=dialog,
                )
                return
            if not guest_user or not guest_pass:
                messagebox.showwarning(
                    "Guest credentials required",
                    "Provide guest username and password used for VM scans.",
                    parent=dialog,
                )
                return

            targets: Dict[str, Dict[str, str]] = {}
            for target_name in target_columns:
                vm_name = normalize_text(target_vars[target_name].get()) or LOCAL_SENTINEL
                targets[target_name] = {
                    "vm_name": vm_name,
                    "username": guest_user,
                    "password": guest_pass,
                    "os_type": "windows",
                }

            result.update(
                {
                    "vcenter": {
                        "server": server,
                        "username": user,
                        "password": password,
                    },
                    "guest": {
                        "username": guest_user,
                        "password": guest_pass,
                    },
                    "targets": targets,
                }
            )
            dialog.destroy()

        def _cancel():
            """Cancel the quick-audit dialog."""
            dialog.destroy()

        btn_row = ttk.Frame(container)
        btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(btn_row, text="Apply Guest Creds To All", command=_apply_guest_to_all).pack(side="left")
        ttk.Button(btn_row, text="Cancel", command=_cancel).pack(side="right")
        ttk.Button(btn_row, text="Run Quick Audit Scan", command=_submit).pack(side="right", padx=(0, 8))

        self.wait_window(dialog)
        return result or None

    def _init_target_info_table(self, parent):
        """Internal helper for init target info table."""
        self.target_info_vars = {}
        self.target_info_dialog = None
        self.save_targets_btn = None
        # Place the button next to the profile selection
        btn = ttk.Button(parent, text="Show/Edit Target VM Info", command=self._show_target_info_dialog)
        btn.pack(side="left", padx=(8, 0))

    def _show_target_info_dialog(self):
        """Internal helper for show target info dialog."""
        if self.target_info_dialog and self.target_info_dialog.winfo_exists():
            self.target_info_dialog.lift()
            return
        self.target_info_dialog = tk.Toplevel(self)
        self.target_info_dialog.title("Edit Target VM Info")
        self.target_info_dialog.resizable(False, False)
        frame = ttk.Frame(self.target_info_dialog, padding=8)
        frame.pack(fill="both", expand=True)
        self.target_info_vars = {}
        header = ttk.Frame(frame)
        header.pack(fill="x")
        ttk.Label(header, text="Target", width=30, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 4))
        ttk.Label(header, text="VM Name", width=24, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=(0, 4))
        ttk.Label(header, text="Username", width=18, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 4))
        ttk.Label(header, text="Password", width=18, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=3, sticky="w", padx=(0, 4))
        ttk.Label(header, text="OS Type", width=10, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=4, sticky="w")
        profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
        targets = profile.get("targets", {})
        target_names = self._resolve_target_names(profile)
        for idx, target in enumerate(target_names):
            info = targets.get(target, {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"})
            row = ttk.Frame(frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=target, width=30, anchor="w").grid(row=0, column=0, sticky="w", padx=(0, 4))
            vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
            user_var = tk.StringVar(value=info.get("username", ""))
            pass_var = tk.StringVar(value=info.get("password", ""))
            os_var = tk.StringVar(value=info.get("os_type", "windows"))
            ttk.Entry(row, textvariable=vm_var, width=24).grid(row=0, column=1, sticky="we", padx=(0, 4))
            ttk.Entry(row, textvariable=user_var, width=18).grid(row=0, column=2, sticky="we", padx=(0, 4))
            ttk.Entry(row, textvariable=pass_var, width=18, show="*").grid(row=0, column=3, sticky="we", padx=(0, 4))
            ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=10, state="readonly").grid(row=0, column=4, sticky="w")
            self.target_info_vars[target] = (vm_var, user_var, pass_var, os_var)
        def _apply_shared_credentials_to_targets():
            """Internal helper for apply shared credentials to targets."""
            shared_user = normalize_text(self.guest_username.get()) or normalize_text(self.vcenter_username.get())
            shared_password = self.guest_password.get() or self.vcenter_password.get()
            if not shared_user or not shared_password:
                messagebox.showwarning(
                    "Shared credentials missing",
                    "Set shared VM credentials (or vCenter credentials) first, then apply shared credentials.",
                )
                return
            for _target, (_vm_var, user_var, pass_var, _os_var) in self.target_info_vars.items():
                user_var.set(shared_user)
                pass_var.set(shared_password)
        ttk.Button(frame, text="Apply Shared Login To All", command=_apply_shared_credentials_to_targets).pack(pady=(6, 2))
        self.save_targets_btn = ttk.Button(frame, text="Save Target Info to Profile", command=self._save_target_info)
        self.save_targets_btn.pack(pady=(2, 8))
        self.target_info_dialog.transient(self)
        self.target_info_dialog.grab_set()
        self.target_info_dialog.wait_window()


    def _save_target_info(self):
        # Save edited info back to profile
        """Internal helper for save target info."""
        profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
        targets = profile.get("targets", {})
        default_user = normalize_text(profile.get("vcenter_username", ""))
        default_password = profile.get("vcenter_password", "")
        for target, (vm_var, user_var, pass_var, os_var) in self.target_info_vars.items():
            target_user = user_var.get().strip() or default_user
            target_password = pass_var.get().strip() or default_password
            targets[target] = {
                "vm_name": vm_var.get().strip(),
                "username": target_user,
                "password": target_password,
                "os_type": os_var.get().strip() or "windows"
            }
        profile["targets"] = targets
        self.profile_service.save_profile(self.profile_name.get().strip(), profile)
        self.append_log("Saved target VM info to profile.")
        if self.target_info_dialog and self.target_info_dialog.winfo_exists():
            self.target_info_dialog.destroy()

    def __init__(self, parent, controller):
        """Initialize the AuditFrame instance."""
        super().__init__(parent, controller)
        self._compact_label_width = 16
        self._audit_profile_override: Optional[Dict[str, Any]] = None
        self._audit_mode_label = "standard"
        self.profile_service = VMProfileService()
        self.style = ttk.Style()
        self.style.configure("Bold.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        default_audit = AUDIT_CHECKLIST_DIR / "TG_Audit_Checklist_test.xlsx"
        default_results = AUDIT_RESULTS_DIR / "testing_sbl_RESULTS.xlsx"
        self.audit_path = tk.StringVar(value=str(default_audit))
        self.output_path = tk.StringVar(value=str(default_results))
        self.profile_name = tk.StringVar()
        self.profile_options = self._get_profile_options()
        self.detected_target_columns = default_target_columns()
        self.build_type_value = tk.StringVar(value="unknown")
        self.audit_schema_var = tk.StringVar(value="Build type: unknown | VM targets: legacy fallback")
        self.last_schema_source = ""
        if self.profile_options:
            self.profile_name.set(self.profile_options[0])
        else:
            self.profile_name.set("")
        self.connection_mode = tk.StringVar(value="vSphere")
        self.vcenter_server = tk.StringVar()
        self.vcenter_username = tk.StringVar()
        self.vcenter_password = tk.StringVar()
        self.guest_username = tk.StringVar()
        self.guest_password = tk.StringVar()
        self.ssh_gateway_host = tk.StringVar()
        self.ssh_gateway_port = tk.StringVar(value="22")
        self.ssh_gateway_username = tk.StringVar()
        self.ssh_gateway_password = tk.StringVar()
        self.ssh_target_port = tk.StringVar(value="22")
        self.show_ssh_settings = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Status: Ready")
        self.progress_var = tk.DoubleVar(value=0)
        self.logger = FileLogger(LOGS_DIR, "audit_run")
        # Only call _init_target_info_table after profile_row is defined (moved below)
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
        ttk.Label(top, text="Run Audit", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
        cfg = ttk.LabelFrame(self, text="Audit Workbook", padding=8)
        cfg.pack(fill="x", pady=8)
        self._path_row(cfg, "Audit workbook", self.audit_path, self.pick_audit)
        self._path_row(cfg, "Save audited results", self.output_path, self.pick_output)
        ttk.Label(cfg, textvariable=self.audit_schema_var, foreground="#35556b").pack(anchor="w", pady=(4, 0))
        creds = ttk.LabelFrame(self, text="Profile and Credentials", padding=8)
        creds.pack(fill="x", pady=(0, 8))
        # Dropdown for VM profiles
        profile_row = ttk.Frame(creds)
        profile_row.pack(fill="x", pady=2)
        ttk.Label(profile_row, text="VM profile", width=self._compact_label_width).pack(side="left")
        self.profile_dropdown = ttk.Combobox(profile_row, textvariable=self.profile_name, state="readonly", values=self.profile_options)
        self.profile_dropdown.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(profile_row, text="Load Profile", command=self.load_profile_defaults).pack(side="left")
        self._init_target_info_table(profile_row)

    
        self.fallback_texts = {
            "vSphere": "Use SSH tunnel as fallback if vSphere fails",
            "ssh tunnel": "Use vSphere as fallback if SSH fails",
        }
        mode_row = ttk.Frame(creds)
        mode_row.pack(fill="x", pady=2)
        ttk.Label(mode_row, text="Connection mode", width=self._compact_label_width).pack(side="left")
        ttk.Combobox(mode_row, textvariable=self.connection_mode, state="readonly", values=["vSphere", "SSH Tunnel"]).pack(side="left", fill="x", expand=True, padx=(0, 8))
        toggle_row = ttk.Frame(creds)
        toggle_row.pack(fill="x", pady=2)
        self.fallback_checkbox = ttk.Checkbutton(
            toggle_row,
            text=self.fallback_texts[normalize_text(self.connection_mode.get())],
            variable=self.show_ssh_settings,
            command=self._toggle_ssh_section,
        )
        self.fallback_checkbox.pack(side="left", padx=(self._compact_label_width * 6, 0))
        self.vcenter_section = ttk.LabelFrame(creds, text="vCenter Settings", padding=4, labelanchor="nw", style="Bold.TLabelframe")
        self.vcenter_section.pack(fill="x", pady=(4, 0))
        self._entry_row(self.vcenter_section, "vCenter server", self.vcenter_server)
        self._entry_row(self.vcenter_section, "vCenter username", self.vcenter_username)
        self._entry_row(self.vcenter_section, "vCenter password", self.vcenter_password, show="*")

        self.ssh_section = ttk.LabelFrame(creds, text="SSH Tunnel Settings", padding=6, labelanchor="nw", style="Bold.TLabelframe")
        self._entry_pair_row(self.ssh_section, "SSH jump host", self.ssh_gateway_host, "Jump port", self.ssh_gateway_port)
        self._entry_pair_row(self.ssh_section, "Jump username", self.ssh_gateway_username, "Jump password", self.ssh_gateway_password, show2="*")
        self._entry_pair_row(self.ssh_section, "Target SSH username", self.guest_username, "Target port", self.ssh_target_port)
        self._entry_half_row(self.ssh_section, "Target SSH password", self.guest_password, show="*", label_width=20)
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=(0, 8))
        self.local_only = tk.BooleanVar(value=False)
        # Move the local scan checkbox next to the fallback checkbox
        ttk.Checkbutton(toggle_row, text="Scan only local machine (ignore VMs)", variable=self.local_only).pack(side="left", padx=(16, 0))
        self.run_button = ttk.Button(controls, text="Run Audit", command=self.start_audit)
        self.run_button.pack(side="left")
        self.quick_run_button = ttk.Button(controls, text="Quick Audit Scan", command=self.start_quick_audit)
        self.quick_run_button.pack(side="left", padx=(8, 0))
        self.probe_button = ttk.Button(controls, text="Test vCenter Probe", command=self.start_probe)
        self.probe_button.pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
        ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=(12, 0))
        ttk.Progressbar(self, variable=self.progress_var, maximum=100).pack(fill="x")
        log_box = ttk.LabelFrame(self, text="Log", padding=6)
        log_box.pack(fill="both", expand=True, pady=(8, 0))
        self.log = tk.Text(log_box, wrap="word")
        self.log.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log.yview)
        scroll.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=scroll.set)

        self.connection_mode.trace_add("write", self._on_connection_mode_changed)
        self._set_ssh_section_visible(False)
        self._refresh_audit_source_metadata(prompt_user=False)
    def _get_profile_options(self):
        """Internal helper for get profile options."""
        profiles_dir = PROFILES_DIR
        if not profiles_dir.exists():
            return []
        return [f.stem for f in profiles_dir.glob("*.json") if f.is_file()]
    def _path_row(self, parent, label, variable, command):
        """Internal helper for path row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=self._compact_label_width).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse", command=command).pack(side="left")

    def _entry_row(self, parent, label, variable, show=None, button=None, label_width=None):
        """Internal helper for entry row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        width = self._compact_label_width if label_width is None else label_width
        ttk.Label(row, text=label, width=width).pack(side="left")
        ttk.Entry(row, textvariable=variable, show=show).pack(side="left", fill="x", expand=True, padx=(0, 8))
        if button:
            ttk.Button(row, text=button[0], command=button[1]).pack(side="left")

    def _entry_pair_row(self, parent, label1, var1, label2, var2, show1=None, show2=None):
        """Internal helper for entry pair row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)

        left = ttk.Frame(row)
        left.pack(side="left", fill="x", expand=True, padx=(0, 4))
        ttk.Label(left, text=label1, width=20).pack(side="left")
        ttk.Entry(left, textvariable=var1, show=show1).pack(side="left", fill="x", expand=True) # type: ignore

        right = ttk.Frame(row)
        right.pack(side="left", fill="x", expand=True, padx=(4, 0))
        ttk.Label(right, text=label2, width=16).pack(side="left")
        ttk.Entry(right, textvariable=var2, show=show2).pack(side="left", fill="x", expand=True)

    def _entry_half_row(self, parent, label, variable, show=None, label_width=None):
        """Internal helper for entry half row."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)

        left = ttk.Frame(row)
        left.pack(side="left", fill="x", expand=True, padx=(0, 4))
        width = self._compact_label_width if label_width is None else label_width
        ttk.Label(left, text=label, width=width).pack(side="left")
        ttk.Entry(left, textvariable=variable, show=show).pack(side="left", fill="x", expand=True, padx=(0, 8))

        right = ttk.Frame(row)
        right.pack(side="left", fill="x", expand=True)
        ttk.Label(right, text="", width=16).pack(side="left")

    def _set_ssh_section_visible(self, visible: bool) -> None:
        """Internal helper for set ssh section visible."""
        if visible:
            if not self.ssh_section.winfo_ismapped():
                self.ssh_section.pack(fill="x", pady=(4, 0))
        else:
            if self.ssh_section.winfo_ismapped():
                self.ssh_section.pack_forget()

    def _toggle_ssh_section(self):
        """Internal helper for toggle ssh section."""
        self._on_connection_mode_changed()

    def _on_connection_mode_changed(self, *_):
        """Internal helper for on connection mode changed."""
        mode = normalize_text(self.connection_mode.get()).lower()
        self.fallback_checkbox.configure(text=self.fallback_texts.get(mode, self.fallback_texts["vSphere"]))

        if mode == "ssh tunnel":
            self._set_ssh_section_visible(True)
            if bool(self.show_ssh_settings.get()):
                if hasattr(self, "vcenter_section") and not self.vcenter_section.winfo_ismapped():
                    self.vcenter_section.pack(fill="x", pady=(4, 0))
            else:
                if hasattr(self, "vcenter_section") and self.vcenter_section.winfo_ismapped():
                    self.vcenter_section.pack_forget()
            if hasattr(self, "probe_button"): 
                self.probe_button.configure(text="Test SSH Probe")
        else:  # vSphere mode
            if hasattr(self, "vcenter_section") and not self.vcenter_section.winfo_ismapped():
                self.vcenter_section.pack(fill="x", pady=(4, 0))
            self._set_ssh_section_visible(bool(self.show_ssh_settings.get()))
            if hasattr(self, "probe_button"):
                self.probe_button.configure(text="Test vCenter Probe")

    def append_log(self, message: str):
        """Append log."""
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.logger.write(message)
        print(message, flush=True)

    def set_status(self, message: str):
        """Set status."""
        self.status_var.set(message)

    @staticmethod
    def _parse_int(value: str, default: int) -> int:
        """Internal helper for parse int."""
        try:
            return int(normalize_text(value))
        except Exception:
            return default

    def _apply_detected_schema(self, target_columns: List[str], build_type: str):
        """Internal helper for apply detected schema."""
        self.detected_target_columns = target_columns or default_target_columns()
        resolved_build_type = infer_build_type(build_type)
        self.build_type_value.set(resolved_build_type)
        summary = ", ".join(self.detected_target_columns[:4])
        if len(self.detected_target_columns) > 4:
            summary += ", ..."
        self.audit_schema_var.set(f"Build type: {resolved_build_type} | VM targets: {summary or 'legacy fallback'}")

    def _refresh_audit_source_metadata(self, prompt_user: bool = True):
        """Internal helper for refresh audit source metadata."""
        source_path = self.audit_path.get().strip()
        if not source_path:
            self._apply_detected_schema(default_target_columns(), "unknown")
            return
        try:
            workbook_service = AuditWorkbookService(source_path)
            workbook_service.detect_header_row()
            workbook_service.build_column_map()
            selected_columns = workbook_service.target_columns
            if prompt_user and source_path != self.last_schema_source:
                selected_columns = confirm_target_column_mapping(
                    self,
                    source_path,
                    workbook_service.target_columns,
                    workbook_service.build_type,
                    current_columns=self.detected_target_columns,
                ) or self.detected_target_columns
            self._apply_detected_schema(selected_columns, workbook_service.build_type)
            self.last_schema_source = source_path
        except Exception:
            self._apply_detected_schema(default_target_columns(), infer_build_type(source_path))

    def _resolve_target_names(self, payload: Optional[Dict[str, Any]] = None) -> List[str]:
        """Internal helper for resolve target names."""
        if payload:
            return resolve_profile_target_columns(payload)
        return self.detected_target_columns or default_target_columns()

    def load_profile_defaults(self):
        """Load profile defaults."""
        payload = self.profile_service.load_profile(self.profile_name.get().strip())
        self.vcenter_server.set(payload.get("vcenter_server", payload.get("vsphere", {}).get("server", "")))
        self.vcenter_username.set(payload.get("vcenter_username", payload.get("vsphere", {}).get("username", "")))
        self.vcenter_password.set(payload.get("vcenter_password", payload.get("vsphere", {}).get("password", "")))
        ssh_tunnel = payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            self.ssh_gateway_host.set(ssh_tunnel.get("gateway_host", ""))
            self.ssh_gateway_port.set(str(ssh_tunnel.get("gateway_port", "22")))
            self.ssh_gateway_username.set(ssh_tunnel.get("gateway_username", ""))
            self.ssh_gateway_password.set(ssh_tunnel.get("gateway_password", ""))
            self.ssh_target_port.set(str(ssh_tunnel.get("target_port", "22")))
        self._apply_detected_schema(self._resolve_target_names(payload), payload.get("build_type", payload.get("target_schema", {}).get("build_type", self.audit_path.get())))

        targets = payload.get("targets", {})
        target_creds = []
        if isinstance(targets, dict):
            for target_name in self._resolve_target_names(payload):
                entry = targets.get(target_name, {})
                if not isinstance(entry, dict):
                    continue
                user = normalize_text(entry.get("username", ""))
                password = entry.get("password", "")
                if user and password:
                    target_creds.append((user, password))

        if target_creds:
            first_user, first_password = target_creds[0]
            self.guest_username.set(first_user)
            self.guest_password.set(first_password)
            if all(user == first_user and pwd == first_password for user, pwd in target_creds):
                self.append_log("Loaded profile defaults: vCenter credentials and shared VM login.")
            else:
                self.append_log("Loaded profile defaults: vCenter credentials; VM credentials vary by target (using first for shared field).")
        else:
            self.append_log(f"Loaded profile defaults from {self.profile_name.get().strip()}")
        # Optionally update other fields if needed

    @staticmethod
    def _coerce_local_only_profile(vm_profile: Dict[str, Any], target_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Internal helper for coerce local only profile."""
        targets = vm_profile.setdefault("targets", {})
        for target_name in (target_names or resolve_profile_target_columns(vm_profile)):
            target_entry = targets.setdefault(target_name, {"vm_name": "", "os_type": "windows"})
            target_entry["vm_name"] = LOCAL_SENTINEL
            target_entry["os_type"] = "windows"
        return vm_profile

    def pick_audit(self):
        """Pick audit."""
        path = filedialog.askopenfilename(title="Select audit workbook", filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")])
        if path:
            self.audit_path.set(path)
            self._refresh_audit_source_metadata(prompt_user=True)

    def pick_output(self):
        """Pick output."""
        path = filedialog.asksaveasfilename(title="Save audited workbook as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if path:
            self.output_path.set(path)

    def start_audit(self):
        """Start audit."""
        self._audit_profile_override = None
        self._audit_mode_label = "standard"
        self.run_button.configure(state="disabled")
        self.quick_run_button.configure(state="disabled")
        self.probe_button.configure(state="disabled")
        self.progress_var.set(0)
        self.set_status(f"Status: Running ({self.build_type_value.get()})")
        self.logger = FileLogger(LOGS_DIR, "audit_run")
        self.append_log(f"Opening workbook: {self.audit_path.get()}")
        self.append_log(f"Build type for this audit: {self.build_type_value.get()}")
        self.append_log(f"Session log file: {self.logger.get_path()}")
        threading.Thread(target=self._worker, daemon=True).start()

    def start_quick_audit(self):
        """Run the quick-audit pipeline: file picker -> VM prompt -> local+VM scan."""
        selected_path = filedialog.askopenfilename(
            title="Quick Audit Scan - Select XLSX Checklist",
            filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")],
        )
        if not selected_path:
            return

        try:
            workbook_service = AuditWorkbookService(selected_path)
            workbook_service.detect_header_row()
            workbook_service.build_column_map()
            target_columns = workbook_service.target_columns or default_target_columns()
            self._apply_detected_schema(target_columns, workbook_service.build_type)
        except Exception as exc:
            messagebox.showerror("Quick Audit Scan", f"Unable to parse selected workbook:\n{exc}")
            return

        quick_details = self._prompt_quick_audit_vm_details(target_columns)
        if not quick_details:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        source_stem = Path(selected_path).stem
        quick_output = AUDIT_RESULTS_DIR / f"quick_audit_scan_{source_stem}_{timestamp}.xlsx"

        self.audit_path.set(selected_path)
        self.output_path.set(str(quick_output))
        self.connection_mode.set("vSphere")
        self.local_only.set(False)
        self.show_ssh_settings.set(False)

        vcenter = quick_details["vcenter"]
        guest = quick_details["guest"]
        self.vcenter_server.set(vcenter["server"])
        self.vcenter_username.set(vcenter["username"])
        self.vcenter_password.set(vcenter["password"])
        self.guest_username.set(guest["username"])
        self.guest_password.set(guest["password"])

        self._audit_profile_override = {
            "profile_name": "quick_audit_scan",
            "build_type": self.build_type_value.get(),
            "target_schema": {
                "source_path": selected_path,
                "target_columns": list(target_columns),
                "build_type": self.build_type_value.get(),
            },
            "targets": quick_details["targets"],
        }
        self._audit_mode_label = "quick_audit_scan"

        self.run_button.configure(state="disabled")
        self.quick_run_button.configure(state="disabled")
        self.probe_button.configure(state="disabled")
        self.progress_var.set(0)
        self.set_status("Status: Running Quick Audit Scan")
        self.logger = FileLogger(LOGS_DIR, "quick_audit_scan")
        self.append_log("Quick Audit Scan started.")
        self.append_log(f"Selected workbook: {selected_path}")
        self.append_log(f"Output workbook: {quick_output}")
        self.append_log(f"Session log file: {self.logger.get_path()}")
        threading.Thread(target=self._worker, daemon=True).start()

    def start_probe(self):
        """Start probe."""
        self.run_button.configure(state="disabled")
        self.quick_run_button.configure(state="disabled")
        self.probe_button.configure(state="disabled")
        self.set_status("Status: Probing remote connection...")
        self.logger = FileLogger(LOGS_DIR, "audit_probe")
        self.append_log(f"Probe log file: {self.logger.get_path()}")
        self.append_log("Starting pre-audit connection probe...")
        threading.Thread(target=self._probe_worker, daemon=True).start()

    def _probe_worker(self):
        """Internal helper for probe worker."""
        service = None
        try:
            mode = normalize_text(self.connection_mode.get()).lower()
            if mode == "ssh tunnel":
                if not PARAMIKO_AVAILABLE:
                    raise RuntimeError("paramiko is not installed. Install with: pip install paramiko")
                if not self.guest_username.get().strip() or not self.guest_password.get():
                    raise ValueError("Target SSH username/password are required for SSH probe.")

                ssh_service = SSHTunnelService(
                    target_username=self.guest_username.get().strip(),
                    target_password=self.guest_password.get(),
                    target_port=self._parse_int(self.ssh_target_port.get(), 22),
                    gateway_host=self.ssh_gateway_host.get().strip(),
                    gateway_username=self.ssh_gateway_username.get().strip(),
                    gateway_password=self.ssh_gateway_password.get(),
                    gateway_port=self._parse_int(self.ssh_gateway_port.get(), 22),
                )
                profile = self.profile_service.load_profile(self.profile_name.get().strip())
                target_names = self._resolve_target_names(profile)
                mapped_hosts = [
                    normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
                    for name in target_names
                ]
                mapped_hosts = sorted({host for host in mapped_hosts if host and host.upper() != LOCAL_SENTINEL})
                if not mapped_hosts:
                    self.after(0, lambda: self.append_log("Probe note | No non-local mapped hosts found in profile."))
                else:
                    self.after(0, lambda: self.append_log(f"SSH probe start | targets={len(mapped_hosts)}"))
                    for host in mapped_hosts:
                        status, output, details = ssh_service.run_powershell(host, "$env:COMPUTERNAME")
                        self.after(0, lambda host=host, status=status, output=output, details=details: self.append_log(f"Probe target | host={host} | status={status} | output={output} | details={details}"))
            else:
                server = self.vcenter_server.get().strip()
                username = self.vcenter_username.get().strip()
                password = self.vcenter_password.get()
                if not server:
                    raise ValueError("vCenter server is required for probe.")
                if not username or not password:
                    raise ValueError("vCenter username/password are required for probe.")

                self.after(0, lambda: self.append_log(f"Connecting to vCenter: {server}"))
                service = VSphereService(server, username, password, True)
                service.connect()
                vm_inventory = service.list_windows_vms()
                self.after(0, lambda: self.append_log(f"vCenter probe PASS | reachable=True | inventory_count={len(vm_inventory)}"))

                try:
                    profile = self.profile_service.load_profile(self.profile_name.get().strip())
                    target_names = self._resolve_target_names(profile)
                    mapped_vm_names = [
                        normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
                        for name in target_names
                    ]
                    mapped_vm_names = [name for name in mapped_vm_names if name and name.upper() != LOCAL_SENTINEL]
                    if mapped_vm_names:
                        report = service.verify_vm_names(mapped_vm_names)
                        for vm_name, info in report.items():
                            self.after(
                                0,
                                lambda vm_name=vm_name, info=info: self.append_log(
                                    f"Probe target | vm={vm_name} | power={info['power_state']} | tools={info['tools_status']} | guest={info['guest_os']}"
                                ),
                            )
                    else:
                        self.after(0, lambda: self.append_log("Probe note | No non-local mapped VM names found in profile."))
                except Exception as exc:
                    self.after(0, lambda: self.append_log(f"Probe warning | Could not load/verify profile mappings: {exc}"))

            self.after(0, lambda: self.set_status("Status: Probe complete"))
        except Exception as exc:
            self.logger.write_exception(exc)
            self.after(0, lambda: self.append_log(f"Probe failed: {exc}"))
            self.after(0, lambda: self.set_status("Status: Probe failed"))
        finally:
            if service is not None:
                try:
                    service.disconnect()
                except Exception:
                    pass
            self.after(0, lambda: self.run_button.configure(state="normal"))
            self.after(0, lambda: self.quick_run_button.configure(state="normal"))
            self.after(0, lambda: self.probe_button.configure(state="normal"))

    def _worker(self):
        """Internal helper for worker."""
        started_at = datetime.now().isoformat(timespec="seconds")
        rows: List[AuditRow] = []
        results: List[ScanResult] = []
        source_audit_path = self.audit_path.get().strip()
        normalized_audit_path = source_audit_path
        normalized_from_fallback = False
        temp_json_path = ""
        temp_xlsx_path = ""

        def build_scan_job_payload(status: str, error_message: str = "") -> Dict[str, Any]:
            """Build scan job payload."""
            row_by_index = {row.row_index: row for row in rows}

            parsed_rows: List[Dict[str, Any]] = []
            special_path_list: List[Dict[str, Any]] = []
            for row in rows:
                rule, _payload = VersionRuleResolver.detect_rule(row.version_locations)
                detection_commands = LocalWindowsScanner.describe_local_detection_commands(
                    row.software_component,
                    row.version_locations,
                )
                marked_targets = [name for name, mark in row.target_vms.items() if is_x_mark(mark)]
                parsed_entry = {
                    "worksheet_row": row.row_index,
                    "software_component": row.software_component,
                    "current_ci_version": row.current_ci_version,
                    "sbl_build_version": row.sbl_build_version,
                    "version_locations": row.version_locations,
                    "rule": rule,
                    "marked_targets": marked_targets,
                    "local_detection_commands": detection_commands,
                }
                parsed_rows.append(parsed_entry)
                if rule != "programs_and_features":
                    special_path_list.append(parsed_entry)

            local_results: List[Dict[str, Any]] = []
            for result in results:
                if result.target_name != "LOCAL_MACHINE":
                    continue
                source_row = row_by_index.get(result.worksheet_row)
                local_results.append(
                    {
                        "worksheet_row": result.worksheet_row,
                        "software_component": result.software_component,
                        "expected_version": result.expected_version,
                        "found_version": result.found_version,
                        "status": result.status,
                        "audit_text": result.audit_text,
                        "details": result.details,
                        "version_locations": source_row.version_locations if source_row else "",
                        "local_detection_commands": LocalWindowsScanner.describe_local_detection_commands(
                            result.software_component,
                            source_row.version_locations if source_row else "",
                        ) if source_row else [],
                    }
                )

            local_summary = {
                "total": len(local_results),
                "pass": sum(1 for item in local_results if item["status"] == "PASS"),
                "fail": sum(1 for item in local_results if item["status"] == "FAIL"),
                "warn": sum(1 for item in local_results if item["status"] == "WARN"),
            }

            audit_path_value = self.audit_path.get().strip()
            output_path_value = self.output_path.get().strip()
            baseline_name = ""
            if rows:
                baseline_name = rows[0].sbl_build_version

            return {
                "status": status,
                "started_at": started_at,
                "completed_at": datetime.now().isoformat(timespec="seconds"),
                "error": error_message,
                "sbl_file": {
                    "name": Path(audit_path_value).name if audit_path_value else "",
                    "path": audit_path_value,
                    "normalized_path": normalized_audit_path,
                    "baseline_name": baseline_name,
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "sbl_model": _get_sbl_model_from_workbook(audit_path_value) if audit_path_value else "UNKNOWN",
                },
                "output": {
                    "workbook_path": output_path_value,
                    "result_base_name": Path(output_path_value).stem if output_path_value else "audit_results",
                },
                "settings": {
                    "profile_name": (
                        "quick_audit_scan"
                        if self._audit_profile_override is not None
                        else self.profile_name.get().strip()
                    ),
                    "audit_mode": self._audit_mode_label,
                    "build_type": self.build_type_value.get(),
                    "connection_mode": normalize_text(self.connection_mode.get()),
                    "local_only": bool(self.local_only.get()),
                    "fallback_enabled": bool(self.show_ssh_settings.get()),
                    "vcenter_server": self.vcenter_server.get().strip(),
                    "ssh_gateway_host": self.ssh_gateway_host.get().strip(),
                    "ssh_gateway_port": self._parse_int(self.ssh_gateway_port.get(), 22),
                    "ssh_target_port": self._parse_int(self.ssh_target_port.get(), 22),
                },
                "sbl_parse": {
                    "target_columns": list(self.detected_target_columns),
                    "row_count": len(parsed_rows),
                    "rows": parsed_rows,
                    "special_path_scan_list": special_path_list,
                },
                "local_machine_scan": {
                    "results": local_results,
                    "comparison_summary": local_summary,
                },
            }

        try:
            template_service = TemplateAssetService()
            try:
                workbook_service = AuditWorkbookService(source_audit_path)
                if workbook_service.repaired_file_path:
                    self.after(0, lambda: self.append_log(f"Recovered workbook during load: {workbook_service.repaired_file_path}"))
                workbook_service.detect_header_row()
                workbook_service.build_column_map()
            except Exception as parse_exc:
                self.after(0, lambda error_text=str(parse_exc): self.append_log(f"Primary workbook parse failed: {error_text}"))
                self.after(0, lambda: self.append_log("Attempting fallback normalization for non-standard workbook format..."))

                import_rows = read_software_list_universal_rows(
                    source_audit_path,
                    debug_logger=lambda message: self.after(0, lambda msg=message: self.append_log(msg)),
                )

                if not import_rows:
                    raise ValueError("Fallback normalization found no data rows")

                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as temp_json:
                    temp_json_path = temp_json.name
                    json.dump(import_rows, temp_json, indent=2)
                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as temp_xlsx:
                    temp_xlsx_path = temp_xlsx.name

                template_service.import_list_to_sbl_workbook(temp_json_path, temp_xlsx_path)

                workbook_service = AuditWorkbookService(temp_xlsx_path)
                workbook_service.detect_header_row()
                workbook_service.build_column_map()
                normalized_audit_path = temp_xlsx_path
                normalized_from_fallback = True
                self.after(0, lambda path=temp_xlsx_path: self.append_log(f"Fallback normalization succeeded: {path}"))

            if workbook_service.repaired_file_path:
                self.after(0, lambda: self.append_log(f"Recovered workbook during load: {workbook_service.repaired_file_path}"))
            rows = workbook_service.iter_audit_rows()
            self.after(0, lambda cols=list(workbook_service.target_columns), build_type=workbook_service.build_type: self._apply_detected_schema(cols, build_type))
            self.after(0, lambda: self.append_log(f"Detected format with {workbook_service.sbl_build_header} and {workbook_service.audit_header}. Rows to process: {len(rows)}"))
            processed = {"count": 0}
            def logger(msg: str):
                """Logger."""
                if msg.startswith("Scanning "):
                    processed["count"] += 1
                total = max(1, len(rows))
                self.after(0, lambda p=min(100, (processed['count'] / total) * 100): self.progress_var.set(p))
                self.after(0, lambda m=msg: self.append_log(m))
            if self._audit_profile_override is not None:
                vm_profile = copy.deepcopy(self._audit_profile_override)
                self.after(0, lambda: self.append_log("Using quick-audit target mapping from dialog input."))
            else:
                vm_profile = self.profile_service.load_profile(self.profile_name.get().strip())
            vcenter_server = self.vcenter_server.get().strip()
            mode = normalize_text(self.connection_mode.get()).lower()
            if self.local_only.get():
                vm_profile = self._coerce_local_only_profile(vm_profile, workbook_service.target_columns)
                self.after(0, lambda: self.append_log("Local-only scan enabled; all targets set to __LOCAL__."))
            elif mode != "ssh tunnel" and not vcenter_server:
                vm_profile = self._coerce_local_only_profile(vm_profile, workbook_service.target_columns)
                self.after(0, lambda: self.append_log("No vCenter server configured; forcing local-only scan mode (__LOCAL__) for all targets."))
            engine = AuditEngine(
                workbook_service,
                logger,
                vm_profile,
                {"server": vcenter_server, "username": self.vcenter_username.get().strip(), "password": self.vcenter_password.get()},
                {"username": self.guest_username.get().strip(), "password": self.guest_password.get()},
                connection_mode=normalize_text(self.connection_mode.get()),
                ssh_config={
                    "gateway_host": self.ssh_gateway_host.get().strip(),
                    "gateway_port": self._parse_int(self.ssh_gateway_port.get(), 22),
                    "gateway_username": self.ssh_gateway_username.get().strip(),
                    "gateway_password": self.ssh_gateway_password.get(),
                    "target_port": self._parse_int(self.ssh_target_port.get(), 22),
                },
                ssh_fallback_enabled=bool(self.show_ssh_settings.get()),
            )

            base_name = Path(self.output_path.get().strip()).stem or "audit_results"
            try:
                registry_snapshot = engine.local_scanner.capture_registry_snapshot()
                registry_snapshot_path = JsonExportService.write_registry_snapshot_json(base_name, registry_snapshot)
                snapshot_status = normalize_text(registry_snapshot.get("status", "unknown"))
                snapshot_count = int(registry_snapshot.get("entry_count", 0) or 0)
                self.after(
                    0,
                    lambda path=registry_snapshot_path, status=snapshot_status, count=snapshot_count: self.append_log(
                        f"Registry snapshot written: {path} | status={status} | entries={count}"
                    ),
                )
            except Exception as snapshot_exc:
                self.after(0, lambda error_text=str(snapshot_exc): self.append_log(f"Registry snapshot failed: {error_text}"))

            results = engine.run()
            workbook_service.save_as(self.output_path.get().strip())
            sbl_model = _get_sbl_model_from_workbook(normalized_audit_path)
            latest_sbl = template_service.update_latest_sbl(self.output_path.get().strip())
            latest_master = template_service.snapshot_current_master_to_latest(sbl_model=sbl_model)
            json_path = JsonExportService.write_result_json(Path(self.output_path.get()).stem, {"audit_workbook": self.audit_path.get(), "normalized_audit_workbook": normalized_audit_path if normalized_from_fallback else self.audit_path.get(), "saved_workbook": self.output_path.get(), "profile_name": self.profile_name.get().strip(), "generated_at": datetime.now().isoformat(timespec="seconds"), "results": [asdict(result) for result in results]})
            scan_job_json_path = JsonExportService.write_scan_job_json(
                Path(self.output_path.get()).stem,
                build_scan_job_payload("completed"),
            )
            summary = self.build_summary(results)
            self.after(0, lambda: self.append_log(summary))
            self.after(0, lambda: self.append_log(f"Saved audited workbook: {self.output_path.get()}"))
            self.after(0, lambda: self.append_log(f"Result JSON written: {json_path}"))
            self.after(0, lambda: self.append_log(f"Scan job JSON written: {scan_job_json_path}"))
            self.after(0, lambda: self.append_log(f"Updated latest SBL snapshot: {latest_sbl}"))
            self.after(0, lambda: self.append_log(f"Updated latest master software list snapshot: {latest_master}"))
            self.after(0, lambda: self.progress_var.set(100))
            self.after(0, lambda: self.set_status("Status: Complete"))
        except Exception as exc:
            self.logger.write_exception(exc)
            self.after(0, lambda: self.append_log(f"ERROR: {exc}"))
            try:
                scan_job_json_path = JsonExportService.write_scan_job_json(
                    Path(self.output_path.get()).stem,
                    build_scan_job_payload("failed", error_message=str(exc)),
                )
                self.after(0, lambda: self.append_log(f"Scan job JSON written (failed run): {scan_job_json_path}"))
            except Exception as scan_job_exc:
                self.after(0, lambda: self.append_log(f"Scan job JSON write failed: {scan_job_exc}"))
            self.after(0, lambda: self.set_status("Status: Failed"))
        finally:
            if temp_json_path:
                try:
                    Path(temp_json_path).unlink(missing_ok=True)
                except Exception:
                    pass
            if temp_xlsx_path:
                try:
                    Path(temp_xlsx_path).unlink(missing_ok=True)
                except Exception:
                    pass
            self.after(0, lambda: self.run_button.configure(state="normal"))
            self.after(0, lambda: self.quick_run_button.configure(state="normal"))
            self.after(0, lambda: self.probe_button.configure(state="normal"))
            self._audit_profile_override = None
            self._audit_mode_label = "standard"

    @staticmethod
    def build_summary(results: List[ScanResult]) -> str:
        """Build summary."""
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warned = sum(1 for r in results if r.status == "WARN")
        return f"Summary | Total target checks: {len(results)} | PASS: {passed} | FAIL: {failed} | WARN: {warned}"


def main():
    """Main."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
