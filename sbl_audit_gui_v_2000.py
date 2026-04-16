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
from typing import Any, Dict, List, Optional, Tuple
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


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def normalize_header(value: Any) -> str:
    return normalize_text(value).upper()


def is_x_mark(value: Any) -> bool:
    return normalize_text(value).upper() == "X"


def today_str() -> str:
    return datetime.now().strftime("%d%b%Y").upper()


def timestamp_str() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def normalize_version(value: str) -> str:
    text = normalize_text(value)
    if not text:
        return ""
    match = re.search(r"\d+(?:\.\d+){1,}", text)
    if match:
        return match.group(0)
    return text.lower()


def parse_version_tuple(value: str) -> Tuple[int, ...]:
    normalized = normalize_version(value)
    if not normalized:
        return tuple()
    parts = [part for part in re.split(r"[^0-9]+", normalized) if part]
    if not parts:
        return tuple()
    return tuple(int(part) for part in parts)


def compare_versions(expected: str, found: str, scan_status: str) -> Tuple[str, str]:
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


def ensure_project_structure() -> None:
    for path in [AUDIT_RESULTS_DIR, AUDIT_CHECKLIST_DIR, JSON_DIR, JSON_RESULTS_DIR, JSON_CHECKLIST_DIR, PROFILES_DIR, LOGS_DIR, TEMPLATES_DIR]:
        path.mkdir(parents=True, exist_ok=True)

    if not MASTER_SOFTWARE_LIST_PATH.exists():
        MASTER_SOFTWARE_LIST_PATH.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")

    if not MASTER_JSON_TEMPLATE_BASELINE_PATH.exists():
        MASTER_JSON_TEMPLATE_BASELINE_PATH.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")

    if not MASTER_JSON_TEMPLATE_LATEST_PATH.exists():
        if MASTER_JSON_TEMPLATE_BASELINE_PATH.exists():
            shutil.copy2(MASTER_JSON_TEMPLATE_BASELINE_PATH, MASTER_JSON_TEMPLATE_LATEST_PATH)
        else:
            MASTER_JSON_TEMPLATE_LATEST_PATH.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")


def normalize_model_key(model_name: str = None) -> str:
    text = normalize_text(model_name)
    if not text or text.upper() == "UNKNOWN":
        return "GENERAL"
    return text


def _new_model_bucket() -> Dict[str, Any]:
    return {
        "software_components": {},
        "vm_components": {
            vm_name: {
                "vm_name": "",
                "os_type": "windows",
                "tracked_software": [],
            }
            for vm_name in SYSTEM_COLUMNS
        },
    }


def _empty_master_software_list_payload() -> Dict[str, Any]:
    return {
        "SBL_models": {
            "GENERAL": _new_model_bucket(),
        },
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }


def _max_workbook_style_index(file_path: str) -> Optional[int]:
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
    from openpyxl.utils import get_column_letter
    for col_idx in range(1, ws.max_column + 1):
        max_len = 0
        for row_idx in range(1, ws.max_row + 1):
            value = ws.cell(row=row_idx, column=col_idx).value
            text = "" if value is None else str(value)
            max_len = max(max_len, len(text))
        ws.column_dimensions[get_column_letter(col_idx)].width = max(min_width, min(max_len + 2, max_width))


def parse_build_and_audit_headers(headers: List[str]) -> Tuple[Optional[str], Optional[str]]:
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
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"{prefix}_{timestamp_str()}.log"
        self._lock = threading.Lock()

    def write(self, message: str) -> None:
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def write_exception(self, exc: Exception) -> None:
        self.write(f"ERROR: {exc}")
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        with self._lock:
            with self.log_file.open("a", encoding="utf-8") as fh:
                fh.write(tb + "\n")

    def get_path(self) -> str:
        return str(self.log_file)


class MasterSoftwarePathService:
    def __init__(self, path: Path = MASTER_SOFTWARE_LIST_PATH):
        self.path = path
        ensure_project_structure()

    def load(self) -> Dict[str, Any]:
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

            for vm_name in SYSTEM_COLUMNS:
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
        payload = self.load()
        model_key = normalize_model_key(model_name)
        models = payload.setdefault("SBL_models", {})
        model_bucket = models.setdefault(model_key, _new_model_bucket())
        bucket = model_bucket.setdefault("software_components", {})
        vm_bucket = model_bucket.setdefault("vm_components", {})
        entry = bucket.get(software_component, {})

        path_meta = derive_path_metadata(path_value)
        entry["generic_name"] = entry.get("generic_name", software_component)
        entry["registry_name"] = entry.get("registry_name", "")
        entry["path"] = path_meta["path"]
        entry["coded_path"] = path_meta["coded_path"]
        entry["verification_source"] = path_meta["verification_source"]
        entry["path_last_verified_date"] = datetime.now().isoformat(timespec="seconds")

        tracked_vms = entry.get("tracked_in_vms", [])
        if not isinstance(tracked_vms, list):
            tracked_vms = []
        is_vm_target = target_name in SYSTEM_COLUMNS
        if is_vm_target and target_name not in tracked_vms:
            tracked_vms.append(target_name)
        entry["tracked_in_vms"] = tracked_vms

        if is_vm_target:
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

        auto_note = entry.get("notes", "")
        if tracked_vms:
            auto_note = f"Tracked in VMs: {', '.join(tracked_vms)}"
        entry["notes"] = notes or auto_note
        bucket[software_component] = entry
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        self.save(payload)


class TemplateAssetService:
    def __init__(self):
        ensure_project_structure()

    @staticmethod
    def _find_first_existing(paths: List[Path]) -> Optional[Path]:
        for candidate in paths:
            if candidate.exists():
                return candidate
        return None

    @staticmethod
    def _blank_master_payload(components: Dict[str, str], sbl_model: str = None) -> Dict[str, Any]:
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
        service = AuditWorkbookService(sbl_path)
        service.detect_header_row()
        service.build_column_map()
        components: Dict[str, str] = {}
        for row in service.iter_audit_rows():
            if row.software_component and row.software_component not in components:
                components[row.software_component] = row.version_locations
        return components

    def _write_blank_master_from_sbl(self, sbl_path: str, output_json_path: Path, sbl_model: str = None) -> str:
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
        """Update latest SBL template, including model-specific filename."""
        sbl_model = _get_sbl_model_from_workbook(sbl_path)
        latest_sbl = get_sbl_template_latest_path(sbl_model)
        shutil.copy2(sbl_path, latest_sbl)
        return str(latest_sbl)

    def snapshot_current_master_to_latest(self, sbl_model: str = None) -> str:
        """Snapshot current master software list to latest."""
        latest_json = get_master_json_template_latest_path(sbl_model)
        
        if MASTER_SOFTWARE_LIST_PATH.exists():
            shutil.copy2(MASTER_SOFTWARE_LIST_PATH, latest_json)
        else:
            payload = _empty_master_software_list_payload()
            latest_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(latest_json)

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
        if not path.exists():
            return "Missing"
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    def get_template_status(self, sbl_model: str = None) -> Dict[str, Dict[str, str]]:
        """Get template status (model-specific if provided)."""
        if sbl_model is None:
            sbl_model = "Geospatial Intelligence Foundation"  # default
        
        targets = {
            "baseline_sbl": get_sbl_template_baseline_path(sbl_model),
            "latest_sbl": get_sbl_template_latest_path(sbl_model),
            "baseline_master_list": get_master_json_template_baseline_path(sbl_model),
            "latest_master_list": get_master_json_template_latest_path(sbl_model),
        }
        status: Dict[str, Dict[str, str]] = {}
        for key, path in targets.items():
            status[key] = {
                "path": str(path),
                "exists": "Yes" if path.exists() else "No",
                "updated": self._format_mtime(path),
            }
        return status

    def import_list_to_sbl_workbook(self, input_path: str, output_path: str) -> str:
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

        wb = Workbook()
        ws = wb.active
        ws.title = "Imported SBL"
        headers = [
            "SOFTWARE COMPONENT",
            "CURRENT CI VERSION",
            "SBL BUILD TEMPLATE",
            "AUDIT TEMPLATE",
            *SYSTEM_COLUMNS,
            "VERSION LOCATIONS",
        ]
        ws.append(headers)

        def pick_value(record: Dict[str, Any], candidates: List[str]) -> str:
            normalized = {normalize_header(k): v for k, v in record.items()}
            for candidate in candidates:
                for key, value in normalized.items():
                    if candidate in key:
                        return normalize_text(value)
            return ""

        for record in rows:
            software_component = pick_value(record, ["SOFTWARE COMPONENT", "NAME", "COMPONENT"])
            current_ci = pick_value(record, ["CURRENT CI VERSION", "CURRENT VERSION", "EXPECTED VERSION", "VERSION"])
            version_locations = pick_value(record, ["VERSION LOCATIONS", "VERSION LOCATION", "PATH", "LOCATION", "RULE"])
            ws.append([
                software_component,
                current_ci,
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                version_locations,
            ])

        auto_fit_columns(ws)
        wb.save(output_path)
        return output_path


class JsonExportService:
    @staticmethod
    def write_checklist_json(base_name: str, payload: Dict[str, Any]) -> str:
        ensure_project_structure()
        output = JSON_CHECKLIST_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_result_json(base_name: str, payload: Dict[str, Any]) -> str:
        ensure_project_structure()
        output = JSON_RESULTS_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)


class VMProfileService:
    def __init__(self, profiles_dir: Path = PROFILES_DIR):
        self.profiles_dir = profiles_dir
        ensure_project_structure()

    def profile_path(self, profile_name: str) -> Path:
        return self.profiles_dir / f"{profile_name}.json"

    def save_profile(self, profile_name: str, payload: Dict[str, Any]) -> str:
        payload["profile_name"] = profile_name
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        path = self.profile_path(profile_name)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(path)

    def load_profile(self, profile_name: str) -> Dict[str, Any]:
        return json.loads(self.profile_path(profile_name).read_text(encoding="utf-8"))


class VSphereService:
    def __init__(self, server: str, username: str, password: str, ignore_ssl: bool = True):
        self.server = server.strip()
        self.username = username.strip()
        self.password = password
        self.ignore_ssl = ignore_ssl
        self.si = None

    def connect(self):
        if not PYVMOMI_AVAILABLE:
            raise RuntimeError("pyVmomi is not installed. Install it with: pip install pyvmomi requests")
        context = ssl._create_unverified_context() if self.ignore_ssl else None
        self.si = SmartConnect(host=self.server, user=self.username, pwd=self.password, sslContext=context)
        return self.si

    def disconnect(self):
        if self.si is not None:
            Disconnect(self.si)
            self.si = None

    def _all_vms(self):
        if self.si is None:
            self.connect()
        content = self.si.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def find_vm(self, vm_name: str):
        for vm_obj in self._all_vms():
            if vm_obj.name == vm_name:
                return vm_obj
        return None

    def list_windows_vms(self) -> List[str]:
        names = [LOCAL_SENTINEL]
        for vm_obj in self._all_vms():
            guest_name = normalize_text(getattr(getattr(vm_obj, "guest", None), "guestFullName", ""))
            if not guest_name or "WINDOWS" in guest_name.upper():
                names.append(vm_obj.name)
        return sorted(set(names), key=lambda x: (x != LOCAL_SENTINEL, x.lower()))

    def verify_vm_names(self, vm_names: List[str]) -> Dict[str, Dict[str, str]]:
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
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _connect_target(self, target_host: str):
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
                username=self.target_username,
                password=self.target_password,
                timeout=self.timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
                sock=sock,
            )
            return target_client, gateway_client

        target_client.connect(
            hostname=target_host,
            port=self.target_port,
            username=self.target_username,
            password=self.target_password,
            timeout=self.timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        return target_client, None

    def run_powershell(self, target_host: str, script: str, timeout_seconds: int = 90) -> Tuple[str, str, str]:
        if not self.target_username or not self.target_password:
            return "WARN", "NO_SSH_CREDS", f"Missing SSH credentials for target {target_host}"
        if not target_host:
            return "WARN", "NO_TARGET", "SSH target host is blank"

        target_client = None
        gateway_client = None
        try:
            target_client, gateway_client = self._connect_target(target_host)
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
    @staticmethod
    def extract_file_paths(version_location: str) -> List[str]:
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
    def __init__(self, file_path: str):
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

    def detect_header_row(self, search_limit: int = 20) -> int:
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
        required = ["SOFTWARE COMPONENT", self.current_ci_header, self.sbl_build_header, self.audit_header, self.version_location_header] + SYSTEM_COLUMNS
        missing = [name for name in required if name not in headers_by_name]
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(missing)}")
        self.column_map = headers_by_name
        return headers_by_name

    def iter_audit_rows(self) -> List[AuditRow]:
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
            marks = {name: normalize_text(self.worksheet.cell(row_idx, self.column_map[name]).value) for name in SYSTEM_COLUMNS}
            if not software_component and not current_ci_version and not sbl_build_version and not version_locations:
                continue
            rows.append(AuditRow(row_idx, software_component, current_ci_version, sbl_build_version, audit_value, marks, version_locations))
        return rows

    def write_audit_result(self, row_index: int, audit_text: str, status: str) -> None:
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
    def __init__(self, worksheet):
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
        self.header_row_index = None
        self.column_map = {}
        self.sbl_build_header = None
        self.audit_header = None
        self.current_ci_header = None
        self.version_location_header = None
        self.displayed_name_header = None
        self.id_number_header = None

    def extract_path(self, version_location: Any) -> str:
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
    # The read_software_list method iterates through the rows of the worksheet starting from the row immediately after the detected header row. For each row, it reads the values for SOFTWARE COMPONENT, DISPLAYED NAME, CURRENT CI VERSION, and VERSION LOCATION(S). It normalizes these values and constructs a list of dictionaries representing the software components to be audited, including their expected versions and where to find them based on the version location information.
    def read_software_list(self) -> List[Dict[str, str]]:
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
                    version_location_value = "GOT YOU BITCH"
            else:
                version_location_value = normalize_text(vl_cell.value)
                if version_location_value is None or pd.isna(version_location_value):
                    version_location_value = "GOT YOU BITCH"
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
    def __init__(self, source_path: str):
        self.source_path = source_path
        self.source_workbook = load_workbook(source_path)
        self.source_ws = self.source_workbook.active
        print(f"Initialized ChecklistGeneratorService with source: {source_path}" ) # added print statement to confirm initialization and source path
    
    # The generate_audit_form method creates a new workbook and copies the content and styles from the source worksheet. It then detects the header row and column mapping, clears any existing audit values, updates the audit header with the current date, auto-fits the columns, and saves the new workbook to the specified output path.
    def generate_audit_form(self, output_path: str) -> None:
        print(f"Generating audit form from '{self.source_path}' to '{output_path}'")
        wb_out = Workbook()
        ws_out = wb_out.active
        ws_out.title = "Tool generated Audit Checklist"
        # Copy cell values and styles from source to destination
        for row in self.source_ws.iter_rows():
            print(f"Copying row {row[0].row}...") # added print statement to track row copying
            for src in row:
                if isinstance(src, MergedCell):
                    continue
                dst = ws_out.cell(src.row, src.column, src.value)
                if src.has_style:
                    dst._style = copy.copy(src._style)
                if src.hyperlink:
                    dst._hyperlink = copy.copy(src.hyperlink)
                if src.comment:
                    dst.comment = copy.copy(src.comment)
        # Recreate merged cell ranges in the new worksheet
        for merged_range in self.source_ws.merged_cells.ranges:
            try:
                print(f"Copying merged range {merged_range}...")  # added print statement to track merged range copying
                ws_out.merge_cells(str(merged_range))
            except Exception as e:
                print(f"Failed to merge range {merged_range}: {e}")
                # Optionally, continue or handle the error as needed
        
        print("Finished copying content and styles. Now detecting headers and clearing audit values...") # added print statement to indicate completion of copying and start of header detection    
        proxy = AuditWorkbookServiceProxy(ws_out)
        col_map, _, audit_header = proxy.build_column_map()
        header_row = proxy.header_row_index
        print(f"Detected header row at index: {header_row}") # added print statement to confirm detected header row
        print(f"Column map: {col_map}, audit header: {audit_header}") # added print statement to show column mapping and audit header   
        audit_col = col_map[audit_header]
        for row_idx in range(header_row + 1, ws_out.max_row + 1):
            cell = ws_out.cell(row_idx, audit_col)
            if not isinstance(cell, MergedCell):
                cell.value = None
                cell.fill = PatternFill(fill_type=None)
        header_cell = ws_out.cell(header_row, audit_col)
        if header_cell.value:
            header_cell.value = re.sub(r"\bXX[A-Z]{3}\d{4}\b", today_str(), str(header_cell.value).upper())
        else:
            print("No audit header found, skipping audit value clearing and header update.")
        auto_fit_columns(ws_out)
        wb_out.save(output_path)

    

    def export_json_payload(self) -> Dict[str, Any]:
        proxy = AuditWorkbookServiceProxy(self.source_ws)
        col_map, sbl_header, audit_header = proxy.build_column_map()
        current_ci_header = proxy.current_ci_header
        if not current_ci_header:
            raise ValueError("No column found with 'CURRENT CI VERSION' in the name.")
        rows = []
        for row_idx in range(proxy.header_row_index + 1, self.source_ws.max_row + 1):
            software_component = normalize_text(self.source_ws.cell(row_idx, col_map["SOFTWARE COMPONENT"]).value)
            if not software_component:
                continue
            vl_cell = self.source_ws.cell(row_idx, col_map[proxy.version_location_header])
            if isinstance(vl_cell, MergedCell):
                vl_value = None
                for merged_range in self.source_ws.merged_cells.ranges:
                    if vl_cell.coordinate in merged_range:
                        vl_value = self.source_ws.cell(merged_range.min_row, merged_range.min_col).value
                        break
                version_locations = normalize_text(vl_value)
            else:
                version_locations = normalize_text(vl_cell.value)
            rows.append({
                "software_component": software_component,
                "current_ci_version": normalize_text(self.source_ws.cell(row_idx, col_map[current_ci_header]).value),
                "sbl_build_version": normalize_text(self.source_ws.cell(row_idx, col_map[sbl_header]).value),
                "audit_value": normalize_text(self.source_ws.cell(row_idx, col_map[audit_header]).value),
                "target_vms": {name: normalize_text(self.source_ws.cell(row_idx, col_map[name]).value) for name in SYSTEM_COLUMNS},
                "version_locations": version_locations,
            })
        return {"source_workbook": self.source_path, "generated_at": datetime.now().isoformat(timespec="seconds"), "rows": rows}


class LocalWindowsScanner:
    def find_programs_and_features_version(self, software_name: str) -> Tuple[str, str, str]:
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
        try:
            completed = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], capture_output=True, text=True, timeout=45, check=False)
            output = (completed.stdout or completed.stderr).strip()
            if completed.returncode == 0:
                return "PASS", output or "BLANK_OUTPUT", "Local PowerShell command completed"
            return "WARN", output or "ERROR", f"Local PowerShell returned {completed.returncode}"
        except Exception as exc:
            return "WARN", "ERROR", f"Local PowerShell failed: {exc}"

    def get_file_version(self, path_value: str) -> Tuple[str, str, str]:
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
        failures: List[str] = []
        for path_value in paths:
            status, version, details = self.get_file_version(path_value)
            if status == "PASS":
                return status, version, details
            failures.append(f"{path_value} -> {version}")
        return "WARN", "NOT_FOUND", "; ".join(failures) if failures else "No candidate file paths found"

    def scan_software_version(self, software_name: str, version_location: str) -> Tuple[str, str, str]:
        rule, payload = VersionRuleResolver.detect_rule(version_location)
        if rule == "programs_and_features":
            return self.find_programs_and_features_version(software_name)
        if rule == "powershell":
            return self.run_powershell(payload["command"])
        if rule == "file_version":
            return self.scan_file_versions(payload["paths"])
        return "WARN", "UNKNOWN", f"No implemented scan rule matched VERSION LOCATIONS for {software_name}"


class AuditEngine:
    def __init__(
        self,
        workbook_service: AuditWorkbookService,
        logger,
        vm_profile: Dict[str, Any],
        vcenter_creds: Dict[str, str],
        guest_creds: Dict[str, str],
        connection_mode: str = "vsphere",
        ssh_config: Optional[Dict[str, Any]] = None,
    ):
        self.workbook_service = workbook_service
        self.logger = logger
        self.vm_profile = vm_profile
        self.vcenter_creds = vcenter_creds
        self.guest_creds = guest_creds
        self.connection_mode = normalize_text(connection_mode).lower() or "vsphere"
        self.ssh_config = ssh_config or {}
        self.local_scanner = LocalWindowsScanner()
        self.master_paths = MasterSoftwarePathService()
        self.master_model_name = normalize_model_key(_get_sbl_model_from_workbook(self.workbook_service.file_path))
        self.vsphere_service: Optional[VSphereService] = None
        self.ssh_service: Optional[SSHTunnelService] = None

    def _build_result(self, row: AuditRow, target_name: str, found_version: str, scan_status: str, details: str) -> ScanResult:
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
        scan_status, found_version, details = self.local_scanner.scan_software_version(row.software_component, row.version_locations)
        return self._build_result(row, target_name, found_version, scan_status, f"local-machine | {details}")

    def _scan_guest_vm(self, row: AuditRow, target_name: str, vm_name: str) -> ScanResult:
        if self.vsphere_service is None:
            return self._build_result(row, target_name, "NO_VSPHERE", "WARN", f"vSphere service is not connected for '{vm_name}'")
        if not self.guest_creds.get("username") or not self.guest_creds.get("password"):
            return self._build_result(row, target_name, "NO_GUEST_CREDS", "WARN", f"Missing guest credentials for '{vm_name}'")
        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, self.guest_creds["username"], self.guest_creds["password"], payload["command"])
            return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details}")
        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, self.guest_creds["username"], self.guest_creds["password"], script)
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
                scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, self.guest_creds["username"], self.guest_creds["password"], script)
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"vm={vm_name} | no candidate file path succeeded | {'; '.join(failures)}")
        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"vm={vm_name} | No implemented scan rule matched VERSION LOCATIONS")

    def _scan_ssh_target(self, row: AuditRow, target_name: str, target_host: str) -> ScanResult:
        if self.ssh_service is None:
            return self._build_result(row, target_name, "NO_SSH_SERVICE", "WARN", f"SSH service is not initialized for '{target_host}'")

        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.ssh_service.run_powershell(target_host, payload["command"])
            return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details}")

        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.ssh_service.run_powershell(target_host, script)
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
                scan_status, found_version, details = self.ssh_service.run_powershell(target_host, script)
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"ssh-host={target_host} | no candidate file path succeeded | {'; '.join(failures)}")

        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"ssh-host={target_host} | No implemented scan rule matched VERSION LOCATIONS")

    def scan_target_row(self, row: AuditRow, target_name: str) -> ScanResult:
        target_profile = self.vm_profile.get("targets", {}).get(target_name, {})
        vm_name = normalize_text(target_profile.get("vm_name", ""))
        if not vm_name:
            return self._build_result(row, target_name, "PROFILE_NOT_MAPPED", "WARN", f"No VM mapping saved for {target_name}")
        if vm_name.upper() == LOCAL_SENTINEL:
            return self._scan_local(row, target_name)
        if self.connection_mode == "ssh tunnel":
            return self._scan_ssh_target(row, target_name, vm_name)

        # vSphere mode - try vSphere first
        result = self._scan_guest_vm(row, target_name, vm_name)

        # If fallback is enabled and vSphere failed, try SSH
        if (self.show_ssh_settings.get() and
            result.status in ("WARN", "FAIL") and
            self.ssh_service is not None):
            self.logger(f"vSphere scan failed for {target_name}, trying SSH fallback...")
            ssh_result = self._scan_ssh_target(row, target_name, vm_name)
            if ssh_result.status == "PASS":
                self.logger(f"SSH fallback succeeded for {target_name}")
                return ssh_result
            else:
                self.logger(f"SSH fallback also failed for {target_name}")

        return result

    @staticmethod
    def choose_best_row_result(row_results: List[ScanResult]) -> ScanResult:
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
                if not PARAMIKO_AVAILABLE:
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
                    if self.show_ssh_settings.get() and PARAMIKO_AVAILABLE:
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
                    elif self.show_ssh_settings.get() and not PARAMIKO_AVAILABLE:
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
        super().__init__(parent, padding=16)
        self.controller = controller

    def open_folder(self, folder: Path):
        try:
            if os.name == "nt":
                os.startfile(folder)
            else:
                messagebox.showinfo("Folder", str(folder))
        except Exception as exc:
            messagebox.showerror("Open folder failed", str(exc))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        ensure_project_structure()
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
        self.frames[name].tkraise()


class HomeFrame(BaseFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="SBL Checklist & Audit Tool", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(outer, text="Tool purpose: This tool helps in generating audit checklists and running audits against SBL builds.", wraplength=1040).pack(anchor="w", pady=(0, 18))
        cards = ttk.Frame(outer)
        cards.pack(fill="x")
        def card(title: str, body: str, button: str, frame_name: str):
            box = ttk.LabelFrame(cards, text=title, padding=18)
            box.pack(fill="x", pady=(0, 12))
            ttk.Label(box, text=body, wraplength=980).pack(anchor="w", pady=(0, 10))
            ttk.Button(box, text=button, command=lambda: controller.show_frame(frame_name)).pack(anchor="w")
        card("Configure VM Profile", f"Map worksheet targets to vSphere VMs or to {LOCAL_SENTINEL} for the machine running the tool.", "Open VM Profile Manager", "ProfileFrame")
        card("Create Audit Form", "Generate an audit workbook in the approved format and export additional JSON checklist payload.", "Open Checklist Generator", "ChecklistFrame")
        card("Run Audit", "Scans local targets first, then scans guest VMs through VMware Tools, compares found version against the SBL Build version, and writes PASS/FAIL text to the AUDIT column.", "Open Audit Runner", "AuditFrame")


class ProfileFrame(BaseFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self.profile_service = VMProfileService()
        self.logger = FileLogger(LOGS_DIR, "vm_profile")
        self.profile_name = tk.StringVar(value="default_vsphere_profile")
        self.vcenter_server = tk.StringVar()
        self.vcenter_username = tk.StringVar()
        self.vcenter_password = tk.StringVar()
        self.ignore_ssl = tk.BooleanVar(value=True)
        self.vm_dropdowns: Dict[str, ttk.Combobox] = {}
        self.target_info: Dict[str, Dict[str, str]] = {name: {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"} for name in SYSTEM_COLUMNS}
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
        ttk.Label(top, text="VM Profile Manager", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
        settings = ttk.LabelFrame(self, text="vSphere Settings", padding=12)
        settings.pack(fill="x", pady=12)
        self._entry_row(settings, "Profile name", self.profile_name)
        self._entry_row(settings, "vCenter server", self.vcenter_server)
        self._entry_row(settings, "vCenter username", self.vcenter_username)
        self._entry_row(settings, "vCenter password", self.vcenter_password, show="*")
        ttk.Checkbutton(settings, text="Ignore SSL warnings", variable=self.ignore_ssl).pack(anchor="w", pady=(6, 0))
        mapping = ttk.LabelFrame(self, text=f"Worksheet Target → VM Name or {LOCAL_SENTINEL}", padding=12)
        mapping.pack(fill="x")
        for target_name in SYSTEM_COLUMNS:
            row = ttk.Frame(mapping)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=target_name, width=22).pack(side="left")
            combo = ttk.Combobox(row, state="readonly")
            combo.pack(side="left", fill="x", expand=True)
            self.vm_dropdowns[target_name] = combo
        # Add button to edit target info
        ttk.Button(mapping, text="Edit Target Info", command=self.edit_target_info_dialog).pack(side="right", padx=8)
        controls = ttk.Frame(self)
        controls.pack(fill="x", pady=10)
        ttk.Button(controls, text="Load VM Inventory", command=self.load_inventory).pack(side="left")
        ttk.Button(controls, text="Save Profile", command=self.save_profile).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Load Saved Profile", command=self.load_saved_profile).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Verify Profile", command=self.verify_profile).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
        self.log = tk.Text(self, wrap="word", height=20)
        self.log.pack(fill="both", expand=True)

    def edit_target_info_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Edit Target VM Info")
        rows = {}
        for idx, target_name in enumerate(SYSTEM_COLUMNS):
            info = self.target_info.get(target_name, {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"})
            row = ttk.Frame(dialog)
            row.grid(row=idx, column=0, sticky="ew", pady=2)
            ttk.Label(row, text=target_name, width=18).pack(side="left")
            vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
            user_var = tk.StringVar(value=info.get("username", ""))
            pass_var = tk.StringVar(value=info.get("password", ""))
            os_var = tk.StringVar(value=info.get("os_type", "windows"))
            ttk.Entry(row, textvariable=vm_var, width=16).pack(side="left", padx=2)
            ttk.Entry(row, textvariable=user_var, width=12).pack(side="left", padx=2)
            ttk.Entry(row, textvariable=pass_var, width=12, show="*").pack(side="left", padx=2)
            ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=8, state="readonly").pack(side="left", padx=2)
            rows[target_name] = (vm_var, user_var, pass_var, os_var)
        def save_and_close():
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
        ttk.Button(dialog, text="Save", command=save_and_close).grid(row=len(SYSTEM_COLUMNS), column=0, pady=8)

    def _entry_row(self, parent, label, var, show=None, command=None):
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
        return VSphereService(self.vcenter_server.get(), self.vcenter_username.get(), self.vcenter_password.get(), self.ignore_ssl.get())

    def load_inventory(self):
        try:
            self.append_log(f"Connecting to {self.vcenter_server.get().strip()} for VM inventory...")
            service = self._service()
            service.connect()
            names = service.list_windows_vms()
            service.disconnect()
            for combo in self.vm_dropdowns.values():
                combo["values"] = names
                if not combo.get():
                    combo.set(LOCAL_SENTINEL)
            self.append_log(f"Loaded {len(names)} selectable targets, including {LOCAL_SENTINEL}.")
        except Exception as exc:
            self.logger.write_exception(exc)
            self.append_log(f"ERROR: {exc}")

    def save_profile(self):
        # Merge dropdowns and target_info for saving
        for name, combo in self.vm_dropdowns.items():
            if name not in self.target_info:
                self.target_info[name] = {"vm_name": combo.get().strip(), "username": "", "password": "", "os_type": "windows"}
            else:
                self.target_info[name]["vm_name"] = combo.get().strip()
        payload = {
            "vcenter_server": self.vcenter_server.get().strip(),
            "ignore_ssl": self.ignore_ssl.get(),
            "targets": self.target_info,
            "last_verified": ""
        }
        path = self.profile_service.save_profile(self.profile_name.get().strip(), payload)
        self.append_log(f"Saved profile: {path}")

    def load_saved_profile(self):
        payload = self.profile_service.load_profile(self.profile_name.get().strip())
        self.vcenter_server.set(payload.get("vcenter_server", ""))
        self.ignore_ssl.set(bool(payload.get("ignore_ssl", True)))
        self.target_info = payload.get("targets", {name: {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"} for name in SYSTEM_COLUMNS})
        for name, combo in self.vm_dropdowns.items():
            combo.set(self.target_info.get(name, {}).get("vm_name", LOCAL_SENTINEL))
        self.append_log(f"Loaded profile: {self.profile_name.get().strip()}")

    def verify_profile(self):
        payload = self.profile_service.load_profile(self.profile_name.get().strip())
        service = self._service()
        service.connect()
        vm_names = [payload.get("targets", {}).get(name, {}).get("vm_name", "") for name in SYSTEM_COLUMNS if payload.get("targets", {}).get(name, {}).get("vm_name", "")]
        report = service.verify_vm_names(vm_names)
        service.disconnect()
        payload["last_verified"] = datetime.now().isoformat(timespec="seconds")
        self.profile_service.save_profile(self.profile_name.get().strip(), payload)
        for vm_name, info in report.items():
            self.append_log(f"{vm_name} | power={info['power_state']} | tools={info['tools_status']} | guest={info['guest_os']}")


class ChecklistFrame(BaseFrame):
    def __init__(self, parent, controller):
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
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=5)
        ttk.Label(row, text=label, width=16).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse", command=command).pack(side="left")

    def _template_status_row(self, parent, label, variable):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=22).pack(side="left")
        ttk.Label(row, textvariable=variable, anchor="w").pack(side="left", fill="x", expand=True)

    def refresh_template_status_panel(self):
        # Try to infer model from current audit path
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
        self.log_widget.insert("end", message + "\n")
        self.log_widget.see("end")
        self.logger.write(message)

    def set_status(self, message: str):
        self.status_var.set(message)

    def pick_source(self):
        path = filedialog.askopenfilename(title="Select main SBL workbook", filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")])
        if path:
            self.source_path.set(path)

    def pick_output(self):
        path = filedialog.asksaveasfilename(title="Save generated audit form as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if path:
            self.output_path.set(path)

    def load_baseline_template(self):
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
        print("Starting checklist generation...")
        self.generate_button.configure(state="disabled")
        if hasattr(self, "progress"):
            self.progress.configure(style="TProgressbar")
        self.progress_var.set(0)
        self.set_status("Status: Generating...")
        self.logger = FileLogger(LOGS_DIR, "checklist_generation")
        self.append_log(f"Starting checklist generation")
        self.append_log(f"Source workbook: {self.source_path.get()}")
        self.append_log(f"Output workbook: {self.output_path.get()}")
        self.append_log(f"Session log file: {self.logger.get_path()}")
        threading.Thread(target=self._generate_worker, daemon=True).start()

    def _generate_worker(self):
        print("In checklist generation worker thread...")
        try:
            source = self.source_path.get().strip()
            output = self.output_path.get().strip()
            if not source:
                raise ValueError("Select a source workbook first.")
            if not output:
                raise ValueError("Choose an output workbook path first.")

            self.after(0, lambda: self.progress_var.set(10))
            self.after(0, lambda: self.append_log("Loading source workbook..."))
            generator = ChecklistGeneratorService(source)
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
    def _init_target_info_table(self, parent):
        self.target_info_vars = {}
        self.target_info_dialog = None
        self.save_targets_btn = None
        # Place the button next to the profile selection
        btn = ttk.Button(parent, text="Show/Edit Target VM Info", command=self._show_target_info_dialog)
        btn.pack(side="left", padx=(8, 0))

    def _show_target_info_dialog(self):
        if self.target_info_dialog and tk.Toplevel.winfo_exists(self.target_info_dialog):
            self.target_info_dialog.lift()
            return
        self.target_info_dialog = tk.Toplevel(self)
        self.target_info_dialog.title("Edit Target VM Info")
        frame = ttk.Frame(self.target_info_dialog, padding=8)
        frame.pack(fill="both", expand=True)
        self.target_info_vars = {}
        header = ttk.Frame(frame)
        header.pack(fill="x")
        for col, text in enumerate(["Target", "VM Name", "Username", "Password", "OS Type"]):
            ttk.Label(header, text=text, width=14 if col else 18, font=("Segoe UI", 9, "bold")).grid(row=0, column=col)
        profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
        targets = profile.get("targets", {})
        for idx, target in enumerate(SYSTEM_COLUMNS):
            info = targets.get(target, {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"})
            row = ttk.Frame(frame)
            row.pack(fill="x")
            ttk.Label(row, text=target, width=18).grid(row=0, column=0)
            vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
            user_var = tk.StringVar(value=info.get("username", ""))
            pass_var = tk.StringVar(value=info.get("password", ""))
            os_var = tk.StringVar(value=info.get("os_type", "windows"))
            ttk.Entry(row, textvariable=vm_var, width=16).grid(row=0, column=1)
            ttk.Entry(row, textvariable=user_var, width=14).grid(row=0, column=2)
            ttk.Entry(row, textvariable=pass_var, width=14, show="*").grid(row=0, column=3)
            ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=10, state="readonly").grid(row=0, column=4)
            self.target_info_vars[target] = (vm_var, user_var, pass_var, os_var)
        self.save_targets_btn = ttk.Button(frame, text="Save Target Info to Profile", command=self._save_target_info)
        self.save_targets_btn.pack(pady=8)
        self.target_info_dialog.transient(self)
        self.target_info_dialog.grab_set()
        self.target_info_dialog.wait_window()


    def _save_target_info(self):
        # Save edited info back to profile
        profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
        targets = profile.get("targets", {})
        for target, (vm_var, user_var, pass_var, os_var) in self.target_info_vars.items():
            targets[target] = {
                "vm_name": vm_var.get().strip(),
                "username": user_var.get().strip(),
                "password": pass_var.get().strip(),
                "os_type": os_var.get().strip() or "windows"
            }
        profile["targets"] = targets
        self.profile_service.save_profile(self.profile_name.get().strip(), profile)
        self.append_log("Saved target VM info to profile.")
    def __init__(self, parent, controller):
        super().__init__(parent, controller)
        self._compact_label_width = 16
        self.profile_service = VMProfileService()
        self.style = ttk.Style()
        self.style.configure("Bold.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
        default_audit = AUDIT_CHECKLIST_DIR / "TG_Audit_Checklist_test.xlsx"
        default_results = AUDIT_RESULTS_DIR / "testing_sbl_RESULTS.xlsx"
        self.audit_path = tk.StringVar(value=str(default_audit))
        self.output_path = tk.StringVar(value=str(default_results))
        self.profile_name = tk.StringVar()
        self.profile_options = self._get_profile_options()
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
        creds = ttk.LabelFrame(self, text="Profile and Credentials", padding=8)
        creds.pack(fill="x", pady=(0, 8))
        # Dropdown for VM profiles
        profile_row = ttk.Frame(creds)
        profile_row.pack(fill="x", pady=2)
        ttk.Label(profile_row, text="VM profile", width=self._compact_label_width).pack(side="left")
        self.profile_dropdown = ttk.Combobox(profile_row, textvariable=self.profile_name, state="readonly", values=self.profile_options)
        self.profile_dropdown.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(profile_row, text="Load Profile", command=self.load_profile_defaults).pack(side="left")
        # Removed duplicate call to _init_target_info_table
    
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
    def _get_profile_options(self):
        profiles_dir = PROFILES_DIR
        if not profiles_dir.exists():
            return []
        return [f.stem for f in profiles_dir.glob("*.json") if f.is_file()]
    def _path_row(self, parent, label, variable, command):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=self._compact_label_width).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse", command=command).pack(side="left")

    def _entry_row(self, parent, label, variable, show=None, button=None, label_width=None):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        width = self._compact_label_width if label_width is None else label_width
        ttk.Label(row, text=label, width=width).pack(side="left")
        ttk.Entry(row, textvariable=variable, show=show).pack(side="left", fill="x", expand=True, padx=(0, 8))
        if button:
            ttk.Button(row, text=button[0], command=button[1]).pack(side="left")

    def _entry_pair_row(self, parent, label1, var1, label2, var2, show1=None, show2=None):
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
        if visible:
            if not self.ssh_section.winfo_ismapped():
                self.ssh_section.pack(fill="x", pady=(4, 0))
        else:
            if self.ssh_section.winfo_ismapped():
                self.ssh_section.pack_forget()

    def _toggle_ssh_section(self):
        self._on_connection_mode_changed()

    def _on_connection_mode_changed(self, *_):
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
        self.log.insert("end", message + "\n")
        self.log.see("end")
        self.logger.write(message)

    def set_status(self, message: str):
        self.status_var.set(message)

    @staticmethod
    def _parse_int(value: str, default: int) -> int:
        try:
            return int(normalize_text(value))
        except Exception:
            return default

    def load_profile_defaults(self):
        payload = self.profile_service.load_profile(self.profile_name.get().strip())
        self.vcenter_server.set(payload.get("vcenter_server", ""))
        self.append_log(f"Loaded profile defaults from {self.profile_name.get().strip()}")
        # Optionally update other fields if needed

    @staticmethod
    def _coerce_local_only_profile(vm_profile: Dict[str, Any]) -> Dict[str, Any]:
        targets = vm_profile.setdefault("targets", {})
        for target_name in SYSTEM_COLUMNS:
            target_entry = targets.setdefault(target_name, {"vm_name": "", "os_type": "windows"})
            target_entry["vm_name"] = LOCAL_SENTINEL
            target_entry["os_type"] = "windows"
        return vm_profile

    def pick_audit(self):
        path = filedialog.askopenfilename(title="Select audit workbook", filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")])
        if path:
            self.audit_path.set(path)

    def pick_output(self):
        path = filedialog.asksaveasfilename(title="Save audited workbook as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if path:
            self.output_path.set(path)

    def start_audit(self):
        self.run_button.configure(state="disabled")
        self.probe_button.configure(state="disabled")
        self.progress_var.set(0)
        self.set_status("Status: Running...")
        self.logger = FileLogger(LOGS_DIR, "audit_run")
        self.append_log(f"Opening workbook: {self.audit_path.get()}")
        self.append_log(f"Session log file: {self.logger.get_path()}")
        threading.Thread(target=self._worker, daemon=True).start()

    def start_probe(self):
        self.run_button.configure(state="disabled")
        self.probe_button.configure(state="disabled")
        self.set_status("Status: Probing remote connection...")
        self.logger = FileLogger(LOGS_DIR, "audit_probe")
        self.append_log(f"Probe log file: {self.logger.get_path()}")
        self.append_log("Starting pre-audit connection probe...")
        threading.Thread(target=self._probe_worker, daemon=True).start()

    def _probe_worker(self):
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
                mapped_hosts = [
                    normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
                    for name in SYSTEM_COLUMNS
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
                    mapped_vm_names = [
                        normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
                        for name in SYSTEM_COLUMNS
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
            self.after(0, lambda: self.probe_button.configure(state="normal"))

    def _worker(self):
        try:
            template_service = TemplateAssetService()
            workbook_service = AuditWorkbookService(self.audit_path.get().strip())
            if workbook_service.repaired_file_path:
                self.after(0, lambda: self.append_log(f"Recovered workbook during load: {workbook_service.repaired_file_path}"))
            workbook_service.detect_header_row()
            workbook_service.build_column_map()
            rows = workbook_service.iter_audit_rows()
            self.after(0, lambda: self.append_log(f"Detected format with {workbook_service.sbl_build_header} and {workbook_service.audit_header}. Rows to process: {len(rows)}"))
            processed = {"count": 0}
            def logger(msg: str):
                if msg.startswith("Scanning "):
                    processed["count"] += 1
                total = max(1, len(rows))
                self.after(0, lambda p=min(100, (processed['count'] / total) * 100): self.progress_var.set(p))
                self.after(0, lambda m=msg: self.append_log(m))
            vm_profile = self.profile_service.load_profile(self.profile_name.get().strip())
            vcenter_server = self.vcenter_server.get().strip()
            mode = normalize_text(self.connection_mode.get()).lower()
            if self.local_only.get():
                vm_profile = self._coerce_local_only_profile(vm_profile)
                self.after(0, lambda: self.append_log("Local-only scan enabled; all targets set to __LOCAL__."))
            elif mode != "ssh tunnel" and not vcenter_server:
                vm_profile = self._coerce_local_only_profile(vm_profile)
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
            )
            results = engine.run()
            workbook_service.save_as(self.output_path.get().strip())
            sbl_model = _get_sbl_model_from_workbook(self.audit_path.get().strip())
            latest_sbl = template_service.update_latest_sbl(self.output_path.get().strip())
            latest_master = template_service.snapshot_current_master_to_latest(sbl_model=sbl_model)
            json_path = JsonExportService.write_result_json(Path(self.output_path.get()).stem, {"audit_workbook": self.audit_path.get(), "saved_workbook": self.output_path.get(), "profile_name": self.profile_name.get().strip(), "generated_at": datetime.now().isoformat(timespec="seconds"), "results": [asdict(result) for result in results]})
            summary = self.build_summary(results)
            self.after(0, lambda: self.append_log(summary))
            self.after(0, lambda: self.append_log(f"Saved audited workbook: {self.output_path.get()}"))
            self.after(0, lambda: self.append_log(f"Result JSON written: {json_path}"))
            self.after(0, lambda: self.append_log(f"Updated latest SBL snapshot: {latest_sbl}"))
            self.after(0, lambda: self.append_log(f"Updated latest master software list snapshot: {latest_master}"))
            self.after(0, lambda: self.progress_var.set(100))
            self.after(0, lambda: self.set_status("Status: Complete"))
        except Exception as exc:
            self.logger.write_exception(exc)
            self.after(0, lambda: self.append_log(f"ERROR: {exc}"))
            self.after(0, lambda: self.set_status("Status: Failed"))
        finally:
            self.after(0, lambda: self.run_button.configure(state="normal"))
            self.after(0, lambda: self.probe_button.configure(state="normal"))

    @staticmethod
    def build_summary(results: List[ScanResult]) -> str:
        passed = sum(1 for r in results if r.status == "PASS")
        failed = sum(1 for r in results if r.status == "FAIL")
        warned = sum(1 for r in results if r.status == "WARN")
        return f"Summary | Total target checks: {len(results)} | PASS: {passed} | FAIL: {failed} | WARN: {warned}"


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
