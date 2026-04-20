"""Audit workbook parsing and checklist generation services."""

import copy
import json
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import pandas as pd
from openpyxl import Workbook, load_workbook
from openpyxl.cell.cell import MergedCell
from openpyxl.styles import PatternFill

from config import TEMPLATES_DIR
from models import AuditRow, WorkbookSchema
from services.file_logger import FileLogger
from services.utils import (
    derive_import_target_columns,
    default_target_columns,
    detect_header_row_index,
    detect_target_columns,
    detect_workbook_format,
    ensure_project_structure,
    extract_path_from_version_location,
    infer_build_type,
    is_known_non_target_header,
    is_x_mark,
    normalize_header,
    normalize_text,
    normalize_version,
    parse_build_and_audit_headers,
    pick_record_value,
    timestamp_str,
    today_str,
)


# Helper functions for workbook repair and example creation
def _max_workbook_style_index(file_path: str) -> Optional[int]:
    """Internal helper for max workbook style index."""
    try:
        with zipfile.ZipFile(file_path, "r") as archive:
            style_content = archive.read("xl/styles.xml")
            root = ET.fromstring(style_content)
            namespace = {"ss": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            cell_xfs = root.find("ss:cellXfs", namespace)
            if cell_xfs is not None:
                return len(list(cell_xfs)) - 1
    except Exception:
        pass
    return None


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


def read_software_list_universal_rows(
    file_path: str,
    debug_logger: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Read heterogeneous SBL-like sources and normalize rows for import/checklist pipelines."""
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
        version_col = _select_column(
            columns,
            [
                r"version\s*locations?",
                r"\bversion\s*location\b",
                r"\bverification\s*steps?\b",
                r"\bverification\b",
                r"\blocation\b",
                r"\bpath\b",
                r"\brule\b",
            ],
        )
        displayed_col = _select_column(columns, [r"displayed\s*name", r"display\s*name"])
        id_col = _select_column(columns, [r"cm\s*tool\s*id\s*number", r"\btool\s*id\b", r"\bid\b"])

        if not software_col:
            _dbg("software_component column not found in dataframe candidate")
            return []
        if not version_col:
            _dbg("version_locations column not found in dataframe candidate")
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
            if not software_component or software_component.lower() == "nan":
                continue
            displayed_name = normalize_text(row.get(displayed_src, "")) if displayed_src else software_component
            expected_version = normalize_text(row.get(current_src, "")) if current_src else ""
            version_locations = extract_path_from_version_location(row.get(version_src, "")) if version_src else ""
            if expected_version.lower() == "nan":
                expected_version = ""
            if version_locations.lower() in ("", "nan", "version locations", "version location"):
                continue
            cm_id = normalize_text(row.get(id_src, "")) if id_src else ""
            if cm_id.lower() == "nan":
                cm_id = ""

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

    def _score_rows(rows: List[Dict[str, Any]]) -> int:
        """Score parsed rows: prefer candidates with actionable VERSION LOCATIONS rules."""
        non_empty_locations = 0
        known_rule_rows = 0
        placeholder_locations = 0
        for row in rows:
            version_locations = normalize_text(row.get("VERSION LOCATIONS", ""))
            if not version_locations:
                continue
            non_empty_locations += 1
            rule, _ = VersionRuleResolver.detect_rule(version_locations)
            if rule != "unknown":
                known_rule_rows += 1
            if version_locations.lower() in ("version locations", "version location"):
                placeholder_locations += 1
        return (known_rule_rows * 10) + non_empty_locations - (placeholder_locations * 10)

    if format_type == "excel":
        primary_header = detect_header_row_index(file_path, format_type)
        header_candidates: List[int] = [primary_header, *list(range(0, 21))]
        _dbg(f"excel_header_candidates={header_candidates}")
        seen: set = set()
        best_rows: List[Dict[str, Any]] = []
        best_header_index: Optional[int] = None
        best_score = -1
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
                score = _score_rows(normalized_rows)
                _dbg(f"header_index={header_index} candidate_rows={len(normalized_rows)} score={score}")
                if score > best_score:
                    best_score = score
                    best_rows = normalized_rows
                    best_header_index = header_index
        if best_rows:
            _dbg(f"selected_header_index={best_header_index}")
            return best_rows
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


def _create_mock_audit_checklist_workbook(file_path: Path) -> None:
    """Create a mock audit checklist workbook."""
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


def _create_mock_audit_results_workbook(file_path: Path) -> None:
    """Create a mock audit results workbook."""
    baseline_template = TEMPLATES_DIR / "sbl_template_baseline_GEOINT_FD.xlsx"
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


def _create_example_audit_checklist_workbook(file_path: Path) -> None:
    """Backward-compatible wrapper for old example seed naming."""
    _create_mock_audit_checklist_workbook(file_path)


def _create_example_audit_results_workbook(file_path: Path) -> None:
    """Backward-compatible wrapper for old example seed naming."""
    _create_mock_audit_results_workbook(file_path)


# Version rule and path metadata detection
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
        if "START MENU" in upper:
            return "manual_steps", {"instructions": version_location}
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


# Pastefill colors for audit results
PASS_FILL = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
FAIL_FILL = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
WARN_FILL = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")


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

    def _extract_build_identifier(self) -> str:
        """Extract a build identifier from workbook values (e.g., 'CGW-L-N 2.0.2.2')."""
        if self.header_row_index is None or not self.column_map:
            return ""

        software_col = self.column_map.get("SOFTWARE COMPONENT")
        if not software_col:
            return ""

        candidate_headers: List[str] = []
        for header in (self.sbl_build_header, self.audit_header, self.current_ci_header):
            if header and header in self.column_map:
                candidate_headers.append(header)

        # Match values containing a version-like suffix and leading build text.
        build_pattern = re.compile(r"[A-Za-z]+[-_A-Za-z0-9\s]*\d+\.\d+(?:\.\d+){0,3}")
        max_row = min(self.worksheet.max_row, (self.header_row_index or 1) + 20)
        for row_idx in range((self.header_row_index or 1) + 1, max_row + 1):
            software_component = normalize_text(self.worksheet.cell(row_idx, software_col).value)
            if not software_component:
                continue
            for header in candidate_headers:
                value = normalize_text(self.worksheet.cell(row_idx, self.column_map[header]).value)
                if value and build_pattern.search(value):
                    return value
        return ""

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
        if legacy_present:
            return legacy_present
        return default_target_columns()

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
            has_version_loc = (
                "VERSION LOCATION" in normalized
                or "VERSION LOCATIONS" in normalized
                or any("VERIFICATION" in header for header in normalized)
            )
            if has_software and has_current_ci and has_version_loc:
                self.header_row_index = row_idx
                return row_idx
        raise ValueError("Could not find header row with SOFTWARE COMPONENT, CURRENT CI VERSION, and VERSION LOCATION(S)/VERIFICATION column.")

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
            (
                header
                for header in raw_headers
                if normalize_header(header) in ("VERSION LOCATION", "VERSION LOCATIONS")
                or "VERIFICATION" in normalize_header(header)
            ),
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
        extracted_build = self._extract_build_identifier()
        if extracted_build:
            self.build_type = extracted_build
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

    def detect_header_row(self, search_limit: int = 20) -> int:
        """Detect the header row in generated/imported worksheets."""
        print("Detecting header row...")
        if self.header_row_index is not None:
            return self.header_row_index
        for row_idx in range(1, min(search_limit, self.worksheet.max_row) + 1):
            print(f"Checking row {row_idx} for headers...")
            row_headers = [
                normalize_header(self.worksheet.cell(row=row_idx, column=col_idx).value)
                for col_idx in range(1, self.worksheet.max_column + 1)
            ]
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

        for col_idx in range(1, self.worksheet.max_column + 1):
            print(f"Reading header from column {col_idx}...")
            value = self.worksheet.cell(self.header_row_index, col_idx).value
            text = normalize_text(value)
            print(f"Column {col_idx}: raw header value = {repr(value)}, normalized = {repr(text)}")
            if text:
                headers_by_name[text] = col_idx
                raw_headers.append(text)
                print(f"Added header '{text}' to column map with index {col_idx}.")

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
                for merged_range in self.worksheet.merged_cells.ranges:
                    print(f"Checking if cell {vl_cell.coordinate} is in merged range {merged_range}...")
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


class ChecklistGeneratorService:
    """Generate workbook audit forms from Excel/JSON/CSV checklist sources."""

    def __init__(self, source_path: str):
        """Initialize the ChecklistGeneratorService instance."""
        self.source_path = source_path
        self.template_service = None  # Import here to avoid circular dependency
        self.normalized_source_path = source_path
        source_format = detect_workbook_format(source_path)
        if source_format != "excel":
            with tempfile.NamedTemporaryFile(prefix="auditmatic_import_", suffix=".xlsx", delete=False) as temp_file:
                normalized_path = temp_file.name
            from services.template_service import TemplateAssetService
            self.template_service = TemplateAssetService()
            self.template_service.import_list_to_sbl_workbook(source_path, normalized_path)
            self.normalized_source_path = normalized_path
        self.source_workbook = load_workbook(self.normalized_source_path)
        self.source_ws = self.source_workbook.active
        print(f"Initialized ChecklistGeneratorService with source: {source_path} (normalized={self.normalized_source_path})")

    @staticmethod
    def _match_header(headers_by_name: Dict[str, int], candidates: List[str]) -> Optional[str]:
        """Return the first header key that contains one of the candidate tokens."""
        for candidate in candidates:
            token = normalize_header(candidate)
            for header_name in headers_by_name.keys():
                if token in normalize_header(header_name):
                    return header_name
        return None

    def _detect_header_row_tolerant(self, worksheet, search_limit: int = 30) -> int:
        """Detect header row for non-standard SBL-like sheets with relaxed matching."""
        max_search = min(search_limit, worksheet.max_row)
        for row_idx in range(1, max_search + 1):
            headers = [
                normalize_header(worksheet.cell(row=row_idx, column=col_idx).value)
                for col_idx in range(1, worksheet.max_column + 1)
            ]
            has_software = any(
                ("SOFTWARE COMPONENT" in header) or ("COMPONENT" in header) or ("SOFTWARE" in header)
                for header in headers
            )
            has_version_location = any(
                ("VERSION LOCATION" in header) or ("VERSION LOCATIONS" in header) or ("LOCATION" in header)
                for header in headers
            )
            has_current_version = any(
                ("CURRENT CI VERSION" in header) or ("CURRENT VERSION" in header) or ("EXPECTED VERSION" in header)
                for header in headers
            )
            if has_software and (has_version_location or has_current_version):
                return row_idx
        return 1

    def _build_header_map(self, worksheet, header_row: int) -> Dict[str, int]:
        """Build a raw header-to-column index map for the selected header row."""
        headers_by_name: Dict[str, int] = {}
        for col_idx in range(1, worksheet.max_column + 1):
            text = normalize_text(worksheet.cell(header_row, col_idx).value)
            if text and text not in headers_by_name:
                headers_by_name[text] = col_idx
        return headers_by_name

    def preview_source_mapping(self) -> Dict[str, Any]:
        """Preview source parsing, mapped headers, and sample rows before generation."""
        header_row = self._detect_header_row_tolerant(self.source_ws)
        headers_by_name = self._build_header_map(self.source_ws, header_row)
        software_header = self._match_header(headers_by_name, ["SOFTWARE COMPONENT", "COMPONENT", "SOFTWARE", "NAME"])
        current_header = self._match_header(headers_by_name, ["CURRENT CI VERSION", "CURRENT VERSION", "EXPECTED VERSION", "VERSION"])
        location_header = self._match_header(headers_by_name, ["VERSION LOCATIONS", "VERSION LOCATION", "LOCATION", "PATH", "RULE"])
        sbl_header = self._match_header(headers_by_name, ["SBL BUILD", "SBL BUILD VERSION", "BASELINE VERSION", "BUILD VERSION"])
        audit_header = self._match_header(headers_by_name, ["AUDIT", "AUDIT RESULT", "VERSION STATUS", "STATUS"])

        rows = read_software_list_universal_rows(self.source_path)
        sample_components = [normalize_text(row.get("SOFTWARE COMPONENT", "")) for row in rows[:5]]
        sample_components = [value for value in sample_components if value]
        target_columns = [name for name in headers_by_name.keys() if not is_known_non_target_header(name)]

        return {
            "source_path": self.source_path,
            "normalized_source_path": self.normalized_source_path,
            "header_row": header_row,
            "mapped_headers": {
                "software_component": software_header or "",
                "current_version": current_header or "",
                "version_locations": location_header or "",
                "sbl_build": sbl_header or "",
                "audit": audit_header or "",
            },
            "target_columns": target_columns,
            "row_count": len(rows),
            "sample_components": sample_components,
        }

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
        header_row = self._detect_header_row_tolerant(ws_out)
        headers_by_name = self._build_header_map(ws_out, header_row)
        software_header = self._match_header(headers_by_name, ["SOFTWARE COMPONENT", "COMPONENT", "SOFTWARE", "NAME"])
        audit_header = self._match_header(headers_by_name, ["AUDIT", "AUDIT RESULT", "VERSION STATUS", "STATUS"])

        if not audit_header:
            audit_col = ws_out.max_column + 1
            ws_out.cell(header_row, audit_col).value = "AUDIT"
            audit_header = "AUDIT"
            headers_by_name[audit_header] = audit_col
        else:
            audit_col = headers_by_name[audit_header]

        print(f"Detected header row at index: {header_row}")
        print(f"Header map: {headers_by_name}, audit header: {audit_header}")

        data_start_row = header_row + 1
        software_col = headers_by_name.get(software_header) if software_header else None
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
        rows: List[Dict[str, Any]] = []
        target_columns: List[str] = []
        build_type = "unknown"
        try:
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
            target_columns = list(service.target_columns)
            build_type = service.build_type
        except Exception:
            fallback_rows = read_software_list_universal_rows(self.source_path)
            rows = [
                {
                    "software_component": normalize_text(row.get("SOFTWARE COMPONENT", "")),
                    "current_ci_version": normalize_text(row.get("CURRENT CI VERSION", "")),
                    "sbl_build_version": normalize_text(row.get("SBL BUILD", "")),
                    "audit_value": normalize_text(row.get("AUDIT", "")),
                    "target_vms": row.get("target_vms", {}) if isinstance(row.get("target_vms", {}), dict) else {},
                    "version_locations": normalize_text(row.get("VERSION LOCATIONS", "")),
                }
                for row in fallback_rows
            ]
            target_columns = derive_import_target_columns(fallback_rows)
        return {
            "source_workbook": self.source_path,
            "normalized_source_workbook": self.normalized_source_path,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target_columns": target_columns,
            "build_type": build_type,
            "rows": rows,
        }
