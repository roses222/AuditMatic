"""
AuditMatic JSON Export Service

Utilities for exporting audit checklists, results, and scan jobs to JSON format.
"""

import json
from pathlib import Path
from typing import Any, Dict

from config import JSON_CHECKLIST_DIR, JSON_RESULTS_DIR, JSON_REGISTRY_SNAPSHOTS_DIR, JSON_SCAN_JOBS_DIR
from services.utils import timestamp_str, ensure_project_structure


class JsonExportService:
    """Service for writing JSON payloads to standardized output directories."""

    @staticmethod
    def write_checklist_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write checklist JSON to json_checklist directory."""
        ensure_project_structure()
        output = JSON_CHECKLIST_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_result_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write result JSON to json_result directory."""
        ensure_project_structure()
        output = JSON_RESULTS_DIR / f"{base_name}_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_registry_snapshot_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write registry snapshot JSON to registry_snapshots directory."""
        ensure_project_structure()
        output = JSON_REGISTRY_SNAPSHOTS_DIR / f"{base_name}_registry_snapshot_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)

    @staticmethod
    def write_scan_job_json(base_name: str, payload: Dict[str, Any]) -> str:
        """Write scan job JSON to scan_jobs directory."""
        ensure_project_structure()
        output = JSON_SCAN_JOBS_DIR / f"{base_name}_scan_job_{timestamp_str()}.json"
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(output)
