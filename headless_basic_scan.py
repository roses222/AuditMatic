#!/usr/bin/env python
"""Headless basic scan: local-only audit without any UI or dialogs."""

from pathlib import Path
import sys
import copy
from datetime import datetime
from dataclasses import asdict
import uuid

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config import AUDIT_RESULTS_DIR, LOCAL_SENTINEL
from services import (
    AuditEngine, AuditWorkbookService, FileLogger, JsonExportService,
    VersionRuleResolver
)
from services.template_service import _get_sbl_model_from_workbook

# Create a logger that captures debug output to file only
logger = FileLogger(Path("logs"), "headless_basic_scan")
debug_file = open(str(Path("logs") / "headless_basic_scan_debug.log"), "w", encoding="utf-8", buffering=1)

def log_user(msg: str) -> None:
    """Write message to user (console + user log)."""
    logger.write(msg)
    print(msg, flush=True)

def log_debug(msg: str) -> None:
    """Write debug message to debug log only, not console."""
    debug_file.write(msg + "\n")
    debug_file.flush()

def main():
    """Run headless local-only basic audit."""
    try:
        log_user("")
        log_user("=" * 70)
        log_user("AuditMatic Headless Basic Scan")
        log_user("=" * 70)
        
        # Use the default SBL template
        checklist_path = Path("templates/sbl_template_baseline_GEOINT_FD.xlsx")
        
        if not checklist_path.exists():
            log_user(f"[ERROR] Checklist not found: {checklist_path}")
            return 1
        
        # Load workbook
        log_user(f"[1/4] Loading checklist...")
        log_debug(f"Checklist: {checklist_path}")
        workbook_service = AuditWorkbookService(str(checklist_path))
        workbook_service.detect_header_row()
        workbook_service.build_column_map()
        target_columns = workbook_service.target_columns or []
        log_user(f"      Found {len(target_columns)} targets: {', '.join(target_columns[:3])}{'...' if len(target_columns) > 3 else ''}")
        
        # Build profile for local-only scan
        vm_profile = {
            "profile_name": "headless_basic_scan",
            "build_type": workbook_service.build_type,
            "target_schema": {
                "source_path": str(checklist_path),
                "target_columns": list(target_columns),
                "build_type": workbook_service.build_type,
            },
            "targets": {
                target: {
                    "vm_name": LOCAL_SENTINEL,  # Local machine only
                    "username": "",
                    "password": "",
                    "os_type": "windows",
                }
                for target in target_columns
            },
        }
        
        # Run local scan only
        log_user(f"[2/4] Scanning local machine...")
        log_debug("Initializing audit engine")
        
        engine = AuditEngine(
            workbook_service,
            log_debug,  # Use debug logger for engine output
            copy.deepcopy(vm_profile),
            {},  # No vCenter credentials
            {},  # No guest credentials
            connection_mode="local",
            ssh_config={},
            ssh_fallback_enabled=False,
        )
        
        # Run audit with output suppression
        log_debug("Running audit checks")
        
        # Suppress the noisy engine print output during scan
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        try:
            # Redirect to null file
            null_file = open('/dev/null', 'w') if sys.platform != 'win32' else open('nul', 'w')
            sys.stdout = null_file
            sys.stderr = null_file
            
            results = engine.run()
        finally:
            sys.stdout = original_stdout
            sys.stderr = original_stderr
            try:
                null_file.close()
            except:
                pass
        
        log_user(f"      Completed audit checks ({len(results)} items)")
        
        # Capture registry snapshot
        try:
            job_id = str(uuid.uuid4())
            log_debug("Capturing registry snapshot")
            registry_snapshot = engine.local_scanner.capture_registry_snapshot()
            registry_snapshot["job_id"] = job_id
            registry_snapshot_path = JsonExportService.write_registry_snapshot_json(
                "audit_scan", registry_snapshot
            )
            log_debug(f"Registry snapshot: {registry_snapshot_path}")
        except Exception as e:
            log_debug(f"Registry snapshot failed: {e}")
            job_id = str(uuid.uuid4())
        
        # Count results
        passed = sum(1 for r in results if getattr(r, "status", "") == "PASS")
        failed = sum(1 for r in results if getattr(r, "status", "") == "FAIL")
        warned = sum(1 for r in results if getattr(r, "status", "") == "WARN")
        
        # Save workbook
        log_user(f"[3/4] Saving results...")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        output_path = AUDIT_RESULTS_DIR / f"headless_basic_scan_{timestamp}.xlsx"
        workbook_service.save_as(str(output_path))
        log_debug(f"Workbook saved: {output_path}")
        
        # Write result JSON
        result_json_path = JsonExportService.write_result_json(
            "audit_scan",
            {
                "audit_mode": "headless_basic_scan",
                "audit_workbook": str(checklist_path),
                "saved_workbook": str(output_path),
                "profile_name": "headless_basic_scan",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "results": [asdict(result) for result in results],
            },
        )
        log_debug(f"Result JSON: {result_json_path}")
        
        # Write scan job JSON
        parsed_rows = []
        for row in workbook_service.iter_audit_rows():
            if not row.software_component:
                continue
            rule, _ = VersionRuleResolver.detect_rule(row.version_locations)
            parsed_rows.append({
                "worksheet_row": row.row_index,
                "software_component": row.software_component,
                "sbl_build_version": row.sbl_build_version,
                "version_locations": row.version_locations,
                "rule": rule,
            })
        
        scan_job_path = JsonExportService.write_scan_job_json(
            "audit_scan",
            {
                "job_id": job_id,
                "status": "completed",
                "audit_mode": "headless_basic_scan",
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "sbl_file": {
                    "name": checklist_path.name,
                    "path": str(checklist_path),
                    "sbl_model": _get_sbl_model_from_workbook(str(checklist_path)),
                },
                "settings": {
                    "profile_name": "headless_basic_scan",
                    "connection_mode": "local",
                    "local_only": True,
                },
                "sbl_parse": {
                    "target_columns": list(target_columns),
                    "row_count": len(parsed_rows),
                },
                "results": [asdict(result) for result in results],
            },
        )
        log_debug(f"Scan job JSON: {scan_job_path}")
        
        log_user(f"[4/4] Audit complete!")
        log_user("")
        log_user("RESULTS:")
        log_user(f"  Total checks: {len(results)}")
        log_user(f"  [PASS]:  {passed}")
        log_user(f"  [FAIL]:  {failed}")  
        log_user(f"  [WARN]:  {warned}")
        log_user("")
        log_user("OUTPUT FILES:")
        log_user(f"  Workbook:     {output_path.name}")
        log_user(f"  Result JSON:  {Path(result_json_path).name}")
        log_user(f"  Scan Job:     {Path(scan_job_path).name}")
        log_user("")
        log_user(f"Detailed log: {logger.get_path()}")
        log_user("=" * 70)
        
        return 0
        
    except Exception as e:
        log_user(f"[ERROR] {e}")
        log_debug(f"Exception: {e}")
        import traceback
        log_debug(traceback.format_exc())
        return 1
    finally:
        debug_file.close()

if __name__ == "__main__":
    sys.exit(main())
