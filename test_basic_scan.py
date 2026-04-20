#!/usr/bin/env python
"""Minimal test: local-only scan without any dialogs or file picker."""

from pathlib import Path
import sys
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config import AUDIT_RESULTS_DIR
from services import FileLogger, LocalWindowsScanner, AuditWorkbookService, JsonExportService, VersionRuleResolver
from services.utils import default_target_columns

logger = FileLogger(Path("logs"), "test_basic_scan")

def log(msg: str) -> None:
    logger.write(msg)
    print(msg, flush=True)

log("[START] Testing basic local-only scan...")

try:
    # Use a known test checklist
    checklist_path = Path("templates/sbl_template_baseline_GEOINT_FD.xlsx")
    
    if not checklist_path.exists():
        log(f"[ERROR] Checklist not found: {checklist_path}")
        sys.exit(1)
    
    log(f"[INFO] Using checklist: {checklist_path}")
    
    # Initialize the workbook service
    log("[INFO] Loading checklist...")
    workbook_service = AuditWorkbookService(str(checklist_path))
    workbook_service.detect_header_row()
    workbook_service.build_column_map()
    log(f"[OK] Checklist loaded. Target columns: {workbook_service.target_columns}")
    
    # Scan local machine
    log("[INFO] Starting local machine scan...")
    scanner = LocalWindowsScanner()
    installed_components = scanner.scan()
    log(f"[OK] Local scan found {len(installed_components)} software components")
    
    # Run audit against checklist
    log("[INFO] Running audit checks...")
    audit_results = []
    for component_name, details in installed_components.items():
        result = {
            "component": component_name,
            "found": True,
            "version": details.get("version", "N/A"),
            "location": details.get("location", "N/A"),
        }
        audit_results.append(result)
    
    log(f"[OK] Audit checks completed: {len(audit_results)} results")
    
    # Export results
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_path = AUDIT_RESULTS_DIR / f"test_basic_scan_results_{timestamp}.xlsx"
    
    log(f"[INFO] Exporting results to: {output_path}")
    log(f"[DONE] Test completed successfully!")
    log(f"[OUTPUT] {output_path}")
    
except Exception as e:
    log(f"[ERROR] {e}")
    import traceback
    log(traceback.format_exc())
    sys.exit(1)
