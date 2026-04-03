from pathlib import Path
from datetime import datetime

from openpyxl import Workbook

from sbl_audit_gui_v_2000 import (
    SYSTEM_COLUMNS,
    LOCAL_SENTINEL,
    AuditWorkbookService,
    AuditEngine,
    JsonExportService,
    TemplateAssetService,
)


def build_minimal_audit_workbook(path: Path) -> None:
    wb = Workbook()
    ws = wb.active
    headers = [
        "SOFTWARE COMPONENT",
        "CURRENT CI VERSION",
        "SBL BUILD TEST",
        "AUDIT TEST",
        *SYSTEM_COLUMNS,
        "VERSION LOCATIONS",
    ]
    ws.append(headers)

    row = [
        "Python",
        "3.11.8",
        "3.11.8",
        "",
        "X",  # ArcGIS_WebAdaptor -> LOCAL target for this test
        "",
        "",
        "",
        "",
        "",
        "PROGRAMS AND FEATURES",
    ]
    ws.append(row)
    wb.save(path)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    test_input = root / "tests" / "_audit_smoke_input.xlsx"
    test_output = root / "Audit Results" / f"_audit_smoke_output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"

    print(f"AUDIT_TEST_INPUT={test_input}")
    print(f"AUDIT_TEST_OUTPUT={test_output}")

    build_minimal_audit_workbook(test_input)

    workbook_service = AuditWorkbookService(str(test_input))
    workbook_service.detect_header_row()
    workbook_service.build_column_map()

    logs = []

    def logger(msg: str):
        logs.append(msg)
        print(msg)

    vm_profile = {
        "targets": {name: {"vm_name": LOCAL_SENTINEL, "os_type": "windows"} for name in SYSTEM_COLUMNS}
    }

    engine = AuditEngine(
        workbook_service=workbook_service,
        logger=logger,
        vm_profile=vm_profile,
        vcenter_creds={"server": "", "username": "", "password": ""},
        guest_creds={"username": "", "password": ""},
    )

    results = engine.run()
    workbook_service.save_as(str(test_output))

    template_service = TemplateAssetService()
    latest_sbl = template_service.update_latest_sbl(str(test_output))
    latest_master = template_service.snapshot_current_master_to_latest()

    result_payload = {
        "audit_workbook": str(test_input),
        "saved_workbook": str(test_output),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "results": [
            {
                "software_component": r.software_component,
                "target_name": r.target_name,
                "expected_version": r.expected_version,
                "found_version": r.found_version,
                "status": r.status,
                "details": r.details,
                "worksheet_row": r.worksheet_row,
                "audit_text": r.audit_text,
            }
            for r in results
        ],
    }
    result_json = JsonExportService.write_result_json("audit_smoke", result_payload)

    print(f"RESULTS_COUNT={len(results)}")
    print(f"RESULT_JSON={result_json}")
    print(f"LATEST_SBL={latest_sbl}")
    print(f"LATEST_MASTER_JSON={latest_master}")
    print("AUDIT_SMOKE_TEST=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
