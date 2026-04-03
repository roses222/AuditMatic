from pathlib import Path
import traceback

from sbl_audit_gui_v_2000 import ChecklistGeneratorService, AuditWorkbookService


def main() -> int:
    root = Path(__file__).resolve().parent
    source = root / "testing_sbl.xlsx"
    output = root / "Audit Checklist" / "smoke_test_output_TG.xlsx"

    print(f"SOURCE={source}")
    print(f"OUTPUT={output}")

    if not source.exists():
        print("ERROR: source workbook does not exist")
        return 2

    try:
        generator = ChecklistGeneratorService(str(source))
        generator.generate_audit_form(str(output))

        payload = generator.export_json_payload()
        print(f"JSON_ROWS={len(payload.get('rows', []))}")

        audit_service = AuditWorkbookService(str(output))
        header_row = audit_service.detect_header_row()
        col_map = audit_service.build_column_map()
        rows = audit_service.iter_audit_rows()

        print(f"HEADER_ROW={header_row}")
        print(f"HAS_AUDIT_HEADER={bool(audit_service.audit_header)}")
        print(f"HAS_SBL_HEADER={bool(audit_service.sbl_build_header)}")
        print(f"COLUMN_COUNT={len(col_map)}")
        print(f"AUDIT_ROWS={len(rows)}")
        print("SMOKE_TEST=PASS")
        return 0
    except Exception as exc:
        print(f"SMOKE_TEST=FAIL: {exc}")
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
