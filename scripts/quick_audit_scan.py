import copy
import json
import tempfile
from dataclasses import asdict
import uuid
from datetime import datetime
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from config import AUDIT_RESULTS_DIR, LOCAL_SENTINEL
from services import AuditEngine, AuditWorkbookService, FileLogger, JsonExportService, LocalWindowsScanner, TemplateAssetService, VersionRuleResolver
from services.template_service import _get_sbl_model_from_workbook
from services.workbook_service import read_software_list_universal_rows
from services.utils import default_target_columns, normalize_text


class QuickAuditDialog(tk.Toplevel):
    """Collect quick-audit VM details in a compact, fixed-size dialog."""

    def __init__(self, parent: tk.Tk, target_columns: List[str]):
        super().__init__(parent)
        self.title("Quick Audit Scan")
        self.transient(parent)
        self.resizable(False, False)
        self.result: Optional[Dict[str, Any]] = None
        self._target_columns = target_columns

        container = ttk.Frame(self, padding=10)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container,
            text="Local scan runs first, then VM targets are scanned through vSphere.",
            wraplength=760,
        ).pack(anchor="w", pady=(0, 8))

        self.vcenter_server = tk.StringVar()
        self.vcenter_username = tk.StringVar()
        self.vcenter_password = tk.StringVar()
        self.guest_username = tk.StringVar()
        self.guest_password = tk.StringVar()

        creds = ttk.LabelFrame(container, text="Connection Details", padding=8)
        creds.pack(fill="x", pady=(0, 8))
        self._entry_row(creds, "vCenter server", self.vcenter_server, width=30)
        self._entry_row(creds, "vCenter username", self.vcenter_username, width=30)
        self._entry_row(creds, "vCenter password", self.vcenter_password, show="*", width=30)
        self._entry_row(creds, "Guest username", self.guest_username, width=30)
        self._entry_row(creds, "Guest password", self.guest_password, show="*", width=30)

        mapping = ttk.LabelFrame(container, text="Target -> VM Name", padding=8)
        mapping.pack(fill="both", expand=True)

        header = ttk.Frame(mapping)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Target", width=34, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
        ttk.Label(header, text="VM Name", width=34, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")

        self.target_vars: Dict[str, tk.StringVar] = {}
        for target_name in target_columns:
            row = ttk.Frame(mapping)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=target_name, width=34, anchor="w").pack(side="left")
            vm_var = tk.StringVar(value=LOCAL_SENTINEL)
            ttk.Entry(row, textvariable=vm_var, width=34).pack(side="left")
            self.target_vars[target_name] = vm_var

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=(10, 0))
        ttk.Button(controls, text="Set All To Local", command=self._set_all_local).pack(side="left")
        ttk.Button(controls, text="Cancel", command=self._cancel).pack(side="right")
        ttk.Button(controls, text="Run Quick Audit Scan", command=self._submit).pack(side="right", padx=(0, 8))

        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self.grab_set()

    @staticmethod
    def _entry_row(parent: ttk.Widget, label: str, variable: tk.StringVar, show: Optional[str] = None, width: int = 24) -> None:
        """Render one row containing a label and entry widget."""
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=2)
        ttk.Label(row, text=label, width=18).pack(side="left")
        if show is not None:
            ttk.Entry(row, textvariable=variable, show=show, width=width).pack(side="left", fill="x", expand=True)
        else:
            ttk.Entry(row, textvariable=variable, width=width).pack(side="left", fill="x", expand=True)

    def _set_all_local(self) -> None:
        """Set each target mapping to the local sentinel."""
        for vm_var in self.target_vars.values():
            vm_var.set(LOCAL_SENTINEL)

    def _cancel(self) -> None:
        """Close the dialog without returning data."""
        self.result = None
        self.destroy()

    def _submit(self) -> None:
        """Validate data and return dialog payload."""
        server = normalize_text(self.vcenter_server.get())
        vcenter_user = normalize_text(self.vcenter_username.get())
        vcenter_password = self.vcenter_password.get()
        guest_user = normalize_text(self.guest_username.get())
        guest_password = self.guest_password.get()

        if not server or not vcenter_user or not vcenter_password:
            messagebox.showwarning(
                "Missing vCenter details",
                "Provide vCenter server, username, and password.",
                parent=self,
            )
            return
        if not guest_user or not guest_password:
            messagebox.showwarning(
                "Missing guest details",
                "Provide guest username and password for VM scans.",
                parent=self,
            )
            return

        targets: Dict[str, Dict[str, str]] = {}
        for target_name in self._target_columns:
            vm_name = normalize_text(self.target_vars[target_name].get()) or LOCAL_SENTINEL
            targets[target_name] = {
                "vm_name": vm_name,
                "username": guest_user,
                "password": guest_password,
                "os_type": "windows",
            }

        self.result = {
            "vcenter": {
                "server": server,
                "username": vcenter_user,
                "password": vcenter_password,
            },
            "guest": {
                "username": guest_user,
                "password": guest_password,
            },
            "targets": targets,
        }
        self.destroy()


def build_summary(results: List[Any]) -> str:
    """Build a concise run summary string."""
    passed = sum(1 for r in results if getattr(r, "status", "") == "PASS")
    failed = sum(1 for r in results if getattr(r, "status", "") == "FAIL")
    warned = sum(1 for r in results if getattr(r, "status", "") == "WARN")
    return f"Summary | Total target checks: {len(results)} | PASS: {passed} | FAIL: {failed} | WARN: {warned}"


def main() -> None:
    """Run quick audit workflow without showing the main application GUI."""
    root = tk.Tk()
    root.withdraw()
    normalized_source_path = ""
    normalized_from_fallback = False

    selected_path = filedialog.askopenfilename(
        title="Quick Audit Scan - Select XLSX Checklist",
        filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")],
        parent=root,
    )
    if not selected_path:
        root.destroy()
        return

    logger = FileLogger(Path("logs"), "quick_audit_scan")

    def log(message: str) -> None:
        """Write quick-scan log messages to file and stdout."""
        logger.write(message)
        print(message, flush=True)

    try:
        workbook_service: Optional[AuditWorkbookService] = None
        target_columns: List[str] = []
        normalized_source_path = selected_path
        normalized_from_fallback = False

        try:
            workbook_service = AuditWorkbookService(selected_path)
            workbook_service.detect_header_row()
            workbook_service.build_column_map()
            target_columns = workbook_service.target_columns or default_target_columns()
        except Exception as parse_exc:
            log(f"Primary header parse failed: {parse_exc}")
            log("Attempting fallback normalization for non-standard input format...")

            temp_json_path = ""
            temp_xlsx_path = ""

            try:
                rows = read_software_list_universal_rows(selected_path, debug_logger=log)
                if not rows:
                    raise ValueError("No data rows found in the selected file")

                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as temp_json:
                    temp_json_path = temp_json.name
                    json.dump(rows, temp_json, indent=2)

                with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as temp_xlsx:
                    temp_xlsx_path = temp_xlsx.name

                TemplateAssetService().import_list_to_sbl_workbook(temp_json_path, temp_xlsx_path)

                workbook_service = AuditWorkbookService(temp_xlsx_path)
                workbook_service.detect_header_row()
                workbook_service.build_column_map()
                target_columns = workbook_service.target_columns or default_target_columns()
                normalized_source_path = temp_xlsx_path
                normalized_from_fallback = True
                log(f"Fallback normalization succeeded: {temp_xlsx_path}")
            finally:
                if temp_json_path:
                    try:
                        Path(temp_json_path).unlink(missing_ok=True)
                    except Exception:
                        pass

        if workbook_service is None:
            raise RuntimeError("Unable to prepare workbook service for quick scan")

        dialog = QuickAuditDialog(root, target_columns)
        root.wait_window(dialog)
        if not dialog.result:
            if normalized_from_fallback:
                try:
                    Path(normalized_source_path).unlink(missing_ok=True)
                except Exception:
                    pass
            root.destroy()
            return

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        source_stem = Path(selected_path).stem
        output_path = AUDIT_RESULTS_DIR / f"quick_audit_scan_{source_stem}_{timestamp}.xlsx"

        vcenter = dialog.result["vcenter"]
        guest = dialog.result["guest"]
        vm_profile = {
            "profile_name": "quick_audit_scan",
            "build_type": workbook_service.build_type,
            "target_schema": {
                "source_path": selected_path,
                "target_columns": list(target_columns),
                "build_type": workbook_service.build_type,
            },
            "targets": dialog.result["targets"],
        }

        log("Quick Audit Scan started.")
        log(f"Source workbook: {selected_path}")
        if normalized_from_fallback:
            log(f"Normalized workbook used for scan: {normalized_source_path}")
        log(f"Output workbook: {output_path}")
        log(f"Session log file: {logger.get_path()}")

        engine = AuditEngine(
            workbook_service,
            log,
            copy.deepcopy(vm_profile),
            {"server": vcenter["server"], "username": vcenter["username"], "password": vcenter["password"]},
            {"username": guest["username"], "password": guest["password"]},
            connection_mode="vSphere",
            ssh_config={"gateway_port": 22, "target_port": 22},
            ssh_fallback_enabled=False,
        )

        job_id = str(uuid.uuid4())
        try:
            registry_snapshot = engine.local_scanner.capture_registry_snapshot()
            registry_snapshot["job_id"] = job_id
            registry_snapshot_path = JsonExportService.write_registry_snapshot_json(source_stem, registry_snapshot)
            log(f"Registry snapshot written: {registry_snapshot_path}")
        except Exception as snapshot_exc:
            log(f"Registry snapshot failed: {snapshot_exc}")

        results = engine.run()
        workbook_service.save_as(str(output_path))

        result_json_path = JsonExportService.write_result_json(
            source_stem,
            {
                "audit_mode": "quick_audit_scan",
                "audit_workbook": selected_path,
                "normalized_audit_workbook": normalized_source_path if normalized_from_fallback else selected_path,
                "saved_workbook": str(output_path),
                "profile_name": "quick_audit_scan",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "results": [asdict(result) for result in results],
            },
        )

        parsed_rows: List[Dict[str, Any]] = []
        for row in workbook_service.iter_audit_rows():
            if not row.software_component:
                continue
            rule, _ = VersionRuleResolver.detect_rule(row.version_locations)
            parsed_rows.append(
                {
                    "worksheet_row": row.row_index,
                    "software_component": row.software_component,
                    "sbl_build_version": row.sbl_build_version,
                    "version_locations": row.version_locations,
                    "rule": rule,
                    "local_detection_commands": LocalWindowsScanner.describe_local_detection_commands(
                        row.software_component,
                        row.version_locations,
                    ),
                }
            )

        scan_job_path = JsonExportService.write_scan_job_json(
            source_stem,
            {
                "job_id": job_id,
                "status": "completed",
                "audit_mode": "quick_audit_scan",
                "started_at": datetime.now().isoformat(timespec="seconds"),
                "sbl_file": {
                    "name": Path(selected_path).name,
                    "path": selected_path,
                    "normalized_path": normalized_source_path if normalized_from_fallback else selected_path,
                    "sbl_model": _get_sbl_model_from_workbook(selected_path),
                },
                "settings": {
                    "profile_name": "quick_audit_scan",
                    "connection_mode": "vSphere",
                    "local_only": False,
                    "vcenter_server": vcenter["server"],
                },
                "sbl_parse": {
                    "target_columns": list(target_columns),
                    "row_count": len(parsed_rows),
                    "rows": parsed_rows,
                },
                "results": [asdict(result) for result in results],
            },
        )

        summary = build_summary(results)
        log(summary)
        log(f"Result JSON written: {result_json_path}")
        log(f"Scan job JSON written: {scan_job_path}")
        messagebox.showinfo(
            "Quick Audit Scan Complete",
            f"{summary}\n\nSaved workbook:\n{output_path}\n\nLog file:\n{logger.get_path()}",
            parent=root,
        )
    except Exception as exc:
        logger.write_exception(exc)
        messagebox.showerror(
            "Quick Audit Scan Failed",
            f"{exc}\n\nLog file:\n{logger.get_path()}",
            parent=root,
        )
    finally:
        try:
            if 'normalized_from_fallback' in locals() and normalized_from_fallback:
                Path(normalized_source_path).unlink(missing_ok=True)
        except Exception:
            pass
        root.destroy()


if __name__ == "__main__":
    main()
