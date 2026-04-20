# AuditMatic

AuditMatic is a tkinter desktop tool that helps you:

- generate audit checklists from SBL-like sources (XLSX/CSV/JSON)
- run local and remote software version audits
- write results back into workbook format
- export JSON artifacts for checklist, results, registry snapshots, and scan jobs

## Run In 60 Seconds

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Seamless Setup For New Clones (Windows)

If you cloned the repo and want the fastest setup path, run:

```powershell
.\setup.bat
```

What this automates:

- finds Python on your PATH (`py -3` or `python`)
- creates `venv/` if missing
- upgrades `pip`, `setuptools`, and `wheel`
- installs all dependencies from `requirements.txt`
- runs `pip check` health validation
- ensures desktop shortcuts for Basic Scan and GUI launchers

If `setup.bat` is blocked by enterprise policy/admin controls, use the no-admin Python bootstrap:

```powershell
python .\bootstrap_setup.py
```

## Main Entry Points

- Main GUI: `python main.py`
- Quick audit flow: `python quick_audit_scan.py`
- Basic standalone scan launcher (terminal): `Launch_Basic_Scan.bat`
- Full GUI launcher: `Launch_AuditMatic_GUI.bat`
- Backward-compatible quick launcher alias: `Launch_Quick_Audit_Scan.bat`

`main.py` is the primary launch path for the refactored application.

`quick_audit_scan.py` is intentionally a lightweight standalone flow (file picker + compact dialog), not the full multi-page app UI.

## Double-Click Quick Scan (Windows)

Use `Launch_Basic_Scan.bat` to run the standalone scan flow directly from Explorer.

Use `Launch_AuditMatic_GUI.bat` to open the full GUI app.

Desktop shortcut automation:

- `setup.bat` and `bootstrap_setup.py` automatically run `ensure_desktop_shortcuts.bat`
- it checks for both desktop shortcuts first and only creates missing ones:
  - `AuditMatic Basic Scan.lnk`
  - `AuditMatic GUI.lnk`
- in-app option: Home page -> **Utilities** -> **Ensure Desktop Shortcuts**

Suggested desktop shortcut setup:

1. Right-click `Launch_Basic_Scan.bat`.
2. Select **Send to > Desktop (create shortcut)**.
3. Rename the shortcut to something like **AuditMatic Basic Scan**.

## Typical Workflow

1. Configure a target profile in the GUI.
2. Generate or import an audit checklist.
3. Run audit and export results.

## Demo Readiness Checklist

Use this checklist before presenting AuditMatic:

1. Run setup and dependency validation:
  - `setup.bat` (or `python .\\bootstrap_setup.py` in restricted environments)
2. Ensure desktop launchers exist:
  - `ensure_desktop_shortcuts.bat`
  - or Home page -> **Utilities** -> **Ensure Desktop Shortcuts**
3. Smoke-check GUI startup:
  - `Launch_AuditMatic_GUI.bat`
4. Smoke-check standalone basic scan launcher:
  - `Launch_Basic_Scan.bat`
5. Run unit tests and confirm success:
  - `run_tests.bat`
6. Confirm clean demo outputs and locations:
  - logs in `logs/`
  - result workbooks in `Audit Results/`
  - JSON outputs in `JSON/json_result/` and `JSON/scan_jobs/`

## Project Structure (Refactored)

- `main.py`: application entrypoint
- `ui/`: GUI app + frames (`App`, `HomeFrame`, `ProfileFrame`, `ChecklistFrame`, `AuditFrame`)
- `services/`: business logic (audit engine, workbook parsing, VM/SSH profile services, watch-folder orchestration, template management, JSON export, logging)
- `config.py`: application constants and paths
- `models.py`: dataclasses for audit rows/results/schema
- `utils.py`: shared helpers and project bootstrap utilities
- `scripts/`: utility launchers and standalone helper scripts (`quick_audit_scan.py`, diagnostics, test readers)
- `SBLs/`: default user workbook drop zone used by file pickers and watch-folder inputs

## Requirements

Install dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

Current requirements:

- `pandas`
- `openpyxl`
- `requests`
- `pyvmomi`
- `paramiko`
- `cryptography`

## Recommended Setup (Windows)

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Then run:

```powershell
python main.py
```

## How To Use

### 1) Configure VM Profile

- Open **Target Profile Manager** from the home screen.
- Set vCenter connection info.
- Map workbook target columns to VM names, or map targets to `__LOCAL__` for local-only scanning.
- Save profile.

### 2) Create Audit Form

- Open **Create Audit Form**.
- Select a source SBL/checklist file.
- Generate an audit workbook.
- Optional: import CSV/JSON into workbook format first.

### 3) Run Audit

- Open **Run Audit**.
- Select audit workbook and output workbook path.
- Choose connection mode (`vSphere` or `SSH Tunnel`).
- Run audit (or use **Quick Audit Scan**).

### 4) Watch Folder Automation

- Configure a profile pipeline with `Input source = Watch Folder` and `Output action = Save to Local Folder`.
- In **Run Audit**, click **Start Pipeline** to process matching `.xlsx/.xlsm` inputs as they arrive.
- Optional watch behaviors:
  - process existing files on startup
  - archive processed files to a `processed/` subfolder
- Duplicate workbook content is suppressed by persisted SHA-256 state in `JSON/scan_jobs/watch_folder_state.json`.
- Runtime compatibility indicator is shown in **Run Audit** for all pipeline types:
  - `Watch Folder/File Explorer Folder -> Save to Local Folder`: in-app auto-run is enabled
  - all other trigger/output combinations: configuration is recognized and validated, but treated as external/manual runtime flows

## Key Output Folders

- `Audit Checklist/`
- `Audit Results/`
- `JSON/json_checklist/`
- `JSON/json_result/`
- `JSON/registry_snapshots/`
- `JSON/scan_jobs/`
- `profiles/vm_profiles/`
- `logs/`

## Notes On Remote Scanning

- `pyvmomi` is used for vSphere operations.
- `paramiko` is used for SSH tunnel mode.
- `cryptography` is used to encrypt stored profile credentials.

If remote dependencies are unavailable, local scan paths can still be used by mapping targets to `__LOCAL__`.

## Troubleshooting

- If workbook parsing fails on a non-standard input, AuditMatic attempts fallback normalization.
- If remote probes fail, verify:
  - vCenter/SSH credentials
  - network reachability
  - VM guest tools or SSH readiness
- Check `logs/` for detailed errors and run traces.

## Testing Helpers

- `tests/Test Scripts/test_gui_mock.py` launches the GUI with mocked remote behavior.
- `tests/Test Scripts/test_watch_pipeline_service.py` validates watch lifecycle, dedupe persistence, and archive behavior.
- `tests/Test Scripts/test_pipeline_runtime_compatibility.py` validates runtime compatibility classification across pipeline types.
- `tests/Test Scripts/test_watch_state_compaction.py` validates persisted watch-state migration and compaction.
- `tests/Test Scripts/test_remote_scan_mocked.py` validates vSphere/SSH target routing, X-mark sublist behavior, and remote fallback paths (SSH->vSphere and vSphere->SSH) with fully mocked services (no real environment required).
- `tests/Test Scripts/run_unit_test_suite.py` runs the unit suite and writes a report to `tests/reports/unit_test_report_*.json`.
- `quick_audit_scan.py` (root compatibility launcher) and `scripts/quick_audit_scan.py` provide the accelerated quick-audit flow.

Run the unit suite and generate a report:

```powershell
& ".\venv\Scripts\python.exe" "tests\Test Scripts\run_unit_test_suite.py"
```

## Branches

- `legacy`: pre-refactor checkpoint
- `current`: active refactored branch