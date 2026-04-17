# AuditMatic

AuditMatic is a tkinter desktop tool that helps you:

- generate audit checklists from SBL-like sources (XLSX/CSV/JSON)
- run local and remote software version audits
- write results back into workbook format
- export JSON artifacts for checklist, results, registry snapshots, and scan jobs

## Current App Entry Points

- Main GUI: `python main.py`
- Quick audit flow: `python quick_audit_scan.py`

`main.py` is the primary launch path for the refactored application.

## Project Structure (Refactored)

- `main.py`: application entrypoint
- `ui/`: GUI app + frames (`App`, `HomeFrame`, `ProfileFrame`, `ChecklistFrame`, `AuditFrame`)
- `services/`: business logic (audit engine, workbook parsing, VM/SSH profile services, template management, JSON export, logging)
- `config.py`: application constants and paths
- `models.py`: dataclasses for audit rows/results/schema
- `utils.py`: shared helpers and project bootstrap utilities
- `sbl_audit_gui_v_2000.py`: legacy compatibility fallback (not the primary path)

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

- Open **VM Profile Manager** from the home screen.
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

## Output Locations

AuditMatic creates and uses these folders:

- `Audit Checklist/`: generated audit checklists
- `Audit Results/`: audited result workbooks
- `JSON/json_checklist/`: checklist JSON exports
- `JSON/json_result/`: audit result JSON exports
- `JSON/registry_snapshots/`: local registry inventory snapshots
- `JSON/scan_jobs/`: run-level scan-job JSON payloads
- `profiles/vm_profiles/`: saved profiles
- `logs/`: run logs

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
- `quick_audit_scan.py` provides an accelerated quick-audit flow with minimal UI steps.

## Branching Context

- `legacy` branch: pre-refactor checkpoint branch
- `current` branch: refactored UI/services split and active development path