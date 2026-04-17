# AuditMatic

Quick-start guide for the current refactored app.

For full documentation, see [docs/README_FULL.md](docs/README_FULL.md).

## Run In 60 Seconds

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python main.py
```

## Main Entry Points

- Main GUI: `python main.py`
- Quick audit flow: `python quick_audit_scan.py`

## Typical Workflow

1. Configure a VM profile in the GUI.
2. Generate or import an audit checklist.
3. Run audit and export results.

## Key Output Folders

- `Audit Checklist/`
- `Audit Results/`
- `JSON/json_checklist/`
- `JSON/json_result/`
- `JSON/registry_snapshots/`
- `JSON/scan_jobs/`
- `profiles/vm_profiles/`
- `logs/`

## Branches

- `legacy`: pre-refactor checkpoint
- `current`: active refactored branch
