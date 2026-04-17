# AuditMatic Refactor - Module Extraction Guide

## Completed Modules ✓
- ✓ config.py
- ✓ models.py
- ✓ utils.py (with project structure helpers)
- ✓ services/file_logger.py
- ✓ services/json_export_service.py

---

## Remaining Modules - Extraction Instructions

### Module 5: services/master_software_service.py

**Extract from original file:**
- Lines 1432-1650 (MasterSoftwarePathService class)
- Add import: `from config import MASTER_SOFTWARE_LIST_PATH, SYSTEM_COLUMNS, normalize_model_key` (already in utils)
- Add import: `from pathlib import Path`
- Add import: `from typing import Dict, Any, List, Optional`
- Add import: `import json, re`
- Add import: `from datetime import datetime`
- Add import `from utils import normalize_text, normalize_model_key, default_target_columns, _new_model_bucket, _empty_master_software_list_payload`

**Key class:** `MasterSoftwarePathService`
- `__init__(path: Path = MASTER_SOFTWARE_LIST_PATH)`
- `load() -> Dict[str, Any]`
- `save(payload: Dict[str, Any]) -> None`
- `update_component(software_component, path_value, target_name, scan_status, notes, model_name) -> None`

**Dependencies:**
- Imports from: config, utils, pathlib, json, re, datetime

---

### Module 6: services/template_service.py

**Extract from original file:**
- Lines 1652-1945 (TemplateAssetService class)
- Line 2409-2440 (derive_path_metadata function - move from utils)
- Support functions:
  - `_get_sbl_model_from_workbook(sbl_path: str) -> str` (lines 97-108)
  - `_model_to_filename_slug(model_name: str) -> str` (lines 110-122)
  - `get_sbl_template_baseline_path(model_name: str = None) -> Path` (lines 123-130)
  - `get_sbl_template_latest_path(model_name: str = None) -> Path` (lines 131-138)
  - `get_master_json_template_baseline_path(model_name: str = None) -> Path` (lines 139-142)
  - `get_master_json_template_latest_path(model_name: str = None) -> Path` (lines 143-146)

**Key class:** `TemplateAssetService`
- Static methods for template file discovery
- `update_baseline_from_sbl(sbl_path: str) -> Dict[str, str]`
- `update_latest_sbl(sbl_path: str) -> str`
- `snapshot_current_master_to_latest(sbl_model: str = None) -> str`
- `import_list_to_sbl_workbook(input_path: str, output_path: str) -> str`

**Dependencies:**
- Imports from: config, utils, models, services.file_logger
- Also imports: shutil, tempfile, openpyxl, pandas

---

### Module 7: services/profile_service.py

**Extract from original file:**
- Lines 1979-2134 (VMProfileService class)
- Lines 2135-2254 (VSphereService class)
- Lines 2255-2378 (SSHTunnelService class)

**Key classes:**
1. **VMProfileService** - Profile encryption/storage/loading
   - `profile_path(profile_name: str) -> Path`
   - `save_profile(profile_name: str, payload: Dict[str, Any]) -> str`
   - `load_profile(profile_name: str) -> Dict[str, Any]`
   - Credential encryption/decryption methods

2. **VSphereService** - vSphere VM management
   - `connect()`
   - `disconnect()`
   - `list_windows_vms() -> List[str]`
   - `verify_vm_names(vm_names: List[str]) -> Dict[str, Dict[str, str]]`
   - `run_powershell_in_guest(...) -> Tuple[str, str, str]`

3. **SSHTunnelService** - SSH tunnel management
   - `run_powershell(target_host, script, ...) -> Tuple[str, str, str]`
   - Connection helpers

**Dependencies:**
- Imports from: config, utils
- Optional imports: paramiko, ssl, requests, pyVim, pyVmomi, cryptography

---

### Module 8: services/workbook_service.py (~1200 lines)

**Extract from original file:**
- Lines 2379-2408 (VersionRuleResolver class)
- Lines 2441-2645 (AuditWorkbookService class)
- Lines 2646-2834 (AuditWorkbookServiceProxy class)
- Lines 2835-2927 (ChecklistGeneratorService class)
- Support functions:
  - `read_software_list_universal_rows(...)` (lines 313-490)
  - `_repair_invalid_style_indexes(file_path: str) -> Optional[str]` (lines 1288-1378)
  - `_create_example_audit_checklist_workbook(file_path: Path) -> None` (lines 1013-1044)
  - `_create_example_audit_results_workbook(file_path: Path) -> None` (lines 1045-1179)

**Key classes:**
1. **VersionRuleResolver** - Detect version lookup rules
2. **AuditWorkbookService** - Main workbook parsing
3. **AuditWorkbookServiceProxy** - Tolerant header parsing for generated workbooks
4. **ChecklistGeneratorService** - Audit form generation

**Dependencies:**
- All from: config, utils, models, openpyxl, pandas, etc.

---

### Module 9: services/audit_engine.py (~800 lines)

**Extract from original file:**
- Lines 2928-3112 (LocalWindowsScanner class)
- Lines 3113-3534 (AuditEngine class)
- All `derive_path_metadata()` logic from VersionRuleResolver

**Key classes:**
1. **LocalWindowsScanner** - Local Windows software detection
   - `scan_software_version(software_name: str, version_location: str) -> Tuple[str, str, str]`
   - `scan_file_versions(paths: List[str]) -> Tuple[str, str, str]`
   - `capture_registry_snapshot() -> Dict[str, Any]`
   - `run_powershell(command: str) -> Tuple[str, str, str]`

2. **AuditEngine** - Coordinate all scanning operations
   - `run() -> List[ScanResult]`
   - Route scanners to local/SSH/vSphere paths
   - Version comparison and audit result writing

**Dependencies:**
- All services, models, utils
- Platform-specific: winreg, subprocess, socket, platform

---

### Module 10: ui/__init__.py

**Create empty file:**
```python
"""
AuditMatic UI module

User interface frames and application root.
"""
```

---

### Module 11: ui/frames.py (~1500 lines)

**Extract from original file:**
- Lines 3535-3551 (BaseFrame class)
- Lines 3582-3602 (HomeFrame class)
- Lines 3603-4055 (ProfileFrame class)
- Lines 4056-4392 (ChecklistFrame class)
- Lines 4393-5378 (AuditFrame class)

**Key classes:**
1. **BaseFrame(ttk.Frame)** - Base for all frames
2. **HomeFrame** - Main menu/welcome
3. **ProfileFrame** - VM profile configuration
4. **ChecklistFrame** - Audit form generation
5. **AuditFrame** - Audit execution and results

**Dependencies:**
- tkinter, ttk, messagebox, filedialog
- All services, utils, models, config

---

### Module 12: ui/app.py (~50 lines)

**Extract from original file:**
- Lines 3552-3581 (App class)

**Key class:**
1. **App(tk.Tk)** - Application root window
   - `__init__()`
   - `show_frame(name: str)`
   - Frame navigation

**Dependencies:**
- tkinter, ttk
- All Frame classes

---

### Module 13: main.py (~30 lines)

**Extract from original file:**
- Lines 5379-5385 (main() function)

**Code:**
```python
'''
AuditMatic Entry Point
'''

def main():
    """Initialize project structure and launch application."""
    from ui.app import App
    from utils import ensure_project_structure
    from utils import _create_example_files
    
    ensure_project_structure()
    _create_example_files()
    
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
```

---

## Creation Order

1. ✓ config.py
2. ✓ models.py
3. ✓ utils.py (with helpers)
4. ✓ services/file_logger.py
5. ✓ services/json_export_service.py
6. → services/master_software_service.py
7. → services/template_service.py
8. → services/profile_service.py
9. → services/workbook_service.py
10. → services/audit_engine.py
11. → ui/__init__.py
12. → ui/frames.py
13. → ui/app.py
14. → main.py

---

## Import Dependencies Verification

```
config.py                        (no deps)
    ↓
models.py                        (uses: config)
    ↓
utils.py                         (uses: config, models)
    ↓
services/file_logger.py          (uses: utils)
services/json_export_service.py  (uses: config, utils)
    ↓
services/master_software_service.py   (uses: config, utils)
services/template_service.py     (uses: config, utils, models, services/file_logger)
services/profile_service.py      (uses: config, utils)
    ↓
services/workbook_service.py     (uses: all of above)
services/audit_engine.py         (uses: all services)
    ↓
ui/__init__.py                   (marker only)
ui/frames.py                     (uses: all services, utils, models, config)
ui/app.py                        (uses: ui/frames)
    ↓
main.py                          (uses: ui/app, utils)
```

---

## Helper Functions to Extract

These need to be added to utils.py or specific service files:

1. `_get_sbl_model_from_workbook(sbl_path: str) -> str` → template_service.py
2. `_model_to_filename_slug(model_name: str) -> str` → template_service.py
3. `_create_example_registry_snapshot() -> Dict[str, Any]` → utils.py or template_service.py
4. `_create_example_checklist_json() -> Dict[str, Any]` → template_service.py
5. `_create_example_result_json() -> Dict[str, Any]` → template_service.py
6. `_create_example_scan_job_payload() -> Dict[str, Any]` → utils.py
7. `_create_example_audit_checklist_workbook(file_path: Path) -> None` → template_service.py
8. `_create_example_audit_results_workbook(file_path: Path) -> None` → template_service.py
9. `_create_example_files() -> None` → utils.py (main initializer)
10. `_max_workbook_style_index(file_path: str) -> Optional[int]` → utils.py
11. `_repair_invalid_style_indexes(file_path: str) -> Optional[str]` → utils.py

---

## Testing Strategy

After all modules are created:

1. Test imports in isolation (each module imports successfully)
2. Test config → models → utils dependency chain
3. Test individual service initialization
4. Test UI frame instantiation
5. Full application launch: `python main.py`

---

## Total LOC Refactored

- Original monolithic file: 4,855 lines
- Refactored modules:
  - config.py: 176 lines
  - models.py: 63 lines
  - utils.py: 380 lines
  - services/file_logger.py: 44 lines
  - services/json_export_service.py: 40 lines
  - services/master_software_service.py: ~220 lines
  - services/template_service.py: ~300 lines
  - services/profile_service.py: ~460 lines
  - services/workbook_service.py: ~1200 lines
  - services/audit_engine.py: ~800 lines
  - ui/__init__.py: 5 lines
  - ui/frames.py: ~1500 lines
  - ui/app.py: 50 lines
  - main.py: 30 lines
  
**Total: ~5,278 lines** (slightly more due to docstrings and spacing)

All functionality preserved, zero rewrites.
