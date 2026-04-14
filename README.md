# AutoMatic
Automatic Audit scan

## SBL Audit GUI Usage

1. Install dependencies:
   - `pip install PySide6 pandas openpyxl`
   - optional: `pip install paramiko` (for VM SSH checks)
2. Run the app:
   - `python main.py`
3. In the app:
   - "Create SBL Checklist" loads Excel and exports JSON checklist.
   - "Run Audit" loads Excel, enter credentials, run local + VM scan.

## Excel format

Expected columns (case-insensitivities accepted):
- `host` (target VM / host)
- `item` (command to execute remotely, or scan item)
- `expected` (expected text to match in command output)
- `notes` (optional)

## Dependency conflict note (tflite-support + paramiko)

If you have `tflite-support==0.4.4` in your environment, it requires `protobuf<4,>=3.18.0`. `paramiko` installation can be affected by a conflicting protobuf version.

Recommended steps:

1. Create an isolated virtual environment:
   - `python -m venv .venv`
   - `\.venv\Scripts\activate` (Windows)
   - `pip install --upgrade pip setuptools wheel`
2. Pin protobuf to a compatible version first:
   - `pip install "protobuf>=3.18.0,<4"`
3. Install paramiko:
   - `pip install paramiko`
4. Install GUI/audit dependencies:
   - `pip install PySide6 pandas openpyxl`
5. Add tflite-support (preserving your existing requirement):
   - `pip install "tflite-support==0.4.4"`

Alternative with constraints file:

- Create `constraints.txt` with:
  - `protobuf<4,>=3.18.0`
- Then run:
  - `pip install -r requirements.txt -c constraints.txt`

Run tests:

- `pip install pytest`
- `pytest -q`

## Virtual environment setup (recommended)

1. In project root:
   - `python -m venv .venv`
2. Activate:
   - PowerShell: `\.venv\Scripts\Activate.ps1`
   - cmd: `\.venv\Scripts\activate.bat`
3. Upgrade and install:
   - `pip install --upgrade pip setuptools wheel`
   - `pip install PySide6 pandas openpyxl`
   - `pip install paramiko` (optional, SSH checks)
   - `pip install pytest` (tests)
4. Run app:
   - `python main.py`
5. Run tests:
   - `pytest -q`

### Configure VS Code interpreter to venv

1. Open command palette (`Ctrl+Shift+P`).
2. `Python: Select Interpreter`.
3. Choose `.venv\Scripts\python.exe`.
4. Validate status bar lists the venv interpreter.

### Optional VS Code settings (`.vscode/settings.json`)

```json
{
  "python.defaultInterpreterPath": ".venv\\Scripts\\python.exe",
  "python.terminal.activateEnvironment": true
}
```

> If using an existing interpreter, install dependencies there as well and point VS Code to it; keep this project in one stable environment.

