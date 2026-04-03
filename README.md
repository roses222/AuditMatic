# AuditMatic

**v2.0.0.0**

AuditMatic is an automated auditing tool designed to streamline and standardize the process of reviewing, analyzing, and reporting on data integrity, compliance, and system health. It reduces manual effort by automating repetitive audit tasks and producing structured, actionable reports.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Tool Structure](#tool-structure)
- [Data Types](#data-types)
  - [Accepted Input Types](#accepted-input-types)
  - [Output Data](#output-data)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [First-Time Setup](#first-time-setup)
  - [Running Your First Audit](#running-your-first-audit)
- [Usage](#usage)
  - [Basic Usage](#basic-usage)
  - [Advanced Options](#advanced-options)
- [Configuration](#configuration)
- [Output Reference](#output-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Changelog](#changelog)
- [License](#license)

---

## Features

- **Automated data auditing** — Scans data sources for inconsistencies, missing values, duplicates, and anomalies.
- **Rule-based validation** — Define custom audit rules in a simple configuration file; AuditMatic enforces them on every run.
- **Multiple input formats** — Accepts CSV, JSON, Excel (`.xlsx`), and plain-text files out of the box.
- **Structured reports** — Produces human-readable Markdown summaries and machine-readable JSON/CSV audit logs.
- **Severity levels** — Findings are classified as `INFO`, `WARNING`, or `ERROR` so you can triage quickly.
- **Extensible** — Add your own validator modules without modifying the core engine.
- **Cross-platform** — Runs on Windows, macOS, and Linux.

---

## How It Works

AuditMatic follows a three-stage pipeline:

```
Input Data  ──►  Validation Engine  ──►  Report Generator
                 (rules + checks)        (Markdown / JSON / CSV)
```

1. **Ingestion** — AuditMatic reads the target data file(s) and parses them into an internal tabular representation.
2. **Validation** — Each row and field is evaluated against the rules defined in your configuration file (`auditmatic.config.json`). Built-in checks (type checking, null detection, range validation, duplicate detection) run automatically.
3. **Reporting** — Results are written to an output directory as structured reports. A summary is also printed to the terminal.

---

## Tool Structure

```
AuditMatic/
├── src/
│   ├── core/
│   │   ├── engine.py          # Main validation engine
│   │   ├── ingestor.py        # Parses input files into internal format
│   │   └── reporter.py        # Generates output reports
│   ├── validators/
│   │   ├── type_validator.py  # Checks field data types
│   │   ├── null_validator.py  # Detects missing/null values
│   │   ├── range_validator.py # Validates numeric/date ranges
│   │   └── dupe_validator.py  # Detects duplicate rows or key fields
│   └── main.py                # CLI entry point
├── tests/
│   ├── test_engine.py
│   ├── test_validators.py
│   └── fixtures/              # Sample data files for testing
├── docs/
│   └── configuration.md       # Detailed configuration reference
├── auditmatic.config.json      # Default configuration file
├── requirements.txt
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md
```

### Key Components

| Component | File | Responsibility |
|---|---|---|
| CLI Entry Point | `src/main.py` | Parses command-line arguments and launches the engine |
| Validation Engine | `src/core/engine.py` | Orchestrates ingestor → validators → reporter pipeline |
| Ingestor | `src/core/ingestor.py` | Reads CSV, JSON, XLSX, and TXT input files |
| Reporter | `src/core/reporter.py` | Writes Markdown, JSON, and CSV output reports |
| Validators | `src/validators/` | Pluggable modules — one per type of check |
| Configuration | `auditmatic.config.json` | User-defined rules and settings |

---

## Data Types

### Accepted Input Types

AuditMatic can process files in the following formats:

| Format | Extension | Notes |
|---|---|---|
| CSV | `.csv` | Comma-separated values; first row treated as header |
| JSON | `.json` | Array of objects; each object is one record |
| Excel | `.xlsx` | First sheet is used by default; configurable |
| Plain text | `.txt` | Tab- or pipe-delimited; first row treated as header |

#### Supported Field (Column) Data Types

Within those files, AuditMatic recognizes and validates these field types:

| Type | Keyword in config | Description |
|---|---|---|
| String | `string` | Any text value |
| Integer | `integer` | Whole numbers (positive, negative, or zero) |
| Float | `float` | Decimal numbers |
| Boolean | `boolean` | `true`/`false`, `yes`/`no`, `1`/`0` |
| Date | `date` | ISO 8601 format (`YYYY-MM-DD`) by default; configurable |
| DateTime | `datetime` | ISO 8601 date and time (`YYYY-MM-DDTHH:MM:SS`) |
| Email | `email` | Validated against standard email format |
| URL | `url` | Must begin with `http://` or `https://` |
| Enum | `enum` | Value must belong to a defined list of allowed values |
| Nullable | append `?` | Any type can be made nullable (e.g. `string?`, `integer?`) |

Example column definition in `auditmatic.config.json`:

```json
{
  "columns": {
    "user_id":    { "type": "integer" },
    "email":      { "type": "email" },
    "signup_date":{ "type": "date" },
    "role":       { "type": "enum",  "values": ["admin", "user", "guest"] },
    "notes":      { "type": "string?" }
  }
}
```

### Output Data

After each run, AuditMatic writes files to the `./audit_output/` directory (configurable). Three formats are produced:

#### 1. Markdown Summary (`summary.md`)

A human-readable audit report. Includes:
- Run metadata (timestamp, source file, total records scanned)
- Overall pass/fail status
- Count of findings per severity level
- A table listing each finding with: row number, column name, rule that failed, severity, and a plain-English message

Example excerpt:

```markdown
## Audit Summary — 2024-06-15 09:32:11

| Metric | Value |
|---|---|
| Source file | data/users.csv |
| Records scanned | 1,204 |
| Findings | 7 |
| ERRORs | 2 |
| WARNINGs | 4 |
| INFOs | 1 |

### Findings

| Row | Column | Rule | Severity | Message |
|---|---|---|---|---|
| 14 | email | email_format | ERROR | Value "john@" is not a valid email address |
| 57 | user_id | no_duplicates | ERROR | Duplicate key detected (value: 1042) |
| 203 | signup_date | date_format | WARNING | Value "06/15/2024" does not match expected format YYYY-MM-DD |
```

#### 2. JSON Log (`audit_log.json`)

Machine-readable log suitable for ingestion by other tools or dashboards:

```json
{
  "run_id": "a3f2c1d0",
  "timestamp": "2024-06-15T09:32:11Z",
  "source": "data/users.csv",
  "records_scanned": 1204,
  "findings": [
    {
      "row": 14,
      "column": "email",
      "rule": "email_format",
      "severity": "ERROR",
      "message": "Value \"john@\" is not a valid email address"
    }
  ]
}
```

#### 3. CSV Findings Export (`findings.csv`)

A flat table of all findings. Useful for importing into spreadsheet tools or databases:

```
row,column,rule,severity,message
14,email,email_format,ERROR,"Value ""john@"" is not a valid email address"
57,user_id,no_duplicates,ERROR,"Duplicate key detected (value: 1042)"
```

---

## Getting Started

### Prerequisites

Before installing AuditMatic, make sure you have the following installed:

- **Python 3.9 or higher** ([download](https://www.python.org/downloads/))
- **pip** (bundled with Python 3.9+)

Verify your setup:

```bash
python --version   # Should print Python 3.9.x or higher
pip --version
```

### Installation

#### Option A — Install from PyPI (recommended)

```bash
pip install auditmatic
```

#### Option B — Install from source

```bash
# 1. Clone the repository
git clone https://github.com/roses222/AuditMatic.git
cd AuditMatic

# 2. (Optional but recommended) Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### First-Time Setup

1. **Initialize a configuration file** in your project directory:

   ```bash
   auditmatic init
   ```

   This creates a starter `auditmatic.config.json` with sensible defaults that you can customize.

2. **Open `auditmatic.config.json`** in any text editor and define your columns:

   ```json
   {
     "output_dir": "./audit_output",
     "date_format": "YYYY-MM-DD",
     "columns": {
       "id":    { "type": "integer" },
       "name":  { "type": "string" },
       "email": { "type": "email" },
       "score": { "type": "float", "range": { "min": 0, "max": 100 } }
     },
     "rules": {
       "no_nulls":      ["id", "name", "email"],
       "no_duplicates": ["id"]
     }
   }
   ```

3. **Place your data file** (e.g., `data/records.csv`) in your project directory.

### Running Your First Audit

```bash
auditmatic run --input data/records.csv
```

You will see terminal output similar to:

```
[AuditMatic v2.0.0.0] Starting audit...
  ✔  Loaded 1,204 records from data/records.csv
  ✔  Running 6 validators...
  ⚠  7 findings detected (2 ERRORs, 4 WARNINGs, 1 INFO)
  ✔  Reports written to ./audit_output/

Run complete. See ./audit_output/summary.md for the full report.
```

Open `./audit_output/summary.md` to review the detailed findings.

---

## Usage

### Basic Usage

```bash
# Audit a CSV file using the default config
auditmatic run --input data/records.csv

# Specify a custom config file
auditmatic run --input data/records.csv --config my_rules.config.json

# Audit a JSON file
auditmatic run --input data/records.json

# Audit an Excel file and specify the sheet name
auditmatic run --input data/records.xlsx --sheet "Sheet2"
```

### Advanced Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--input` | `-i` | *(required)* | Path to the input data file |
| `--config` | `-c` | `auditmatic.config.json` | Path to the configuration file |
| `--output-dir` | `-o` | `./audit_output` | Directory to write output reports |
| `--sheet` | | `Sheet1` | Excel sheet name (`.xlsx` only) |
| `--severity` | | `INFO` | Minimum severity to include in output (`INFO`, `WARNING`, `ERROR`) |
| `--format` | | `all` | Output format: `markdown`, `json`, `csv`, or `all` |
| `--fail-on-error` | | `false` | Exit with a non-zero code if any `ERROR` findings are present |
| `--quiet` | `-q` | `false` | Suppress terminal output |
| `--version` | `-v` | | Print the AuditMatic version and exit |

Example — CI/CD integration with strict mode:

```bash
auditmatic run --input data/export.csv --severity WARNING --fail-on-error
```

---

## Configuration

The `auditmatic.config.json` file controls all aspects of AuditMatic's behavior.

### Full Configuration Reference

```json
{
  "output_dir": "./audit_output",
  "date_format": "YYYY-MM-DD",
  "datetime_format": "YYYY-MM-DDTHH:MM:SS",
  "columns": {
    "<column_name>": {
      "type": "<data_type>",
      "values": ["<allowed_value_1>", "<allowed_value_2>"],
      "range": { "min": <number>, "max": <number> }
    }
  },
  "rules": {
    "no_nulls":      ["<column_name>", "..."],
    "no_duplicates": ["<column_name>", "..."],
    "custom": [
      {
        "name": "<rule_name>",
        "column": "<column_name>",
        "condition": "<expression>"
      }
    ]
  }
}
```

### Configuration Options

| Key | Type | Default | Description |
|---|---|---|---|
| `output_dir` | string | `./audit_output` | Directory where reports are written |
| `date_format` | string | `YYYY-MM-DD` | Expected format for `date` fields |
| `datetime_format` | string | `YYYY-MM-DDTHH:MM:SS` | Expected format for `datetime` fields |
| `columns` | object | `{}` | Column definitions (name → type/constraints) |
| `rules.no_nulls` | array | `[]` | Columns that must not contain null/empty values |
| `rules.no_duplicates` | array | `[]` | Columns whose values must be unique across all rows |
| `rules.custom` | array | `[]` | Custom validation rules (see advanced configuration) |

---

## Output Reference

All output files are written to the directory specified by `output_dir` (default: `./audit_output/`).

| File | Format | Description |
|---|---|---|
| `summary.md` | Markdown | Human-readable report with findings table and run metadata |
| `audit_log.json` | JSON | Machine-readable structured log for programmatic use |
| `findings.csv` | CSV | Flat findings table for spreadsheet analysis or database import |

### Severity Levels

| Level | Meaning |
|---|---|
| `INFO` | Informational note; no action required |
| `WARNING` | Potential issue that should be reviewed |
| `ERROR` | Definitive rule violation; action required |

---

## Examples

### Example 1 — Validate a user export

**Input (`users.csv`):**

```csv
user_id,name,email,role,created_at
1,Alice,alice@example.com,admin,2024-01-10
2,Bob,bob@,user,2024-02-20
3,Carol,carol@example.com,superuser,2024-03-05
```

**Config snippet:**

```json
{
  "columns": {
    "user_id":    { "type": "integer" },
    "email":      { "type": "email" },
    "role":       { "type": "enum", "values": ["admin", "user", "guest"] },
    "created_at": { "type": "date" }
  },
  "rules": { "no_nulls": ["user_id", "email"], "no_duplicates": ["user_id"] }
}
```

**Command:**

```bash
auditmatic run --input users.csv
```

**Expected findings:**
- Row 2, `email` — `ERROR`: `"bob@"` is not a valid email address
- Row 3, `role`  — `ERROR`: `"superuser"` is not in the allowed enum values

---

### Example 2 — CI/CD pipeline step

```yaml
# .github/workflows/data_audit.yml
- name: Audit data export
  run: |
    pip install auditmatic
    auditmatic run --input data/export.csv --fail-on-error
```

---

## Troubleshooting

### "Config file not found"

Make sure `auditmatic.config.json` exists in your working directory, or pass the path explicitly:

```bash
auditmatic run --input data/file.csv --config path/to/my.config.json
```

### "Unsupported file format"

AuditMatic supports `.csv`, `.json`, `.xlsx`, and `.txt`. Check the file extension and ensure the file is not corrupted.

### "Module not found" error on startup

Ensure your virtual environment is activated and dependencies are installed:

```bash
source .venv/bin/activate   # macOS / Linux
pip install -r requirements.txt
```

### Findings are not appearing in output

By default, only `INFO` and above findings are included. If you used `--severity WARNING`, only `WARNING` and `ERROR` findings will appear. Lower the severity threshold if needed.

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to submit bug reports, feature requests, and pull requests.

Quick steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "Add my feature"`
4. Push the branch: `git push origin feature/my-feature`
5. Open a Pull Request against `main`

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a full history of releases and changes.

---

## License

This project is licensed under the [MIT License](LICENSE).

