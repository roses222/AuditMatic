# Changelog

All notable changes to AuditMatic are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

---

## [2.0.0.0] — Current

### Added
- Rule-based validation engine with pluggable validator modules.
- Built-in validators: type checking, null detection, range validation, duplicate detection, email format, URL format, and enum membership.
- Support for CSV, JSON, Excel (`.xlsx`), and plain-text (`.txt`) input formats.
- Three output formats: Markdown summary, JSON audit log, and CSV findings export.
- Severity classification system: `INFO`, `WARNING`, and `ERROR`.
- `auditmatic init` command to scaffold a starter configuration file.
- `--fail-on-error` flag for CI/CD pipeline integration.
- Nullable type support (append `?` to any type keyword, e.g., `string?`).
- Configurable date and datetime format strings.
- Configurable output directory via `output_dir` in the configuration file.

---

## [1.x.x.x] — Legacy

> Release notes for versions prior to 2.0.0.0 are not available in this repository.
> See the project's original documentation or release archives if you need information about earlier versions.

---

*For unreleased changes, see the [open pull requests](https://github.com/roses222/AuditMatic/pulls) and [commit history](https://github.com/roses222/AuditMatic/commits/main).*
