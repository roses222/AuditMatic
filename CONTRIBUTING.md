# Contributing to AuditMatic

Thank you for your interest in contributing to AuditMatic! This document outlines the process for reporting issues, suggesting improvements, and submitting code changes.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Report a Bug](#how-to-report-a-bug)
- [How to Request a Feature](#how-to-request-a-feature)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Commit Message Guidelines](#commit-message-guidelines)

---

## Code of Conduct

Please be respectful and constructive in all interactions. We expect contributors to follow common open-source norms: inclusive language, good-faith feedback, and collaborative problem-solving.

---

## How to Report a Bug

1. **Search existing issues** first to avoid duplicates.
2. If no existing issue covers your problem, [open a new issue](https://github.com/roses222/AuditMatic/issues/new).
3. Include the following in your report:
   - AuditMatic version (`auditmatic --version`)
   - Python version (`python --version`)
   - Operating system
   - Steps to reproduce the problem
   - Expected behavior vs. actual behavior
   - Any relevant output or error messages

---

## How to Request a Feature

1. [Open a new issue](https://github.com/roses222/AuditMatic/issues/new) and label it `enhancement`.
2. Describe the feature, the use case it solves, and any alternative approaches you considered.

---

## Development Setup

```bash
# 1. Fork and clone the repository
git clone https://github.com/<your-username>/AuditMatic.git
cd AuditMatic

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate    # macOS / Linux
.venv\Scripts\activate       # Windows

# 3. Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt   # linting, testing tools
```

---

## Submitting a Pull Request

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes, following the [coding standards](#coding-standards) below.
3. Add or update tests for your changes (see [Testing](#testing)).
4. Run the test suite and confirm all tests pass.
5. Push your branch and open a Pull Request against `main`.
6. Fill in the PR template — describe what changed and why.
7. A maintainer will review your PR and may request changes before merging.

---

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) style for Python code.
- Use type hints for all function signatures.
- Keep functions focused and small; prefer composition over large monolithic functions.
- Add docstrings (Google style) to all public classes, methods, and functions.
- Do not introduce new dependencies without discussion in an issue first.

---

## Testing

AuditMatic uses `pytest`. To run the test suite:

```bash
pytest tests/ -v
```

To run a specific test file:

```bash
pytest tests/test_validators.py -v
```

All new features and bug fixes must include corresponding tests in the `tests/` directory.

---

## Commit Message Guidelines

Use the [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <short description>
```

Common types:

| Type | When to use |
|---|---|
| `feat` | A new feature |
| `fix` | A bug fix |
| `docs` | Documentation changes only |
| `test` | Adding or updating tests |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `chore` | Maintenance tasks (dependency updates, build scripts, etc.) |

Examples:

```
feat(validators): add regex validator for custom patterns
fix(ingestor): handle BOM encoding in UTF-8 CSV files
docs(readme): clarify date format configuration
```
