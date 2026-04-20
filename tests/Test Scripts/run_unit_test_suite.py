"""Run AuditMatic unit tests and emit a structured report artifact."""

from __future__ import annotations

import importlib.util
import json
import sys
import time
import unittest
from datetime import datetime
from pathlib import Path
from typing import Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_SCRIPTS_DIR = PROJECT_ROOT / "tests" / "Test Scripts"
REPORTS_DIR = PROJECT_ROOT / "tests" / "reports"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


TEST_FILES = [
    TEST_SCRIPTS_DIR / "test_watch_pipeline_service.py",
    TEST_SCRIPTS_DIR / "test_pipeline_runtime_compatibility.py",
    TEST_SCRIPTS_DIR / "test_watch_state_compaction.py",
    TEST_SCRIPTS_DIR / "test_remote_scan_mocked.py",
]


def _load_test_module(file_path: Path):
    module_name = f"auditmatic_unit_{file_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load test module: {file_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _collect_suite() -> unittest.TestSuite:
    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    for file_path in TEST_FILES:
        if not file_path.exists():
            raise FileNotFoundError(f"Configured test file not found: {file_path}")
        module = _load_test_module(file_path)
        suite.addTests(loader.loadTestsFromModule(module))
    return suite


def _test_ids(items: List[tuple]) -> List[str]:
    return [case.id() for case, _ in items]


def _build_report(result: unittest.TestResult, started_at: float, duration: float) -> Dict[str, object]:
    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(getattr(result, "skipped", []))
    expected_failures = len(getattr(result, "expectedFailures", []))
    unexpected_successes = len(getattr(result, "unexpectedSuccesses", []))
    passed = total - failures - errors - skipped - expected_failures - unexpected_successes

    return {
        "started_at": datetime.fromtimestamp(started_at).isoformat(timespec="seconds"),
        "finished_at": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 3),
        "summary": {
            "total": total,
            "passed": passed,
            "failures": failures,
            "errors": errors,
            "skipped": skipped,
            "expected_failures": expected_failures,
            "unexpected_successes": unexpected_successes,
            "success": result.wasSuccessful(),
        },
        "details": {
            "failure_tests": _test_ids(result.failures),
            "error_tests": _test_ids(result.errors),
            "skipped_tests": _test_ids(getattr(result, "skipped", [])),
            "expected_failure_tests": _test_ids(getattr(result, "expectedFailures", [])),
            "unexpected_success_tests": [case.id() for case in getattr(result, "unexpectedSuccesses", [])],
            "test_files": [str(path.relative_to(PROJECT_ROOT)) for path in TEST_FILES],
        },
    }


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    suite = _collect_suite()
    started_at = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    duration = time.time() - started_at

    report_payload = _build_report(result, started_at, duration)
    report_name = f"unit_test_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
    report_path = REPORTS_DIR / report_name
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")

    print(f"\n[REPORT] {report_path}")
    print(json.dumps(report_payload["summary"], indent=2))

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
