"""Unit tests for pipeline runtime compatibility classification."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.watch_pipeline_service import WatchFolderPipelineService


class PipelineRuntimeCompatibilityTests(unittest.TestCase):
    def test_missing_pipeline_payload(self) -> None:
        runtime = WatchFolderPipelineService.evaluate_runtime_compatibility({})
        self.assertFalse(runtime.can_auto_run)
        self.assertEqual(runtime.mode, "missing")

    def test_watch_folder_local_output_is_auto_runnable(self) -> None:
        runtime = WatchFolderPipelineService.evaluate_runtime_compatibility(
            {
                "input_source": "Watch Folder",
                "output_action": "Save to Local Folder",
            }
        )
        self.assertTrue(runtime.can_auto_run)
        self.assertEqual(runtime.mode, "watch-auto")

    def test_watch_folder_non_local_output_is_recognized_but_manual(self) -> None:
        runtime = WatchFolderPipelineService.evaluate_runtime_compatibility(
            {
                "input_source": "Watch Folder",
                "output_action": "Send Email",
            }
        )
        self.assertFalse(runtime.can_auto_run)
        self.assertEqual(runtime.mode, "watch-manual-output")

    def test_external_trigger_modes_are_classified(self) -> None:
        for input_source in ["Email Trigger", "Ticket System Trigger", "Database Trigger", "API Trigger"]:
            runtime = WatchFolderPipelineService.evaluate_runtime_compatibility(
                {
                    "input_source": input_source,
                    "output_action": "Write to Database",
                }
            )
            self.assertFalse(runtime.can_auto_run)
            self.assertEqual(runtime.mode, "external-trigger")


if __name__ == "__main__":
    unittest.main()
