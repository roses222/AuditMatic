"""Integration-style tests for watch-folder orchestration service."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.watch_pipeline_service import WatchFolderPipelineService


class WatchPipelineServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.watch_dir = self.root / "watch"
        self.output_dir = self.root / "out"
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.root / "watch_state.json"
        self.logs: list[str] = []

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _pipeline_payload(self) -> dict:
        return {
            "input_source": "Watch Folder",
            "input_config": {"folder": str(self.watch_dir)},
            "output_action": "Save to Local Folder",
            "output_config": {"folder": str(self.output_dir)},
        }

    def _create_file(self, name: str, content: bytes) -> Path:
        path = self.watch_dir / name
        path.write_bytes(content)
        # Make file stable for watch candidate checks.
        current = path.stat().st_mtime
        os.utime(path, (current - 5, current - 5))
        return path

    def _new_service(self) -> WatchFolderPipelineService:
        service = WatchFolderPipelineService()
        service.STATE_FILE = self.state_file
        return service

    def test_start_without_process_existing_marks_existing_files_as_seen(self) -> None:
        existing = self._create_file("existing.xlsx", b"existing-workbook")
        service = self._new_service()

        service.start(
            profile_name="local_watch_profile",
            pipeline_payload=self._pipeline_payload(),
            logger=self.logs.append,
            process_existing=False,
            archive_processed=False,
        )

        self.assertTrue(service.active)
        self.assertIn(str(existing.resolve()), service.seen_files)
        self.assertTrue(self.state_file.exists())

    def test_hash_dedupe_persists_across_restart(self) -> None:
        file_one = self._create_file("first.xlsx", b"same-content")
        service = self._new_service()

        service.start(
            profile_name="local_watch_profile",
            pipeline_payload=self._pipeline_payload(),
            logger=self.logs.append,
            process_existing=True,
            archive_processed=False,
        )

        dispatch = service.poll(is_busy=False, logger=self.logs.append)
        self.assertIsNotNone(dispatch)
        if dispatch is None:
            self.fail("Expected dispatch for first watch candidate")
        self.assertEqual(dispatch.input_path.resolve(), file_one.resolve())

        # Simulate active audit run, then completion on next poll.
        self.assertIsNone(service.poll(is_busy=True, logger=self.logs.append))
        self.assertIsNone(service.poll(is_busy=False, logger=self.logs.append))
        service.stop(self.logs.append)

        # Restart service and drop duplicate content under a new filename.
        self.logs.clear()
        self._create_file("duplicate.xlsx", b"same-content")
        restarted = self._new_service()
        restarted.start(
            profile_name="local_watch_profile",
            pipeline_payload=self._pipeline_payload(),
            logger=self.logs.append,
            process_existing=True,
            archive_processed=False,
        )

        self.assertIsNone(restarted.poll(is_busy=False, logger=self.logs.append))
        self.assertTrue(any("skipped duplicate content" in msg.lower() for msg in self.logs))

    def test_archive_processed_moves_file_after_run(self) -> None:
        source_file = self._create_file("to_archive.xlsx", b"archive-me")
        service = self._new_service()
        service.start(
            profile_name="local_watch_profile",
            pipeline_payload=self._pipeline_payload(),
            logger=self.logs.append,
            process_existing=True,
            archive_processed=True,
        )

        dispatch = service.poll(is_busy=False, logger=self.logs.append)
        self.assertIsNotNone(dispatch)

        # Simulate completion of a run that consumed the dispatched workbook.
        self.assertIsNone(service.poll(is_busy=True, logger=self.logs.append))
        self.assertIsNone(service.poll(is_busy=False, logger=self.logs.append))

        processed_dir = self.watch_dir / "processed"
        archived = list(processed_dir.glob("to_archive_*.xlsx"))
        self.assertFalse(source_file.exists())
        self.assertEqual(len(archived), 1)


if __name__ == "__main__":
    unittest.main()
