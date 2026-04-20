"""Unit tests for watch state-file compaction and legacy format migration."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.watch_pipeline_service import WatchFolderPipelineService


class WatchStateCompactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.state_file = self.root / "watch_folder_state.json"
        self.original_state_file = WatchFolderPipelineService.STATE_FILE
        WatchFolderPipelineService.STATE_FILE = self.state_file

    def tearDown(self) -> None:
        WatchFolderPipelineService.STATE_FILE = self.original_state_file
        self.temp_dir.cleanup()

    def _write_state(self, payload: dict) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.state_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_compaction_migrates_legacy_string_hashes(self) -> None:
        now = datetime.now().isoformat(timespec="seconds")
        payload = {
            "profiles": {
                "key-a": {
                    "profile_name": "p1",
                    "watch_folder": "C:/watch",
                    "updated_at": now,
                    "seen_hashes": ["hash-1", "hash-2"],
                }
            }
        }
        self._write_state(payload)

        result = WatchFolderPipelineService.compact_state_file(max_age_days=30, max_hashes_per_profile=100)
        self.assertEqual(result["profiles"], 1)

        saved = json.loads(self.state_file.read_text(encoding="utf-8"))
        entries = saved["profiles"]["key-a"]["seen_hashes"]
        self.assertTrue(all(isinstance(item, dict) for item in entries))
        self.assertEqual({item["hash"] for item in entries}, {"hash-1", "hash-2"})

    def test_compaction_prunes_old_and_bounds_count(self) -> None:
        now = datetime.now()
        old_time = (now - timedelta(days=90)).isoformat(timespec="seconds")
        recent_times = [
            (now - timedelta(days=idx)).isoformat(timespec="seconds")
            for idx in [1, 2, 3, 4]
        ]

        payload = {
            "profiles": {
                "key-b": {
                    "profile_name": "p2",
                    "watch_folder": "C:/watch2",
                    "updated_at": now.isoformat(timespec="seconds"),
                    "seen_hashes": [
                        {"hash": "old-hash", "last_seen": old_time},
                        {"hash": "recent-1", "last_seen": recent_times[0]},
                        {"hash": "recent-2", "last_seen": recent_times[1]},
                        {"hash": "recent-3", "last_seen": recent_times[2]},
                        {"hash": "recent-4", "last_seen": recent_times[3]},
                    ],
                }
            }
        }
        self._write_state(payload)

        result = WatchFolderPipelineService.compact_state_file(max_age_days=30, max_hashes_per_profile=2)
        self.assertGreaterEqual(result["removed"], 3)

        saved = json.loads(self.state_file.read_text(encoding="utf-8"))
        hashes = [item["hash"] for item in saved["profiles"]["key-b"]["seen_hashes"]]
        self.assertEqual(len(hashes), 2)
        self.assertNotIn("old-hash", hashes)


if __name__ == "__main__":
    unittest.main()
