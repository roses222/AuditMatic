"""Watch-folder pipeline orchestration service."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple

from config import JSON_SCAN_JOBS_DIR, PROJECT_DIR
from services.utils import ensure_project_structure, normalize_text


@dataclass
class WatchDispatch:
    """Represents one watch-folder file ready to be processed."""

    profile_name: str
    input_path: Path
    output_path: Path


@dataclass
class PipelineRuntimeStatus:
    """Describes runtime compatibility for a configured pipeline payload."""

    input_source: str
    output_action: str
    mode: str
    can_auto_run: bool
    summary: str


class WatchFolderPipelineService:
    """Manage watch-folder lifecycle, candidate selection, and dedupe state."""

    SUPPORTED_INPUT_EXTENSIONS = {".xlsx", ".xlsm"}
    STATE_FILE = JSON_SCAN_JOBS_DIR / "watch_folder_state.json"

    def __init__(self) -> None:
        self.active = False
        self.profile_name = ""
        self.watch_folder_path = Path()
        self.output_folder_path = Path()
        self.process_existing = False
        self.archive_processed = True
        self.seen_files: Set[str] = set()
        self.seen_hashes: Set[str] = set()
        self.seen_hash_meta: Dict[str, str] = {}
        self.current_file: Optional[Path] = None
        self.current_hash = ""

    @staticmethod
    def evaluate_runtime_compatibility(pipeline_payload: Dict[str, object]) -> PipelineRuntimeStatus:
        """Evaluate runtime compatibility for all configured pipeline trigger/output types."""
        if not isinstance(pipeline_payload, dict) or not pipeline_payload:
            return PipelineRuntimeStatus(
                input_source="",
                output_action="",
                mode="missing",
                can_auto_run=False,
                summary="Pipeline status: not configured",
            )

        input_source = normalize_text(pipeline_payload.get("input_source", ""))
        output_action = normalize_text(pipeline_payload.get("output_action", ""))

        if input_source in {"Watch Folder", "File Explorer Folder"}:
            if output_action == "Save to Local Folder":
                return PipelineRuntimeStatus(
                    input_source=input_source,
                    output_action=output_action,
                    mode="watch-auto",
                    can_auto_run=True,
                    summary=f"Pipeline status: auto-run enabled ({input_source} -> {output_action})",
                )
            return PipelineRuntimeStatus(
                input_source=input_source,
                output_action=output_action,
                mode="watch-manual-output",
                can_auto_run=False,
                summary=(
                    "Pipeline status: configured, but in-app auto-run currently supports "
                    "Watch Folder/File Explorer Folder -> Save to Local Folder"
                ),
            )

        if input_source in {"Email Trigger", "Ticket System Trigger", "Database Trigger", "API Trigger"}:
            return PipelineRuntimeStatus(
                input_source=input_source,
                output_action=output_action,
                mode="external-trigger",
                can_auto_run=False,
                summary=f"Pipeline status: configured ({input_source}) - external trigger flow",
            )

        return PipelineRuntimeStatus(
            input_source=input_source,
            output_action=output_action,
            mode="unknown",
            can_auto_run=False,
            summary="Pipeline status: unknown or invalid configuration",
        )

    @staticmethod
    def _resolve_dir(path_text: str) -> Path:
        """Resolve a possibly relative directory path against project root."""
        resolved = Path(normalize_text(path_text))
        if not resolved.is_absolute():
            resolved = PROJECT_DIR / resolved
        return resolved

    @staticmethod
    def _is_candidate(path: Path) -> bool:
        """Return True when file is a supported watch input candidate."""
        return path.is_file() and path.suffix.lower() in WatchFolderPipelineService.SUPPORTED_INPUT_EXTENSIONS

    @staticmethod
    def _is_stable(path: Path, min_age_seconds: int = 2) -> bool:
        """Return True when file timestamp suggests writing is complete."""
        try:
            return (datetime.now().timestamp() - path.stat().st_mtime) >= min_age_seconds
        except Exception:
            return False

    @staticmethod
    def _hash_sha256(path: Path) -> str:
        """Compute SHA-256 for file content, returning empty string on failure."""
        try:
            hasher = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def _output_path(output_dir: Path, input_path: Path) -> Path:
        """Build output workbook path for a watch-triggered run."""
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return output_dir / f"{input_path.stem}_RESULTS_{stamp}.xlsx"

    def _state_key(self) -> str:
        """Build a stable persistence key for current profile + folder pair."""
        return f"{self.profile_name}|{str(self.watch_folder_path.resolve()).lower()}"

    @staticmethod
    def _parse_hash_entries(raw_entries: object, default_timestamp: str) -> Dict[str, str]:
        """Normalize persisted hash payloads from legacy or current schema."""
        parsed: Dict[str, str] = {}
        if not isinstance(raw_entries, list):
            return parsed
        for entry in raw_entries:
            if isinstance(entry, str):
                hash_value = normalize_text(entry)
                if hash_value:
                    parsed[hash_value] = default_timestamp
                continue
            if isinstance(entry, dict):
                hash_value = normalize_text(entry.get("hash", ""))
                if not hash_value:
                    continue
                last_seen = normalize_text(entry.get("last_seen", "")) or default_timestamp
                parsed[hash_value] = last_seen
        return parsed

    @staticmethod
    def _is_recent_timestamp(timestamp_text: str, min_allowed: datetime) -> bool:
        """Return True when timestamp is parseable and within retention window."""
        try:
            return datetime.fromisoformat(timestamp_text) >= min_allowed
        except Exception:
            return False

    @staticmethod
    def _bound_hash_meta(hash_meta: Dict[str, str], max_hashes: int) -> Dict[str, str]:
        """Keep newest N hash records by last_seen timestamp."""
        if len(hash_meta) <= max_hashes:
            return hash_meta
        ordered = sorted(hash_meta.items(), key=lambda item: item[1])
        bounded_items = ordered[-max_hashes:]
        return {key: value for key, value in bounded_items}

    @classmethod
    def compact_state_file(cls, max_age_days: int = 30, max_hashes_per_profile: int = 5000) -> Dict[str, int]:
        """Compact persisted watch state by age and max hashes per profile key."""
        ensure_project_structure()
        if not cls.STATE_FILE.exists():
            return {"profiles": 0, "removed": 0}

        try:
            payload = json.loads(cls.STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {"profiles": 0, "removed": 0}

        profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
        if not isinstance(profiles, dict):
            return {"profiles": 0, "removed": 0}

        now = datetime.now()
        min_allowed = now - timedelta(days=max(1, max_age_days))
        changed = False
        total_removed = 0

        for profile_key, entry in list(profiles.items()):
            if not isinstance(entry, dict):
                profiles.pop(profile_key, None)
                changed = True
                continue

            default_timestamp = normalize_text(entry.get("updated_at", "")) or now.isoformat(timespec="seconds")
            raw_hashes = entry.get("seen_hashes", [])
            hash_meta = cls._parse_hash_entries(raw_hashes, default_timestamp)

            before_count = len(hash_meta)
            hash_meta = {
                hash_value: last_seen
                for hash_value, last_seen in hash_meta.items()
                if cls._is_recent_timestamp(last_seen, min_allowed)
            }
            hash_meta = cls._bound_hash_meta(hash_meta, max(1, max_hashes_per_profile))
            after_count = len(hash_meta)
            total_removed += max(0, before_count - after_count)

            entry["seen_hashes"] = [
                {"hash": hash_value, "last_seen": last_seen}
                for hash_value, last_seen in sorted(hash_meta.items(), key=lambda item: item[1])
            ]
            if before_count != after_count or raw_hashes != entry["seen_hashes"]:
                changed = True

        if changed:
            cls.STATE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        return {"profiles": len(profiles), "removed": total_removed}

    def _load_persisted_hashes(self) -> Tuple[Set[str], Dict[str, str]]:
        """Load previously seen hashes and metadata for this watch configuration."""
        ensure_project_structure()
        if not self.STATE_FILE.exists():
            return set(), {}
        try:
            payload = json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
            entry = profiles.get(self._state_key(), {}) if isinstance(profiles, dict) else {}
            hashes = entry.get("seen_hashes", []) if isinstance(entry, dict) else []
            default_timestamp = normalize_text(entry.get("updated_at", "")) or datetime.now().isoformat(timespec="seconds")
            hash_meta = self._parse_hash_entries(hashes, default_timestamp)
            return set(hash_meta.keys()), hash_meta
        except Exception:
            return set(), {}

    def _touch_hash(self, hash_value: str, timestamp_text: Optional[str] = None) -> None:
        """Record hash with last-seen timestamp for persistence."""
        normalized = normalize_text(hash_value)
        if not normalized:
            return
        self.seen_hashes.add(normalized)
        self.seen_hash_meta[normalized] = timestamp_text or datetime.now().isoformat(timespec="seconds")

    def _save_persisted_hashes(self) -> None:
        """Persist seen hashes for this watch configuration."""
        ensure_project_structure()
        payload: Dict[str, object] = {"profiles": {}}
        if self.STATE_FILE.exists():
            try:
                existing = json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
                if isinstance(existing, dict):
                    payload = existing
            except Exception:
                payload = {"profiles": {}}

        profiles = payload.setdefault("profiles", {})
        if not isinstance(profiles, dict):
            profiles = {}
            payload["profiles"] = profiles

        bounded_meta = self._bound_hash_meta(self.seen_hash_meta, 5000)
        self.seen_hash_meta = bounded_meta
        self.seen_hashes = set(bounded_meta.keys())
        serialized_hashes: List[Dict[str, str]] = [
            {"hash": hash_value, "last_seen": last_seen}
            for hash_value, last_seen in sorted(bounded_meta.items(), key=lambda item: item[1])
        ]

        profiles[self._state_key()] = {
            "profile_name": self.profile_name,
            "watch_folder": str(self.watch_folder_path),
            "updated_at": datetime.now().isoformat(timespec="seconds"),
            "seen_hashes": serialized_hashes,
        }
        self.STATE_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _archive_current_file(self, logger: Callable[[str], None]) -> None:
        """Move processed file into watch-folder processed subdirectory."""
        if not self.current_file or not self.current_file.exists() or not self.archive_processed:
            return
        try:
            archive_dir = self.watch_folder_path / "processed"
            archive_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            target_path = archive_dir / f"{self.current_file.stem}_{stamp}{self.current_file.suffix}"
            shutil.move(str(self.current_file), str(target_path))
            logger(f"Watch folder archived input: {target_path}")
        except Exception as exc:
            logger(f"Watch folder archive warning: {exc}")

    def start(
        self,
        profile_name: str,
        pipeline_payload: Dict[str, object],
        logger: Callable[[str], None],
        process_existing: bool,
        archive_processed: bool,
    ) -> None:
        """Start watching based on profile pipeline config."""
        selected_profile = normalize_text(profile_name)
        if not selected_profile:
            raise ValueError("Select a profile first.")

        input_source = normalize_text(pipeline_payload.get("input_source", ""))
        if input_source not in {"Watch Folder", "File Explorer Folder"}:
            raise ValueError("Pipeline input type/source must be Watch Folder.")

        input_config = pipeline_payload.get("input_config", {})
        if not isinstance(input_config, dict):
            input_config = {}
        watch_folder_raw = normalize_text(input_config.get("folder", ""))
        if not watch_folder_raw:
            raise ValueError("Pipeline watch folder is not configured.")

        output_action = normalize_text(pipeline_payload.get("output_action", ""))
        if output_action != "Save to Local Folder":
            raise ValueError("Watch runner currently supports output action Save to Local Folder only.")

        output_config = pipeline_payload.get("output_config", {})
        if not isinstance(output_config, dict):
            output_config = {}
        output_folder_raw = normalize_text(output_config.get("folder", ""))
        if not output_folder_raw:
            raise ValueError("Pipeline output folder is not configured.")

        self.profile_name = selected_profile
        self.watch_folder_path = self._resolve_dir(watch_folder_raw)
        self.output_folder_path = self._resolve_dir(output_folder_raw)
        self.watch_folder_path.mkdir(parents=True, exist_ok=True)
        self.output_folder_path.mkdir(parents=True, exist_ok=True)

        self.process_existing = bool(process_existing)
        self.archive_processed = bool(archive_processed)
        self.active = True
        self.current_file = None
        self.current_hash = ""
        self.seen_files = set()
        compact_results = self.compact_state_file(max_age_days=30, max_hashes_per_profile=5000)
        self.seen_hashes, self.seen_hash_meta = self._load_persisted_hashes()
        if compact_results.get("removed", 0):
            logger(
                f"Watch state compacted: removed={compact_results.get('removed', 0)} hashes across "
                f"{compact_results.get('profiles', 0)} profile entries"
            )

        if not self.process_existing:
            for path in self.watch_folder_path.glob("*"):
                if not self._is_candidate(path):
                    continue
                self.seen_files.add(str(path.resolve()))
                hash_value = self._hash_sha256(path)
                if hash_value:
                    self._touch_hash(hash_value)

        self._save_persisted_hashes()
        logger(
            f"Watch folder started -> profile={self.profile_name} | input={self.watch_folder_path} | "
            f"output={self.output_folder_path} | process_existing={self.process_existing} | archive={self.archive_processed}"
        )

    def stop(self, logger: Callable[[str], None]) -> None:
        """Stop watch mode and persist current dedupe state."""
        self.active = False
        self.current_file = None
        self.current_hash = ""
        self._save_persisted_hashes()
        logger("Watch folder stopped.")

    def poll(self, is_busy: bool, logger: Callable[[str], None]) -> Optional[WatchDispatch]:
        """Poll for work and return next dispatch when available."""
        if not self.active:
            return None

        # Complete in-flight bookkeeping when run is done.
        if self.current_file is not None and not is_busy:
            if self.current_hash:
                self._touch_hash(self.current_hash)
            self._archive_current_file(logger)
            self.current_file = None
            self.current_hash = ""
            self._save_persisted_hashes()
            logger("Watch folder ready for next file.")

        if is_busy:
            return None

        candidates = sorted(
            [path for path in self.watch_folder_path.glob("*") if self._is_candidate(path)],
            key=lambda p: p.stat().st_mtime,
        )
        for candidate in candidates:
            resolved = str(candidate.resolve())
            if resolved in self.seen_files:
                continue
            if not self._is_stable(candidate):
                continue

            hash_value = self._hash_sha256(candidate)
            if hash_value and hash_value in self.seen_hashes:
                self.seen_files.add(resolved)
                self._touch_hash(hash_value)
                logger(f"Watch folder skipped duplicate content: {candidate}")
                continue

            self.seen_files.add(resolved)
            self.current_file = candidate
            self.current_hash = hash_value
            dispatch = WatchDispatch(
                profile_name=self.profile_name,
                input_path=candidate,
                output_path=self._output_path(self.output_folder_path, candidate),
            )
            return dispatch

        return None
