"""Master software list management and persistence service."""

import copy
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import MASTER_SOFTWARE_LIST_PATH, SYSTEM_COLUMNS
from services.utils import (
    _empty_master_software_list_payload,
    _new_model_bucket,
    default_target_columns,
    normalize_text,
    normalize_model_key,
    ensure_project_structure,
    derive_path_metadata,
    derive_path_metadata,
)


class MasterSoftwarePathService:
    def __init__(self, path: Path = MASTER_SOFTWARE_LIST_PATH):
        """Initialize the MasterSoftwarePathService instance."""
        self.path = path
        ensure_project_structure()

    def load(self) -> Dict[str, Any]:
        """Load."""
        if not self.path.exists():
            self.path.write_text(json.dumps(_empty_master_software_list_payload(), indent=2), encoding="utf-8")

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        changed = False

        if "SBL_models" not in payload or not isinstance(payload.get("SBL_models"), dict):
            legacy_model = normalize_model_key(payload.get("sbl_model"))
            payload = {
                "SBL_models": {
                    legacy_model: {
                        "software_components": payload.get("software_components", {}),
                        "vm_components": payload.get("vm_components", {}),
                    }
                },
                "updated_at": datetime.now().isoformat(timespec="seconds"),
            }
            changed = True

        models = payload.setdefault("SBL_models", {})
        if "GENERAL" not in models:
            models["GENERAL"] = _new_model_bucket()
            changed = True

        for model_name, model_bucket in list(models.items()):
            if not isinstance(model_bucket, dict):
                models[model_name] = _new_model_bucket()
                model_bucket = models[model_name]
                changed = True

            bucket = model_bucket.setdefault("software_components", {})
            vm_bucket = model_bucket.setdefault("vm_components", {})

            if not isinstance(bucket, dict):
                model_bucket["software_components"] = {}
                bucket = model_bucket["software_components"]
                changed = True
            if not isinstance(vm_bucket, dict):
                model_bucket["vm_components"] = {}
                vm_bucket = model_bucket["vm_components"]
                changed = True

            target_columns = list(vm_bucket.keys()) or default_target_columns()
            for vm_name in target_columns:
                vm_entry = vm_bucket.get(vm_name)
                if not isinstance(vm_entry, dict):
                    vm_entry = {}
                    vm_bucket[vm_name] = vm_entry
                    changed = True
                if "vm_name" not in vm_entry:
                    vm_entry["vm_name"] = ""
                    changed = True
                if "os_type" not in vm_entry:
                    vm_entry["os_type"] = "windows"
                    changed = True
                if "tracked_software" not in vm_entry or not isinstance(vm_entry.get("tracked_software"), list):
                    vm_entry["tracked_software"] = []
                    changed = True

            for component, entry in list(bucket.items()):
                if not isinstance(entry, dict):
                    entry = {}
                    bucket[component] = entry
                    changed = True

                path_value = entry.get("path", entry.get("display_path", ""))
                meta = derive_path_metadata(path_value)

                defaults = {
                    "generic_name": entry.get("generic_name", component),
                    "registry_name": entry.get("registry_name", ""),
                    "path": meta["path"],
                    "coded_path": meta["coded_path"],
                    "verification_source": entry.get("verification_source", entry.get("verification_rule", meta["verification_source"])),
                    "path_last_verified_date": entry.get("path_last_verified_date", ""),
                    "notes": entry.get("notes", ""),
                    "tracked_in_vms": entry.get("tracked_in_vms", entry.get("verified_targets", [])),
                }

                for key, value in defaults.items():
                    if key not in entry:
                        entry[key] = value
                        changed = True

                if entry.get("coded_path") == "PROGRAMS_AND_FEATURES":
                    entry["coded_path"] = meta["coded_path"]
                    changed = True

                if not isinstance(entry.get("tracked_in_vms", []), list):
                    entry["tracked_in_vms"] = []
                    changed = True

                if not entry.get("tracked_in_vms"):
                    note_text = normalize_text(entry.get("notes", ""))
                    legacy_match = re.match(r"^Verified via\s+(.+)$", note_text, flags=re.IGNORECASE)
                    if legacy_match:
                        target = legacy_match.group(1).strip()
                        if target:
                            entry["tracked_in_vms"] = [target]
                            entry["notes"] = f"Tracked in VMs: {target}"
                            changed = True

                note_text = normalize_text(entry.get("notes", ""))
                if note_text.upper().startswith("VERIFIED VIA TARGETS:"):
                    vm_text = note_text.split(":", 1)[1].strip()
                    entry["notes"] = f"Tracked in VMs: {vm_text}"
                    changed = True

                for legacy_key in ("verified_targets", "verification_rule", "display_path", "last_verified_target", "last_scan_status"):
                    if legacy_key in entry:
                        del entry[legacy_key]
                        changed = True

                tracked_vms = entry.get("tracked_in_vms", [])
                if isinstance(tracked_vms, list):
                    for vm_name in tracked_vms:
                        if vm_name not in SYSTEM_COLUMNS:
                            continue
                        vm_entry = vm_bucket.setdefault(vm_name, {"vm_name": "", "os_type": "windows", "tracked_software": []})
                        tracked_software = vm_entry.get("tracked_software", [])
                        if not isinstance(tracked_software, list):
                            tracked_software = []
                        if component not in tracked_software:
                            tracked_software.append(component)
                            vm_entry["tracked_software"] = tracked_software
                            changed = True

        if "updated_at" not in payload:
            payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
            changed = True

        if changed:
            self.save(payload)
        return payload

    def save(self, payload: Dict[str, Any]) -> None:
        """Save."""
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def update_component(
        self,
        software_component: str,
        path_value: str,
        target_name: str = "",
        scan_status: str = "",
        notes: str = "",
        model_name: str = "",
    ) -> None:
        """Update component."""
        payload = self.load()
        model_key = normalize_model_key(model_name)
        models = payload.setdefault("SBL_models", {})
        model_bucket = models.setdefault(model_key, _new_model_bucket())
        bucket = model_bucket.setdefault("software_components", {})
        vm_bucket = model_bucket.setdefault("vm_components", {})
        existing_entry = bucket.get(software_component)
        path_meta = derive_path_metadata(path_value)
        is_new_component = not isinstance(existing_entry, dict)

        if is_new_component:
            tracked_vms: List[str] = []
            is_vm_target = target_name in SYSTEM_COLUMNS
            if is_vm_target:
                tracked_vms.append(target_name)
                vm_entry = vm_bucket.get(target_name)
                if not isinstance(vm_entry, dict):
                    vm_entry = {"vm_name": "", "os_type": "windows", "tracked_software": []}
                tracked_software = vm_entry.get("tracked_software", [])
                if not isinstance(tracked_software, list):
                    tracked_software = []
                if software_component and software_component not in tracked_software:
                    tracked_software.append(software_component)
                vm_entry["tracked_software"] = tracked_software
                vm_entry.setdefault("vm_name", "")
                vm_entry.setdefault("os_type", "windows")
                vm_bucket[target_name] = vm_entry

            entry = {
                "generic_name": software_component,
                "registry_name": "",
                "path": path_meta["path"],
                "coded_path": path_meta["coded_path"],
                "verification_source": path_meta["verification_source"],
                "path_last_verified_date": datetime.now().isoformat(timespec="seconds"),
                "notes": notes or (f"Tracked in VMs: {', '.join(tracked_vms)}" if tracked_vms else ""),
                "tracked_in_vms": tracked_vms,
            }
            bucket[software_component] = entry
            payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
            self.save(payload)
            return

        old_path = normalize_text(existing_entry.get("path", ""))
        old_coded = normalize_text(existing_entry.get("coded_path", ""))
        old_source = normalize_text(existing_entry.get("verification_source", ""))
        new_path = normalize_text(path_meta["path"])
        new_coded = normalize_text(path_meta["coded_path"])
        new_source = normalize_text(path_meta["verification_source"])

        location_changed = old_path != new_path or old_coded != new_coded or old_source != new_source
        if not location_changed:
            return

        existing_entry["path"] = path_meta["path"]
        existing_entry["coded_path"] = path_meta["coded_path"]
        existing_entry["verification_source"] = path_meta["verification_source"]
        existing_entry["path_last_verified_date"] = datetime.now().isoformat(timespec="seconds")
        bucket[software_component] = existing_entry
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        self.save(payload)
