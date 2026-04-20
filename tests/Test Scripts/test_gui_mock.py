"""
Test script to monkey-patch the extracted AuditMatic GUI and services.
Allows GUI testing without real infrastructure.
"""
import sys
import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

# Allow running this file directly from the tests folder.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import main as auditmatic_main
from config import LOCAL_SENTINEL, PROFILES_DIR, SYSTEM_COLUMNS
from services.audit_engine import LocalWindowsScanner
from services.profile_service import SSHTunnelService, VSphereService
from ui.frames import AuditFrame


FIXTURES_PROFILES_DIR = PROJECT_ROOT / "fixtures" / "profiles"


def _sync_fixture_profiles() -> int:
    """Force-sync fixture profiles into runtime profile folder when present."""
    if not FIXTURES_PROFILES_DIR.exists():
        return 0

    synced = 0
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    for fixture_profile in FIXTURES_PROFILES_DIR.glob("*.json"):
        destination = PROFILES_DIR / fixture_profile.name
        shutil.copy2(fixture_profile, destination)
        synced += 1
    return synced


def ensure_mock_profile() -> None:
    synced = _sync_fixture_profiles()
    if synced:
        print(f"[INFO] Synced {synced} profile(s) from fixtures into runtime profiles: {FIXTURES_PROFILES_DIR}")

    profiles_dir = PROFILES_DIR
    profiles_dir.mkdir(parents=True, exist_ok=True)
    existing_profiles = list(profiles_dir.glob("*.json"))
    if existing_profiles:
        print(f"[INFO] Found {len(existing_profiles)} existing profile(s); using existing profiles.")
        return

    targets = {}
    for target_name in SYSTEM_COLUMNS:
        targets[target_name] = {
            "vm_name": LOCAL_SENTINEL,
            "username": "",
            "password": "",
            "os_type": "windows",
        }

    profile_payload = {
        "profile_name": "mock_local_watchfolder_pipeline_profile",
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "vcenter_server": "",
        "ignore_ssl": True,
        "ssh_tunnel": {
            "gateway_host": "",
            "gateway_port": 22,
            "gateway_username": "",
            "gateway_password": "",
            "target_port": 22,
        },
        "targets": targets,
        "last_verified": "",
    }

    profile_path = profiles_dir / "mock_local_watchfolder_pipeline_profile.json"
    profile_path.write_text(json.dumps(profile_payload, indent=2), encoding="utf-8")
    print(f"[INFO] Created fallback mock profile for test GUI: {profile_path}")

# --- Mock vSphere connection ---
def mock_vsphere_connect(self, *args: Any, **kwargs: Any):
    print("[MOCK] vSphere connection established.")
    self.si = True
    return self.si

def mock_vsphere_list_windows_vms(self, *args: Any, **kwargs: Any):
    print("[MOCK] Returning fake VM list.")
    return [LOCAL_SENTINEL, "TestVM01", "TestVM02"]

def mock_vsphere_verify_vm_names(self, vm_names):
    print(f"[MOCK] Verifying VMs: {vm_names}")
    return {name: {"power_state": "MOCKED", "tools_status": "MOCKED", "guest_os": "MOCKED"} for name in vm_names}

# --- Mock SSH connection ---
def mock_ssh_run_powershell(self, target_host, script, timeout_seconds=90, target_username="", target_password=""):
    print(f"[MOCK] SSH run_powershell on {target_host} with script: {script}")
    return ("PASS", "MOCKED_OUTPUT", f"SSH PowerShell completed on '{target_host}' (mock)")

# --- Mock local scan logic ---
def mock_run_local_powershell(self, command):
    print(f"[MOCK] Local run_powershell: {command}")
    return ("PASS", "MOCKED_LOCAL_OUTPUT", "Local PowerShell completed (mock)")

# Patch services used by the extracted UI.
setattr(VSphereService, "connect", mock_vsphere_connect)
setattr(VSphereService, "list_windows_vms", mock_vsphere_list_windows_vms)
setattr(VSphereService, "verify_vm_names", mock_vsphere_verify_vm_names)
setattr(SSHTunnelService, "run_powershell", mock_ssh_run_powershell)
setattr(LocalWindowsScanner, "run_powershell", mock_run_local_powershell)
if hasattr(AuditFrame, 'run_local_powershell'):
    setattr(AuditFrame, 'run_local_powershell', mock_run_local_powershell)

ensure_mock_profile()

print("[INFO] Monkey-patching complete. Launching GUI...")

if __name__ == "__main__":
    try:
        auditmatic_main.main()
    except KeyboardInterrupt:
        print("[INFO] GUI run interrupted by user; exiting test launcher cleanly.")
