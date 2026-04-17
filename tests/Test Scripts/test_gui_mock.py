"""
Test script to monkey-patch VM and SSH connection logic for sbl_audit_gui_v_2000.py.
Allows GUI testing without real infrastructure.
"""
import sys
import json
from datetime import datetime
from pathlib import Path

# Allow running this file directly from the tests folder.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import sbl_audit_gui_v_2000


def ensure_mock_profile() -> None:
    profiles_dir = sbl_audit_gui_v_2000.PROFILES_DIR
    profiles_dir.mkdir(parents=True, exist_ok=True)
    existing_profiles = list(profiles_dir.glob("*.json"))
    if existing_profiles:
        print(f"[INFO] Found {len(existing_profiles)} existing profile(s); using existing profiles.")
        return

    targets = {}
    for target_name in sbl_audit_gui_v_2000.SYSTEM_COLUMNS:
        targets[target_name] = {
            "vm_name": sbl_audit_gui_v_2000.LOCAL_SENTINEL,
            "username": "",
            "password": "",
            "os_type": "windows",
        }

    profile_payload = {
        "profile_name": "mock_local_profile",
        "updated_at": datetime.now().isoformat(timespec="seconds"),
        "vcenter_server": "",
        "ignore_ssl": True,
        "targets": targets,
        "last_verified": "",
    }

    profile_path = profiles_dir / "mock_local_profile.json"
    profile_path.write_text(json.dumps(profile_payload, indent=2), encoding="utf-8")
    print(f"[INFO] Created mock profile for test GUI: {profile_path}")

# --- Mock vSphere connection ---
def mock_vsphere_connect(self, *args, **kwargs):
    print("[MOCK] vSphere connection established.")
    self.si = True
    return True

def mock_vsphere_list_windows_vms(self, *args, **kwargs):
    print("[MOCK] Returning fake VM list.")
    return [sbl_audit_gui_v_2000.LOCAL_SENTINEL, "TestVM01", "TestVM02"]

def mock_vsphere_verify_vm_names(self, vm_names):
    print(f"[MOCK] Verifying VMs: {vm_names}")
    return {name: {"power_state": "MOCKED", "tools_status": "MOCKED", "guest_os": "MOCKED"} for name in vm_names}

# --- Mock SSH connection ---
def mock_ssh_run_powershell(self, target_host, script, timeout_seconds=90):
    print(f"[MOCK] SSH run_powershell on {target_host} with script: {script}")
    return ("PASS", "MOCKED_OUTPUT", f"SSH PowerShell completed on '{target_host}' (mock)")

# --- Mock local scan logic ---
def mock_run_local_powershell(self, command):
    print(f"[MOCK] Local run_powershell: {command}")
    return ("PASS", "MOCKED_LOCAL_OUTPUT", "Local PowerShell completed (mock)")

# Patch VSphereService
sbl_audit_gui_v_2000.VSphereService.connect = mock_vsphere_connect
sbl_audit_gui_v_2000.VSphereService.list_windows_vms = mock_vsphere_list_windows_vms
sbl_audit_gui_v_2000.VSphereService.verify_vm_names = mock_vsphere_verify_vm_names
# Patch SSHTunnelService
sbl_audit_gui_v_2000.SSHTunnelService.run_powershell = mock_ssh_run_powershell
# Patch any local scan logic if present
if hasattr(sbl_audit_gui_v_2000, 'run_local_powershell'):
    sbl_audit_gui_v_2000.run_local_powershell = mock_run_local_powershell
# Patch on AuditFrame if method exists
if hasattr(sbl_audit_gui_v_2000, 'AuditFrame'):
    setattr(sbl_audit_gui_v_2000.AuditFrame, 'run_local_powershell', mock_run_local_powershell)

ensure_mock_profile()

print("[INFO] Monkey-patching complete. Launching GUI...")

if __name__ == "__main__":
    sbl_audit_gui_v_2000.main()
