"""
Test script to monkey-patch VM and SSH connection logic for sbl_audit_gui_v_2000.py.
Allows GUI testing without real infrastructure.
"""
import sbl_audit_gui_v_2000

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

print("[INFO] Monkey-patching complete. Launching GUI...")

if __name__ == "__main__":
    sbl_audit_gui_v_2000.main()
