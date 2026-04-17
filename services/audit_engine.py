"""Main audit execution engine for scanning and version comparison."""

import copy
import platform
import re
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import winreg
except ImportError:
    winreg = None

from config import LOCAL_SENTINEL
from models import AuditRow, ScanResult
from services.master_software_service import MasterSoftwarePathService
from services.profile_service import SSHTunnelService, VSphereService
from services.template_service import _get_sbl_model_from_workbook
from services.workbook_service import AuditWorkbookService, VersionRuleResolver
from utils import compare_versions, is_x_mark, normalize_model_key, normalize_text


class LocalWindowsScanner:
    """Run local Windows software detection commands used by the audit engine."""

    @staticmethod
    def describe_local_detection_commands(software_name: str, version_location: str) -> List[str]:
        """Return diagnostic PowerShell commands that correspond to a VERSION LOCATIONS rule."""
        rule, payload = VersionRuleResolver.detect_rule(version_location)
        commands: List[str] = []

        if rule == "programs_and_features":
            safe_name = software_name.replace("'", "''")
            commands.append(
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
                "'HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1"
            )
            return commands

        if rule == "powershell":
            command = payload.get("command", "")
            if command:
                commands.append(command)
            return commands

        if rule == "file_version":
            for path_value in payload.get("paths", []):
                safe_path = path_value.replace("'", "''")
                commands.append(
                    f"$p='{safe_path}'; if (Test-Path $p) {{ (Get-Item $p).VersionInfo.ProductVersion }}"
                )
            return commands

        commands.append(
            "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
            "'HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            "Get-ItemProperty $paths -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion"
        )
        for path_value in VersionRuleResolver.extract_file_paths(version_location):
            safe_path = path_value.replace("'", "''")
            commands.append(f"$p='{safe_path}'; if (Test-Path $p) {{ (Get-Item $p).VersionInfo.ProductVersion }}")
        return commands

    def capture_registry_snapshot(self) -> Dict[str, Any]:
        """Capture an inventory snapshot from uninstall registry keys on the local machine."""
        from utils import normalize_header, normalize_version
        snapshot: Dict[str, Any] = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "host": socket.gethostname(),
            "platform": platform.platform(),
            "status": "ok",
            "entries": [],
            "entry_count": 0,
        }
        if winreg is None or platform.system().lower() != "windows":
            snapshot["status"] = "not_supported"
            snapshot["reason"] = "Registry snapshot requires Windows with winreg support"
            return snapshot

        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        entries: List[Dict[str, str]] = []
        try:
            for hive, root in roots:
                with winreg.OpenKey(hive, root) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        try:
                            sub_name = winreg.EnumKey(base, i)
                            with winreg.OpenKey(base, sub_name) as sub:
                                display_name = normalize_text(winreg.QueryValueEx(sub, "DisplayName")[0])
                                if not display_name:
                                    continue
                                try:
                                    display_version = normalize_text(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                except Exception:
                                    display_version = ""
                                try:
                                    publisher = normalize_text(winreg.QueryValueEx(sub, "Publisher")[0])
                                except Exception:
                                    publisher = ""

                                entries.append(
                                    {
                                        "registry_key": f"{root}\\{sub_name}",
                                        "display_name": display_name,
                                        "display_name_normalized": normalize_header(display_name),
                                        "display_version": display_version,
                                        "display_version_normalized": normalize_version(display_version),
                                        "publisher": publisher,
                                    }
                                )
                        except Exception:
                            continue
            entries.sort(key=lambda item: (item["display_name_normalized"], item["display_version_normalized"], item["registry_key"]))
            snapshot["entries"] = entries
            snapshot["entry_count"] = len(entries)
            return snapshot
        except Exception as exc:
            snapshot["status"] = "error"
            snapshot["reason"] = str(exc)
            snapshot["entries"] = entries
            snapshot["entry_count"] = len(entries)
            return snapshot

    def find_programs_and_features_version(self, software_name: str) -> Tuple[str, str, str]:
        """Find software version by matching DisplayName in Programs and Features registry keys."""
        if winreg is None or platform.system().lower() != "windows":
            return "WARN", "NOT_WINDOWS", "Registry-based scan requires Windows"
        target = software_name.lower()
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        try:
            for hive, root in roots:
                with winreg.OpenKey(hive, root) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        try:
                            sub_name = winreg.EnumKey(base, i)
                            with winreg.OpenKey(base, sub_name) as sub:
                                display_name = str(winreg.QueryValueEx(sub, "DisplayName")[0])
                                try:
                                    version = str(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                except Exception:
                                    version = ""
                                if target in display_name.lower():
                                    return "PASS", version or "FOUND_NO_VERSION", f"Matched installed app '{display_name}'"
                        except Exception:
                            continue
        except Exception as exc:
            return "WARN", "ERROR", f"Registry scan failed: {exc}"
        return "FAIL", "NOT_FOUND", "Software not found in Programs and Features"

    def run_powershell(self, command: str) -> Tuple[str, str, str]:
        """Execute a local PowerShell command and normalize status/output semantics."""
        try:
            completed = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], capture_output=True, text=True, timeout=45, check=False)
            output = (completed.stdout or completed.stderr).strip()
            if completed.returncode == 0:
                return "PASS", output or "BLANK_OUTPUT", "Local PowerShell command completed"
            return "WARN", output or "ERROR", f"Local PowerShell returned {completed.returncode}"
        except Exception as exc:
            return "WARN", "ERROR", f"Local PowerShell failed: {exc}"

    def get_file_version(self, path_value: str) -> Tuple[str, str, str]:
        """Read ProductVersion/FileVersion from a local executable or library path."""
        safe_path = path_value.replace("'", "''")
        command = (
            f"$p='{safe_path}';"
            "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
            "$item = Get-Item $p;"
            "$ver = $item.VersionInfo.ProductVersion;"
            "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
            "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
            "Write-Output $ver"
        )
        status, version, details = self.run_powershell(command)
        if status == "PASS" and version == "MISSING_FILE":
            return "FAIL", "MISSING_FILE", f"File not found: {path_value}"
        if status == "PASS":
            return "PASS", version, f"Read file version from {path_value}"
        return status, version, f"File version query failed for {path_value}: {details}"

    def scan_file_versions(self, paths: List[str]) -> Tuple[str, str, str]:
        """Try candidate file paths and return the first successful version lookup."""
        failures: List[str] = []
        for path_value in paths:
            status, version, details = self.get_file_version(path_value)
            if status == "PASS":
                return status, version, details
            failures.append(f"{path_value} -> {version}")
        return "WARN", "NOT_FOUND", "; ".join(failures) if failures else "No candidate file paths found"

    def scan_software_version(self, software_name: str, version_location: str) -> Tuple[str, str, str]:
        """Resolve and execute the appropriate local scan rule for one software component."""
        rule, payload = VersionRuleResolver.detect_rule(version_location)
        if rule == "programs_and_features":
            return self.find_programs_and_features_version(software_name)
        if rule == "powershell":
            return self.run_powershell(payload["command"])
        if rule == "file_version":
            return self.scan_file_versions(payload["paths"])
        return "WARN", "UNKNOWN", f"No implemented scan rule matched VERSION LOCATIONS for {software_name}"


class AuditEngine:
    """Coordinate local/remote scanning and version comparison for parsed audit rows."""

    def __init__(
        self,
        workbook_service: AuditWorkbookService,
        logger,
        vm_profile: Dict[str, Any],
        vcenter_creds: Dict[str, str],
        guest_creds: Dict[str, str],
        connection_mode: str = "vsphere",
        ssh_config: Optional[Dict[str, Any]] = None,
        ssh_fallback_enabled: bool = False,
    ):
        """Initialize the AuditEngine instance."""
        self.workbook_service = workbook_service
        self.logger = logger
        self.vm_profile = vm_profile
        self.vcenter_creds = vcenter_creds
        self.guest_creds = guest_creds
        self.connection_mode = normalize_text(connection_mode).lower() or "vsphere"
        self.ssh_config = ssh_config or {}
        self.ssh_fallback_enabled = bool(ssh_fallback_enabled)
        self.local_scanner = LocalWindowsScanner()
        self.master_paths = MasterSoftwarePathService()
        self.master_model_name = normalize_model_key(_get_sbl_model_from_workbook(self.workbook_service.file_path))
        self.vsphere_service: Optional[VSphereService] = None
        self.ssh_service: Optional[SSHTunnelService] = None

    def _build_result(self, row: AuditRow, target_name: str, found_version: str, scan_status: str, details: str) -> ScanResult:
        """Build a ScanResult and update master path metadata for the scanned component."""
        if row.version_locations:
            self.master_paths.update_component(
                row.software_component,
                row.version_locations,
                target_name=target_name,
                scan_status=scan_status,
                model_name=self.master_model_name,
            )
        status, audit_text = compare_versions(row.sbl_build_version, found_version, scan_status)
        return ScanResult(row.software_component, target_name, row.sbl_build_version, found_version, status, details, row.row_index, audit_text)

    def _scan_local(self, row: AuditRow, target_name: str) -> ScanResult:
        """Scan a row against the local machine and convert output into ScanResult."""
        scan_status, found_version, details = self.local_scanner.scan_software_version(row.software_component, row.version_locations)
        return self._build_result(row, target_name, found_version, scan_status, f"local-machine | {details}")

    def _scan_guest_vm(self, row: AuditRow, target_name: str, vm_name: str, guest_username: str, guest_password: str) -> ScanResult:
        """Scan a target VM through vSphere guest execution using the resolved scan rule."""
        if self.vsphere_service is None:
            return self._build_result(row, target_name, "NO_VSPHERE", "WARN", f"vSphere service is not connected for '{vm_name}'")
        if not guest_username or not guest_password:
            return self._build_result(row, target_name, "NO_GUEST_CREDS", "WARN", f"Missing guest credentials for '{vm_name}'")
        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, payload["command"])
            return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details}")
        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, script)
            if scan_status == "PASS" and found_version == "NOT_FOUND":
                scan_status = "FAIL"
            return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details}")
        if rule == "file_version":
            failures: List[str] = []
            for path_value in payload["paths"]:
                safe_path = path_value.replace("'", "''")
                script = (
                    f"$p='{safe_path}';"
                    "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
                    "$item = Get-Item $p;"
                    "$ver = $item.VersionInfo.ProductVersion;"
                    "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
                    "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
                    "Write-Output $ver"
                )
                scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, script)
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"vm={vm_name} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"vm={vm_name} | no candidate file path succeeded | {'; '.join(failures)}")
        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"vm={vm_name} | No implemented scan rule matched VERSION LOCATIONS")

    def _scan_ssh_target(self, row: AuditRow, target_name: str, target_host: str, target_username: str, target_password: str) -> ScanResult:
        """Scan a target host over SSH tunnel mode using the resolved scan rule."""
        if self.ssh_service is None:
            return self._build_result(row, target_name, "NO_SSH_SERVICE", "WARN", f"SSH service is not initialized for '{target_host}'")

        rule, payload = VersionRuleResolver.detect_rule(row.version_locations)
        if rule == "powershell":
            scan_status, found_version, details = self.ssh_service.run_powershell(
                target_host,
                payload["command"],
                target_username=target_username,
                target_password=target_password,
            )
            return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details}")

        if rule == "programs_and_features":
            safe_name = row.software_component.replace("'", "''")
            script = (
                "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
                f"$hit = Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object {{$_.DisplayName -like '*{safe_name}*'}} | Select-Object -First 1;"
                "if (-not $hit) { Write-Output 'NOT_FOUND'; exit 4 };"
                "$v = $hit.DisplayVersion; if (-not $v) { $v = 'FOUND_NO_VERSION' }; Write-Output $v"
            )
            scan_status, found_version, details = self.ssh_service.run_powershell(
                target_host,
                script,
                target_username=target_username,
                target_password=target_password,
            )
            if scan_status == "PASS" and found_version == "NOT_FOUND":
                scan_status = "FAIL"
            return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details}")

        if rule == "file_version":
            failures: List[str] = []
            for path_value in payload["paths"]:
                safe_path = path_value.replace("'", "''")
                script = (
                    f"$p='{safe_path}';"
                    "if (-not (Test-Path $p)) { Write-Output 'MISSING_FILE'; exit 3 };"
                    "$item = Get-Item $p;"
                    "$ver = $item.VersionInfo.ProductVersion;"
                    "if (-not $ver) { $ver = $item.VersionInfo.FileVersion };"
                    "if (-not $ver) { $ver = 'FOUND_NO_VERSION' };"
                    "Write-Output $ver"
                )
                scan_status, found_version, details = self.ssh_service.run_powershell(
                    target_host,
                    script,
                    target_username=target_username,
                    target_password=target_password,
                )
                if scan_status == "PASS" and found_version != "MISSING_FILE":
                    return self._build_result(row, target_name, found_version, scan_status, f"ssh-host={target_host} | {details} | source={path_value}")
                failures.append(f"{path_value} -> {found_version}")
            return self._build_result(row, target_name, "NOT_FOUND", "WARN", f"ssh-host={target_host} | no candidate file path succeeded | {'; '.join(failures)}")

        return self._build_result(row, target_name, "UNKNOWN", "WARN", f"ssh-host={target_host} | No implemented scan rule matched VERSION LOCATIONS")

    def scan_target_row(self, row: AuditRow, target_name: str) -> ScanResult:
        """Route a row scan to local, SSH, or vSphere paths based on profile mapping."""
        target_profile = self.vm_profile.get("targets", {}).get(target_name, {})
        vm_name = normalize_text(target_profile.get("vm_name", ""))
        target_username = normalize_text(target_profile.get("username", "")) or normalize_text(self.guest_creds.get("username", ""))
        target_password = target_profile.get("password", "") or self.guest_creds.get("password", "")
        if not vm_name:
            return self._build_result(row, target_name, "PROFILE_NOT_MAPPED", "WARN", f"No VM mapping saved for {target_name}")
        if vm_name.upper() == LOCAL_SENTINEL:
            return self._scan_local(row, target_name)
        if self.connection_mode == "ssh tunnel":
            result = self._scan_ssh_target(row, target_name, vm_name, target_username, target_password)
            if (
                self.ssh_fallback_enabled
                and result.status in ("WARN", "FAIL")
                and self.vsphere_service is not None
            ):
                self.logger(f"SSH scan failed for {target_name}, trying vSphere fallback...")
                vm_result = self._scan_guest_vm(row, target_name, vm_name, target_username, target_password)
                if vm_result.status == "PASS":
                    self.logger(f"vSphere fallback succeeded for {target_name}")
                    return vm_result
                self.logger(f"vSphere fallback also failed for {target_name}")
            return result

        # vSphere mode - try vSphere first
        result = self._scan_guest_vm(row, target_name, vm_name, target_username, target_password)

        # If fallback is enabled and vSphere failed, try SSH
        if (self.ssh_fallback_enabled and
            result.status in ("WARN", "FAIL") and
            self.ssh_service is not None):
            self.logger(f"vSphere scan failed for {target_name}, trying SSH fallback...")
            ssh_result = self._scan_ssh_target(row, target_name, vm_name, target_username, target_password)
            if ssh_result.status == "PASS":
                self.logger(f"SSH fallback succeeded for {target_name}")
                return ssh_result
            else:
                self.logger(f"SSH fallback also failed for {target_name}")

        return result

    @staticmethod
    def choose_best_row_result(row_results: List[ScanResult]) -> ScanResult:
        """Choose best row result."""
        if not row_results:
            return ScanResult("", "", "", "", "WARN", "No targets", 0, "WARN | no targets")
        for result in row_results:
            if result.status == "FAIL":
                return result
        for result in row_results:
            if result.status == "WARN":
                return result
        return row_results[0]

    def run(self) -> List[ScanResult]:
        """Run."""
        PYVMOMI_AVAILABLE = True
        PARAMIKO_AVAILABLE = True
        try:
            from pyVim.connect import Disconnect, SmartConnect
            from pyVmomi import vim
        except Exception:
            PYVMOMI_AVAILABLE = False

        try:
            import paramiko
        except Exception:
            PARAMIKO_AVAILABLE = False

        rows = self.workbook_service.iter_audit_rows()
        results: List[ScanResult] = []
        self.logger(f"Loaded {len(rows)} audit rows.")
        self.logger("Starting local-machine scan phase...")

        for row in rows:
            if not row.software_component:
                continue
            self.logger(f"Scanning {row.software_component} [LOCAL baseline]...")
            result = self._scan_local(row, "LOCAL_MACHINE")
            results.append(result)
            self.logger(result.audit_text + f" | {result.details}")

        for row in rows:
            if not row.software_component:
                continue
            for target_name, mark in row.target_vms.items():
                if not is_x_mark(mark):
                    continue
                vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                if not vm_name:
                    self.logger(f"Scanning {row.software_component} on {target_name} [UNMAPPED]...")
                    result = self.scan_target_row(row, target_name)
                    results.append(result)
                    self.logger(result.audit_text + f" | {result.details}")
                elif vm_name.upper() == LOCAL_SENTINEL:
                    continue

        needs_remote = any(
            normalize_text(self.vm_profile.get("targets", {}).get(target, {}).get("vm_name", "")).upper() not in ("", LOCAL_SENTINEL)
            for row in rows for target, mark in row.target_vms.items() if is_x_mark(mark)
        )

        if needs_remote:
            self.logger(f"Starting remote scan phase using mode: {self.connection_mode}...")
            if self.connection_mode == "ssh tunnel":
                try:
                    if self.ssh_fallback_enabled:
                        if not PYVMOMI_AVAILABLE:
                            self.logger("vSphere fallback enabled, but pyVmomi is not installed; SSH-only mode will be used.")
                        elif not self.vcenter_creds.get("server", "") or not self.vcenter_creds.get("username", "") or not self.vcenter_creds.get("password", ""):
                            self.logger("vSphere fallback enabled, but vCenter credentials/server are incomplete; SSH-only mode will be used.")
                        else:
                            try:
                                self.vsphere_service = VSphereService(
                                    self.vcenter_creds.get("server", ""),
                                    self.vcenter_creds.get("username", ""),
                                    self.vcenter_creds.get("password", ""),
                                    True,
                                )
                                self.vsphere_service.connect()
                                self.logger("vSphere fallback service initialized for SSH mode.")
                            except Exception as exc:
                                self.vsphere_service = None
                                self.logger(f"Could not initialize vSphere fallback in SSH mode: {exc}")

                    if not PARAMIKO_AVAILABLE:
                        if self.ssh_fallback_enabled and self.vsphere_service is not None:
                            self.logger("paramiko is not installed; attempting vSphere fallback-only scans.")
                            for row in rows:
                                if not row.software_component:
                                    continue
                                for target_name, mark in row.target_vms.items():
                                    if not is_x_mark(mark):
                                        continue
                                    vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                    if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                        target_profile = self.vm_profile.get("targets", {}).get(target_name, {})
                                        target_username = normalize_text(target_profile.get("username", "")) or normalize_text(self.guest_creds.get("username", ""))
                                        target_password = target_profile.get("password", "") or self.guest_creds.get("password", "")
                                        self.logger(f"Scanning {row.software_component} on {target_name} [vSphere fallback={vm_name}]...")
                                        result = self._scan_guest_vm(row, target_name, vm_name, target_username, target_password)
                                        results.append(result)
                                        self.logger(result.audit_text + f" | {result.details}")
                        else:
                            self.logger("paramiko is not installed; SSH targets will be marked WARN.")
                            for row in rows:
                                if not row.software_component:
                                    continue
                                for target_name, mark in row.target_vms.items():
                                    if not is_x_mark(mark):
                                        continue
                                    vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                    if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                        result = self._build_result(
                                            row,
                                            target_name,
                                            "NO_PARAMIKO",
                                            "WARN",
                                            f"ssh-host={vm_name} | paramiko is not installed",
                                        )
                                        results.append(result)
                                        self.logger(result.audit_text + f" | {result.details}")
                    else:
                        self.ssh_service = SSHTunnelService(
                            target_username=self.guest_creds.get("username", ""),
                            target_password=self.guest_creds.get("password", ""),
                            target_port=int(self.ssh_config.get("target_port", 22)),
                            gateway_host=self.ssh_config.get("gateway_host", ""),
                            gateway_username=self.ssh_config.get("gateway_username", ""),
                            gateway_password=self.ssh_config.get("gateway_password", ""),
                            gateway_port=int(self.ssh_config.get("gateway_port", 22)),
                        )
                        self.logger("SSH tunnel mode initialized.")
                        for row in rows:
                            if not row.software_component:
                                continue
                            for target_name, mark in row.target_vms.items():
                                if not is_x_mark(mark):
                                    continue
                                vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                                if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                    self.logger(f"Scanning {row.software_component} on {target_name} [SSH={vm_name}]...")
                                    result = self.scan_target_row(row, target_name)
                                    results.append(result)
                                    self.logger(result.audit_text + f" | {result.details}")
                finally:
                    if self.vsphere_service is not None:
                        try:
                            self.vsphere_service.disconnect()
                        except Exception:
                            pass
                        self.vsphere_service = None
            elif not PYVMOMI_AVAILABLE:
                self.logger("pyVmomi is not installed; VM targets will be marked WARN.")
                for row in rows:
                    if not row.software_component:
                        continue
                    for target_name, mark in row.target_vms.items():
                        if not is_x_mark(mark):
                            continue
                        vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                        if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                            result = self._build_result(
                                row,
                                target_name,
                                "NO_PYVMOMI",
                                "WARN",
                                f"vm={vm_name} | pyVmomi is not installed",
                            )
                            results.append(result)
                            self.logger(result.audit_text + f" | {result.details}")
            else:
                self.vsphere_service = VSphereService(
                    self.vcenter_creds.get("server", ""),
                    self.vcenter_creds.get("username", ""),
                    self.vcenter_creds.get("password", ""),
                    True,
                )
                self.logger(f"Connecting to vSphere server {self.vcenter_creds.get('server', '')}...")
                try:
                    self.vsphere_service.connect()
                    self.logger("Connected to vSphere.")

                    # Initialize SSH service for fallback if enabled
                    if self.ssh_fallback_enabled and PARAMIKO_AVAILABLE:
                        self.ssh_service = SSHTunnelService(
                            target_username=self.guest_creds.get("username", ""),
                            target_password=self.guest_creds.get("password", ""),
                            target_port=int(self.ssh_config.get("target_port", 22)),
                            gateway_host=self.ssh_config.get("gateway_host", ""),
                            gateway_username=self.ssh_config.get("gateway_username", ""),
                            gateway_password=self.ssh_config.get("gateway_password", ""),
                            gateway_port=int(self.ssh_config.get("gateway_port", 22)),
                        )
                        self.logger("SSH tunnel service initialized for fallback.")
                    elif self.ssh_fallback_enabled and not PARAMIKO_AVAILABLE:
                        self.logger("SSH fallback enabled but paramiko is not installed; fallback will be skipped.")

                    for row in rows:
                        if not row.software_component:
                            continue
                        for target_name, mark in row.target_vms.items():
                            if not is_x_mark(mark):
                                continue
                            vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                            if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                self.logger(f"Scanning {row.software_component} on {target_name} [VM={vm_name}]...")
                                result = self.scan_target_row(row, target_name)
                                results.append(result)
                                self.logger(result.audit_text + f" | {result.details}")
                except Exception as exc:
                    self.logger(f"vSphere connection failed; VM targets will be marked WARN: {exc}")
                    for row in rows:
                        if not row.software_component:
                            continue
                        for target_name, mark in row.target_vms.items():
                            if not is_x_mark(mark):
                                continue
                            vm_name = normalize_text(self.vm_profile.get("targets", {}).get(target_name, {}).get("vm_name", ""))
                            if vm_name and vm_name.upper() != LOCAL_SENTINEL:
                                result = self._build_result(
                                    row,
                                    target_name,
                                    "VSPHERE_CONNECT_FAILED",
                                    "WARN",
                                    f"vm={vm_name} | vSphere connect failed: {exc}",
                                )
                                results.append(result)
                                self.logger(result.audit_text + f" | {result.details}")
                finally:
                    if self.vsphere_service is not None:
                        try:
                            self.vsphere_service.disconnect()
                            self.logger("Disconnected from vSphere.")
                        except Exception:
                            pass
        else:
            self.logger("No VM targets selected.")

        for row in rows:
            row_results = [r for r in results if r.worksheet_row == row.row_index]
            if not row_results:
                continue
            best = self.choose_best_row_result(row_results)
            self.workbook_service.write_audit_result(row.row_index, best.audit_text, best.status)

        return results
