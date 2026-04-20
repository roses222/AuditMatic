"""Mocked remote-scan tests for vSphere and SSH tunnel paths.

These tests validate routing and comparison behavior without requiring real
vCenter, SSH gateways, or remote VMs.
"""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from typing import Any, cast

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from models import AuditRow
import services.audit_engine as audit_engine


class _FakeWorkbookService:
    def __init__(self, rows: list[AuditRow]) -> None:
        self.file_path = str(PROJECT_ROOT / "tests" / "fake_sbl.xlsx")
        self._rows = rows
        self.writes: list[tuple[int, str, str]] = []

    def iter_audit_rows(self):
        return list(self._rows)

    def write_audit_result(self, row_index: int, audit_text: str, status: str) -> None:
        self.writes.append((row_index, audit_text, status))


class _FakeMasterPaths:
    def update_component(self, *args, **kwargs):
        return None


class _FakeLocalScanner:
    def scan_software_version(self, software_name: str, version_location: str):
        return "PASS", "1.2.3", f"mock-local-scan {software_name} {version_location}"


class _FakeVSphereService:
    instances: list["_FakeVSphereService"] = []

    def __init__(self, server: str, username: str, password: str, ignore_ssl: bool = True):
        self.server = server
        self.username = username
        self.password = password
        self.ignore_ssl = ignore_ssl
        self.connected = False
        self.calls: list[tuple[str, str, str, str]] = []
        _FakeVSphereService.instances.append(self)

    def connect(self):
        self.connected = True
        return True

    def disconnect(self):
        self.connected = False

    def run_powershell_in_guest(self, vm_name: str, guest_username: str, guest_password: str, script: str, timeout_seconds: int = 90):
        self.calls.append((vm_name, guest_username, guest_password, script))
        return "PASS", "VER=1.2.3;MATCH_TAG=HIGH;MATCH_PCT=95;MATCH_NAME=TestApp", "mock-vsphere"


class _FakeSSHTunnelService:
    instances: list["_FakeSSHTunnelService"] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.calls: list[tuple[str, str, str, str]] = []
        _FakeSSHTunnelService.instances.append(self)

    def run_powershell(self, target_host: str, script: str, timeout_seconds: int = 90, target_username: str = "", target_password: str = ""):
        self.calls.append((target_host, target_username, target_password, script))
        return "PASS", "VER=1.2.3;MATCH_TAG=HIGH;MATCH_PCT=95;MATCH_NAME=TestApp", "mock-ssh"


class MockedRemoteScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_get_model = audit_engine._get_sbl_model_from_workbook
        self._orig_vsphere_cls = audit_engine.VSphereService
        self._orig_ssh_cls = audit_engine.SSHTunnelService

        audit_engine._get_sbl_model_from_workbook = lambda _path: "GENERAL"
        audit_engine.VSphereService = _FakeVSphereService
        audit_engine.SSHTunnelService = _FakeSSHTunnelService
        _FakeVSphereService.instances.clear()
        _FakeSSHTunnelService.instances.clear()

        # Ensure run() import probes succeed even without real packages installed.
        self._install_fake_runtime_modules()

    def tearDown(self) -> None:
        audit_engine._get_sbl_model_from_workbook = self._orig_get_model
        audit_engine.VSphereService = self._orig_vsphere_cls
        audit_engine.SSHTunnelService = self._orig_ssh_cls
        self._remove_fake_runtime_modules()

    def _install_fake_runtime_modules(self) -> None:
        pyvim_module = types.ModuleType("pyVim")
        pyvim_connect = types.ModuleType("pyVim.connect")
        setattr(pyvim_connect, "SmartConnect", object())
        setattr(pyvim_connect, "Disconnect", object())
        pyvmomi_module = types.ModuleType("pyVmomi")
        setattr(pyvmomi_module, "vim", object())
        paramiko_module = types.ModuleType("paramiko")

        self._fake_modules = {
            "pyVim": pyvim_module,
            "pyVim.connect": pyvim_connect,
            "pyVmomi": pyvmomi_module,
            "paramiko": paramiko_module,
        }

        self._old_modules = {}
        for name, module in self._fake_modules.items():
            self._old_modules[name] = sys.modules.get(name)
            sys.modules[name] = module

    def _remove_fake_runtime_modules(self) -> None:
        for name in self._fake_modules.keys():
            old = self._old_modules.get(name)
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old

    @staticmethod
    def _sample_row() -> AuditRow:
        return AuditRow(
            row_index=10,
            software_component="Test App",
            current_ci_version="1.2.3",
            sbl_build_version="1.2.3",
            audit_value="",
            target_vms={"Target_A": "X", "Target_B": ""},
            version_locations="Programs and Features",
        )

    @staticmethod
    def _sample_profile(vm_name: str) -> dict:
        return {
            "targets": {
                "Target_A": {
                    "vm_name": vm_name,
                    "username": "guest_user",
                    "password": "guest_pw",
                    "os_type": "windows",
                },
                "Target_B": {
                    "vm_name": "__LOCAL__",
                    "username": "",
                    "password": "",
                    "os_type": "windows",
                },
            }
        }

    def test_run_vsphere_mode_uses_mock_service_and_filters_non_x_targets(self) -> None:
        row = self._sample_row()
        workbook = _FakeWorkbookService([row])
        logs: list[str] = []

        engine = audit_engine.AuditEngine(
            workbook_service=cast(Any, workbook),
            logger=logs.append,
            vm_profile=self._sample_profile("vm-prod-01"),
            vcenter_creds={"server": "vc.local", "username": "svc", "password": "pw"},
            guest_creds={"username": "fallback_user", "password": "fallback_pw"},
            connection_mode="vSphere",
        )
        engine.local_scanner = cast(Any, _FakeLocalScanner())
        engine.master_paths = cast(Any, _FakeMasterPaths())

        results = engine.run()

        self.assertTrue(_FakeVSphereService.instances)
        self.assertEqual(len(_FakeVSphereService.instances), 1)
        vsphere = _FakeVSphereService.instances[0]

        # One remote call only: Target_A is marked X, Target_B is not.
        self.assertEqual(len(vsphere.calls), 1)
        self.assertEqual(vsphere.calls[0][0], "vm-prod-01")

        # One local baseline + one remote target result.
        self.assertEqual(len(results), 2)
        statuses = [item.status for item in results]
        self.assertEqual(statuses.count("PASS"), 2)

    def test_run_ssh_tunnel_mode_uses_mock_service(self) -> None:
        row = self._sample_row()
        workbook = _FakeWorkbookService([row])
        logs: list[str] = []

        engine = audit_engine.AuditEngine(
            workbook_service=cast(Any, workbook),
            logger=logs.append,
            vm_profile=self._sample_profile("ssh-target-01"),
            vcenter_creds={"server": "", "username": "", "password": ""},
            guest_creds={"username": "fallback_user", "password": "fallback_pw"},
            connection_mode="SSH Tunnel",
            ssh_config={
                "gateway_host": "bastion.local",
                "gateway_username": "gw",
                "gateway_password": "pw",
                "gateway_port": 22,
                "target_port": 22,
            },
        )
        engine.local_scanner = cast(Any, _FakeLocalScanner())
        engine.master_paths = cast(Any, _FakeMasterPaths())

        results = engine.run()

        self.assertTrue(_FakeSSHTunnelService.instances)
        self.assertEqual(len(_FakeSSHTunnelService.instances), 1)
        ssh_service = _FakeSSHTunnelService.instances[0]
        self.assertEqual(len(ssh_service.calls), 1)
        self.assertEqual(ssh_service.calls[0][0], "ssh-target-01")

        # One local baseline + one remote target result.
        self.assertEqual(len(results), 2)
        self.assertTrue(all(item.status == "PASS" for item in results))

    def test_ssh_mode_falls_back_to_vsphere_when_ssh_warns(self) -> None:
        row = self._sample_row()
        workbook = _FakeWorkbookService([row])
        logs: list[str] = []

        original_ssh_method = _FakeSSHTunnelService.run_powershell
        original_vsphere_method = _FakeVSphereService.run_powershell_in_guest

        def _warn_ssh(self, target_host: str, script: str, timeout_seconds: int = 90, target_username: str = "", target_password: str = ""):
            self.calls.append((target_host, target_username, target_password, script))
            return "WARN", "SSH_FAIL", "mock-ssh-warn"

        def _pass_vsphere(self, vm_name: str, guest_username: str, guest_password: str, script: str, timeout_seconds: int = 90):
            self.calls.append((vm_name, guest_username, guest_password, script))
            return "PASS", "VER=1.2.3;MATCH_TAG=HIGH;MATCH_PCT=95;MATCH_NAME=TestApp", "mock-vsphere-pass"

        setattr(cast(Any, _FakeSSHTunnelService), "run_powershell", _warn_ssh)
        setattr(cast(Any, _FakeVSphereService), "run_powershell_in_guest", _pass_vsphere)
        try:
            engine = audit_engine.AuditEngine(
                workbook_service=cast(Any, workbook),
                logger=logs.append,
                vm_profile=self._sample_profile("ssh-target-02"),
                vcenter_creds={"server": "vc.local", "username": "svc", "password": "pw"},
                guest_creds={"username": "fallback_user", "password": "fallback_pw"},
                connection_mode="SSH Tunnel",
                ssh_config={
                    "gateway_host": "bastion.local",
                    "gateway_username": "gw",
                    "gateway_password": "pw",
                    "gateway_port": 22,
                    "target_port": 22,
                },
                ssh_fallback_enabled=True,
            )
            engine.local_scanner = cast(Any, _FakeLocalScanner())
            engine.master_paths = cast(Any, _FakeMasterPaths())

            results = engine.run()

            self.assertEqual(len(_FakeSSHTunnelService.instances), 1)
            self.assertEqual(len(_FakeVSphereService.instances), 1)
            self.assertEqual(len(_FakeSSHTunnelService.instances[0].calls), 1)
            self.assertEqual(len(_FakeVSphereService.instances[0].calls), 1)
            self.assertTrue(any("vSphere fallback succeeded" in msg for msg in logs))
            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.status == "PASS" for item in results))
        finally:
            setattr(cast(Any, _FakeSSHTunnelService), "run_powershell", original_ssh_method)
            setattr(cast(Any, _FakeVSphereService), "run_powershell_in_guest", original_vsphere_method)

    def test_vsphere_mode_falls_back_to_ssh_when_vsphere_warns(self) -> None:
        row = self._sample_row()
        workbook = _FakeWorkbookService([row])
        logs: list[str] = []

        original_ssh_method = _FakeSSHTunnelService.run_powershell
        original_vsphere_method = _FakeVSphereService.run_powershell_in_guest

        def _warn_vsphere(self, vm_name: str, guest_username: str, guest_password: str, script: str, timeout_seconds: int = 90):
            self.calls.append((vm_name, guest_username, guest_password, script))
            return "WARN", "VSPHERE_FAIL", "mock-vsphere-warn"

        def _pass_ssh(self, target_host: str, script: str, timeout_seconds: int = 90, target_username: str = "", target_password: str = ""):
            self.calls.append((target_host, target_username, target_password, script))
            return "PASS", "VER=1.2.3;MATCH_TAG=HIGH;MATCH_PCT=95;MATCH_NAME=TestApp", "mock-ssh-pass"

        setattr(cast(Any, _FakeVSphereService), "run_powershell_in_guest", _warn_vsphere)
        setattr(cast(Any, _FakeSSHTunnelService), "run_powershell", _pass_ssh)
        try:
            engine = audit_engine.AuditEngine(
                workbook_service=cast(Any, workbook),
                logger=logs.append,
                vm_profile=self._sample_profile("vm-prod-02"),
                vcenter_creds={"server": "vc.local", "username": "svc", "password": "pw"},
                guest_creds={"username": "fallback_user", "password": "fallback_pw"},
                connection_mode="vSphere",
                ssh_config={
                    "gateway_host": "bastion.local",
                    "gateway_username": "gw",
                    "gateway_password": "pw",
                    "gateway_port": 22,
                    "target_port": 22,
                },
                ssh_fallback_enabled=True,
            )
            engine.local_scanner = cast(Any, _FakeLocalScanner())
            engine.master_paths = cast(Any, _FakeMasterPaths())

            results = engine.run()

            self.assertEqual(len(_FakeVSphereService.instances), 1)
            self.assertEqual(len(_FakeSSHTunnelService.instances), 1)
            self.assertEqual(len(_FakeVSphereService.instances[0].calls), 1)
            self.assertEqual(len(_FakeSSHTunnelService.instances[0].calls), 1)
            self.assertTrue(any("SSH fallback succeeded" in msg for msg in logs))
            self.assertEqual(len(results), 2)
            self.assertTrue(all(item.status == "PASS" for item in results))
        finally:
            setattr(cast(Any, _FakeSSHTunnelService), "run_powershell", original_ssh_method)
            setattr(cast(Any, _FakeVSphereService), "run_powershell_in_guest", original_vsphere_method)


if __name__ == "__main__":
    unittest.main()
