"""VM profile management and remote connection services."""

import base64
import copy
import json
import platform
import socket
import ssl
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from config import PROFILES_DIR
from services.utils import normalize_text, ensure_project_structure

try:
    from cryptography.fernet import Fernet, InvalidToken
    CRYPTO_AVAILABLE = True
except Exception:
    Fernet = None
    InvalidToken = Exception
    CRYPTO_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except Exception:
    paramiko = None
    PARAMIKO_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except Exception:
    requests = None
    REQUESTS_AVAILABLE = False

try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim
    PYVMOMI_AVAILABLE = True
except Exception:
    Disconnect = None
    SmartConnect = None
    vim = None
    PYVMOMI_AVAILABLE = False

LOCAL_SENTINEL = "__LOCAL__"


class VMProfileService:
    def __init__(self, profiles_dir: Path = PROFILES_DIR):
        """Initialize the VMProfileService instance."""
        self.profiles_dir = profiles_dir
        ensure_project_structure()

    @staticmethod
    def _key_path() -> Path:
        """Internal helper for key path."""
        return Path.home() / ".auditmatic" / "profile_credentials.key"

    def _get_fernet(self):
        """Internal helper for get fernet."""
        if not CRYPTO_AVAILABLE or Fernet is None:
            return None
        key_path = self._key_path()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            key = key_path.read_bytes()
        else:
            key = Fernet.generate_key()
            key_path.write_bytes(key)
        return Fernet(key)

    @staticmethod
    def encryption_supported() -> bool:
        """Encryption supported."""
        return bool(CRYPTO_AVAILABLE and Fernet is not None)

    def profile_credential_storage_mode(self, profile_name: str) -> str:
        """Profile credential storage mode."""
        path = self.profile_path(profile_name)
        if not path.exists():
            return "no-profile"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return "unknown"
        if bool(payload.get("credentials_encrypted", False)):
            return "encrypted"
        return "legacy-plain"

    @staticmethod
    def _encrypt_value(fernet, value: str) -> str:
        """Internal helper for encrypt value."""
        if not fernet or not value:
            return value
        return fernet.encrypt(value.encode("utf-8")).decode("ascii")

    @staticmethod
    def _decrypt_value(fernet, value: str) -> str:
        """Internal helper for decrypt value."""
        if not fernet or not value:
            return value
        try:
            return fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except Exception:
            return ""

    def _encrypt_profile_credentials(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Internal helper for encrypt profile credentials."""
        fernet = self._get_fernet()
        encrypted_payload = copy.deepcopy(payload)

        vcenter_user = normalize_text(encrypted_payload.get("vcenter_username", ""))
        vcenter_password = encrypted_payload.get("vcenter_password", "")
        if vcenter_user:
            encrypted_payload["vcenter_username_enc"] = self._encrypt_value(fernet, vcenter_user)
        if vcenter_password:
            encrypted_payload["vcenter_password_enc"] = self._encrypt_value(fernet, vcenter_password)
        encrypted_payload.pop("vcenter_username", None)
        encrypted_payload.pop("vcenter_password", None)

        targets = encrypted_payload.get("targets", {})
        if isinstance(targets, dict):
            for target_name, target_info in targets.items():
                if not isinstance(target_info, dict):
                    continue
                target_user = normalize_text(target_info.get("username", ""))
                target_password = target_info.get("password", "")
                if target_user:
                    target_info["username_enc"] = self._encrypt_value(fernet, target_user)
                if target_password:
                    target_info["password_enc"] = self._encrypt_value(fernet, target_password)
                target_info.pop("username", None)
                target_info.pop("password", None)

        ssh_tunnel = encrypted_payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            gateway_password = ssh_tunnel.get("gateway_password", "")
            if gateway_password:
                ssh_tunnel["gateway_password_enc"] = self._encrypt_value(fernet, gateway_password)
            ssh_tunnel.pop("gateway_password", None)

        encrypted_payload["credentials_encrypted"] = bool(fernet)
        encrypted_payload["credentials_scheme"] = "fernet-v1" if fernet else "none"
        return encrypted_payload

    def _decrypt_profile_credentials(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Internal helper for decrypt profile credentials."""
        fernet = self._get_fernet()
        decrypted_payload = copy.deepcopy(payload)

        if decrypted_payload.get("vcenter_username_enc"):
            decrypted_payload["vcenter_username"] = self._decrypt_value(fernet, decrypted_payload.get("vcenter_username_enc", ""))
        else:
            decrypted_payload["vcenter_username"] = normalize_text(decrypted_payload.get("vcenter_username", ""))

        if decrypted_payload.get("vcenter_password_enc"):
            decrypted_payload["vcenter_password"] = self._decrypt_value(fernet, decrypted_payload.get("vcenter_password_enc", ""))
        else:
            decrypted_payload["vcenter_password"] = decrypted_payload.get("vcenter_password", "")

        targets = decrypted_payload.get("targets", {})
        if isinstance(targets, dict):
            for target_name, target_info in targets.items():
                if not isinstance(target_info, dict):
                    continue
                if target_info.get("username_enc"):
                    target_info["username"] = self._decrypt_value(fernet, target_info.get("username_enc", ""))
                else:
                    target_info["username"] = normalize_text(target_info.get("username", ""))

                if target_info.get("password_enc"):
                    target_info["password"] = self._decrypt_value(fernet, target_info.get("password_enc", ""))
                else:
                    target_info["password"] = target_info.get("password", "")

        ssh_tunnel = decrypted_payload.get("ssh_tunnel", {})
        if isinstance(ssh_tunnel, dict):
            if ssh_tunnel.get("gateway_password_enc"):
                ssh_tunnel["gateway_password"] = self._decrypt_value(fernet, ssh_tunnel.get("gateway_password_enc", ""))
            else:
                ssh_tunnel["gateway_password"] = ssh_tunnel.get("gateway_password", "")

        return decrypted_payload

    def profile_path(self, profile_name: str) -> Path:
        """Profile path."""
        return self.profiles_dir / f"{profile_name}.json"

    def save_profile(self, profile_name: str, payload: Dict[str, Any]) -> str:
        """Save profile."""
        payload = self._encrypt_profile_credentials(payload)
        payload["profile_name"] = profile_name
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        path = self.profile_path(profile_name)
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(path)

    def load_profile(self, profile_name: str) -> Dict[str, Any]:
        """Load profile."""
        payload = json.loads(self.profile_path(profile_name).read_text(encoding="utf-8"))
        return self._decrypt_profile_credentials(payload)


class VSphereService:
    def __init__(self, server: str, username: str, password: str, ignore_ssl: bool = True):
        """Initialize the VSphereService instance."""
        self.server = server.strip()
        self.username = username.strip()
        self.password = password
        self.ignore_ssl = ignore_ssl
        self.si = None

    def connect(self):
        """Connect."""
        if not PYVMOMI_AVAILABLE:
            raise RuntimeError("pyVmomi is not installed. Install it with: pip install pyvmomi requests")
        context = ssl._create_unverified_context() if self.ignore_ssl else None
        self.si = SmartConnect(host=self.server, user=self.username, pwd=self.password, sslContext=context)
        return self.si

    def disconnect(self):
        """Disconnect."""
        if self.si is not None:
            Disconnect(self.si)
            self.si = None

    def _all_vms(self):
        """Internal helper for all vms."""
        if self.si is None:
            self.connect()
        content = self.si.RetrieveContent()
        view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
        try:
            return list(view.view)
        finally:
            view.Destroy()

    def find_vm(self, vm_name: str):
        """Find vm."""
        for vm_obj in self._all_vms():
            if vm_obj.name == vm_name:
                return vm_obj
        return None

    def list_windows_vms(self) -> List[str]:
        """List windows vms."""
        names = [LOCAL_SENTINEL]
        for vm_obj in self._all_vms():
            guest_name = normalize_text(getattr(getattr(vm_obj, "guest", None), "guestFullName", ""))
            if not guest_name or "WINDOWS" in guest_name.upper():
                names.append(vm_obj.name)
        return sorted(set(names), key=lambda x: (x != LOCAL_SENTINEL, x.lower()))

    def verify_vm_names(self, vm_names: List[str]) -> Dict[str, Dict[str, str]]:
        """Verify vm names."""
        inventory: Dict[str, Dict[str, str]] = {}
        for vm_obj in self._all_vms():
            inventory[vm_obj.name] = {
                "power_state": normalize_text(getattr(getattr(vm_obj, "runtime", None), "powerState", "")),
                "tools_status": normalize_text(getattr(getattr(vm_obj, "guest", None), "toolsRunningStatus", "")),
                "guest_os": normalize_text(getattr(getattr(vm_obj, "guest", None), "guestFullName", "")),
            }
        inventory[LOCAL_SENTINEL] = {"power_state": "LOCAL", "tools_status": "LOCAL", "guest_os": platform.platform()}
        return {name: inventory.get(name, {"power_state": "NOT_FOUND", "tools_status": "NOT_FOUND", "guest_os": "NOT_FOUND"}) for name in vm_names}

    def run_powershell_in_guest(self, vm_name: str, guest_username: str, guest_password: str, script: str, timeout_seconds: int = 90) -> Tuple[str, str, str]:
        """Run powershell in guest."""
        if requests is None:
            return "WARN", "ERROR", "requests is not installed. Install with: pip install requests"
        vm_obj = self.find_vm(vm_name)
        if vm_obj is None:
            return "WARN", "NOT_FOUND", f"VM '{vm_name}' not found"
        power_state = normalize_text(getattr(getattr(vm_obj, "runtime", None), "powerState", ""))
        if power_state.lower() != "poweredon":
            return "WARN", "VM_OFF", f"VM '{vm_name}' is not powered on"
        tools_status = normalize_text(getattr(getattr(vm_obj, "guest", None), "toolsRunningStatus", ""))
        if "guestToolsRunning" not in tools_status and "running" not in tools_status.lower():
            return "WARN", "TOOLS_NOT_READY", f"VMware Tools not ready on '{vm_name}'"

        content = self.si.RetrieveContent()
        guest_ops = content.guestOperationsManager
        creds = vim.vm.guest.NamePasswordAuthentication(username=guest_username, password=guest_password, interactiveSession=False)
        marker = datetime.now().strftime("%Y%m%d_%H%M%S")
        remote_out = fr"C:\Windows\Temp\sbl_audit_{marker}.txt"
        remote_err = fr"C:\Windows\Temp\sbl_audit_{marker}_err.txt"
        wrapped = (
            "$ErrorActionPreference='Stop';"
            f"try {{ {script} | Out-File -FilePath '{remote_out}' -Encoding UTF8 -Force }} "
            f"catch {{ $_ | Out-File -FilePath '{remote_err}' -Encoding UTF8 -Force; exit 1 }}"
        )
        spec = vim.vm.guest.ProcessManager.ProgramSpec(
            programPath=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            arguments=f"-NoProfile -ExecutionPolicy Bypass -Command \"{wrapped}\"",
        )
        pid = guest_ops.processManager.StartProgramInGuest(vm_obj, creds, spec)
        start = time.time()
        end_code = None
        while time.time() - start < timeout_seconds:
            info = guest_ops.processManager.ListProcessesInGuest(vm_obj, creds, [pid])
            if info and info[0].endTime is not None:
                end_code = info[0].exitCode
                break
            time.sleep(2)
        if end_code is None:
            return "WARN", "TIMEOUT", f"Timed out waiting for guest command on '{vm_name}'"

        def fetch_text(remote_path: str) -> str:
            """Fetch text."""
            try:
                file_info = guest_ops.fileManager.InitiateFileTransferFromGuest(vm_obj, creds, remote_path)
                response = requests.get(file_info.url, verify=not self.ignore_ssl, timeout=30)
                response.raise_for_status()
                return response.text.strip()
            except Exception:
                return ""

        stdout = fetch_text(remote_out)
        stderr = fetch_text(remote_err)
        if end_code == 0:
            return "PASS", stdout or "BLANK_OUTPUT", f"Guest PowerShell completed on '{vm_name}'"
        return "WARN", stderr or stdout or "ERROR", f"Guest PowerShell failed on '{vm_name}' with exit code {end_code}"


class SSHTunnelService:
    def __init__(
        self,
        target_username: str,
        target_password: str,
        target_port: int = 22,
        gateway_host: str = "",
        gateway_username: str = "",
        gateway_password: str = "",
        gateway_port: int = 22,
        timeout_seconds: int = 30,
    ):
        """Initialize the SSHTunnelService instance."""
        self.target_username = target_username.strip()
        self.target_password = target_password
        self.target_port = target_port
        self.gateway_host = gateway_host.strip()
        self.gateway_username = gateway_username.strip()
        self.gateway_password = gateway_password
        self.gateway_port = gateway_port
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _encode_powershell(script: str) -> str:
        """Internal helper for encode powershell."""
        return base64.b64encode(script.encode("utf-16le")).decode("ascii")

    def _connect_target(self, target_host: str, target_username: str, target_password: str):
        """Internal helper for connect target."""
        if not PARAMIKO_AVAILABLE:
            raise RuntimeError("paramiko is not installed. Install it with: pip install paramiko")

        target_client = paramiko.SSHClient()
        target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.gateway_host:
            gateway_client = paramiko.SSHClient()
            gateway_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            gateway_client.connect(
                hostname=self.gateway_host,
                port=self.gateway_port,
                username=self.gateway_username,
                password=self.gateway_password,
                timeout=self.timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = gateway_client.get_transport()
            if transport is None:
                gateway_client.close()
                raise RuntimeError(f"SSH gateway transport is unavailable for {self.gateway_host}")

            sock = transport.open_channel(
                "direct-tcpip",
                (target_host, self.target_port),
                ("127.0.0.1", 0),
            )
            target_client.connect(
                hostname=target_host,
                port=self.target_port,
                username=target_username,
                password=target_password,
                timeout=self.timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
                sock=sock,
            )
            return target_client, gateway_client

        target_client.connect(
            hostname=target_host,
            port=self.target_port,
            username=target_username,
            password=target_password,
            timeout=self.timeout_seconds,
            look_for_keys=False,
            allow_agent=False,
        )
        return target_client, None

    def run_powershell(
        self,
        target_host: str,
        script: str,
        timeout_seconds: int = 90,
        target_username: str = "",
        target_password: str = "",
    ) -> Tuple[str, str, str]:
        """Run powershell."""
        resolved_username = normalize_text(target_username) or self.target_username
        resolved_password = target_password or self.target_password
        if not resolved_username or not resolved_password:
            return "WARN", "NO_SSH_CREDS", f"Missing SSH credentials for target {target_host}"
        if not target_host:
            return "WARN", "NO_TARGET", "SSH target host is blank"

        target_client = None
        gateway_client = None
        try:
            target_client, gateway_client = self._connect_target(target_host, resolved_username, resolved_password)
            encoded = self._encode_powershell(script)
            command = f"powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"
            _, stdout, stderr = target_client.exec_command(command, timeout=timeout_seconds)
            out_text = stdout.read().decode(errors="ignore").strip()
            err_text = stderr.read().decode(errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()
            if exit_code == 0:
                return "PASS", out_text or "BLANK_OUTPUT", f"SSH PowerShell completed on '{target_host}'"
            return "WARN", err_text or out_text or "ERROR", f"SSH PowerShell failed on '{target_host}' with exit code {exit_code}"
        except Exception as exc:
            return "WARN", "SSH_ERROR", f"SSH execution failed on '{target_host}': {exc}"
        finally:
            try:
                if target_client is not None:
                    target_client.close()
            except Exception:
                pass
            try:
                if gateway_client is not None:
                    gateway_client.close()
            except Exception:
                pass
