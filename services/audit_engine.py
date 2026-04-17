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
from services.utils import compare_versions, is_x_mark, normalize_model_key, normalize_text, parse_version_tuple


class LocalWindowsScanner:
    """Run local Windows software detection commands used by the audit engine."""

    MIN_AUTO_MATCH_PERCENT = 85

    GENERIC_SOFTWARE_TOKENS = {
        "microsoft", "windows", "version", "client", "plugin", "tools", "tool",
        "software", "edition", "release", "lite", "professional", "plus",
    }
    COMMON_APP_EXECUTABLES = {
        "excel": "excel.exe",
        "word": "winword.exe",
        "powerpoint": "powerpnt.exe",
        "onenote": "onenote.exe",
        "outlook": "outlook.exe",
        "swift": "swift.exe",
        "winver": "winver.exe",
    }
    COMMON_UNINSTALL_ALIASES = {
        "excel": ["Office 16 Click-to-Run", "Microsoft 365 Apps", "Office"],
        "word": ["Office 16 Click-to-Run", "Microsoft 365 Apps", "Office"],
        "powerpoint": ["Office 16 Click-to-Run", "Microsoft 365 Apps", "Office"],
        "onenote": ["Office 16 Click-to-Run", "Microsoft 365 Apps", "Office"],
        "outlook": ["Office 16 Click-to-Run", "Microsoft 365 Apps", "Office"],
    }

    @staticmethod
    def _tokenize_name(value: str) -> List[str]:
        """Tokenize and normalize software names for resilient comparison."""
        tokens = [t.lower() for t in re.findall(r"[A-Za-z0-9]+", normalize_text(value))]
        return [
            token
            for token in tokens
            if len(token) >= 3 and token not in LocalWindowsScanner.GENERIC_SOFTWARE_TOKENS
        ]

    @staticmethod
    def _score_display_name_match(target_name: str, display_name: str) -> Tuple[int, bool]:
        """Return a score plus candidate-eligibility for DisplayName matching."""
        target = normalize_text(target_name).lower()
        display = normalize_text(display_name).lower()
        if not target or not display:
            return 0, False

        exact = display == target
        starts = display.startswith(target)
        contains = target in display

        target_tokens = LocalWindowsScanner._tokenize_name(target)
        display_tokens = set(LocalWindowsScanner._tokenize_name(display))
        common_count = sum(1 for token in target_tokens if token in display_tokens)
        coverage = (common_count / len(target_tokens)) if target_tokens else 0.0

        score = 0
        if exact:
            score += 120
        elif starts:
            score += 90
        elif contains:
            score += 75
        score += int(40 * coverage)

        if len(target_tokens) >= 2 and coverage == 1.0:
            score += 15

        eligible = exact or starts or contains or coverage >= 0.6
        return score, eligible

    @staticmethod
    def _score_to_percent(score: int) -> int:
        """Convert internal score to a user-facing confidence percentage."""
        if score >= 120:
            return 99
        if score >= 95:
            return 90
        if score >= 80:
            return 78
        if score >= 65:
            return 65
        return 50

    @staticmethod
    def _percent_to_tag(percent: int) -> str:
        """Map confidence percentage to a concise confidence tag."""
        if percent >= 90:
            return "HIGH"
        if percent >= 75:
            return "MEDIUM"
        return "LOW"

    def _pick_best_uninstall_match(self, software_name: str, entries: List[Dict[str, str]]) -> Optional[Tuple[Dict[str, str], int, int, str]]:
        """Pick best uninstall entry using deterministic scored matching."""
        best_entry: Optional[Dict[str, str]] = None
        best_key: Tuple[int, int] = (-1, -1)
        best_score = 0

        print(f"[MATCH] target='{software_name}' candidate_count={len(entries)}", flush=True)

        for entry in entries:
            display_name = entry.get("display_name", "")
            score, eligible = self._score_display_name_match(software_name, display_name)
            print(
                f"[MATCH] compare target='{software_name}' display='{display_name}' score={score} eligible={eligible}",
                flush=True,
            )
            if not eligible:
                continue
            # Prefer higher score; break ties using shorter display names.
            tie_break = -len(display_name)
            key = (score, tie_break)
            if key > best_key:
                best_key = key
                best_entry = entry
                best_score = score

        if best_entry is None:
            print(f"[MATCH] no_eligible_match target='{software_name}'", flush=True)
            return None
        percent = self._score_to_percent(best_score)
        tag = self._percent_to_tag(percent)
        print(
            f"[MATCH] selected target='{software_name}' matched='{best_entry.get('display_name', '')}' "
            f"score={best_score} percent={percent} tag={tag}",
            flush=True,
        )
        return best_entry, best_score, percent, tag

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

        if rule == "manual_steps":
            instructions = payload.get("instructions", "")
            if instructions:
                commands.append(f"MANUAL_STEPS: {instructions}")
            commands.append("Fallback-1: uninstall registry DisplayName/DisplayVersion lookup")
            commands.append("Fallback-2: explicit file path ProductVersion/FileVersion lookup")
            commands.append("Fallback-3: resolve EXE/DLL via App Paths/where/search then file version lookup")
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
        from services.utils import normalize_header, normalize_version
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
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        candidates: List[Dict[str, str]] = []
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
                                    version = normalize_text(winreg.QueryValueEx(sub, "DisplayVersion")[0])
                                except Exception:
                                    version = ""
                                candidates.append(
                                    {
                                        "display_name": display_name,
                                        "version": version,
                                        "registry_key": f"{root}\\{sub_name}",
                                    }
                                )
                        except Exception:
                            continue
        except Exception as exc:
            return "WARN", "ERROR", f"Registry scan failed: {exc}"

        best = self._pick_best_uninstall_match(software_name, candidates)
        if best is not None:
            best_entry, score, percent, tag = best
            if percent < self.MIN_AUTO_MATCH_PERCENT:
                return (
                    "WARN",
                    "LOW_CONFIDENCE_MATCH",
                    f"Best candidate '{best_entry.get('display_name', '')}' below auto-match threshold | "
                    f"name_match={tag} ({percent}%) | threshold={self.MIN_AUTO_MATCH_PERCENT}% | "
                    f"name_match_score={score}",
                )
            version = best_entry.get("version", "") or "FOUND_NO_VERSION"
            return (
                "PASS",
                version,
                f"Matched installed app '{best_entry.get('display_name', '')}' ({best_entry.get('registry_key', '')}) | "
                f"name_match={tag} ({percent}%) | name_match_score={score}",
            )
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

    @staticmethod
    def _extract_executable_tokens(text: str) -> List[str]:
        """Extract executable or DLL file names from instructions like '... Outlook.exe ...'."""
        if not text:
            return []
        matches = re.findall(r"\b([A-Za-z0-9_.-]+\.(?:exe|dll))\b", text, flags=re.IGNORECASE)
        tokens: List[str] = []
        for item in matches:
            normalized = item.strip().strip('"').strip("'")
            if normalized and normalized not in tokens:
                tokens.append(normalized)
        return tokens

    @staticmethod
    def _build_software_aliases(software_name: str) -> List[str]:
        """Build ordered alias candidates for uninstall-registry matching."""
        name = normalize_text(software_name)
        if not name:
            return []
        aliases: List[str] = [name]
        words = re.findall(r"[A-Za-z0-9]+", name)
        filtered = [w for w in words if len(w) >= 4 and w.lower() not in LocalWindowsScanner.GENERIC_SOFTWARE_TOKENS]
        if filtered:
            aliases.append(" ".join(filtered))
        for token in filtered:
            aliases.append(token)
            for mapped in LocalWindowsScanner.COMMON_UNINSTALL_ALIASES.get(token.lower(), []):
                aliases.append(mapped)
        deduped: List[str] = []
        for alias in aliases:
            if alias and alias not in deduped:
                deduped.append(alias)
        return deduped

    @staticmethod
    def _extract_executable_hints(text: str) -> List[str]:
        """Extract EXE/DLL hints from manual instruction text, including common app name mappings."""
        hints: List[str] = []
        for token in LocalWindowsScanner._extract_executable_tokens(text):
            if token not in hints:
                hints.append(token)

        lowered = normalize_text(text).lower()
        for key, exe in LocalWindowsScanner.COMMON_APP_EXECUTABLES.items():
            if re.search(rf"\b{re.escape(key)}\b", lowered):
                if exe not in hints:
                    hints.append(exe)
        return hints

    def _resolve_app_path_executable(self, executable_name: str) -> List[str]:
        """Resolve executable paths using App Paths, where.exe, and targeted Program Files search."""
        exe = normalize_text(executable_name)
        if not exe:
            return []

        candidates: List[str] = []

        app_paths_query = (
            "$roots=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths',"
            "'HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths');"
            f"$name='{exe.replace("'", "''")}';"
            "$hits=@();"
            "foreach($r in $roots){"
            "  $k=Join-Path $r $name;"
            "  try {"
            "    $d=(Get-ItemProperty -Path $k -ErrorAction Stop).'(default)';"
            "    if($d){$hits += $d}"
            "  } catch {}"
            "};"
            "$hits | Select-Object -Unique"
        )
        status, output, _ = self.run_powershell(app_paths_query)
        if status == "PASS" and output and output not in ("BLANK_OUTPUT", "ERROR"):
            for line in output.splitlines():
                line = line.strip()
                if line and line not in candidates:
                    candidates.append(line)

        where_cmd = f"where.exe {exe}"
        status, output, _ = self.run_powershell(where_cmd)
        if status == "PASS" and output and output not in ("BLANK_OUTPUT", "ERROR"):
            for line in output.splitlines():
                line = line.strip()
                if line and line.lower().endswith((".exe", ".dll")) and line not in candidates:
                    candidates.append(line)

        # Targeted fallback search in common install roots for the executable name.
        file_search_query = (
            "$roots=@('C:\\Program Files','C:\\Program Files (x86)','C:\\Windows');"
            f"$name='{exe.replace("'", "''")}';"
            "$hits=@();"
            "foreach($r in $roots){"
            "  if(Test-Path $r){"
            "    try {"
            "      $hits += Get-ChildItem -Path $r -Filter $name -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3 -ExpandProperty FullName"
            "    } catch {}"
            "  }"
            "};"
            "$hits | Select-Object -Unique | Select-Object -First 5"
        )
        status, output, _ = self.run_powershell(file_search_query)
        if status == "PASS" and output and output not in ("BLANK_OUTPUT", "ERROR"):
            for line in output.splitlines():
                line = line.strip()
                if line and line not in candidates:
                    candidates.append(line)

        return candidates

    def _scan_instruction_fallback(self, software_name: str, instructions: str) -> Tuple[str, str, str]:
        """Systematic fallback chain for manual instruction rows.

        Order: uninstall registry -> explicit paths -> executable resolution -> file-version lookup.
        """
        notes: List[str] = []

        # Step 0: targeted special-case queries for known manual-only categories.
        special = self._scan_special_cases(software_name, instructions)
        if special is not None:
            return special

        # Step 1: uninstall registry matching with software aliases.
        for alias in self._build_software_aliases(software_name):
            status, version, details = self.find_programs_and_features_version(alias)
            notes.append(f"uninstall[{alias}]={status}:{version}")
            if status == "PASS":
                return "PASS", version, f"fallback=uninstall-registry | {details}"

        # Step 2: explicit full paths embedded in instructions.
        explicit_paths = VersionRuleResolver.extract_file_paths(instructions)
        if explicit_paths:
            status, version, details = self.scan_file_versions(explicit_paths)
            notes.append(f"explicit_paths={status}:{version}")
            if status == "PASS":
                return "PASS", version, f"fallback=explicit-path | {details}"

        # Step 3: EXE/DLL token resolution, then file version lookup.
        exe_tokens = self._extract_executable_hints(instructions)
        resolved_paths: List[str] = []
        for token in exe_tokens:
            for candidate in self._resolve_app_path_executable(token):
                if candidate not in resolved_paths:
                    resolved_paths.append(candidate)
        if resolved_paths:
            status, version, details = self.scan_file_versions(resolved_paths)
            notes.append(f"resolved_paths={status}:{version}")
            if status == "PASS":
                return "PASS", version, f"fallback=exe-dll-resolution | {details}"

        # None of the automated fallback steps found a definitive version.
        note_text = "; ".join(notes) if notes else "no-fallback-attempts"
        return "WARN", "MANUAL_CHECK", f"fallback_exhausted | {note_text} | instructions={instructions or 'n/a'}"

    def _scan_special_cases(self, software_name: str, instructions: str) -> Optional[Tuple[str, str, str]]:
        """Run dedicated queries for known special-case checks before generic fallback."""
        name = normalize_text(software_name).lower()
        instr = normalize_text(instructions).lower()

        # Microsoft Defender client and signature versions.
        if "defender" in name or "windows security" in instr:
            if "antivirus definitions" in name or "signature" in name:
                status, value, details = self.run_powershell("$s=Get-MpComputerStatus; if($s -and $s.AntivirusSignatureVersion){$s.AntivirusSignatureVersion}else{Write-Output 'NOT_FOUND'; exit 4}")
                if status == "PASS" and value not in ("NOT_FOUND", "BLANK_OUTPUT"):
                    return "PASS", value, "special=defender-signature | Get-MpComputerStatus.AntivirusSignatureVersion"
                return "WARN", "MANUAL_CHECK", f"special=defender-signature unavailable | {details}"

            if "antimalware client" in name or "defender" in name:
                status, value, details = self.run_powershell("$s=Get-MpComputerStatus; if($s -and $s.AMProductVersion){$s.AMProductVersion}else{Write-Output 'NOT_FOUND'; exit 4}")
                if status == "PASS" and value not in ("NOT_FOUND", "BLANK_OUTPUT"):
                    return "PASS", value, "special=defender-client | Get-MpComputerStatus.AMProductVersion"
                return "WARN", "MANUAL_CHECK", f"special=defender-client unavailable | {details}"

        # Swift XMPP Client: check known install paths for swift.exe file version.
        if "swift" in name and ("xmpp" in name or "swift" in instr):
            swift_query = r"""
$paths=@(
    "C:\Program Files\Swift\swift.exe",
    "C:\Program Files (x86)\Isode\Swift\swift.exe",
    "C:\Program Files (x86)\Swift\swift.exe",
    "C:\Program Files\Isode\Swift\swift.exe"
)
foreach($p in $paths){
    if(Test-Path $p){
        try{$v=(Get-Item $p).VersionInfo.ProductVersion; if($v){Write-Output $v; exit 0}}catch{}
        try{$v=(Get-Item $p).VersionInfo.FileVersion; if($v){Write-Output $v; exit 0}}catch{}
    }
}
$reg=@(
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
foreach($h in $reg){
    try{
        $e=Get-ItemProperty $h -ErrorAction SilentlyContinue | Where-Object{$_.DisplayName -match 'Swift'}
        if($e -and $e.DisplayVersion){Write-Output $e.DisplayVersion; exit 0}
    }catch{}
}
Write-Output 'NOT_FOUND'; exit 4
"""
            status, value, details = self.run_powershell(swift_query)
            if status == "PASS" and value not in ("NOT_FOUND", "BLANK_OUTPUT"):
                return "PASS", value, "special=swift-xmpp | file-version"

        # MTI Plugin: search ArcGIS Pro Add-In Manager shared add-ins for MTI Tools .esriAddinX file.
        if "mti" in name and ("plugin" in name or "arcgis" in instr or "add-in manager" in instr):
            mti_query = r"""
$roots=@(
    "$env:APPDATA\ESRI\ArcGISPro\Addins",
    "$env:USERPROFILE\Documents\ArcGIS\AddIns\ArcGISPro",
    "C:\Program Files\ArcGIS\Pro\bin\Extensions",
    "C:\Program Files\ArcGIS\Pro\Resources\AddIns",
    "$env:PUBLIC\Documents\ArcGIS\AddIns\ArcGISPro"
)
foreach($r in $roots){
    if(Test-Path $r){
        $files=Get-ChildItem -Path $r -Recurse -ErrorAction SilentlyContinue |
            Where-Object{$_.Name -match 'MTI' -or $_.DirectoryName -match 'MTI'}
        foreach($f in $files){
            # Try version from .esriAddinX (zip) embedded config.daml XML
            if($f.Extension -eq '.esriAddinX'){
                try{
                    Add-Type -Assembly System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                    $zip=[System.IO.Compression.ZipFile]::OpenRead($f.FullName)
                    $entry=$zip.Entries | Where-Object{$_.Name -eq 'config.daml'} | Select-Object -First 1
                    if($entry){
                        $sr=New-Object System.IO.StreamReader($entry.Open())
                        $xml=$sr.ReadToEnd(); $sr.Close()
                        $zip.Dispose()
                        $m=[regex]::Match($xml,'version\s*=\s*"([\d.]+)"')
                        if($m.Success){Write-Output $m.Groups[1].Value; exit 0}
                    }else{$zip.Dispose()}
                }catch{}
            }
            # Fallback: version from dll/exe in same folder
            if($f.Extension -in '.dll','.exe'){
                try{$v=(Get-Item $f.FullName).VersionInfo.ProductVersion; if($v){Write-Output $v; exit 0}}catch{}
            }
            # Fallback: version number embedded in filename
            $m=[regex]::Match($f.Name,'(\d+\.\d+(?:\.\d+){0,3})')
            if($m.Success){Write-Output $m.Groups[1].Value; exit 0}
        }
    }
}
Write-Output 'NOT_FOUND'; exit 4
"""
            status, value, details = self.run_powershell(mti_query)
            if status == "PASS" and value not in ("NOT_FOUND", "BLANK_OUTPUT"):
                return "PASS", value, "special=mti-arcgis-addin | esriAddinX-search"

        # ESRI add-ins/plugins: search ArcGIS Pro add-in locations and attempt to derive version from file metadata/name.
        if "plugin" in name or "add-in" in instr or "add in" in instr or "arcgis" in name:
            query_term = ""
            tokens = re.findall(r"[A-Za-z0-9]+", software_name)
            for token in tokens:
                token_l = token.lower()
                if len(token_l) >= 3 and token_l not in self.GENERIC_SOFTWARE_TOKENS:
                    query_term = token
                    break
            if not query_term:
                query_term = "arcgis"

            escaped_term = query_term.replace("'", "''")
            plugin_query = f"""
$roots=@(
    "$env:APPDATA\\ESRI\\ArcGISPro\\Addins",
    "$env:USERPROFILE\\Documents\\ArcGIS\\AddIns\\ArcGISPro",
    "C:\\Program Files\\ArcGIS\\Pro\\bin\\Extensions",
    "C:\\Program Files\\ArcGIS\\Pro\\Resources\\AddIns"
)
$term='{escaped_term}'
$hits=@()
foreach($r in $roots){{
    if(Test-Path $r){{
        $hits += Get-ChildItem -Path $r -Recurse -ErrorAction SilentlyContinue |
            Where-Object {{ $_.Name -match [Regex]::Escape($term) }} | Select-Object -First 8
    }}
}}
foreach($h in $hits){{
    if($h.PSIsContainer){{ continue }}
    $ver=''
    if($h.Extension -in '.exe','.dll'){{
        try {{ $ver=(Get-Item $h.FullName).VersionInfo.ProductVersion }} catch {{}}
        if(-not $ver){{ try {{ $ver=(Get-Item $h.FullName).VersionInfo.FileVersion }} catch {{}} }}
    }}
    if(-not $ver){{
        $m=[regex]::Match($h.Name,'(\\d+\\.\\d+(?:\\.\\d+){{0,3}})')
        if($m.Success){{ $ver=$m.Groups[1].Value }}
    }}
    if($ver){{ Write-Output $ver; exit 0 }}
}}
Write-Output 'NOT_FOUND'
exit 4
"""
            status, value, details = self.run_powershell(plugin_query)
            if status == "PASS" and value not in ("NOT_FOUND", "BLANK_OUTPUT"):
                return "PASS", value, f"special=esri-plugin-search | term={query_term}"

        return None

    def scan_software_version(self, software_name: str, version_location: str) -> Tuple[str, str, str]:
        """Resolve and execute the appropriate local scan rule for one software component.

        Primary rule is attempted first. If it does not return PASS, the full special-case
        + systematic fallback chain is invoked before giving up.
        """
        rule, payload = VersionRuleResolver.detect_rule(version_location)

        # 1. Run the primary rule.
        primary_result: Optional[Tuple[str, str, str]] = None
        if rule == "programs_and_features":
            primary_result = self.find_programs_and_features_version(software_name)
        elif rule == "powershell":
            primary_result = self.run_powershell(payload["command"])
        elif rule == "file_version":
            primary_result = self.scan_file_versions(payload["paths"])
        elif rule == "manual_steps":
            # manual_steps goes straight to the fallback chain — no primary to attempt.
            instructions = payload.get("instructions", "")
            return self._scan_instruction_fallback(software_name, instructions)

        # 2. If primary succeeded, return immediately.
        if primary_result is not None and primary_result[0] == "PASS":
            return primary_result

        # 3. Primary failed / no rule matched — run special-case probes then systematic fallback.
        primary_note = f"primary_rule={rule}:{primary_result[1] if primary_result else 'no_rule'}"
        special = self._scan_special_cases(software_name, version_location)
        if special is not None:
            return special
        fb_status, fb_version, fb_details = self._scan_instruction_fallback(software_name, version_location)
        if fb_status == "PASS":
            return fb_status, fb_version, f"{primary_note} | {fb_details}"
        return fb_status, fb_version, f"{primary_note} | {fb_details}"


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

    @staticmethod
    def _build_ranked_programs_and_features_script(software_name: str) -> str:
        """Build a ranked Programs-and-Features query script for remote targets."""
        safe_name = software_name.replace("'", "''")
        return (
            "$paths=@('HKLM:SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
            f"$target='{safe_name}'.ToLower();"
            "$targetTokens=[regex]::Matches($target,'[a-z0-9]+') | ForEach-Object { $_.Value } | Where-Object { $_.Length -ge 3 } | Select-Object -Unique;"
            "$items=Get-ItemProperty $paths -ErrorAction SilentlyContinue;"
            "$best=$null; $bestScore=-1; $bestTie=-999999;"
            "foreach($item in $items){"
            "  $dn=[string]$item.DisplayName;"
            "  if(-not $dn){ continue }"
            "  $dnl=$dn.ToLower();"
            "  $score=0; $eligible=$false;"
            "  if($dnl -eq $target){ $score += 120; $eligible=$true }"
            "  elseif($dnl.StartsWith($target)){ $score += 90; $eligible=$true }"
            "  elseif($dnl.Contains($target)){ $score += 75; $eligible=$true }"
            "  if($targetTokens.Count -gt 0){"
            "    $dispTokens=[regex]::Matches($dnl,'[a-z0-9]+') | ForEach-Object { $_.Value } | Where-Object { $_.Length -ge 3 } | Select-Object -Unique;"
            "    $common=0;"
            "    foreach($tok in $targetTokens){ if($dispTokens -contains $tok){ $common += 1 } }"
            "    $coverage=[double]$common / [double]$targetTokens.Count;"
            "    $score += [int](40 * $coverage);"
            "    if($coverage -ge 0.6){ $eligible=$true }"
            "  }"
            "  if(-not $eligible){ continue }"
            "  $tie = -($dn.Length);"
            "  if($score -gt $bestScore -or ($score -eq $bestScore -and $tie -gt $bestTie)){"
            "    $best=$item; $bestScore=$score; $bestTie=$tie"
            "  }"
            "}"
            "if(-not $best){ Write-Output 'NOT_FOUND'; exit 4 };"
            "$v=[string]$best.DisplayVersion; if(-not $v){ $v='FOUND_NO_VERSION' };"
            "$pct=50;"
            "if($bestScore -ge 120){ $pct=99 }"
            "elseif($bestScore -ge 95){ $pct=90 }"
            "elseif($bestScore -ge 80){ $pct=78 }"
            "elseif($bestScore -ge 65){ $pct=65 };"
            "$tag='LOW'; if($pct -ge 90){$tag='HIGH'} elseif($pct -ge 75){$tag='MEDIUM'};"
            "$name=[string]$best.DisplayName;"
            "Write-Output ('VER=' + $v + ';MATCH_TAG=' + $tag + ';MATCH_PCT=' + $pct + ';MATCH_NAME=' + $name)"
        )

    def _resolve_expected_version(self, row: AuditRow) -> str:
        """Pick the best expected-version string for comparison.

        Prefer sbl_build_version when it parses as a real version number.
        Fall back to current_ci_version (the CURRENT CI VERSION column) when
        sbl_build_version is blank, a checkmark, or otherwise non-numeric.
        """
        sbl = normalize_text(row.sbl_build_version)
        if sbl and parse_version_tuple(sbl):
            return sbl
        return normalize_text(row.current_ci_version)

    @staticmethod
    def _extract_name_match_metadata(details: str) -> Tuple[str, str]:
        """Extract name-match confidence metadata from details text."""
        detail_text = details or ""
        tag_match = re.search(r"name_match=([A-Z]+)", detail_text)
        pct_match = re.search(r"name_match=[A-Z]+\s*\((\d{1,3})%\)", detail_text)
        tag = tag_match.group(1) if tag_match else ""
        pct = pct_match.group(1) if pct_match else ""
        return tag, pct

    @staticmethod
    def _append_name_match_to_audit_text(audit_text: str, details: str) -> str:
        """Append name-match confidence to audit text when metadata is available."""
        tag, pct = AuditEngine._extract_name_match_metadata(details)
        if not tag or not pct:
            return audit_text
        if "name_match=" in audit_text:
            return audit_text
        return f"{audit_text} | name_match={tag} ({pct}%)"

    @staticmethod
    def _parse_ranked_programs_output(output: str) -> Tuple[str, str, str, str]:
        """Parse ranked Programs-and-Features script output.

        Returns: (found_version, match_tag, match_pct, match_name)
        """
        text = normalize_text(output)
        if not text:
            return output, "", "", ""
        if text in ("NOT_FOUND", "FOUND_NO_VERSION", "BLANK_OUTPUT"):
            return text, "", "", ""
        if not text.startswith("VER="):
            return output, "", "", ""

        parsed: Dict[str, str] = {}
        for part in text.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            parsed[normalize_text(key).upper()] = normalize_text(value)
        return (
            parsed.get("VER", output),
            parsed.get("MATCH_TAG", ""),
            parsed.get("MATCH_PCT", ""),
            parsed.get("MATCH_NAME", ""),
        )

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
        expected_version = self._resolve_expected_version(row)
        status, audit_text = compare_versions(expected_version, found_version, scan_status)
        audit_text = self._append_name_match_to_audit_text(audit_text, details)
        return ScanResult(row.software_component, target_name, expected_version, found_version, status, details, row.row_index, audit_text)

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
            script = self._build_ranked_programs_and_features_script(row.software_component)
            scan_status, found_version, details = self.vsphere_service.run_powershell_in_guest(vm_name, guest_username, guest_password, script)
            parsed_version, match_tag, match_pct, match_name = self._parse_ranked_programs_output(found_version)
            if match_tag and match_pct:
                details = f"{details} | matched='{match_name}' | name_match={match_tag} ({match_pct}%)"
                found_version = parsed_version
                try:
                    if int(match_pct) < LocalWindowsScanner.MIN_AUTO_MATCH_PERCENT:
                        scan_status = "WARN"
                        found_version = "LOW_CONFIDENCE_MATCH"
                        details = f"{details} | below auto-match threshold={LocalWindowsScanner.MIN_AUTO_MATCH_PERCENT}%"
                except Exception:
                    pass
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
            script = self._build_ranked_programs_and_features_script(row.software_component)
            scan_status, found_version, details = self.ssh_service.run_powershell(
                target_host,
                script,
                target_username=target_username,
                target_password=target_password,
            )
            parsed_version, match_tag, match_pct, match_name = self._parse_ranked_programs_output(found_version)
            if match_tag and match_pct:
                details = f"{details} | matched='{match_name}' | name_match={match_tag} ({match_pct}%)"
                found_version = parsed_version
                try:
                    if int(match_pct) < LocalWindowsScanner.MIN_AUTO_MATCH_PERCENT:
                        scan_status = "WARN"
                        found_version = "LOW_CONFIDENCE_MATCH"
                        details = f"{details} | below auto-match threshold={LocalWindowsScanner.MIN_AUTO_MATCH_PERCENT}%"
                except Exception:
                    pass
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
