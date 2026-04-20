"""No-admin bootstrap setup for AuditMatic clones.

Usage:
  python bootstrap_setup.py
  python bootstrap_setup.py --run
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_step(cmd: list[str], label: str) -> None:
    print(f"[INFO] {label}")
    print(f"       {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def main() -> int:
    repo_root = Path(__file__).resolve().parent
    venv_dir = repo_root / "venv"

    if sys.platform.startswith("win"):
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    try:
        print(f"[INFO] Repo root: {repo_root}")
        print(f"[INFO] Bootstrap interpreter: {sys.executable}")

        if not venv_python.exists():
            run_step([sys.executable, "-m", "venv", str(venv_dir)], "Creating virtual environment")
        else:
            print("[INFO] Reusing existing virtual environment")

        run_step(
            [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
            "Upgrading packaging tools",
        )
        run_step(
            [str(venv_python), "-m", "pip", "install", "-r", str(repo_root / "requirements.txt")],
            "Installing requirements",
        )
        run_step([str(venv_python), "-m", "pip", "check"], "Validating dependency health")
        run_step([str(repo_root / "ensure_desktop_shortcuts.bat")], "Ensuring desktop shortcuts")

        print("\n[OK] Setup complete.")
        print(f"[NEXT] Launch app:  {venv_python} {repo_root / 'main.py'}")
        print(f"[NEXT] Basic scan:  {repo_root / 'Launch_Basic_Scan.bat'}")
        print(f"[NEXT] Run tests:   {repo_root / 'run_tests.bat'}")

        if "--run" in sys.argv[1:]:
            run_step([str(venv_python), str(repo_root / "main.py")], "Starting AuditMatic")

        return 0
    except subprocess.CalledProcessError as exc:
        print(f"\n[ERROR] Step failed with exit code {exc.returncode}")
        return exc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
