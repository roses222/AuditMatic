"""
AuditMatic Entry Point

Run this file to start the application:
    python main.py
"""

import sys
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ui.app import App


def main():
    """Launch the AuditMatic GUI application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
