"""
AuditMatic Data Models

Dataclass definitions for core domain objects used throughout the audit system.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List
from pathlib import Path

# =====================================================================
# Audit Row Model
# =====================================================================
@dataclass
class AuditRow:
    """
    Represents a single row parsed from an audit workbook.
    Contains software component info and target VM mappings.
    """
    row_index: int
    software_component: str
    current_ci_version: str
    sbl_build_version: str
    audit_value: str
    target_vms: Dict[str, str]
    version_locations: str


# =====================================================================
# Scan Result Model
# =====================================================================
@dataclass
class ScanResult:
    """
    Result of scanning a software component on a target.
    Contains version comparison outcome and audit details.
    """
    software_component: str
    target_name: str
    expected_version: str
    found_version: str
    status: str
    details: str
    worksheet_row: int
    audit_text: str


# =====================================================================
# Workbook Schema Model
# =====================================================================
@dataclass
class WorkbookSchema:
    """
    Dynamically discovered workbook structure.
    Replaces hardcoded SYSTEM_COLUMNS by detecting actual columns in the workbook.
    """
    source_path: str
    source_format: str  # 'excel', 'json', 'csv'
    header_row_index: int
    software_column: str  # e.g., "SOFTWARE COMPONENT"
    current_version_column: str  # e.g., "CURRENT CI VERSION"
    sbl_version_column: str  # e.g., "VERSION LOCATIONS" or "SBL BUILD VERSION"
    target_columns: List[str]  # e.g., ["Target_1", "Target_2", "vm-prod-01", ...]
    other_columns: List[str]  # non-target columns
    
    def get_all_columns(self) -> List[str]:
        """Return all columns in order: required + targets + others."""
        return (
            [self.software_column, self.current_version_column, self.sbl_version_column]
            + self.target_columns
            + self.other_columns
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize for storage in profiles."""
        return asdict(self)
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "WorkbookSchema":
        """Deserialize from profile storage."""
        return WorkbookSchema(**data)
