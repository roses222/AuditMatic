"""UI frames.

Small, low-risk frames are extracted here first. Larger frames continue to
bridge to the legacy module until they are moved in smaller slices.
"""

import os
import copy
import json
import re
import sys
import subprocess
import tempfile
import threading
from dataclasses import asdict
from pathlib import Path
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from config import AUDIT_CHECKLIST_DIR, AUDIT_RESULTS_DIR, BUILD_TYPE_OPTIONS, LOCAL_SENTINEL, LOGS_DIR, PROFILES_DIR, SBLS_DIR, TEMPLATES_DIR, TESTS_DIR
from models import AuditRow, ScanResult
from services.audit_engine import AuditEngine, LocalWindowsScanner
from services.file_logger import FileLogger
from services.json_export_service import JsonExportService
from services.profile_service import PARAMIKO_AVAILABLE, SSHTunnelService, VMProfileService, VSphereService
from services.template_service import TemplateAssetService, _get_sbl_model_from_workbook
from services.watch_pipeline_service import PipelineRuntimeStatus, WatchFolderPipelineService
from services.workbook_service import AuditWorkbookService, ChecklistGeneratorService, VersionRuleResolver, read_software_list_universal_rows
from services.utils import (
	build_target_schema_payload,
	default_target_columns,
	detect_header_row_index,
	detect_target_columns,
	detect_workbook_format,
	infer_build_type,
	normalize_text,
	resolve_profile_target_columns,
	timestamp_str,
)


def confirm_target_column_mapping(
	parent: tk.Widget,
	source_path: str,
	detected_columns: List[str],
	build_type: str,
	current_columns: Optional[List[str]] = None,
) -> Optional[List[str]]:
	"""Prompt the user to confirm or adjust detected VM target columns."""
	detected = [normalize_text(name) for name in detected_columns if normalize_text(name)]
	fallback = default_target_columns()
	if not detected:
		return fallback

	preview = "\n".join(f"- {name}" for name in detected)
	build_label = normalize_text(build_type)
	if not build_label:
		build_label = infer_build_type(build_type)
	message = (
		f"Detected VM target columns from source:\n{source_path or 'N/A'}\n"
		f"Build type: {build_label}\n\n"
		f"Detected columns:\n{preview}\n\n"
		"Choose Yes to use detected columns, No to use legacy fallback columns, or Cancel to keep current selection."
	)
	choice = messagebox.askyesnocancel("Confirm Target Column Mapping", message, parent=parent)
	if choice is True:
		return detected
	if choice is False:
		return fallback
	if current_columns:
		return list(current_columns)
	return None


def normalize_ssh_tunnel_profile_fields(ssh_tunnel: Any) -> Dict[str, str]:
	"""Normalize SSH tunnel profile keys into one UI-friendly shape."""
	if not isinstance(ssh_tunnel, dict):
		return {
			"gateway_host": "",
			"gateway_port": "22",
			"gateway_username": "",
			"gateway_password": "",
			"target_port": "22",
		}

	gateway_host = normalize_text(ssh_tunnel.get("gateway_host", ""))
	gateway_port = normalize_text(ssh_tunnel.get("gateway_port", "") or "22")
	gateway_username = normalize_text(ssh_tunnel.get("gateway_username", ""))
	gateway_password = ssh_tunnel.get("gateway_password", "") or ""
	target_port = normalize_text(ssh_tunnel.get("target_port", "") or "22")

	return {
		"gateway_host": gateway_host,
		"gateway_port": gateway_port,
		"gateway_username": gateway_username,
		"gateway_password": gateway_password,
		"target_port": target_port,
	}


class BaseFrame(ttk.Frame):
	"""Base class for all UI frames."""

	def __init__(self, parent, controller):
		"""Initialize the BaseFrame instance."""
		super().__init__(parent, padding=16)
		self.controller = controller

	def open_folder(self, folder: Path):
		"""Open a filesystem folder using the platform default behavior."""
		try:
			if os.name == "nt":
				os.startfile(folder)
			else:
				messagebox.showinfo("Folder", str(folder))
		except Exception as exc:
			messagebox.showerror("Open folder failed", str(exc))

	def ensure_desktop_shortcuts(self) -> None:
		"""Run shortcut bootstrap script so required desktop shortcuts exist."""
		script_path = Path(__file__).resolve().parents[1] / "ensure_desktop_shortcuts.bat"
		if not script_path.exists():
			messagebox.showerror("Shortcuts", f"Shortcut script not found:\n{script_path}")
			return

		try:
			result = subprocess.run(
				["cmd", "/c", str(script_path)],
				cwd=str(script_path.parent),
				capture_output=True,
				text=True,
				check=False,
			)
		except Exception as exc:
			messagebox.showerror("Shortcuts", f"Unable to run shortcut setup:\n{exc}")
			return

		output = (result.stdout or "").strip()
		error_output = (result.stderr or "").strip()
		if result.returncode == 0:
			message = "Desktop shortcuts checked successfully."
			if output:
				message = f"{message}\n\n{output}"
			messagebox.showinfo("Shortcuts", message)
			return

		failure_message = "Shortcut setup reported an error."
		if output:
			failure_message = f"{failure_message}\n\n{output}"
		if error_output:
			failure_message = f"{failure_message}\n\n{error_output}"
		messagebox.showwarning("Shortcuts", failure_message)


class HomeFrame(BaseFrame):
	"""Home frame with tool description and navigation."""

	def __init__(self, parent, controller):
		"""Initialize the HomeFrame instance."""
		super().__init__(parent, controller)
		outer = ttk.Frame(self)
		outer.pack(fill="both", expand=True)
		ttk.Label(outer, text="SBL Checklist & Audit Tool", font=("Segoe UI", 20, "bold")).pack(anchor="w", pady=(0, 8))
		ttk.Label(outer, text="Tool purpose: This tool helps in generating audit checklists and running audits against SBL builds.", wraplength=1040).pack(anchor="w", pady=(0, 18))
		cards = ttk.Frame(outer)
		cards.pack(fill="x")

		def card(title: str, body: str, button: str, frame_name: str):
			"""Render a navigation card."""
			box = ttk.LabelFrame(cards, text=title, padding=18)
			box.pack(fill="x", pady=(0, 12))
			ttk.Label(box, text=body, wraplength=980).pack(anchor="w", pady=(0, 10))
			ttk.Button(box, text=button, command=lambda: controller.show_frame(frame_name)).pack(anchor="w")

		card("Configure Target Profile", f"Map worksheet targets to vSphere VMs or to {LOCAL_SENTINEL} for the machine running the tool.", "Open Target Profile Manager", "ProfileFrame")
		card("Create Audit Form", "Generate an audit workbook in the approved format and export additional JSON checklist payload.", "Open Checklist Generator", "ChecklistFrame")
		card("Run Audit", "Scans local targets first, then scans guest VMs through VMware Tools, compares found version against the SBL Build version, and writes PASS/FAIL text to the AUDIT column.", "Open Audit Runner", "AuditFrame")

		utilities = ttk.LabelFrame(outer, text="Utilities", padding=12)
		utilities.pack(fill="x", pady=(4, 0))
		ttk.Label(
			utilities,
			text="Create missing desktop launch shortcuts for standalone Basic Scan and full GUI.",
			wraplength=980,
		).pack(anchor="w", pady=(0, 8))
		ttk.Button(utilities, text="Ensure Desktop Shortcuts", command=self.ensure_desktop_shortcuts).pack(anchor="w")


class ProfileFrame(BaseFrame):
	"""Profile management frame for target mappings and connection settings."""

	INPUT_SOURCE_OPTIONS = [
		"Watch Folder",
		"File Explorer Folder",
		"Email Trigger",
		"Ticket System Trigger",
		"Database Trigger",
		"API Trigger",
	]

	OUTPUT_ACTION_OPTIONS = [
		"Save to Local Folder",
		"Save to Remote Folder",
		"Send Email",
		"Save to Spreadsheet",
		"Write to Database",
	]

	def __init__(self, parent, controller):
		"""Initialize the ProfileFrame instance."""
		super().__init__(parent, controller)
		self.profile_service = VMProfileService()
		self.logger = FileLogger(LOGS_DIR, "vm_profile")
		self.profile_name = tk.StringVar(value="")
		self.saved_profile_name = tk.StringVar(value="")
		self.profile_options = self._get_profile_options()
		self.vcenter_server = tk.StringVar()
		self.vcenter_username = tk.StringVar()
		self.vcenter_password = tk.StringVar()
		self.ignore_ssl = tk.BooleanVar(value=True)
		self.source_sbl_path = tk.StringVar()
		self.build_type = tk.StringVar(value="unknown")
		self.ssh_gateway_host = tk.StringVar()
		self.ssh_gateway_port = tk.StringVar(value="22")
		self.ssh_gateway_username = tk.StringVar()
		self.ssh_gateway_password = tk.StringVar()
		self.ssh_target_port = tk.StringVar(value="22")

		self.pipeline_input_source = tk.StringVar(value="")
		self.pipeline_output_action = tk.StringVar(value="")
		self.pipeline_input_folder = tk.StringVar(value="")
		self.pipeline_email_address = tk.StringVar(value="")
		self.pipeline_email_folder = tk.StringVar(value="Inbox")
		self.pipeline_email_subject_filter = tk.StringVar(value="")
		self.pipeline_ticket_system = tk.StringVar(value="ServiceNow")
		self.pipeline_ticket_queue = tk.StringVar(value="")
		self.pipeline_ticket_filter = tk.StringVar(value="")
		self.pipeline_input_db_connection = tk.StringVar(value="")
		self.pipeline_input_db_table = tk.StringVar(value="")
		self.pipeline_api_endpoint = tk.StringVar(value="")
		self.pipeline_api_token_ref = tk.StringVar(value="")
		self.pipeline_output_local_folder = tk.StringVar(value="")
		self.pipeline_output_remote_path = tk.StringVar(value="")
		self.pipeline_output_email_recipients = tk.StringVar(value="")
		self.pipeline_output_spreadsheet_path = tk.StringVar(value="")
		self.pipeline_output_db_connection = tk.StringVar(value="")
		self.pipeline_output_db_table = tk.StringVar(value="")
		self.target_columns = default_target_columns()
		self.inventory_values = [LOCAL_SENTINEL]
		self.vm_dropdowns: Dict[str, ttk.Combobox] = {}
		self.target_info: Dict[str, Dict[str, str]] = {
			name: {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"}
			for name in self.target_columns
		}
		# ── top bar ───────────────────────────────────────────────────────────────
		top = ttk.Frame(self)
		top.pack(fill="x")
		ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
		ttk.Label(top, text="Target Profile Manager (vSphere + Local)", font=("Segoe UI", 14, "bold")).pack(side="left", padx=(12, 0))

		# ── horizontal PanedWindow: form left | right pane ───────────────────────
		paned = ttk.PanedWindow(self, orient="horizontal")
		paned.pack(fill="both", expand=True, pady=(4, 0))

		# ── left pane: scrollable form ────────────────────────────────────────────
		left_outer = ttk.Frame(paned)
		paned.add(left_outer, weight=0)

		scroll_canvas = tk.Canvas(left_outer, highlightthickness=0)
		scrollbar = ttk.Scrollbar(left_outer, orient="vertical", command=scroll_canvas.yview)
		scroll_canvas.configure(yscrollcommand=scrollbar.set)
		scrollbar.pack(side="right", fill="y")
		scroll_canvas.pack(side="left", fill="both", expand=True)
		self._scroll_canvas = scroll_canvas

		inner = ttk.Frame(scroll_canvas)
		self._scroll_inner_id = scroll_canvas.create_window((0, 0), window=inner, anchor="nw")

		def _on_inner_configure(event):
			req_w = inner.winfo_reqwidth()
			scroll_canvas.configure(scrollregion=scroll_canvas.bbox("all"))
			# widen the canvas (and therefore the pane) to fit content when it grows
			if scroll_canvas.winfo_width() < req_w:
				scroll_canvas.configure(width=req_w)
			# keep inner width pinned to canvas width so entries fill the pane
			scroll_canvas.itemconfigure(self._scroll_inner_id, width=max(scroll_canvas.winfo_width(), req_w))
		inner.bind("<Configure>", _on_inner_configure)
		scroll_canvas.bind("<Configure>", lambda e: scroll_canvas.itemconfigure(
			self._scroll_inner_id, width=max(e.width, inner.winfo_reqwidth())
		))

		def _on_mousewheel(event):
			scroll_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
		scroll_canvas.bind_all("<MouseWheel>", _on_mousewheel)

		# ── right pane: controls + log ────────────────────────────────────────────
		right_outer = ttk.Frame(paned)
		paned.add(right_outer, weight=1)

		controls = ttk.Frame(right_outer)
		controls.pack(fill="x", pady=(0, 4))
		ttk.Button(controls, text="Load VM Inventory", command=self.load_inventory).pack(side="left")
		self.save_profile_button = ttk.Button(controls, text="Save Profile", command=self.save_profile)
		self.save_profile_button.pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Verify Profile", command=self.verify_profile).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))

		log_frame = ttk.LabelFrame(right_outer, text="Log", padding=4)
		log_frame.pack(fill="both", expand=True)
		log_scroll = ttk.Scrollbar(log_frame)
		log_scroll.pack(side="right", fill="y")
		self.log = tk.Text(log_frame, wrap="word", yscrollcommand=log_scroll.set)
		log_scroll.configure(command=self.log.yview)
		self.log.pack(fill="both", expand=True)

		settings = ttk.LabelFrame(inner, text="vSphere Settings", padding=8)
		settings.pack(fill="x", pady=(8, 4), padx=4)
		self._entry_row(settings, "Profile name", self.profile_name)
		profile_select_row = ttk.Frame(settings)
		profile_select_row.pack(fill="x", pady=2)
		ttk.Label(profile_select_row, text="Saved profiles", width=18).pack(side="left")
		self.profile_selector = ttk.Combobox(
			profile_select_row,
			textvariable=self.saved_profile_name,
			values=self.profile_options,
			state="readonly",
		)
		self.profile_selector.pack(side="left", fill="x", expand=True, padx=(0, 8))
		ttk.Button(profile_select_row, text="Refresh", command=self._refresh_profile_options).pack(side="left")
		ttk.Button(profile_select_row, text="Use Selected", command=self._use_selected_profile).pack(side="left", padx=(8, 0))
		self._entry_row(settings, "Source workbook", self.source_sbl_path, command=self.pick_profile_source)
		build_row = ttk.Frame(settings)
		build_row.pack(fill="x", pady=2)
		ttk.Label(build_row, text="Build type", width=18).pack(side="left")
		ttk.Combobox(build_row, textvariable=self.build_type, values=BUILD_TYPE_OPTIONS, state="readonly").pack(side="left", fill="x", expand=True, padx=(0, 8))
		ttk.Button(build_row, text="Detect Targets", command=self.detect_profile_targets).pack(side="left")
		self._entry_row(settings, "vCenter server", self.vcenter_server)
		self._entry_row(settings, "vCenter username", self.vcenter_username)
		self._entry_row(settings, "vCenter password", self.vcenter_password, show="*")
		ttk.Checkbutton(settings, text="Ignore SSL warnings", variable=self.ignore_ssl).pack(anchor="w", pady=(4, 0))
		self.credential_status_var = tk.StringVar(value="Credentials protection: checking...")
		ttk.Label(settings, textvariable=self.credential_status_var, foreground="#2f6f2f").pack(anchor="w", pady=(2, 0))

		ssh_settings = ttk.LabelFrame(inner, text="SSH Tunnel Settings", padding=8)
		ssh_settings.pack(fill="x", pady=(0, 4), padx=4)
		self._entry_row(ssh_settings, "SSH gateway host", self.ssh_gateway_host)
		self._entry_row(ssh_settings, "Gateway port", self.ssh_gateway_port)
		self._entry_row(ssh_settings, "Gateway username", self.ssh_gateway_username)
		self._entry_row(ssh_settings, "Gateway password", self.ssh_gateway_password, show="*")
		self._entry_row(ssh_settings, "Target SSH port", self.ssh_target_port)

		pipeline_settings = ttk.LabelFrame(inner, text="Pipeline Config", padding=8)
		pipeline_settings.pack(fill="x", pady=(0, 4), padx=4)
		pipeline_source_row = ttk.Frame(pipeline_settings)
		pipeline_source_row.pack(fill="x", pady=4)
		ttk.Label(pipeline_source_row, text="Input type/source", width=18).pack(side="left")
		ttk.Combobox(
			pipeline_source_row,
			textvariable=self.pipeline_input_source,
			values=self.INPUT_SOURCE_OPTIONS,
			state="readonly",
		).pack(side="left", fill="x", expand=True)
		self.pipeline_input_source.trace_add("write", self._on_profile_pipeline_input_changed)

		self.pipeline_input_dynamic = ttk.LabelFrame(pipeline_settings, text="Input Details", padding=8)
		self.pipeline_input_dynamic.pack(fill="x", pady=6)

		pipeline_output_row = ttk.Frame(pipeline_settings)
		pipeline_output_row.pack(fill="x", pady=4)
		ttk.Label(pipeline_output_row, text="Output action", width=18).pack(side="left")
		ttk.Combobox(
			pipeline_output_row,
			textvariable=self.pipeline_output_action,
			values=self.OUTPUT_ACTION_OPTIONS,
			state="readonly",
		).pack(side="left", fill="x", expand=True)
		self.pipeline_output_action.trace_add("write", self._on_profile_pipeline_output_changed)

		self.pipeline_output_dynamic = ttk.LabelFrame(pipeline_settings, text="Output Details", padding=8)
		self.pipeline_output_dynamic.pack(fill="x", pady=4)
		self._render_profile_pipeline_input_fields()
		self._render_profile_pipeline_output_fields()

		mapping = ttk.LabelFrame(inner, text=f"SBL VM Targets → Selected VM Name or {LOCAL_SENTINEL}", padding=8)
		mapping.pack(fill="x", pady=(0, 4), padx=4)
		self.mapping_rows = ttk.Frame(mapping)
		self.mapping_rows.pack(fill="x")
		self._render_target_rows()
		ttk.Button(mapping, text="Edit Target Info", command=self.edit_target_info_dialog).pack(side="right", padx=8)
		self.profile_name.trace_add("write", self._refresh_profile_save_state)
		self._refresh_profile_save_state()
		self._refresh_profile_options()
		self._refresh_credential_status()

	def _render_profile_pipeline_field(self, parent: ttk.Widget, label: str, variable: tk.StringVar, browse_mode: str = ""):
		"""Render a labeled pipeline field row with optional browse button."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=3)
		ttk.Label(row, text=label, width=18).pack(side="left")
		ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
		if browse_mode == "folder":
			ttk.Button(row, text="Browse", command=lambda: self._browse_into(variable, "folder")).pack(side="left")
		elif browse_mode == "file":
			ttk.Button(row, text="Browse", command=lambda: self._browse_into(variable, "file")).pack(side="left")

	def _browse_into(self, variable: tk.StringVar, mode: str):
		"""Pick a file or folder path for pipeline fields."""
		if mode == "folder":
			picked = filedialog.askdirectory(title="Select folder")
		else:
			picked = filedialog.askopenfilename(title="Select file")
		if picked:
			variable.set(picked)

	def _clear_dynamic(self, container: ttk.Widget):
		"""Clear dynamic child widgets from a container."""
		for child in container.winfo_children():
			child.destroy()

	def _render_profile_pipeline_input_fields(self):
		"""Render input details fields for the selected pipeline source."""
		self._clear_dynamic(self.pipeline_input_dynamic)
		source = normalize_text(self.pipeline_input_source.get())
		if source in {"Watch Folder", "File Explorer Folder"}:
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Input folder", self.pipeline_input_folder, browse_mode="folder")
		elif source == "Email Trigger":
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Mailbox", self.pipeline_email_address)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Mailbox folder", self.pipeline_email_folder)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Subject filter", self.pipeline_email_subject_filter)
		elif source == "Ticket System Trigger":
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Ticket system", self.pipeline_ticket_system)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Queue/Project", self.pipeline_ticket_queue)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Filter query", self.pipeline_ticket_filter)
		elif source == "Database Trigger":
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "DB connection", self.pipeline_input_db_connection)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Table/View", self.pipeline_input_db_table)
		elif source == "API Trigger":
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "API endpoint", self.pipeline_api_endpoint)
			self._render_profile_pipeline_field(self.pipeline_input_dynamic, "Token ref/secret", self.pipeline_api_token_ref)

	def _render_profile_pipeline_output_fields(self):
		"""Render output details fields for the selected pipeline destination."""
		self._clear_dynamic(self.pipeline_output_dynamic)
		action = normalize_text(self.pipeline_output_action.get())
		if action == "Save to Local Folder":
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "Output folder", self.pipeline_output_local_folder, browse_mode="folder")
		elif action == "Save to Remote Folder":
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "Remote path", self.pipeline_output_remote_path)
		elif action == "Send Email":
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "Recipients", self.pipeline_output_email_recipients)
		elif action == "Save to Spreadsheet":
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "Spreadsheet path", self.pipeline_output_spreadsheet_path, browse_mode="file")
		elif action == "Write to Database":
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "DB connection", self.pipeline_output_db_connection)
			self._render_profile_pipeline_field(self.pipeline_output_dynamic, "Table", self.pipeline_output_db_table)

	def _on_profile_pipeline_input_changed(self, *_args):
		"""Refresh input details rows when pipeline source changes."""
		self._render_profile_pipeline_input_fields()

	def _on_profile_pipeline_output_changed(self, *_args):
		"""Refresh output details rows when pipeline action changes."""
		self._render_profile_pipeline_output_fields()

	def _collect_profile_pipeline_input_config(self) -> Dict[str, str]:
		"""Collect input-source-specific pipeline settings."""
		source = normalize_text(self.pipeline_input_source.get())
		if source in {"Watch Folder", "File Explorer Folder"}:
			return {"folder": normalize_text(self.pipeline_input_folder.get())}
		if source == "Email Trigger":
			return {
				"mailbox": normalize_text(self.pipeline_email_address.get()),
				"folder": normalize_text(self.pipeline_email_folder.get()),
				"subject_filter": normalize_text(self.pipeline_email_subject_filter.get()),
			}
		if source == "Ticket System Trigger":
			return {
				"system": normalize_text(self.pipeline_ticket_system.get()),
				"queue": normalize_text(self.pipeline_ticket_queue.get()),
				"filter": normalize_text(self.pipeline_ticket_filter.get()),
			}
		if source == "Database Trigger":
			return {
				"connection": normalize_text(self.pipeline_input_db_connection.get()),
				"table": normalize_text(self.pipeline_input_db_table.get()),
			}
		if source == "API Trigger":
			return {
				"endpoint": normalize_text(self.pipeline_api_endpoint.get()),
				"token_ref": normalize_text(self.pipeline_api_token_ref.get()),
			}
		return {}

	def _collect_profile_pipeline_output_config(self) -> Dict[str, str]:
		"""Collect output-action-specific pipeline settings."""
		action = normalize_text(self.pipeline_output_action.get())
		if action == "Save to Local Folder":
			return {"folder": normalize_text(self.pipeline_output_local_folder.get())}
		if action == "Save to Remote Folder":
			return {"remote_path": normalize_text(self.pipeline_output_remote_path.get())}
		if action == "Send Email":
			return {"recipients": normalize_text(self.pipeline_output_email_recipients.get())}
		if action == "Save to Spreadsheet":
			return {"spreadsheet_path": normalize_text(self.pipeline_output_spreadsheet_path.get())}
		if action == "Write to Database":
			return {
				"connection": normalize_text(self.pipeline_output_db_connection.get()),
				"table": normalize_text(self.pipeline_output_db_table.get()),
			}
		return {}

	def _validate_profile_pipeline_config(self) -> List[str]:
		"""Validate required pipeline fields before profile save."""
		errors: List[str] = []

		source = normalize_text(self.pipeline_input_source.get())
		if source in {"Watch Folder", "File Explorer Folder"}:
			if not normalize_text(self.pipeline_input_folder.get()):
				errors.append("Pipeline input source requires Input folder")
		elif source == "Email Trigger":
			if not normalize_text(self.pipeline_email_address.get()):
				errors.append("Email Trigger requires Mailbox")
			if not normalize_text(self.pipeline_email_folder.get()):
				errors.append("Email Trigger requires Mailbox folder")
		elif source == "Ticket System Trigger":
			if not normalize_text(self.pipeline_ticket_system.get()):
				errors.append("Ticket System Trigger requires Ticket system")
			if not normalize_text(self.pipeline_ticket_queue.get()):
				errors.append("Ticket System Trigger requires Queue/Project")
		elif source == "Database Trigger":
			if not normalize_text(self.pipeline_input_db_connection.get()):
				errors.append("Database Trigger requires DB connection")
			if not normalize_text(self.pipeline_input_db_table.get()):
				errors.append("Database Trigger requires Table/View")
		elif source == "API Trigger":
			if not normalize_text(self.pipeline_api_endpoint.get()):
				errors.append("API Trigger requires API endpoint")
			if not normalize_text(self.pipeline_api_token_ref.get()):
				errors.append("API Trigger requires Token ref/secret")
		else:
			errors.append("Select a valid pipeline Input source")

		action = normalize_text(self.pipeline_output_action.get())
		if action == "Save to Local Folder":
			if not normalize_text(self.pipeline_output_local_folder.get()):
				errors.append("Save to Local Folder requires Output folder")
		elif action == "Save to Remote Folder":
			if not normalize_text(self.pipeline_output_remote_path.get()):
				errors.append("Save to Remote Folder requires Remote path")
		elif action == "Send Email":
			if not normalize_text(self.pipeline_output_email_recipients.get()):
				errors.append("Send Email requires Recipients")
		elif action == "Save to Spreadsheet":
			if not normalize_text(self.pipeline_output_spreadsheet_path.get()):
				errors.append("Save to Spreadsheet requires Spreadsheet path")
		elif action == "Write to Database":
			if not normalize_text(self.pipeline_output_db_connection.get()):
				errors.append("Write to Database requires DB connection")
			if not normalize_text(self.pipeline_output_db_table.get()):
				errors.append("Write to Database requires Table")
		else:
			errors.append("Select a valid pipeline Output action")

		return errors

	def _build_profile_pipeline_payload(self) -> Dict[str, Any]:
		"""Build the profile pipeline payload from current form values."""
		return {
			"active": "default",
			"items": {
				"default": {
					"title": "Pipeline Config",
					"input_source": normalize_text(self.pipeline_input_source.get()),
					"input_config": self._collect_profile_pipeline_input_config(),
					"output_action": normalize_text(self.pipeline_output_action.get()),
					"output_config": self._collect_profile_pipeline_output_config(),
					"updated_at": datetime.now().isoformat(timespec="seconds"),
				}
			},
		}

	def _load_profile_pipeline_fields(self, payload: Dict[str, Any]):
		"""Load pipeline fields from saved profile payload."""
		pipelines = payload.get("pipelines", {}) if isinstance(payload, dict) else {}
		items = pipelines.get("items", {}) if isinstance(pipelines, dict) else {}
		active = normalize_text(pipelines.get("active", "default")) if isinstance(pipelines, dict) else "default"
		current = items.get(active, {}) if isinstance(items, dict) else {}
		if not isinstance(current, dict):
			return

		input_source = normalize_text(current.get("input_source", self.pipeline_input_source.get())) or self.pipeline_input_source.get()
		if input_source == "File Explorer Folder":
			input_source = "Watch Folder"
		self.pipeline_input_source.set(input_source)
		self.pipeline_output_action.set(normalize_text(current.get("output_action", self.pipeline_output_action.get())) or self.pipeline_output_action.get())

		input_cfg = current.get("input_config", {}) if isinstance(current.get("input_config", {}), dict) else {}
		output_cfg = current.get("output_config", {}) if isinstance(current.get("output_config", {}), dict) else {}

		self.pipeline_input_folder.set(normalize_text(input_cfg.get("folder", self.pipeline_input_folder.get())))
		self.pipeline_email_address.set(normalize_text(input_cfg.get("mailbox", self.pipeline_email_address.get())))
		self.pipeline_email_folder.set(normalize_text(input_cfg.get("folder", self.pipeline_email_folder.get())) or self.pipeline_email_folder.get())
		self.pipeline_email_subject_filter.set(normalize_text(input_cfg.get("subject_filter", self.pipeline_email_subject_filter.get())))
		self.pipeline_ticket_system.set(normalize_text(input_cfg.get("system", self.pipeline_ticket_system.get())) or self.pipeline_ticket_system.get())
		self.pipeline_ticket_queue.set(normalize_text(input_cfg.get("queue", self.pipeline_ticket_queue.get())))
		self.pipeline_ticket_filter.set(normalize_text(input_cfg.get("filter", self.pipeline_ticket_filter.get())))
		self.pipeline_input_db_connection.set(normalize_text(input_cfg.get("connection", self.pipeline_input_db_connection.get())))
		self.pipeline_input_db_table.set(normalize_text(input_cfg.get("table", self.pipeline_input_db_table.get())))
		self.pipeline_api_endpoint.set(normalize_text(input_cfg.get("endpoint", self.pipeline_api_endpoint.get())))
		self.pipeline_api_token_ref.set(normalize_text(input_cfg.get("token_ref", self.pipeline_api_token_ref.get())))

		self.pipeline_output_local_folder.set(normalize_text(output_cfg.get("folder", self.pipeline_output_local_folder.get())))
		self.pipeline_output_remote_path.set(normalize_text(output_cfg.get("remote_path", self.pipeline_output_remote_path.get())))
		self.pipeline_output_email_recipients.set(normalize_text(output_cfg.get("recipients", self.pipeline_output_email_recipients.get())))
		self.pipeline_output_spreadsheet_path.set(normalize_text(output_cfg.get("spreadsheet_path", self.pipeline_output_spreadsheet_path.get())))
		self.pipeline_output_db_connection.set(normalize_text(output_cfg.get("connection", self.pipeline_output_db_connection.get())))
		self.pipeline_output_db_table.set(normalize_text(output_cfg.get("table", self.pipeline_output_db_table.get())))

		self._render_profile_pipeline_input_fields()
		self._render_profile_pipeline_output_fields()

	def pick_profile_source(self):
		"""Prompt for a source SBL or audit workbook."""
		path = filedialog.askopenfilename(
			title="Select SBL or audit workbook",
			initialdir=str(SBLS_DIR),
			filetypes=[("Supported files", "*.xlsx *.xlsm *.json *.csv"), ("All files", "*.*")],
		)
		if path:
			self.source_sbl_path.set(path)
			if self.build_type.get() == "unknown":
				self.build_type.set(infer_build_type(path))

	def _default_target_info(self) -> Dict[str, str]:
		"""Return the default target info structure."""
		return {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"}

	def _render_target_rows(self):
		"""Render one VM-selection row per target column."""
		for child in self.mapping_rows.winfo_children():
			child.destroy()
		self.vm_dropdowns = {}
		for target_name in self.target_columns:
			info = self.target_info.get(target_name, self._default_target_info())
			row = ttk.Frame(self.mapping_rows)
			row.pack(fill="x", pady=4)
			ttk.Label(row, text=f"VM target: {target_name}", width=28).pack(side="left")
			combo = ttk.Combobox(row, state="normal", values=self.inventory_values)
			combo.pack(side="left", fill="x", expand=True)
			combo.set(info.get("vm_name", LOCAL_SENTINEL) or LOCAL_SENTINEL)
			self.vm_dropdowns[target_name] = combo

	def _set_target_columns(self, target_names: List[str]):
		"""Normalize and store target columns, then rerender the mapping rows."""
		normalized: List[str] = []
		for item in target_names:
			name = normalize_text(item)
			if name and name not in normalized:
				normalized.append(name)
		self.target_columns = normalized or default_target_columns()
		for target_name in self.target_columns:
			self.target_info.setdefault(target_name, self._default_target_info())
		self._render_target_rows()

	def detect_profile_targets(self):
		"""Detect target columns from the selected workbook or import file."""
		source_path = self.source_sbl_path.get().strip()
		if not source_path:
			messagebox.showwarning("Source SBL required", "Select an SBL or audit workbook first.")
			return
		try:
			selected_columns: List[str] = []
			source_format = detect_workbook_format(source_path)
			if source_format == "excel":
				workbook_service = AuditWorkbookService(source_path)
				workbook_service.detect_header_row()
				workbook_service.build_column_map()
				selected_columns = confirm_target_column_mapping(
					self,
					source_path,
					workbook_service.target_columns,
					workbook_service.build_type,
					current_columns=self.target_columns,
				) or self.target_columns
				self.build_type.set(workbook_service.build_type)
			else:
				target_columns, _ = detect_target_columns(source_path, source_format, detect_header_row_index(source_path, source_format))
				selected_columns = confirm_target_column_mapping(
					self,
					source_path,
					target_columns,
					infer_build_type(source_path),
					current_columns=self.target_columns,
				) or self.target_columns
				self.build_type.set(infer_build_type(source_path))
			self._set_target_columns(selected_columns)
			self.append_log(f"Detected {len(self.target_columns)} VM target columns from source workbook.")
		except Exception as exc:
			self.logger.write_exception(exc)
			self.append_log(f"Target detection fallback in use: {exc}")
			self._set_target_columns(default_target_columns())

	def _get_profile_options(self) -> List[str]:
		"""Return saved profile names."""
		if not PROFILES_DIR.exists():
			return []
		return sorted([f.stem for f in PROFILES_DIR.glob("*.json") if f.is_file()])

	def _refresh_profile_options(self, select_name: str = ""):
		"""Refresh saved-profile dropdown choices."""
		self.profile_options = self._get_profile_options()
		self.profile_selector.configure(values=self.profile_options)
		candidate = normalize_text(select_name) or normalize_text(self.profile_name.get())
		if candidate and candidate in self.profile_options:
			self.saved_profile_name.set(candidate)
			return
		if self.profile_options:
			self.saved_profile_name.set(self.profile_options[0])
		else:
			self.saved_profile_name.set("")

	def _use_selected_profile(self):
		"""Load the selected saved profile into the form."""
		selected = normalize_text(self.saved_profile_name.get())
		if not selected:
			messagebox.showwarning("No profile selected", "Select a profile from the dropdown first.")
			return
		self.profile_name.set(selected)
		self.load_saved_profile()

	def _refresh_credential_status(self, profile_name: str = ""):
		"""Refresh the credential-protection status text."""
		if not self.profile_service.encryption_supported():
			self.credential_status_var.set("Credentials protection: disabled (install cryptography)")
			return
		key_path = self.profile_service._key_path()
		if key_path.exists():
			base = "Credentials protection: enabled"
		else:
			base = "Credentials protection: enabled (key will be created on first save)"
		selected = normalize_text(profile_name) or normalize_text(self.profile_name.get())
		if not selected:
			self.credential_status_var.set(base)
			return
		mode = self.profile_service.profile_credential_storage_mode(selected)
		if mode == "encrypted":
			self.credential_status_var.set(f"{base} | profile storage: encrypted")
		elif mode == "legacy-plain":
			self.credential_status_var.set(f"{base} | profile storage: legacy/plain")
		elif mode == "no-profile":
			self.credential_status_var.set(f"{base} | profile storage: not saved yet")
		else:
			self.credential_status_var.set(f"{base} | profile storage: unknown")

	def _profile_name_is_valid(self, profile_name: str) -> bool:
		"""Validate the profile name against the supported naming rules."""
		return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", profile_name))

	def _get_profile_name_or_warn(self) -> Optional[str]:
		"""Return the normalized profile name or show a warning."""
		profile_name = normalize_text(self.profile_name.get())
		if not profile_name:
			messagebox.showwarning("Profile name required", "Enter or select a profile name first.")
			return None
		if not self._profile_name_is_valid(profile_name):
			messagebox.showwarning(
				"Invalid profile name",
				"Use 1-64 characters: letters, numbers, underscore, or dash. Must start with a letter or number.",
			)
			return None
		return profile_name

	def _refresh_profile_save_state(self, *_):
		"""Enable or disable save based on the current profile name."""
		profile_name = normalize_text(self.profile_name.get())
		is_valid = self._profile_name_is_valid(profile_name)
		self.save_profile_button.configure(state="normal" if is_valid else "disabled")
		self._refresh_credential_status(profile_name)

	def edit_target_info_dialog(self):
		"""Open the target credential editor dialog."""
		dialog = tk.Toplevel(self)
		dialog.title("Edit Target VM Info")
		dialog.resizable(False, False)
		dialog.transient(self.controller)
		dialog.grab_set()
		container = ttk.Frame(dialog, padding=8)
		container.pack(fill="both", expand=True)

		header = ttk.Frame(container)
		header.pack(fill="x", pady=(0, 4))
		ttk.Label(header, text="Target", width=30, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")
		ttk.Label(header, text="VM Name", width=24, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
		ttk.Label(header, text="Username", width=18, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
		ttk.Label(header, text="Password", width=18, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 4))
		ttk.Label(header, text="OS", width=10, anchor="w", font=("Segoe UI", 9, "bold")).pack(side="left")

		rows = {}
		for target_name in self.target_columns:
			info = self.target_info.get(target_name, self._default_target_info())
			row = ttk.Frame(container)
			row.pack(fill="x", pady=2)
			ttk.Label(row, text=target_name, width=30, anchor="w").pack(side="left")
			vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
			user_var = tk.StringVar(value=info.get("username", ""))
			pass_var = tk.StringVar(value=info.get("password", ""))
			os_var = tk.StringVar(value=info.get("os_type", "windows"))
			ttk.Entry(row, textvariable=vm_var, width=24).pack(side="left", padx=(0, 4))
			ttk.Entry(row, textvariable=user_var, width=18).pack(side="left", padx=(0, 4))
			ttk.Entry(row, textvariable=pass_var, width=18, show="*").pack(side="left", padx=(0, 4))
			ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=10, state="readonly").pack(side="left")
			rows[target_name] = (vm_var, user_var, pass_var, os_var)

		def apply_shared_credentials():
			"""Apply shared credentials to all target rows."""
			shared_user = normalize_text(self.vcenter_username.get())
			shared_password = self.vcenter_password.get()
			if not shared_user or not shared_password:
				messagebox.showwarning(
					"Shared credentials missing",
					"Set vCenter username and password first, then apply shared credentials.",
				)
				return
			for _target_name, (_vm_var, user_var, pass_var, _os_var) in rows.items():
				user_var.set(shared_user)
				pass_var.set(shared_password)

		def save_and_close():
			"""Persist edited target info and close the dialog."""
			for target_name, (vm_var, user_var, pass_var, os_var) in rows.items():
				self.target_info[target_name] = {
					"vm_name": vm_var.get().strip(),
					"username": user_var.get().strip(),
					"password": pass_var.get().strip(),
					"os_type": os_var.get().strip() or "windows",
				}
				self.vm_dropdowns[target_name].set(vm_var.get().strip() or LOCAL_SENTINEL)
			dialog.destroy()

		controls = ttk.Frame(container)
		controls.pack(fill="x", pady=(8, 0))
		ttk.Button(controls, text="Apply Shared Login To All", command=apply_shared_credentials).pack(side="left")
		ttk.Button(controls, text="Save", command=save_and_close).pack(side="right")
		dialog.wait_window()

	def _entry_row(self, parent, label, var, show=None, command=None):
		"""Render a labeled entry row."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=4)
		ttk.Label(row, text=label, width=18).pack(side="left")
		entry_kwargs = {"textvariable": var}
		if show is not None:
			entry_kwargs["show"] = show
		ttk.Entry(row, **entry_kwargs).pack(side="left", fill="x", expand=True, padx=(0, 8))
		if command is not None:
			ttk.Button(row, text="Browse", command=command).pack(side="left")

	def append_log(self, message: str):
		"""Append a message to the frame log and file logger."""
		self.log.insert("end", message + "\n")
		self.log.see("end")
		print(f"[PROFILE] {message}", flush=True)
		self.logger.write(message)

	def _service(self) -> VSphereService:
		"""Create a VSphereService from the current form values."""
		return VSphereService(self.vcenter_server.get(), self.vcenter_username.get(), self.vcenter_password.get(), self.ignore_ssl.get())

	def load_inventory(self):
		"""Load available VM names from vSphere."""
		try:
			self.append_log(f"Connecting to {self.vcenter_server.get().strip()} for VM inventory...")
			service = self._service()
			service.connect()
			names = service.list_windows_vms()
			service.disconnect()
			self.inventory_values = sorted({LOCAL_SENTINEL, *names})
			for combo in self.vm_dropdowns.values():
				combo["values"] = self.inventory_values
				if not combo.get():
					combo.set(LOCAL_SENTINEL)
			self.append_log(f"Loaded {len(names)} selectable targets, including {LOCAL_SENTINEL}.")
		except Exception as exc:
			self.logger.write_exception(exc)
			self.append_log(f"ERROR: {exc}")

	def save_profile(self):
		"""Save the current profile."""
		profile_name = self._get_profile_name_or_warn()
		if profile_name is None:
			return
		pipeline_errors = self._validate_profile_pipeline_config()
		if pipeline_errors:
			messagebox.showerror(
				"Pipeline Config",
				"Provide all required pipeline details before saving profile:\n\n- " + "\n- ".join(pipeline_errors),
			)
			return
		default_user = normalize_text(self.vcenter_username.get())
		default_password = self.vcenter_password.get()
		for name, combo in self.vm_dropdowns.items():
			if name not in self.target_info:
				self.target_info[name] = {"vm_name": combo.get().strip(), "username": "", "password": "", "os_type": "windows"}
			else:
				self.target_info[name]["vm_name"] = combo.get().strip()

		profile_path = self.profile_service.profile_path(profile_name)
		if profile_path.exists():
			should_overwrite = messagebox.askyesno(
				"Overwrite existing profile?",
				f"Profile '{profile_name}' already exists. Do you want to overwrite it?",
			)
			if not should_overwrite:
				self.append_log(f"Save canceled for existing profile: {profile_name}")
				return
		payload = {
			"vcenter_server": self.vcenter_server.get().strip(),
			"vcenter_username": default_user,
			"vcenter_password": default_password,
			"ignore_ssl": self.ignore_ssl.get(),
			"source_sbl_path": self.source_sbl_path.get().strip(),
			"build_type": infer_build_type(self.build_type.get() or self.source_sbl_path.get()),
			"target_schema": build_target_schema_payload(self.source_sbl_path.get().strip(), self.target_columns, self.build_type.get()),
			"ssh_tunnel": {
				"gateway_host": self.ssh_gateway_host.get().strip(),
				"gateway_port": normalize_text(self.ssh_gateway_port.get()) or "22",
				"gateway_username": self.ssh_gateway_username.get().strip(),
				"gateway_password": self.ssh_gateway_password.get(),
				"target_port": normalize_text(self.ssh_target_port.get()) or "22",
			},
			"targets": self.target_info,
			"pipelines": self._build_profile_pipeline_payload(),
			"last_verified": "",
		}
		path = self.profile_service.save_profile(profile_name, payload)
		self.append_log(f"Saved profile: {path}")
		self.append_log(
			f"Saved merged pipeline config: input={self.pipeline_input_source.get().strip()} -> output={self.pipeline_output_action.get().strip()}"
		)
		self._refresh_profile_options(select_name=profile_name)
		self._refresh_credential_status(profile_name)

	def load_saved_profile(self):
		"""Load a saved profile into the form."""
		profile_name = self._get_profile_name_or_warn()
		if profile_name is None:
			return
		payload = self.profile_service.load_profile(profile_name)
		self.vcenter_server.set(payload.get("vcenter_server", payload.get("vsphere", {}).get("server", "")))
		self.vcenter_username.set(payload.get("vcenter_username", payload.get("vsphere", {}).get("username", "")))
		self.vcenter_password.set(payload.get("vcenter_password", payload.get("vsphere", {}).get("password", "")))
		self.ignore_ssl.set(bool(payload.get("ignore_ssl", True)))
		self.source_sbl_path.set(payload.get("source_sbl_path", payload.get("target_schema", {}).get("source_path", "")))
		self.build_type.set(infer_build_type(payload.get("build_type", payload.get("target_schema", {}).get("build_type", self.source_sbl_path.get()))))
		ssh_tunnel = normalize_ssh_tunnel_profile_fields(payload.get("ssh_tunnel", {}))
		self.ssh_gateway_host.set(ssh_tunnel["gateway_host"])
		self.ssh_gateway_port.set(ssh_tunnel["gateway_port"])
		self.ssh_gateway_username.set(ssh_tunnel["gateway_username"])
		self.ssh_gateway_password.set(ssh_tunnel["gateway_password"])
		self.ssh_target_port.set(ssh_tunnel["target_port"])
		self._set_target_columns(resolve_profile_target_columns(payload))
		self.target_info = payload.get("targets", {name: self._default_target_info() for name in self.target_columns})
		for name, combo in self.vm_dropdowns.items():
			combo.set(self.target_info.get(name, {}).get("vm_name", LOCAL_SENTINEL))
		self._load_profile_pipeline_fields(payload)
		self.append_log(f"Loaded profile: {profile_name}")
		self.append_log(
			f"Loaded merged pipeline config: input={self.pipeline_input_source.get().strip()} -> output={self.pipeline_output_action.get().strip()}"
		)
		self._refresh_profile_options(select_name=profile_name)
		self._refresh_credential_status(profile_name)

	def verify_profile(self):
		"""Verify that the mapped VM names exist in vSphere."""
		profile_name = self._get_profile_name_or_warn()
		if profile_name is None:
			return
		payload = self.profile_service.load_profile(profile_name)
		service = self._service()
		service.connect()
		target_names = resolve_profile_target_columns(payload)
		vm_names = [payload.get("targets", {}).get(name, {}).get("vm_name", "") for name in target_names if payload.get("targets", {}).get(name, {}).get("vm_name", "")]
		report = service.verify_vm_names(vm_names)
		service.disconnect()
		payload["last_verified"] = datetime.now().isoformat(timespec="seconds")
		self.profile_service.save_profile(profile_name, payload)
		for vm_name, info in report.items():
			self.append_log(f"{vm_name} | power={info['power_state']} | tools={info['tools_status']} | guest={info['guest_os']}")


class ChecklistFrame(BaseFrame):
	"""Checklist generation frame."""

	def __init__(self, parent, controller):
		"""Initialize the ChecklistFrame instance."""
		super().__init__(parent, controller)

		timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
		default_source = TESTS_DIR / "testing_sbl.xlsx"
		default_output = AUDIT_CHECKLIST_DIR / f"TG_SBL_Audit_Checklist_{timestamp}.xlsx"

		self.source_path = tk.StringVar(value=str(default_source))
		self.output_path = tk.StringVar(value=str(default_output))
		self.status_var = tk.StringVar(value="Status: Ready")
		self.template_baseline_sbl_var = tk.StringVar(value="")
		self.template_latest_sbl_var = tk.StringVar(value="")
		self.template_baseline_json_var = tk.StringVar(value="")
		self.template_latest_json_var = tk.StringVar(value="")
		self.logger = FileLogger(LOGS_DIR, "checklist_generation")
		self.template_service = TemplateAssetService()

		top = ttk.Frame(self)
		top.pack(fill="x")
		ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
		ttk.Label(top, text="Create Audit Form", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
		form = ttk.LabelFrame(self, text="Main SBL Source", padding=12)
		form.pack(fill="x", pady=12)
		self._path_row(form, "Source workbook", self.source_path, self.pick_source)
		self._path_row(form, "Output workbook (tool-generated)", self.output_path, self.pick_output)

		controls = ttk.Frame(self)
		controls.pack(fill="x", pady=(0, 10))
		self.generate_button = ttk.Button(controls, text="Generate Audit Form", command=self.start_generate)
		self.generate_button.pack(side="left")
		ttk.Button(controls, text="Preview Source Mapping", command=self.preview_source_mapping).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Load Baseline Template", command=self.load_baseline_template).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Update Baseline From Source", command=self.update_baseline_template).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Import List (CSV/JSON/XLSX)", command=self.import_list_source).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Open Templates Folder", command=lambda: self.open_folder(TEMPLATES_DIR)).pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Refresh Template Status", command=self.refresh_template_status_panel).pack(side="left", padx=(8, 0))
		ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=(12, 0))

		template_panel = ttk.LabelFrame(self, text="Template Status", padding=10)
		template_panel.pack(fill="x", pady=(0, 10))
		self._template_status_row(template_panel, "Baseline SBL (authoritative)", self.template_baseline_sbl_var)
		self._template_status_row(template_panel, "Latest SBL (tool-generated snapshot)", self.template_latest_sbl_var)
		self._template_status_row(template_panel, "Baseline Master Software List", self.template_baseline_json_var)
		self._template_status_row(template_panel, "Latest Master Software List", self.template_latest_json_var)

		self.progress_var = tk.DoubleVar(value=0)
		style = ttk.Style()
		style.configure("TProgressbar", troughcolor="lightgreen", background="green")
		style.configure("Red.TProgressbar", troughcolor="lightcoral", background="red")
		self.progress = ttk.Progressbar(self, variable=self.progress_var, maximum=100, style="TProgressbar")
		self.progress.pack(fill="x")
		self.log_widget = tk.Text(self, wrap="word", height=22)
		self.log_widget.pack(fill="both", expand=True)
		self.refresh_template_status_panel()

	def _path_row(self, parent, label, variable, command):
		"""Render a path field with browse button."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=5)
		ttk.Label(row, text=label, width=16).pack(side="left")
		ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
		ttk.Button(row, text="Browse", command=command).pack(side="left")

	def _template_status_row(self, parent, label, variable):
		"""Render one template status line."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=2)
		ttk.Label(row, text=label, width=22).pack(side="left")
		ttk.Label(row, textvariable=variable, anchor="w").pack(side="left", fill="x", expand=True)

	def refresh_template_status_panel(self):
		"""Refresh displayed template metadata."""
		sbl_model = None
		audit_path_var = getattr(self, "audit_path", None)
		audit_path = audit_path_var.get().strip() if audit_path_var is not None else ""
		if audit_path and Path(audit_path).exists():
			try:
				sbl_model = _get_sbl_model_from_workbook(audit_path)
			except Exception:
				pass
		if sbl_model:
			status = self.template_service.get_template_status(sbl_model=sbl_model)
		else:
			status = self.template_service.get_template_status()
		self.template_baseline_sbl_var.set(
			f"Exists: {status['baseline_sbl']['exists']} | Updated: {status['baseline_sbl']['updated']} | {status['baseline_sbl']['path']}"
		)
		self.template_latest_sbl_var.set(
			f"Exists: {status['latest_sbl']['exists']} | Updated: {status['latest_sbl']['updated']} | {status['latest_sbl']['path']}"
		)
		self.template_baseline_json_var.set(
			f"Exists: {status['baseline_master_list']['exists']} | Updated: {status['baseline_master_list']['updated']} | {status['baseline_master_list']['path']}"
		)
		self.template_latest_json_var.set(
			f"Exists: {status['latest_master_list']['exists']} | Updated: {status['latest_master_list']['updated']} | {status['latest_master_list']['path']}"
		)

	def append_log(self, message: str):
		"""Append a message to the checklist log pane and file logger."""
		self.log_widget.insert("end", message + "\n")
		self.log_widget.see("end")
		self.logger.write(message)

	def set_status(self, message: str):
		"""Update the checklist status label."""
		self.status_var.set(message)

	def pick_source(self):
		"""Prompt for the checklist source workbook."""
		path = filedialog.askopenfilename(
			title="Select main SBL source",
			initialdir=str(SBLS_DIR),
			filetypes=[("Supported files", "*.xlsx *.xlsm *.csv *.json"), ("All files", "*.*")],
		)
		if path:
			self.source_path.set(path)

	def pick_output(self):
		"""Prompt for the generated checklist output path."""
		path = filedialog.asksaveasfilename(title="Save generated audit form as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
		if path:
			self.output_path.set(path)

	def load_baseline_template(self):
		"""Load the best available baseline template into the source field."""
		source = self.source_path.get().strip()
		sbl_model = None
		if source and Path(source).exists():
			try:
				sbl_model = _get_sbl_model_from_workbook(source)
			except Exception:
				sbl_model = None

		if sbl_model:
			baseline_path = self.template_service.resolve_existing_baseline_sbl_path(sbl_model=sbl_model)
		else:
			baseline_path = self.template_service.resolve_existing_baseline_sbl_path()
		if baseline_path is None and source and Path(source).exists():
			try:
				result = self.template_service.update_baseline_from_sbl(source)
				baseline_path = result.get("sbl_template")
				self.append_log(f"Baseline template was missing and has been created from source: {baseline_path}")
			except Exception as exc:
				self.logger.write_exception(exc)
				messagebox.showerror("Baseline template missing", f"No baseline template found, and auto-create failed: {exc}")
				return

		if not baseline_path or not Path(baseline_path).exists():
			messagebox.showwarning("Baseline template missing", "No baseline template exists yet. Select a source workbook and use 'Update Baseline From Source'.")
			return

		self.source_path.set(baseline_path)
		self.append_log(f"Loaded baseline template as source: {baseline_path}")

	def update_baseline_template(self):
		"""Update baseline templates from the selected source workbook."""
		source = self.source_path.get().strip()
		if not source:
			messagebox.showerror("No source selected", "Select a source workbook before updating baseline template.")
			return
		try:
			result = self.template_service.update_baseline_from_sbl(source)
			sbl_model = _get_sbl_model_from_workbook(source)
			self.append_log(f"Updated baseline template for model: {sbl_model}")
			self.append_log(f"Baseline SBL template: {result['sbl_template']}")
			self.append_log(f"Baseline master software list template: {result['json_template']}")
			self.refresh_template_status_panel()
			messagebox.showinfo("Template updated", "Baseline SBL and master software list templates were updated.")
		except Exception as exc:
			self.logger.write_exception(exc)
			messagebox.showerror("Template update failed", str(exc))

	def import_list_source(self):
		"""Import a CSV, JSON, or workbook into a normalized source workbook."""
		in_path = filedialog.askopenfilename(
			title="Import list file",
			initialdir=str(SBLS_DIR),
			filetypes=[("Supported files", "*.xlsx *.xlsm *.csv *.json"), ("All files", "*.*")],
		)
		if not in_path:
			return
		default_name = f"UP_Imported_SBL_{timestamp_str()}.xlsx"
		out_path = filedialog.asksaveasfilename(
			title="Save imported source workbook as",
			defaultextension=".xlsx",
			initialfile=default_name,
			filetypes=[("Excel files", "*.xlsx")],
		)
		if not out_path:
			return
		try:
			imported = self.template_service.import_list_to_sbl_workbook(in_path, out_path)
			self.source_path.set(imported)
			self.append_log(f"Imported list file into SBL workbook: {imported}")
		except Exception as exc:
			self.logger.write_exception(exc)
			messagebox.showerror("Import failed", str(exc))

	def preview_source_mapping(self):
		"""Preview detected source mapping and sample rows before generation."""
		source = self.source_path.get().strip()
		if not source:
			messagebox.showerror("No source selected", "Select a source workbook before previewing mapping.")
			return

		try:
			generator = ChecklistGeneratorService(source)
			preview = generator.preview_source_mapping()
		except Exception as exc:
			self.logger.write_exception(exc)
			messagebox.showerror("Preview failed", str(exc))
			return

		mapped = preview.get("mapped_headers", {})
		target_columns = preview.get("target_columns", [])
		sample_components = preview.get("sample_components", [])
		row_count = int(preview.get("row_count", 0))

		summary_lines = [
			f"Header row: {preview.get('header_row', '')}",
			f"Rows detected: {row_count}",
			"",
			"Mapped headers:",
			f"- Software component: {mapped.get('software_component', '') or 'not detected'}",
			f"- Current version: {mapped.get('current_version', '') or 'not detected'}",
			f"- Version location: {mapped.get('version_locations', '') or 'not detected'}",
			f"- SBL build: {mapped.get('sbl_build', '') or 'not detected'}",
			f"- Audit: {mapped.get('audit', '') or 'will be created as AUDIT'}",
			"",
			f"Target columns: {', '.join(target_columns[:8]) if target_columns else 'none detected'}",
		]
		if len(target_columns) > 8:
			summary_lines.append(f"(+{len(target_columns) - 8} more target columns)")
		if sample_components:
			summary_lines.extend([
				"",
				"Sample components:",
				"- " + "\n- ".join(sample_components[:5]),
			])

		self.append_log(
			f"Preview mapping complete | rows={row_count} | targets={len(target_columns)} | "
			f"software_header={mapped.get('software_component', '') or 'N/A'}"
		)
		messagebox.showinfo("Source Mapping Preview", "\n".join(summary_lines))

	def extract_path(self, version_locations):
		"""Extract or normalize a path-like VERSION LOCATIONS value."""
		if version_locations is None:
			return ""
		try:
			if pd.isna(version_locations):
				return ""
		except Exception:
			pass
		raw = str(version_locations).strip()
		if not raw:
			return ""
		if re.search(r"programs[_ ]and[_ ]features", raw, re.IGNORECASE):
			return "programs_and_features"
		if raw.lower().startswith("powershell:"):
			return raw
		match = re.match(r"([A-Za-z]:[\\/][^>\n\r\t]+)", raw)
		if match:
			return match.group(1).strip()
		return raw

	def user_read_software_list(self):
		"""Legacy ad-hoc workbook reader retained for manual troubleshooting."""
		file_path = self.source_path.get().strip()
		software_component = "SOFTWARE COMPONENT"
		version_locations = "VERSION LOCATIONS"
		software_list = []

		if file_path.endswith(".xlsx"):
			df = pd.read_excel(file_path)
			df = df.dropna(subset=[software_component])
			df[software_component] = df[software_component].str.strip()
			df_headers = list(df.columns)
			normalized_headers = [str(h).lower() for h in df_headers]
			keywords = ["location", "component", "name", "id"]
			matching_headers = [og for og, norm in zip(df_headers, normalized_headers) if any(k in norm for k in keywords)]
			print(matching_headers)
			df[version_locations] = df[version_locations].apply(self.extract_path)
		else:
			print(f"Unsupported file format: {file_path}")
			sys.exit(1)

		pattern = r".*CURRENT CI VERSION.*"
		matching_column = next((col for col in df.columns if re.match(pattern, col, re.IGNORECASE)), None)
		if matching_column:
			for _, row in df.iterrows():
				print(row.to_dict())
				software_list.append(
					{
						"name": row[software_component],
						"expected_version": row[matching_column],
						"version_locations": row[version_locations],
					}
				)
		else:
			print("No column found with 'CURRENT CI VERSION' in the name.")
		print(software_list)
		return software_list

	def start_generate(self):
		"""Kick off checklist generation on a worker thread."""
		self.generate_button.configure(state="disabled")
		if hasattr(self, "progress"):
			self.progress.configure(style="TProgressbar")
		self.progress_var.set(0)
		self.set_status("Status: Generating...")
		self.logger = FileLogger(LOGS_DIR, "checklist_generation")
		self.append_log("Starting checklist generation")
		self.append_log(f"Source input: {self.source_path.get()}")
		self.append_log(f"Output workbook: {self.output_path.get()}")
		self.append_log(f"Session log file: {self.logger.get_path()}")
		threading.Thread(target=self._generate_worker, daemon=True).start()

	def _generate_worker(self):
		"""Worker for generating the audit checklist workbook and JSON export."""
		try:
			source = self.source_path.get().strip()
			output = self.output_path.get().strip()
			if not source:
				raise ValueError("Select a source workbook first.")
			if not output:
				raise ValueError("Choose an output workbook path first.")

			self.after(0, lambda: self.progress_var.set(10))
			self.after(0, lambda: self.append_log("Loading source input..."))
			generator = ChecklistGeneratorService(source)
			if generator.normalized_source_path != source:
				self.after(0, lambda p=generator.normalized_source_path: self.append_log(f"Normalized non-Excel input to workbook staging file: {p}"))
			self.after(0, lambda: self.progress_var.set(45))
			self.after(0, lambda: self.append_log("Generating audit workbook from source layout..."))
			generator.generate_audit_form(output)

			self.after(0, lambda: self.progress_var.set(80))
			self.after(0, lambda: self.append_log("Writing checklist JSON export..."))
			json_path = JsonExportService.write_checklist_json(Path(output).stem, generator.export_json_payload())
			sbl_model = _get_sbl_model_from_workbook(output)
			latest_sbl = self.template_service.update_latest_sbl(output)
			latest_master = self.template_service.snapshot_current_master_to_latest(sbl_model=sbl_model)

			self.after(0, lambda: self.progress_var.set(100))
			self.after(0, lambda: self.append_log(f"Generated tool-generated audit form: {output}"))
			self.after(0, lambda: self.append_log(f"Checklist JSON written: {json_path}"))
			self.after(0, lambda: self.append_log(f"Updated latest SBL snapshot (tool-generated): {latest_sbl}"))
			self.after(0, lambda: self.append_log(f"Updated latest master software list snapshot: {latest_master}"))
			self.after(0, self.refresh_template_status_panel)
			self.after(0, lambda: self.set_status("Status: Complete"))
			self.after(0, lambda: messagebox.showinfo("Checklist generated", f"Audit checklist created.Saved to:{output}"))
		except Exception as exc:
			self.logger.write_exception(exc)
			error_text = str(exc)
			self.after(0, lambda error_text=error_text: self.append_log(f"ERROR: {error_text}"))
			self.after(0, lambda: self.set_status("Status: Failed"))
			if hasattr(self, "progress"):
				self.after(0, lambda: self.progress.configure(style="Red.TProgressbar"))
			self.after(0, lambda error_text=error_text: messagebox.showerror("Checklist generation failed", error_text))
		finally:
			self.after(0, lambda: self.generate_button.configure(state="normal"))


class AuditFrame(BaseFrame):
	"""Audit execution frame."""

	def _prompt_quick_audit_vm_details(self, target_columns: List[str]) -> Optional[Dict[str, Any]]:
		"""Prompt for quick-audit VM details using a compact modal dialog."""
		dialog = tk.Toplevel(self)
		dialog.title("Quick Audit Scan - VM Details")
		dialog.transient(self.controller)
		dialog.grab_set()
		dialog.resizable(False, False)

		container = ttk.Frame(dialog, padding=10)
		container.pack(fill="both", expand=True)

		vcenter_server = tk.StringVar(value=self.vcenter_server.get().strip())
		vcenter_username = tk.StringVar(value=self.vcenter_username.get().strip())
		vcenter_password = tk.StringVar(value=self.vcenter_password.get())
		guest_username = tk.StringVar(value=self.guest_username.get().strip())
		guest_password = tk.StringVar(value=self.guest_password.get())

		ttk.Label(
			container,
			text="Quick Audit Scan: local scan runs first, then VM targets are scanned.",
			wraplength=620,
		).pack(anchor="w", pady=(0, 8))

		creds = ttk.LabelFrame(container, text="Connection Details", padding=8)
		creds.pack(fill="x", pady=(0, 8))

		def _entry_row(parent: ttk.Widget, label: str, variable: tk.StringVar, show: Optional[str] = None):
			"""Render one label/entry row for the quick-audit dialog."""
			row = ttk.Frame(parent)
			row.pack(fill="x", pady=2)
			ttk.Label(row, text=label, width=22).pack(side="left")
			if show is not None:
				ttk.Entry(row, textvariable=variable, show=show).pack(side="left", fill="x", expand=True)
			else:
				ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)

		_entry_row(creds, "vCenter server", vcenter_server)
		_entry_row(creds, "vCenter username", vcenter_username)
		_entry_row(creds, "vCenter password", vcenter_password, show="*")
		_entry_row(creds, "Guest username", guest_username)
		_entry_row(creds, "Guest password", guest_password, show="*")

		mapping_box = ttk.LabelFrame(container, text="Target -> VM Name Mapping", padding=8)
		mapping_box.pack(fill="both", expand=True)

		target_vars: Dict[str, tk.StringVar] = {}
		for target_name in target_columns:
			row = ttk.Frame(mapping_box)
			row.pack(fill="x", pady=2)
			ttk.Label(row, text=target_name, width=26).pack(side="left")
			vm_var = tk.StringVar(value=LOCAL_SENTINEL)
			combo = ttk.Combobox(row, textvariable=vm_var, values=[LOCAL_SENTINEL], state="normal")
			combo.pack(side="left", fill="x", expand=True)
			target_vars[target_name] = vm_var

		result: Dict[str, Any] = {}

		def _apply_guest_to_all():
			"""Apply shared guest credentials to all target mappings."""
			user = normalize_text(guest_username.get())
			password = guest_password.get()
			if not user or not password:
				messagebox.showwarning(
					"Missing guest credentials",
					"Enter guest username and password first.",
					parent=dialog,
				)
				return
			for _target, vm_var in target_vars.items():
				if not normalize_text(vm_var.get()):
					vm_var.set(LOCAL_SENTINEL)

		def _submit():
			"""Validate and submit the quick-audit dialog."""
			server = normalize_text(vcenter_server.get())
			user = normalize_text(vcenter_username.get())
			password = vcenter_password.get()
			guest_user = normalize_text(guest_username.get())
			guest_pass = guest_password.get()
			if not server or not user or not password:
				messagebox.showwarning(
					"vCenter credentials required",
					"Provide vCenter server, username, and password.",
					parent=dialog,
				)
				return
			if not guest_user or not guest_pass:
				messagebox.showwarning(
					"Guest credentials required",
					"Provide guest username and password used for VM scans.",
					parent=dialog,
				)
				return

			targets: Dict[str, Dict[str, str]] = {}
			for target_name in target_columns:
				vm_name = normalize_text(target_vars[target_name].get()) or LOCAL_SENTINEL
				targets[target_name] = {
					"vm_name": vm_name,
					"username": guest_user,
					"password": guest_pass,
					"os_type": "windows",
				}

			result.update(
				{
					"vcenter": {
						"server": server,
						"username": user,
						"password": password,
					},
					"guest": {
						"username": guest_user,
						"password": guest_pass,
					},
					"targets": targets,
				}
			)
			dialog.destroy()

		def _cancel():
			"""Cancel the quick-audit dialog."""
			dialog.destroy()

		btn_row = ttk.Frame(container)
		btn_row.pack(fill="x", pady=(8, 0))
		ttk.Button(btn_row, text="Apply Guest Creds To All", command=_apply_guest_to_all).pack(side="left")
		ttk.Button(btn_row, text="Cancel", command=_cancel).pack(side="right")
		ttk.Button(btn_row, text="Run Quick Audit Scan", command=_submit).pack(side="right", padx=(0, 8))

		self.wait_window(dialog)
		return result or None

	def _init_target_info_table(self, parent):
		"""Initialize the target-info edit button in the profile row."""
		self.target_info_vars = {}
		self.target_info_dialog = None
		self.save_targets_btn = None
		btn = ttk.Button(parent, text="Show/Edit Target VM Info", command=self._show_target_info_dialog)
		btn.pack(side="left", padx=(8, 0))

	def _show_target_info_dialog(self):
		"""Show a dialog for editing target VM info in the selected profile."""
		if self.target_info_dialog and self.target_info_dialog.winfo_exists():
			self.target_info_dialog.lift()
			return
		self.target_info_dialog = tk.Toplevel(self)
		self.target_info_dialog.title("Edit Target VM Info")
		self.target_info_dialog.resizable(False, False)
		frame = ttk.Frame(self.target_info_dialog, padding=8)
		frame.pack(fill="both", expand=True)
		self.target_info_vars = {}
		header = ttk.Frame(frame)
		header.pack(fill="x")
		ttk.Label(header, text="Target", width=30, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 4))
		ttk.Label(header, text="VM Name", width=24, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=1, sticky="w", padx=(0, 4))
		ttk.Label(header, text="Username", width=18, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=2, sticky="w", padx=(0, 4))
		ttk.Label(header, text="Password", width=18, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=3, sticky="w", padx=(0, 4))
		ttk.Label(header, text="OS", width=10, anchor="w", font=("Segoe UI", 9, "bold")).grid(row=0, column=4, sticky="w")
		profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
		targets = profile.get("targets", {})
		target_names = self._resolve_target_names(profile)
		for target in target_names:
			info = targets.get(target, {"vm_name": LOCAL_SENTINEL, "username": "", "password": "", "os_type": "windows"})
			row = ttk.Frame(frame)
			row.pack(fill="x", pady=2)
			ttk.Label(row, text=target, width=30, anchor="w").grid(row=0, column=0, sticky="w", padx=(0, 4))
			vm_var = tk.StringVar(value=info.get("vm_name", LOCAL_SENTINEL))
			user_var = tk.StringVar(value=info.get("username", ""))
			pass_var = tk.StringVar(value=info.get("password", ""))
			os_var = tk.StringVar(value=info.get("os_type", "windows"))
			ttk.Entry(row, textvariable=vm_var, width=24).grid(row=0, column=1, sticky="we", padx=(0, 4))
			ttk.Entry(row, textvariable=user_var, width=18).grid(row=0, column=2, sticky="we", padx=(0, 4))
			ttk.Entry(row, textvariable=pass_var, width=18, show="*").grid(row=0, column=3, sticky="we", padx=(0, 4))
			ttk.Combobox(row, textvariable=os_var, values=["windows", "linux"], width=10, state="readonly").grid(row=0, column=4, sticky="w")
			self.target_info_vars[target] = (vm_var, user_var, pass_var, os_var)

		def _apply_shared_credentials_to_targets():
			"""Apply shared credentials to all target rows."""
			shared_user = normalize_text(self.guest_username.get()) or normalize_text(self.vcenter_username.get())
			shared_password = self.guest_password.get() or self.vcenter_password.get()
			if not shared_user or not shared_password:
				messagebox.showwarning(
					"Shared credentials missing",
					"Set shared VM credentials (or vCenter credentials) first, then apply shared credentials.",
				)
				return
			for _target, (_vm_var, user_var, pass_var, _os_var) in self.target_info_vars.items():
				user_var.set(shared_user)
				pass_var.set(shared_password)

		ttk.Button(frame, text="Apply Shared Login To All", command=_apply_shared_credentials_to_targets).pack(pady=(6, 2))
		self.save_targets_btn = ttk.Button(frame, text="Save Target Info to Profile", command=self._save_target_info)
		self.save_targets_btn.pack(pady=(2, 8))
		self.target_info_dialog.transient(self.controller)
		self.target_info_dialog.grab_set()
		self.target_info_dialog.wait_window()

	def _save_target_info(self):
		"""Save edited target info back to the selected profile."""
		profile = self.profile_service.load_profile(self.profile_name.get().strip()) if self.profile_name.get().strip() else {}
		targets = profile.get("targets", {})
		default_user = normalize_text(profile.get("vcenter_username", ""))
		default_password = profile.get("vcenter_password", "")
		for target, (vm_var, user_var, pass_var, os_var) in self.target_info_vars.items():
			target_user = user_var.get().strip() or default_user
			target_password = pass_var.get().strip() or default_password
			targets[target] = {
				"vm_name": vm_var.get().strip(),
				"username": target_user,
				"password": target_password,
				"os_type": os_var.get().strip() or "windows",
			}
		profile["targets"] = targets
		self.profile_service.save_profile(self.profile_name.get().strip(), profile)
		self.append_log("Saved target VM info to profile.")
		if self.target_info_dialog and self.target_info_dialog.winfo_exists():
			self.target_info_dialog.destroy()

	def __init__(self, parent, controller):
		"""Initialize the AuditFrame instance."""
		super().__init__(parent, controller)
		self._compact_label_width = 16
		self._audit_profile_override: Optional[Dict[str, Any]] = None
		self._audit_mode_label = "standard"
		self.profile_service = VMProfileService()
		self.style = ttk.Style()
		self.style.configure("Bold.TLabelframe.Label", font=("Segoe UI", 10, "bold"))
		self.audit_path = tk.StringVar()
		self.output_path = tk.StringVar()
		self.profile_name = tk.StringVar()
		self.profile_options = self._get_profile_options()
		self.detected_target_columns = default_target_columns()
		self.detected_local_target_label = "Verification Steps"
		self.build_type_value = tk.StringVar(value="unknown")
		self.audit_schema_var = tk.StringVar(value="Build type: unknown | VM targets: legacy fallback | Local targets: Verification Steps")
		self.last_schema_source = ""
		if self.profile_options:
			self.profile_name.set(self.profile_options[0])
		else:
			self.profile_name.set("")
		self.connection_mode = tk.StringVar(value="vSphere")
		self.vcenter_server = tk.StringVar()
		self.vcenter_username = tk.StringVar()
		self.vcenter_password = tk.StringVar()
		self.guest_username = tk.StringVar()
		self.guest_password = tk.StringVar()
		self.ssh_gateway_host = tk.StringVar()
		self.ssh_gateway_port = tk.StringVar(value="22")
		self.ssh_gateway_username = tk.StringVar()
		self.ssh_gateway_password = tk.StringVar()
		self.ssh_target_port = tk.StringVar(value="22")
		self.show_ssh_settings = tk.BooleanVar(value=False)
		self.status_var = tk.StringVar(value="Status: Ready")
		self.pipeline_runtime_var = tk.StringVar(value="Pipeline status: not loaded")
		self.progress_var = tk.DoubleVar(value=0)
		self.logger = FileLogger(LOGS_DIR, "audit_run")
		self._watch_service = WatchFolderPipelineService()
		self._watch_after_id: Optional[str] = None
		self._watch_process_existing = tk.BooleanVar(value=False)
		self._watch_archive_processed = tk.BooleanVar(value=True)
		top = ttk.Frame(self)
		top.pack(fill="x")
		ttk.Button(top, text="← Back", command=lambda: controller.show_frame("HomeFrame")).pack(side="left")
		ttk.Label(top, text="Run Audit", font=("Segoe UI", 16, "bold")).pack(side="left", padx=(12, 0))
		cfg = ttk.LabelFrame(self, text="Audit Workbook", padding=8)
		cfg.pack(fill="x", pady=8)
		self._path_row(cfg, "Audit workbook", self.audit_path, self.pick_audit)
		self._path_row(cfg, "Save audited results", self.output_path, self.pick_output)
		ttk.Label(cfg, textvariable=self.audit_schema_var, foreground="#35556b").pack(anchor="w", pady=(4, 0))
		creds = ttk.LabelFrame(self, text="Profile and Credentials", padding=8)
		creds.pack(fill="x", pady=(0, 8))
		self.profile_row = ttk.Frame(creds)
		self.profile_row.pack(fill="x", pady=2)
		ttk.Label(self.profile_row, text="VM profile", width=self._compact_label_width).pack(side="left")
		self.profile_dropdown = ttk.Combobox(self.profile_row, textvariable=self.profile_name, state="readonly", values=self.profile_options)
		self.profile_dropdown.pack(side="left", fill="x", expand=True, padx=(0, 8))
		ttk.Button(self.profile_row, text="Load Profile", command=self.load_profile_defaults).pack(side="left")
		self._init_target_info_table(self.profile_row)

		self.fallback_texts = {
			"vsphere": "Use SSH tunnel as fallback if vSphere fails",
			"ssh tunnel": "Use vSphere as fallback if SSH fails",
		}
		mode_row = ttk.Frame(creds)
		mode_row.pack(fill="x", pady=2)
		ttk.Label(mode_row, text="Connection mode", width=self._compact_label_width).pack(side="left")
		ttk.Combobox(mode_row, textvariable=self.connection_mode, state="readonly", values=["vSphere", "SSH Tunnel", "Local Scan Only"]).pack(side="left", fill="x", expand=True, padx=(0, 8))
		self.toggle_row = ttk.Frame(creds)
		self.toggle_row.pack(fill="x", pady=2)
		self.fallback_checkbox = ttk.Checkbutton(
			self.toggle_row,
			text=self.fallback_texts.get(normalize_text(self.connection_mode.get()).lower(), self.fallback_texts["vsphere"]),
			variable=self.show_ssh_settings,
			command=self._toggle_ssh_section,
		)
		self.fallback_checkbox.pack(side="left", padx=(self._compact_label_width * 6, 0))
		self.vcenter_section = ttk.LabelFrame(creds, text="vCenter Settings", padding=4, labelanchor="nw", style="Bold.TLabelframe")
		self.vcenter_section.pack(fill="x", pady=(4, 0))
		self._entry_row(self.vcenter_section, "vCenter server", self.vcenter_server)
		self._entry_row(self.vcenter_section, "vCenter username", self.vcenter_username)
		self._entry_row(self.vcenter_section, "vCenter password", self.vcenter_password, show="*")

		self.ssh_section = ttk.LabelFrame(creds, text="SSH Tunnel Settings", padding=6, labelanchor="nw", style="Bold.TLabelframe")
		self._entry_pair_row(self.ssh_section, "SSH gateway host", self.ssh_gateway_host, "Gateway port", self.ssh_gateway_port)
		self._entry_pair_row(self.ssh_section, "Gateway username", self.ssh_gateway_username, "Gateway password", self.ssh_gateway_password, show2="*")
		self._entry_pair_row(self.ssh_section, "Target SSH username", self.guest_username, "Target port", self.ssh_target_port)
		self._entry_half_row(self.ssh_section, "Target SSH password", self.guest_password, show="*", label_width=20)
		controls = ttk.Frame(self)
		controls.pack(fill="x", pady=(0, 8))
		self.run_button = ttk.Button(controls, text="Run Audit", command=self.start_audit)
		self.run_button.pack(side="left")
		self.quick_run_button = ttk.Button(controls, text="Quick Audit Scan", command=self.start_quick_audit)
		self.quick_run_button.pack(side="left", padx=(8, 0))
		self.watch_start_button = ttk.Button(controls, text="Start Pipeline", command=self.start_watch_folder_pipeline)
		self.watch_start_button.pack(side="left", padx=(8, 0))
		self.watch_stop_button = ttk.Button(controls, text="Stop Pipeline", command=self.stop_watch_folder_pipeline, state="disabled")
		self.watch_stop_button.pack(side="left", padx=(8, 0))
		self.probe_button = ttk.Button(controls, text="Test vCenter Probe", command=self.start_probe)
		self.probe_button.pack(side="left", padx=(8, 0))
		ttk.Button(controls, text="Open Logs Folder", command=lambda: self.open_folder(LOGS_DIR)).pack(side="left", padx=(8, 0))
		ttk.Label(controls, textvariable=self.status_var).pack(side="left", padx=(12, 0))
		watch_options = ttk.Frame(self)
		watch_options.pack(fill="x", pady=(0, 6))
		ttk.Checkbutton(watch_options, text="Watch: process existing files on start", variable=self._watch_process_existing).pack(side="left")
		ttk.Checkbutton(watch_options, text="Watch: archive processed files", variable=self._watch_archive_processed).pack(side="left", padx=(12, 0))
		ttk.Label(watch_options, textvariable=self.pipeline_runtime_var, foreground="#35556b").pack(side="left", padx=(12, 0))
		ttk.Progressbar(self, variable=self.progress_var, maximum=100).pack(fill="x")
		log_box = ttk.LabelFrame(self, text="Log", padding=6)
		log_box.pack(fill="both", expand=True, pady=(8, 0))
		self.log = tk.Text(log_box, wrap="word")
		self.log.pack(side="left", fill="both", expand=True)
		scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log.yview)
		scroll.pack(side="right", fill="y")
		self.log.configure(yscrollcommand=scroll.set)

		self.connection_mode.trace_add("write", self._on_connection_mode_changed)
		self._set_ssh_section_visible(False)
		self._refresh_audit_source_metadata(prompt_user=False)

	def _get_profile_options(self):
		"""Return available saved profile names."""
		profiles_dir = PROFILES_DIR
		if not profiles_dir.exists():
			return []
		return [f.stem for f in profiles_dir.glob("*.json") if f.is_file()]

	def _path_row(self, parent, label, variable, command):
		"""Render a path row with browse button."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=2)
		ttk.Label(row, text=label, width=self._compact_label_width).pack(side="left")
		ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=(0, 8))
		ttk.Button(row, text="Browse", command=command).pack(side="left")

	def _entry_row(self, parent, label, variable, show=None, button=None, label_width=None):
		"""Render a single full-width labeled entry row."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=2)
		width = self._compact_label_width if label_width is None else label_width
		ttk.Label(row, text=label, width=width).pack(side="left")
		entry_kwargs = {"textvariable": variable}
		if show is not None:
			entry_kwargs["show"] = show
		ttk.Entry(row, **entry_kwargs).pack(side="left", fill="x", expand=True, padx=(0, 8))
		if button:
			ttk.Button(row, text=button[0], command=button[1]).pack(side="left")

	def _entry_pair_row(self, parent, label1, var1, label2, var2, show1=None, show2=None):
		"""Render a two-column row of labeled entries."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=2)

		left = ttk.Frame(row)
		left.pack(side="left", fill="x", expand=True, padx=(0, 4))
		ttk.Label(left, text=label1, width=20).pack(side="left")
		left_kwargs = {"textvariable": var1}
		if show1 is not None:
			left_kwargs["show"] = show1
		ttk.Entry(left, **left_kwargs).pack(side="left", fill="x", expand=True)

		right = ttk.Frame(row)
		right.pack(side="left", fill="x", expand=True, padx=(4, 0))
		ttk.Label(right, text=label2, width=16).pack(side="left")
		right_kwargs = {"textvariable": var2}
		if show2 is not None:
			right_kwargs["show"] = show2
		ttk.Entry(right, **right_kwargs).pack(side="left", fill="x", expand=True)

	def _entry_half_row(self, parent, label, variable, show=None, label_width=None):
		"""Render a single entry occupying half a two-column layout row."""
		row = ttk.Frame(parent)
		row.pack(fill="x", pady=2)

		left = ttk.Frame(row)
		left.pack(side="left", fill="x", expand=True, padx=(0, 4))
		width = self._compact_label_width if label_width is None else label_width
		ttk.Label(left, text=label, width=width).pack(side="left")
		left_kwargs = {"textvariable": variable}
		if show is not None:
			left_kwargs["show"] = show
		ttk.Entry(left, **left_kwargs).pack(side="left", fill="x", expand=True, padx=(0, 8))

		right = ttk.Frame(row)
		right.pack(side="left", fill="x", expand=True)
		ttk.Label(right, text="", width=16).pack(side="left")

	def _set_ssh_section_visible(self, visible: bool) -> None:
		"""Show or hide the SSH settings section."""
		if visible:
			if not self.ssh_section.winfo_ismapped():
				self.ssh_section.pack(fill="x", pady=(4, 0))
		else:
			if self.ssh_section.winfo_ismapped():
				self.ssh_section.pack_forget()

	def _toggle_ssh_section(self):
		"""Re-evaluate connection-mode specific section visibility."""
		self._on_connection_mode_changed()

	def _on_connection_mode_changed(self, *_):
		"""Update UI state after the selected connection mode changes."""
		mode = normalize_text(self.connection_mode.get()).lower()
		is_local_only = mode == "local scan only"
		self.fallback_checkbox.configure(text=self.fallback_texts.get(mode, self.fallback_texts["vsphere"]))

		if is_local_only:
			if self.profile_row.winfo_ismapped():
				self.profile_row.pack_forget()
			if self.toggle_row.winfo_ismapped():
				self.toggle_row.pack_forget()
			if hasattr(self, "vcenter_section") and self.vcenter_section.winfo_ismapped():
				self.vcenter_section.pack_forget()
			self._set_ssh_section_visible(False)
			if hasattr(self, "probe_button"):
				self.probe_button.configure(text="Remote Probe Disabled", state="disabled")
			self._update_schema_banner()
			return

		if not self.profile_row.winfo_ismapped():
			self.profile_row.pack(fill="x", pady=2)
		if not self.toggle_row.winfo_ismapped():
			self.toggle_row.pack(fill="x", pady=2)
		if hasattr(self, "probe_button"):
			self.probe_button.configure(state="normal")

		if mode == "ssh tunnel":
			self._set_ssh_section_visible(True)
			if bool(self.show_ssh_settings.get()):
				if hasattr(self, "vcenter_section") and not self.vcenter_section.winfo_ismapped():
					self.vcenter_section.pack(fill="x", pady=(4, 0))
			else:
				if hasattr(self, "vcenter_section") and self.vcenter_section.winfo_ismapped():
					self.vcenter_section.pack_forget()
			if hasattr(self, "probe_button"):
				self.probe_button.configure(text="Test SSH Probe")
		else:
			if hasattr(self, "vcenter_section") and not self.vcenter_section.winfo_ismapped():
				self.vcenter_section.pack(fill="x", pady=(4, 0))
			self._set_ssh_section_visible(bool(self.show_ssh_settings.get()))
			if hasattr(self, "probe_button"):
				self.probe_button.configure(text="Test vCenter Probe")

		self._update_schema_banner()

	def _update_schema_banner(self) -> None:
		"""Refresh the schema summary line based on connection mode and detected columns."""
		resolved_build_type = normalize_text(self.build_type_value.get()) or "unknown"
		mode = normalize_text(self.connection_mode.get()).lower()
		local_label = normalize_text(self.detected_local_target_label) or "Verification Steps"
		if mode == "local scan only":
			self.audit_schema_var.set(f"Build type: {resolved_build_type} | VM targets: N/A | Local targets: {local_label}")
			return

		summary = ", ".join(self.detected_target_columns[:4])
		if len(self.detected_target_columns) > 4:
			summary += ", ..."
		vm_summary = summary or "legacy fallback"
		vcenter_host = normalize_text(self.vcenter_server.get())
		if vcenter_host:
			vm_summary = f"{vm_summary} (vCenter: {vcenter_host})"
		self.audit_schema_var.set(f"Build type: {resolved_build_type} | VM targets: {vm_summary} | Local targets: {local_label}")

	def append_log(self, message: str):
		"""Append a line to the audit log and file logger."""
		self.log.insert("end", message + "\n")
		self.log.see("end")
		self.logger.write(message)
		print(message, flush=True)

	def set_status(self, message: str):
		"""Update the audit status label."""
		self.status_var.set(message)

	@staticmethod
	def _parse_int(value: str, default: int) -> int:
		"""Parse an integer field with a fallback default."""
		try:
			return int(normalize_text(value))
		except Exception:
			return default

	def _apply_detected_schema(self, target_columns: List[str], build_type: str, local_target_label: str = ""):
		"""Apply detected target-column and build-type metadata to the UI."""
		self.detected_target_columns = target_columns or default_target_columns()
		resolved_build_type = normalize_text(build_type) or infer_build_type(build_type)
		self.build_type_value.set(resolved_build_type)
		if normalize_text(local_target_label):
			self.detected_local_target_label = normalize_text(local_target_label)
		self._update_schema_banner()

	def _refresh_audit_source_metadata(self, prompt_user: bool = True):
		"""Refresh detected audit workbook schema from the selected source."""
		source_path = self.audit_path.get().strip()
		if not source_path:
			self._apply_detected_schema(default_target_columns(), "unknown")
			return
		try:
			workbook_service = AuditWorkbookService(source_path)
			workbook_service.detect_header_row()
			workbook_service.build_column_map()
			selected_columns = workbook_service.target_columns
			if prompt_user and source_path != self.last_schema_source:
				selected_columns = confirm_target_column_mapping(
					self,
					source_path,
					workbook_service.target_columns,
					workbook_service.build_type,
					current_columns=self.detected_target_columns,
				) or self.detected_target_columns
			self._apply_detected_schema(selected_columns, workbook_service.build_type, workbook_service.version_location_header or "")
			self.last_schema_source = source_path
		except Exception:
			self._apply_detected_schema(default_target_columns(), infer_build_type(source_path))

	def _resolve_target_names(self, payload: Optional[Dict[str, Any]] = None) -> List[str]:
		"""Resolve the target column names to use for the current audit."""
		if payload:
			return resolve_profile_target_columns(payload)
		return self.detected_target_columns or default_target_columns()

	@staticmethod
	def _legacy_pipeline_path_for_profile(profile_name: str) -> Path:
		"""Return legacy pipeline draft path for backward compatibility."""
		name = normalize_text(profile_name)
		if not name:
			return Path("")
		return PROFILES_DIR / f"pipeline_{name}.json"

	def _resolve_pipeline_for_profile(self, profile_name: str) -> Tuple[Dict[str, Any], str, str]:
		"""Resolve pipeline payload for a profile from profile section, then legacy file fallback.

		Returns: (pipeline_payload, source, reference)
		source: profile | legacy-file | none
		reference: profile path or pipeline file path if available
		"""
		name = normalize_text(profile_name)
		if not name:
			return {}, "none", ""

		profile_path = self.profile_service.profile_path(name)
		try:
			payload = self.profile_service.load_profile(name)
		except Exception:
			payload = {}

		if isinstance(payload, dict):
			pipelines = payload.get("pipelines", {})
			if isinstance(pipelines, dict):
				items = pipelines.get("items", {})
				active = normalize_text(pipelines.get("active", "default")) or "default"
				if isinstance(items, dict):
					pipeline = items.get(active, {})
					if isinstance(pipeline, dict) and pipeline:
						return pipeline, "profile", str(profile_path)

		legacy_path = self._legacy_pipeline_path_for_profile(name)
		if legacy_path and legacy_path.exists():
			try:
				legacy_payload = json.loads(legacy_path.read_text(encoding="utf-8"))
				if isinstance(legacy_payload, dict) and legacy_payload:
					return legacy_payload, "legacy-file", str(legacy_path)
			except Exception:
				pass

		return {}, "none", str(profile_path)

	def load_profile_defaults(self):
		"""Load saved connection defaults and detected target schema from the selected profile."""
		payload = self.profile_service.load_profile(self.profile_name.get().strip())
		self.vcenter_server.set(payload.get("vcenter_server", payload.get("vsphere", {}).get("server", "")))
		self.vcenter_username.set(payload.get("vcenter_username", payload.get("vsphere", {}).get("username", "")))
		self.vcenter_password.set(payload.get("vcenter_password", payload.get("vsphere", {}).get("password", "")))
		ssh_tunnel = normalize_ssh_tunnel_profile_fields(payload.get("ssh_tunnel", {}))
		self.ssh_gateway_host.set(ssh_tunnel["gateway_host"])
		self.ssh_gateway_port.set(ssh_tunnel["gateway_port"])
		self.ssh_gateway_username.set(ssh_tunnel["gateway_username"])
		self.ssh_gateway_password.set(ssh_tunnel["gateway_password"])
		self.ssh_target_port.set(ssh_tunnel["target_port"])
		self._apply_detected_schema(self._resolve_target_names(payload), payload.get("build_type", payload.get("target_schema", {}).get("build_type", self.audit_path.get())))

		target_creds = []
		targets = payload.get("targets", {})
		if isinstance(targets, dict):
			for target_name in self._resolve_target_names(payload):
				entry = targets.get(target_name, {})
				if not isinstance(entry, dict):
					continue
				user = normalize_text(entry.get("username", ""))
				password = entry.get("password", "")
				if user and password:
					target_creds.append((user, password))

		if target_creds:
			first_user, first_password = target_creds[0]
			self.guest_username.set(first_user)
			self.guest_password.set(first_password)
			if all(user == first_user and pwd == first_password for user, pwd in target_creds):
				self.append_log("Loaded profile defaults: vCenter credentials and shared VM login.")
			else:
				self.append_log("Loaded profile defaults: vCenter credentials; VM credentials vary by target (using first for shared field).")
		else:
			self.append_log(f"Loaded profile defaults from {self.profile_name.get().strip()}")

		selected_profile = normalize_text(self.profile_name.get())
		pipeline_payload, pipeline_source, pipeline_ref = self._resolve_pipeline_for_profile(selected_profile)
		if pipeline_payload:
			self.append_log(f"Pipeline detected for profile '{selected_profile}' [{pipeline_source}]: {pipeline_ref}")
			self._refresh_pipeline_runtime_status(pipeline_payload)
		else:
			self.append_log(f"Pipeline not found for profile '{selected_profile}'. Configure one in Target Profile Manager.")
			self.pipeline_runtime_var.set("Pipeline status: not configured")

	def _refresh_pipeline_runtime_status(self, pipeline_payload: Dict[str, Any]) -> PipelineRuntimeStatus:
		"""Refresh user-visible runtime status for the selected pipeline payload."""
		runtime = WatchFolderPipelineService.evaluate_runtime_compatibility(pipeline_payload)
		self.pipeline_runtime_var.set(runtime.summary)
		return runtime

	def start_watch_folder_pipeline(self):
		"""Start pipeline runtime handling based on current profile pipeline configuration."""
		selected_profile = normalize_text(self.profile_name.get())
		if not selected_profile:
			messagebox.showerror("Pipeline Runtime", "Select a profile first.")
			return

		pipeline_payload, pipeline_source, pipeline_ref = self._resolve_pipeline_for_profile(selected_profile)
		if not pipeline_payload:
			messagebox.showerror("Pipeline Runtime", "No pipeline config found for selected profile.")
			return

		runtime = self._refresh_pipeline_runtime_status(pipeline_payload)
		if not runtime.can_auto_run:
			self.append_log(
				f"Pipeline runtime compatibility: mode={runtime.mode} | input={runtime.input_source or 'N/A'} | output={runtime.output_action or 'N/A'}"
			)
			messagebox.showinfo(
				"Pipeline Runtime",
				(
					f"{runtime.summary}\n\n"
					"This pipeline type is recognized and validated, but does not have in-app auto-run execution yet."
				),
			)
			return

		try:
			self._watch_service.start(
				profile_name=selected_profile,
				pipeline_payload=pipeline_payload,
				logger=self.append_log,
				process_existing=bool(self._watch_process_existing.get()),
				archive_processed=bool(self._watch_archive_processed.get()),
			)
		except Exception as exc:
			messagebox.showerror("Pipeline Runtime", str(exc))
			return

		self.watch_start_button.configure(state="disabled")
		self.watch_stop_button.configure(state="normal")
		self.pipeline_runtime_var.set("Pipeline status: watching folder")
		self.append_log(f"Watch folder config source: {pipeline_source} | ref={pipeline_ref}")
		self._schedule_watch_tick()

	def stop_watch_folder_pipeline(self):
		"""Stop watch-folder polling loop."""
		if self._watch_service.active:
			self._watch_service.stop(self.append_log)
		if self._watch_after_id:
			try:
				self.after_cancel(self._watch_after_id)
			except Exception:
				pass
			self._watch_after_id = None
		self.watch_start_button.configure(state="normal")
		self.watch_stop_button.configure(state="disabled")
		if normalize_text(self.profile_name.get()):
			payload, _, _ = self._resolve_pipeline_for_profile(normalize_text(self.profile_name.get()))
			if payload:
				self._refresh_pipeline_runtime_status(payload)
			else:
				self.pipeline_runtime_var.set("Pipeline status: not configured")
		else:
			self.pipeline_runtime_var.set("Pipeline status: not loaded")
		self.append_log("Watch folder stopped.")

	def _schedule_watch_tick(self):
		"""Schedule next watch-folder polling cycle."""
		if not self._watch_service.active:
			return
		self._watch_after_id = self.after(1500, self._watch_tick)

	def _watch_tick(self):
		"""Poll watch folder and launch audit for newly discovered files."""
		if not self._watch_service.active:
			return
		try:
			is_busy = str(self.run_button.cget("state")) != "normal"
			dispatch = self._watch_service.poll(is_busy=is_busy, logger=self.append_log)
			if dispatch is not None:
				if normalize_text(self.profile_name.get()) != dispatch.profile_name:
					self.profile_name.set(dispatch.profile_name)
				self.audit_path.set(str(dispatch.input_path))
				self.output_path.set(str(dispatch.output_path))
				self.pipeline_runtime_var.set("Pipeline status: processing watch input")
				self.append_log(f"Watch folder picked file: {dispatch.input_path}")
				self.append_log(f"Watch folder output path: {dispatch.output_path}")
				self.start_audit()
			elif not is_busy:
				self.pipeline_runtime_var.set("Pipeline status: watching folder")
		except Exception as exc:
			self.append_log(f"Watch folder error: {exc}")
			self.pipeline_runtime_var.set("Pipeline status: watch error")
		finally:
			self._schedule_watch_tick()

	@staticmethod
	def _coerce_local_only_profile(vm_profile: Dict[str, Any], target_names: Optional[List[str]] = None) -> Dict[str, Any]:
		"""Force all target mappings in a profile to the local machine sentinel."""
		targets = vm_profile.setdefault("targets", {})
		for target_name in (target_names or resolve_profile_target_columns(vm_profile)):
			target_entry = targets.setdefault(target_name, {"vm_name": "", "os_type": "windows"})
			target_entry["vm_name"] = LOCAL_SENTINEL
			target_entry["os_type"] = "windows"
		return vm_profile

	def pick_audit(self):
		"""Prompt for the audit workbook path."""
		path = filedialog.askopenfilename(title="Select audit workbook", filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")])
		if path:
			self.audit_path.set(path)
			if not self.output_path.get().strip():
				source_stem = Path(path).stem
				auto_output = AUDIT_CHECKLIST_DIR.parent / "Audit Results" / f"{source_stem}_RESULTS.xlsx"
				self.output_path.set(str(auto_output))
			self._refresh_audit_source_metadata(prompt_user=True)

	def pick_output(self):
		"""Prompt for the audited-results workbook path."""
		path = filedialog.asksaveasfilename(title="Save audited workbook as", defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
		if path:
			self.output_path.set(path)

	def start_audit(self):
		"""Start a standard audit run."""
		self._audit_profile_override = None
		self._audit_mode_label = "standard"

		selected_profile = normalize_text(self.profile_name.get())
		pipeline_payload, pipeline_source, pipeline_ref = self._resolve_pipeline_for_profile(selected_profile)
		pipeline_exists = bool(pipeline_payload)
		if selected_profile and not pipeline_exists:
			proceed = messagebox.askyesno(
				"Pipeline Not Established",
				(
					f"No pipeline is established for profile '{selected_profile}'.\n\n"
					"Continue this audit run anyway?"
				),
			)
			if not proceed:
				self.append_log(f"Audit start cancelled: profile '{selected_profile}' has no established pipeline.")
				self.set_status("Status: Ready")
				return
		elif selected_profile and pipeline_exists:
			self.append_log(f"Pipeline check PASS for profile '{selected_profile}' [{pipeline_source}]: {pipeline_ref}")

		self.run_button.configure(state="disabled")
		self.quick_run_button.configure(state="disabled")
		self.probe_button.configure(state="disabled")
		self.progress_var.set(0)
		self.set_status(f"Status: Running ({self.build_type_value.get()})")
		self.logger = FileLogger(LOGS_DIR, "audit_run")
		self.append_log(f"Opening workbook: {self.audit_path.get()}")
		self.append_log(f"Build type for this audit: {self.build_type_value.get()}")
		self.append_log(f"Session log file: {self.logger.get_path()}")
		threading.Thread(target=self._worker, daemon=True).start()

	def start_quick_audit(self):
		"""Run the quick-audit pipeline: file picker -> VM prompt -> local+VM scan."""
		selected_path = filedialog.askopenfilename(
			title="Quick Audit Scan - Select XLSX Checklist",
			filetypes=[("Excel files", "*.xlsx *.xlsm"), ("All files", "*.*")],
		)
		if not selected_path:
			return

		try:
			workbook_service = AuditWorkbookService(selected_path)
			workbook_service.detect_header_row()
			workbook_service.build_column_map()
			target_columns = workbook_service.target_columns or default_target_columns()
			self._apply_detected_schema(target_columns, workbook_service.build_type)
		except Exception as exc:
			messagebox.showerror("Quick Audit Scan", f"Unable to parse selected workbook:\n{exc}")
			return

		quick_details = self._prompt_quick_audit_vm_details(target_columns)
		if not quick_details:
			return

		timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
		source_stem = Path(selected_path).stem
		quick_output = AUDIT_CHECKLIST_DIR.parent / "Audit Results" / f"quick_audit_scan_{source_stem}_{timestamp}.xlsx"

		self.audit_path.set(selected_path)
		self.output_path.set(str(quick_output))
		self.connection_mode.set("vSphere")
		self.show_ssh_settings.set(False)

		vcenter = quick_details["vcenter"]
		guest = quick_details["guest"]
		self.vcenter_server.set(vcenter["server"])
		self.vcenter_username.set(vcenter["username"])
		self.vcenter_password.set(vcenter["password"])
		self.guest_username.set(guest["username"])
		self.guest_password.set(guest["password"])

		self._audit_profile_override = {
			"profile_name": "quick_audit_scan",
			"build_type": self.build_type_value.get(),
			"target_schema": {
				"source_path": selected_path,
				"target_columns": list(target_columns),
				"build_type": self.build_type_value.get(),
			},
			"targets": quick_details["targets"],
		}
		self._audit_mode_label = "quick_audit_scan"

		self.run_button.configure(state="disabled")
		self.quick_run_button.configure(state="disabled")
		self.probe_button.configure(state="disabled")
		self.progress_var.set(0)
		self.set_status("Status: Running Quick Audit Scan")
		self.logger = FileLogger(LOGS_DIR, "quick_audit_scan")
		self.append_log("Quick Audit Scan started.")
		self.append_log(f"Selected workbook: {selected_path}")
		self.append_log(f"Output workbook: {quick_output}")
		self.append_log(f"Session log file: {self.logger.get_path()}")
		threading.Thread(target=self._worker, daemon=True).start()

	def start_probe(self):
		"""Start a pre-audit connection probe."""
		self.run_button.configure(state="disabled")
		self.quick_run_button.configure(state="disabled")
		self.probe_button.configure(state="disabled")
		self.set_status("Status: Probing remote connection...")
		self.logger = FileLogger(LOGS_DIR, "audit_probe")
		self.append_log(f"Probe log file: {self.logger.get_path()}")
		self.append_log("Starting pre-audit connection probe...")
		threading.Thread(target=self._probe_worker, daemon=True).start()

	def _probe_worker(self):
		"""Run a connection probe for the selected connection mode."""
		service = None
		try:
			mode = normalize_text(self.connection_mode.get()).lower()
			if mode == "local scan only":
				self.after(0, lambda: self.append_log("Local Scan Only mode selected; remote probe skipped."))
				self.after(0, lambda: self.set_status("Status: Probe complete"))
				return
			if mode == "ssh tunnel":
				if not PARAMIKO_AVAILABLE:
					raise RuntimeError("paramiko is not installed. Install with: pip install paramiko")
				if not self.guest_username.get().strip() or not self.guest_password.get():
					raise ValueError("Target SSH username/password are required for SSH probe.")

				ssh_service = SSHTunnelService(
					target_username=self.guest_username.get().strip(),
					target_password=self.guest_password.get(),
					target_port=self._parse_int(self.ssh_target_port.get(), 22),
					gateway_host=self.ssh_gateway_host.get().strip(),
					gateway_username=self.ssh_gateway_username.get().strip(),
					gateway_password=self.ssh_gateway_password.get(),
					gateway_port=self._parse_int(self.ssh_gateway_port.get(), 22),
				)
				profile = self.profile_service.load_profile(self.profile_name.get().strip())
				target_names = self._resolve_target_names(profile)
				mapped_hosts = [
					normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
					for name in target_names
				]
				mapped_hosts = sorted({host for host in mapped_hosts if host and host.upper() != LOCAL_SENTINEL})
				if not mapped_hosts:
					self.after(0, lambda: self.append_log("Probe note | No non-local mapped hosts found in profile."))
				else:
					self.after(0, lambda: self.append_log(f"SSH probe start | targets={len(mapped_hosts)}"))
					for host in mapped_hosts:
						status, output, details = ssh_service.run_powershell(host, "$env:COMPUTERNAME")
						self.after(0, lambda host=host, status=status, output=output, details=details: self.append_log(f"Probe target | host={host} | status={status} | output={output} | details={details}"))
			else:
				server = self.vcenter_server.get().strip()
				username = self.vcenter_username.get().strip()
				password = self.vcenter_password.get()
				if not server:
					raise ValueError("vCenter server is required for probe.")
				if not username or not password:
					raise ValueError("vCenter username/password are required for probe.")

				self.after(0, lambda: self.append_log(f"Connecting to vCenter: {server}"))
				service = VSphereService(server, username, password, True)
				service.connect()
				vm_inventory = service.list_windows_vms()
				self.after(0, lambda: self.append_log(f"vCenter probe PASS | reachable=True | inventory_count={len(vm_inventory)}"))

				try:
					profile = self.profile_service.load_profile(self.profile_name.get().strip())
					target_names = self._resolve_target_names(profile)
					mapped_vm_names = [
						normalize_text(profile.get("targets", {}).get(name, {}).get("vm_name", ""))
						for name in target_names
					]
					mapped_vm_names = [name for name in mapped_vm_names if name and name.upper() != LOCAL_SENTINEL]
					if mapped_vm_names:
						report = service.verify_vm_names(mapped_vm_names)
						for vm_name, info in report.items():
							self.after(
								0,
								lambda vm_name=vm_name, info=info: self.append_log(
									f"Probe target | vm={vm_name} | power={info['power_state']} | tools={info['tools_status']} | guest={info['guest_os']}"
								),
							)
					else:
						self.after(0, lambda: self.append_log("Probe note | No non-local mapped VM names found in profile."))
				except Exception as exc:
					self.after(0, lambda: self.append_log(f"Probe warning | Could not load/verify profile mappings: {exc}"))

			self.after(0, lambda: self.set_status("Status: Probe complete"))
		except Exception as exc:
			self.logger.write_exception(exc)
			self.after(0, lambda: self.append_log(f"Probe failed: {exc}"))
			self.after(0, lambda: self.set_status("Status: Probe failed"))
		finally:
			if service is not None:
				try:
					service.disconnect()
				except Exception:
					pass
			self.after(0, lambda: self.run_button.configure(state="normal"))
			self.after(0, lambda: self.quick_run_button.configure(state="normal"))
			self.after(0, self._on_connection_mode_changed)

	def _worker(self):
		"""Execute the main audit workflow on a worker thread."""
		started_at = datetime.now().isoformat(timespec="seconds")
		rows: List[AuditRow] = []
		results: List[ScanResult] = []
		source_audit_path = self.audit_path.get().strip()
		normalized_audit_path = source_audit_path
		normalized_from_fallback = False
		temp_json_path = ""
		temp_xlsx_path = ""
		job_id = ""

		def build_scan_job_payload(status: str, error_message: str = "") -> Dict[str, Any]:
			"""Build the scan-job JSON payload for the current run."""
			selected_profile_name = "quick_audit_scan" if self._audit_profile_override is not None else self.profile_name.get().strip()
			pipeline_payload, pipeline_source, pipeline_ref = self._resolve_pipeline_for_profile(selected_profile_name)
			row_by_index = {row.row_index: row for row in rows}

			parsed_rows: List[Dict[str, Any]] = []
			special_path_list: List[Dict[str, Any]] = []
			for row in rows:
				rule, _payload = VersionRuleResolver.detect_rule(row.version_locations)
				detection_commands = LocalWindowsScanner.describe_local_detection_commands(
					row.software_component,
					row.version_locations,
				)
				marked_targets = [name for name, mark in row.target_vms.items() if normalize_text(mark).upper() == "X"]
				parsed_entry = {
					"worksheet_row": row.row_index,
					"software_component": row.software_component,
					"current_ci_version": row.current_ci_version,
					"sbl_build_version": row.sbl_build_version,
					"version_locations": row.version_locations,
					"rule": rule,
					"marked_targets": marked_targets,
					"local_detection_commands": detection_commands,
				}
				parsed_rows.append(parsed_entry)
				if rule != "programs_and_features":
					special_path_list.append(parsed_entry)

			local_results: List[Dict[str, Any]] = []
			for result in results:
				if result.target_name != "LOCAL_MACHINE":
					continue
				source_row = row_by_index.get(result.worksheet_row)
				local_results.append(
					{
						"worksheet_row": result.worksheet_row,
						"software_component": result.software_component,
						"expected_version": result.expected_version,
						"found_version": result.found_version,
						"status": result.status,
						"audit_text": result.audit_text,
						"details": result.details,
						"version_locations": source_row.version_locations if source_row else "",
						"local_detection_commands": LocalWindowsScanner.describe_local_detection_commands(
							result.software_component,
							source_row.version_locations if source_row else "",
						) if source_row else [],
					}
				)

			local_summary = {
				"total": len(local_results),
				"pass": sum(1 for item in local_results if item["status"] == "PASS"),
				"fail": sum(1 for item in local_results if item["status"] == "FAIL"),
				"warn": sum(1 for item in local_results if item["status"] == "WARN"),
			}

			audit_path_value = self.audit_path.get().strip()
			output_path_value = self.output_path.get().strip()
			baseline_name = rows[0].sbl_build_version if rows else ""

			return {
				"job_id": job_id,
				"status": status,
				"started_at": started_at,
				"completed_at": datetime.now().isoformat(timespec="seconds"),
				"error": error_message,
				"sbl_file": {
					"name": Path(audit_path_value).name if audit_path_value else "",
					"path": audit_path_value,
					"normalized_path": normalized_audit_path,
					"baseline_name": baseline_name,
					"timestamp": datetime.now().isoformat(timespec="seconds"),
					"sbl_model": _get_sbl_model_from_workbook(audit_path_value) if audit_path_value else "UNKNOWN",
				},
				"output": {
					"workbook_path": output_path_value,
					"result_base_name": Path(output_path_value).stem if output_path_value else "audit_results",
				},
				"settings": {
					"profile_name": selected_profile_name,
					"audit_mode": self._audit_mode_label,
					"build_type": self.build_type_value.get(),
					"connection_mode": normalize_text(self.connection_mode.get()),
					"local_only": normalize_text(self.connection_mode.get()).lower() == "local scan only",
					"fallback_enabled": bool(self.show_ssh_settings.get()) and normalize_text(self.connection_mode.get()).lower() != "local scan only",
					"vcenter_server": self.vcenter_server.get().strip(),
					"ssh_gateway_host": self.ssh_gateway_host.get().strip(),
					"ssh_gateway_port": self._parse_int(self.ssh_gateway_port.get(), 22),
					"ssh_target_port": self._parse_int(self.ssh_target_port.get(), 22),
					"pipeline_established": bool(pipeline_payload),
					"pipeline_source": pipeline_source,
					"pipeline_reference": pipeline_ref,
					"pipeline_input_source": normalize_text(pipeline_payload.get("input_source", "")) if pipeline_payload else "",
					"pipeline_output_action": normalize_text(pipeline_payload.get("output_action", "")) if pipeline_payload else "",
				},
				"sbl_parse": {
					"target_columns": list(self.detected_target_columns),
					"row_count": len(parsed_rows),
					"rows": parsed_rows,
					"special_path_scan_list": special_path_list,
				},
				"local_machine_scan": {
					"results": local_results,
					"comparison_summary": local_summary,
				},
			}

		try:
			template_service = TemplateAssetService()
			try:
				workbook_service = AuditWorkbookService(source_audit_path)
				if workbook_service.repaired_file_path:
					self.after(0, lambda: self.append_log(f"Recovered workbook during load: {workbook_service.repaired_file_path}"))
				workbook_service.detect_header_row()
				workbook_service.build_column_map()
			except Exception as parse_exc:
				self.after(0, lambda error_text=str(parse_exc): self.append_log(f"Primary workbook parse failed: {error_text}"))
				self.after(0, lambda: self.append_log("Attempting fallback normalization for non-standard workbook format..."))

				def fallback_debug_logger(message: str) -> None:
					"""Forward universal-parser debug messages into the UI log."""
					self.after(0, lambda msg=message: self.append_log(msg))

				import_rows = read_software_list_universal_rows(
					source_audit_path,
					debug_logger=fallback_debug_logger,
				)

				if not import_rows:
					raise ValueError("Fallback normalization found no data rows")

				with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as temp_json:
					temp_json_path = temp_json.name
					json.dump(import_rows, temp_json, indent=2)
				with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as temp_xlsx:
					temp_xlsx_path = temp_xlsx.name

				template_service.import_list_to_sbl_workbook(temp_json_path, temp_xlsx_path)

				workbook_service = AuditWorkbookService(temp_xlsx_path)
				workbook_service.detect_header_row()
				workbook_service.build_column_map()
				normalized_audit_path = temp_xlsx_path
				normalized_from_fallback = True
				self.after(0, lambda path=temp_xlsx_path: self.append_log(f"Fallback normalization succeeded: {path}"))

			if workbook_service.repaired_file_path:
				self.after(0, lambda: self.append_log(f"Recovered workbook during load: {workbook_service.repaired_file_path}"))
			rows = workbook_service.iter_audit_rows()
			self.after(0, lambda cols=list(workbook_service.target_columns), build_type=workbook_service.build_type: self._apply_detected_schema(cols, build_type))
			self.after(0, lambda: self.append_log(f"Detected format with {workbook_service.sbl_build_header} and {workbook_service.audit_header}. Rows to process: {len(rows)}"))
			processed = {"count": 0}

			def logger(msg: str):
				"""Forward engine log messages into the UI and progress bar."""
				if msg.startswith("Scanning "):
					processed["count"] += 1
				total = max(1, len(rows))
				self.after(0, lambda p=min(100, (processed['count'] / total) * 100): self.progress_var.set(p))
				self.after(0, lambda m=msg: self.append_log(m))

			if self._audit_profile_override is not None:
				vm_profile = copy.deepcopy(self._audit_profile_override)
				self.after(0, lambda: self.append_log("Using quick-audit target mapping from dialog input."))
			else:
				if normalize_text(self.connection_mode.get()).lower() == "local scan only":
					vm_profile = {"targets": {}}
				else:
					vm_profile = self.profile_service.load_profile(self.profile_name.get().strip())
			vcenter_server = self.vcenter_server.get().strip()
			mode = normalize_text(self.connection_mode.get()).lower()
			if mode == "local scan only":
				vm_profile = self._coerce_local_only_profile(vm_profile, workbook_service.target_columns)
				self.after(0, lambda: self.append_log("Local-only scan enabled; all targets set to __LOCAL__."))
			elif mode != "ssh tunnel" and not vcenter_server:
				vm_profile = self._coerce_local_only_profile(vm_profile, workbook_service.target_columns)
				self.after(0, lambda: self.append_log("No vCenter server configured; forcing local-only scan mode (__LOCAL__) for all targets."))
			engine = AuditEngine(
				workbook_service,
				logger,
				vm_profile,
				{"server": vcenter_server, "username": self.vcenter_username.get().strip(), "password": self.vcenter_password.get()},
				{"username": self.guest_username.get().strip(), "password": self.guest_password.get()},
				connection_mode=normalize_text(self.connection_mode.get()),
				ssh_config={
					"gateway_host": self.ssh_gateway_host.get().strip(),
					"gateway_port": self._parse_int(self.ssh_gateway_port.get(), 22),
					"gateway_username": self.ssh_gateway_username.get().strip(),
					"gateway_password": self.ssh_gateway_password.get(),
					"target_port": self._parse_int(self.ssh_target_port.get(), 22),
				},
				ssh_fallback_enabled=bool(self.show_ssh_settings.get()) and mode != "local scan only",
			)

			base_name = Path(self.output_path.get().strip()).stem or "audit_results"
			try:
				registry_snapshot = engine.local_scanner.capture_registry_snapshot()
				registry_snapshot_path = JsonExportService.write_registry_snapshot_json(base_name, registry_snapshot)
				snapshot_status = normalize_text(registry_snapshot.get("status", "unknown"))
				snapshot_count = int(registry_snapshot.get("entry_count", 0) or 0)
				self.after(
					0,
					lambda path=registry_snapshot_path, status=snapshot_status, count=snapshot_count: self.append_log(
						f"Registry snapshot written: {path} | status={status} | entries={count}"
					),
				)
			except Exception as snapshot_exc:
				self.after(0, lambda error_text=str(snapshot_exc): self.append_log(f"Registry snapshot failed: {error_text}"))

			results = engine.run()
			workbook_service.save_as(self.output_path.get().strip())
			sbl_model = _get_sbl_model_from_workbook(normalized_audit_path)
			latest_sbl = template_service.update_latest_sbl(self.output_path.get().strip())
			latest_master = template_service.snapshot_current_master_to_latest(sbl_model=sbl_model)
			json_path = JsonExportService.write_result_json(Path(self.output_path.get()).stem, {"audit_workbook": self.audit_path.get(), "normalized_audit_workbook": normalized_audit_path if normalized_from_fallback else self.audit_path.get(), "saved_workbook": self.output_path.get(), "profile_name": self.profile_name.get().strip(), "generated_at": datetime.now().isoformat(timespec="seconds"), "results": [asdict(result) for result in results]})
			scan_job_json_path = JsonExportService.write_scan_job_json(
				Path(self.output_path.get()).stem,
				build_scan_job_payload("completed"),
			)
			summary = self.build_summary(results)
			self.after(0, lambda: self.append_log(summary))
			self.after(0, lambda: self.append_log(f"Saved audited workbook: {self.output_path.get()}"))
			self.after(0, lambda: self.append_log(f"Result JSON written: {json_path}"))
			self.after(0, lambda: self.append_log(f"Scan job JSON written: {scan_job_json_path}"))
			self.after(0, lambda: self.append_log(f"Updated latest SBL snapshot: {latest_sbl}"))
			self.after(0, lambda: self.append_log(f"Updated latest master software list snapshot: {latest_master}"))
			self.after(0, lambda: self.progress_var.set(100))
			self.after(0, lambda: self.set_status("Status: Complete"))
		except Exception as exc:
			self.logger.write_exception(exc)
			self.after(0, lambda: self.append_log(f"ERROR: {exc}"))
			try:
				scan_job_json_path = JsonExportService.write_scan_job_json(
					Path(self.output_path.get()).stem,
					build_scan_job_payload("failed", error_message=str(exc)),
				)
				self.after(0, lambda: self.append_log(f"Scan job JSON written (failed run): {scan_job_json_path}"))
			except Exception as scan_job_exc:
				self.after(0, lambda: self.append_log(f"Scan job JSON write failed: {scan_job_exc}"))
			self.after(0, lambda: self.set_status("Status: Failed"))
		finally:
			if temp_json_path:
				try:
					Path(temp_json_path).unlink(missing_ok=True)
				except Exception:
					pass
			if temp_xlsx_path:
				try:
					Path(temp_xlsx_path).unlink(missing_ok=True)
				except Exception:
					pass
			self.after(0, lambda: self.run_button.configure(state="normal"))
			self.after(0, lambda: self.quick_run_button.configure(state="normal"))
			self.after(0, self._on_connection_mode_changed)
			self._audit_profile_override = None
			self._audit_mode_label = "standard"

	@staticmethod
	def build_summary(results: List[ScanResult]) -> str:
		"""Build a short pass/fail summary for the completed audit run."""
		passed = sum(1 for r in results if r.status == "PASS")
		failed = sum(1 for r in results if r.status == "FAIL")
		warned = sum(1 for r in results if r.status == "WARN")
		failed_higher = sum(1 for r in results if r.status == "FAIL" and "result=HIGHER_THAN_EXPECTED" in (r.audit_text or ""))
		failed_lower = sum(1 for r in results if r.status == "FAIL" and "result=LOWER_THAN_EXPECTED" in (r.audit_text or ""))
		failed_other = max(0, failed - failed_higher - failed_lower)

		return (
			f"Summary | Total target checks: {len(results)} | PASS: {passed} | FAIL: {failed} | WARN: {warned}\n"
			f"FAIL breakdown | HIGHER_THAN_EXPECTED: {failed_higher} | LOWER_THAN_EXPECTED: {failed_lower} | OTHER_FAIL: {failed_other}"
		)


__all__ = ["BaseFrame", "HomeFrame", "ProfileFrame", "ChecklistFrame", "AuditFrame"]
