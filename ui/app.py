"""Application root window and UI initialization."""

import tkinter as tk
from tkinter import ttk

from config import APP_GEOMETRY, APP_TITLE
from ui.frames import AuditFrame, ChecklistFrame, HomeFrame, PipelineFrame, ProfileFrame
from services.utils import _create_mock_files


class App(tk.Tk):
	"""Application root window."""

	def __init__(self):
		"""Initialize the App instance."""
		super().__init__()
		_create_mock_files()
		self.title(APP_TITLE)
		self.geometry(APP_GEOMETRY)
		self.resizable(True, True)
		self.minsize(800, 600)
		style = ttk.Style(self)
		try:
			style.theme_use("vista")
		except tk.TclError:
			pass
		container = ttk.Frame(self)
		container.pack(fill="both", expand=True)
		container.rowconfigure(0, weight=1)
		container.columnconfigure(0, weight=1)
		self.frames = {}
		for frame_cls in (HomeFrame, ProfileFrame, ChecklistFrame, AuditFrame, PipelineFrame):
			frame = frame_cls(container, self)
			self.frames[frame_cls.__name__] = frame
			frame.grid(row=0, column=0, sticky="nsew")
		self.show_frame("HomeFrame")

	def show_frame(self, name: str) -> None:
		"""Raise a frame by class name."""
		self.frames[name].tkraise()


__all__ = ["App"]
