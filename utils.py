"""Compatibility shim for utility helpers moved to services.utils.

This shim re-exports both public and legacy underscore-prefixed helpers
because several existing modules import private utility symbols directly.
"""

from services import utils as _utils


for _name in dir(_utils):
	if _name.startswith("__"):
		continue
	globals()[_name] = getattr(_utils, _name)
