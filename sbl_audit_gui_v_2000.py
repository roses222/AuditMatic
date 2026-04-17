"""Compatibility shim for the archived legacy GUI module."""

from legacy.sbl_audit_gui_v_2000 import *  # noqa: F401,F403


if __name__ == "__main__":
    import runpy

    runpy.run_module("legacy.sbl_audit_gui_v_2000", run_name="__main__")
