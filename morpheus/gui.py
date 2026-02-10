"""
GUI entry point — delegates to the wizard UI.

Kept as a thin shim so that ``from morpheus.gui import run_gui`` and
the existing ``morpheus/__main__.py`` continue to work unchanged.
"""

from __future__ import annotations

from .ui.app import MorpheusWizard, run_gui

__all__ = ["MorpheusWizard", "run_gui"]
