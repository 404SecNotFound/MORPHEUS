"""
GUI entry point — delegates to the wizard UI.

Kept as a thin shim so that ``from morpheus_crypt.gui import run_gui`` and
the existing ``morpheus_crypt/__main__.py`` continue to work unchanged.
"""

from __future__ import annotations

from .ui.app import MorpheusWizard, run_gui

__all__ = ["MorpheusWizard", "run_gui"]
