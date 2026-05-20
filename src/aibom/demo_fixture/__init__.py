"""Tiny built-in fixture used by ``aibom demo``.

This package ships a self-contained mini-repo (code + manifests + IaC +
Helm + MLflow run) that exercises every major detector layer. Resolved
at runtime via ``importlib.resources`` so it works both from source and
from a wheel install.
"""

from __future__ import annotations

__all__: list[str] = []
