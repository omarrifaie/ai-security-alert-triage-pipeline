"""AI Security Alert Triage Pipeline.

Public package surface intentionally narrow: callers should use the
submodules (``parser``, ``triage``, ``db``, ``dashboard``) directly.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ai-security-alert-triage-pipeline")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = ["__version__"]
