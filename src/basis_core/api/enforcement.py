"""
basis_core.api.enforcement — DEPRECATED. Use basis_core.enforcement instead.

This module is a deprecated stub scheduled for removal after v0.1.
Importing from it will emit a DeprecationWarning. Switch to the canonical path:

    from basis_core.enforcement import EnforcementPoint
    # or
    from basis_core.enforcement.enforcement import EnforcementPoint
"""

import warnings

warnings.warn(
    "basis_core.api.enforcement is deprecated and will be removed in a future release. "
    "Use basis_core.enforcement instead: "
    "from basis_core.enforcement import EnforcementPoint",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export so existing imports continue to function during the deprecation period.
from basis_core.enforcement.enforcement import EnforcementPoint  # noqa: E402

__all__ = ["EnforcementPoint"]
