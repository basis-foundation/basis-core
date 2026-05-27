"""
basis_core.api — DEPRECATED. Use basis_core.enforcement instead.

This package is a deprecated namespace stub scheduled for removal after v0.1.
Importing from it will emit a DeprecationWarning. Switch to the canonical path:

    from basis_core.enforcement import EnforcementPoint
"""

import warnings

warnings.warn(
    "basis_core.api is deprecated and will be removed in a future release. "
    "Use basis_core.enforcement instead: "
    "from basis_core.enforcement import EnforcementPoint",
    DeprecationWarning,
    stacklevel=2,
)
