"""
basis_core.domain — canonical types for subjects, resources, and actions.

Design constraints
──────────────────
- This package has NO imports from other basis_core subpackages.
- It is the base of the import graph. All other packages may import from here.
- Types here are immutable value objects. No I/O, no network, no side effects.

Contents
────────
  subject.py   Subject identity — who or what is performing an action.
  resource.py  Resource descriptor — what is being acted upon.
  action.py    Action vocabulary — what operation is being requested.
  identity.py  Identity context — verified claims carried across trust boundaries.

Public API
──────────
All stable public symbols are available directly from this package.
The ``action`` sub-module is re-exported as a module object; import it
directly (``from basis_core.domain import action``) to access constants.
See ``docs/public-api.md`` for the full inventory and stability tiers.
"""

from basis_core.domain import action
from basis_core.domain.identity import IdentityContext
from basis_core.domain.resource import (
    Resource,
    ResourceType,
    build_resource_id,
    parse_resource_id,
)
from basis_core.domain.subject import Subject, SubjectType, subject_from_jwt

__all__ = [
    # subject
    "Subject",
    "SubjectType",
    "subject_from_jwt",
    # resource
    "Resource",
    "ResourceType",
    "build_resource_id",
    "parse_resource_id",
    # identity
    "IdentityContext",
    # action vocabulary (module re-export)
    "action",
]
