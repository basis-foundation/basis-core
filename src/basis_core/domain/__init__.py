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
"""
