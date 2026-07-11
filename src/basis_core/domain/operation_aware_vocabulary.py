"""
basis_core.domain.operation_aware_vocabulary — shared closed/open vocabulary
value objects for the operation-aware (v0.2.0) evaluation surface.

This module is the first production code added under `src/basis_core/` for
`basis-core` v0.2.0 (see
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 2,
PR 5 — "Shared vocabulary value objects"). It implements only the two
vocabulary primitives every later operation-aware model (evidence
references, request/response, trace/audit evidence, policy rules) is
expected to depend on:

  RedactionClassification   A closed, five-value enum classifying how a
                             piece of evidence may appear in a trace, audit,
                             or explanation artifact. Published by
                             `basis-schemas` v0.2.0's `redaction-classification`
                             contract (ADR-0003 §10).
  ReasonCode                A validated, machine-readable string token —
                             lowercase snake_case, non-empty. Published by
                             `basis-schemas` v0.2.0's `reason-code` contract
                             (ADR-0003 §12; policy/rule model §13) as a
                             *format*, deliberately not a closed enum: this
                             contract does not enumerate a fixed vocabulary
                             of codes, only the shape a code must satisfy.

Both types are immutable, have deterministic equality/hashing/repr, perform
explicit validation with no silent coercion, and have no I/O, no protocol- or
identity-provider-specific dependencies, and no YAML-loading dependency. They
do not implement redaction behavior, reason-code semantics, or any evaluation
logic — vocabulary only, per the roadmap's Milestone 2 scope.

Not implemented by this module (deferred to later, separately-scoped roadmap
PRs): evidence-reference models (PR 6), operation-aware context value objects
(PR 7), the operation-aware request/response models (PR 8-10, Milestone 10),
any policy or condition model (Milestone 4+), and any specific reason-code
*vocabulary* (which concrete codes `basis-core` emits is decided incrementally
as evaluation stages are implemented, not here).

Public API status: internal to the operation-aware package for now. Not
re-exported from `basis_core.domain` or any other package `__init__.py`;
see `docs/public-api.md`'s "Open API questions" convention and Section 6 of
the roadmap plan for when operation-aware symbols are expected to graduate
to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations

import re
from enum import Enum

_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)*$")


class RedactionClassification(str, Enum):
    """
    The five redaction classifications evidence is sorted into before it may
    appear in a trace, audit, or explanation artifact.

    Closed vocabulary — per `basis-schemas` v0.2.0's `redaction-classification`
    contract (ADR-0003 §10), adding a sixth classification requires an
    architecture decision in `basis-architecture`, not a change made here.

    SAFE_TO_EXPOSE        May appear in appropriately authorized views
                          without additional content redaction (e.g. a
                          matched rule ID or reason code). Does not mean the
                          value is public — normal access controls still
                          apply to whatever view carries it.
    SAFE_AFTER_REDACTION  May be retained or displayed only after
                          deterministic redaction/minimization has removed
                          sensitive content.
    REFERENCE_ONLY        The raw value must not be duplicated into
                          trace/audit/explanation artifacts; a stable
                          identifier, hash, or reference must be used
                          instead.
    NEVER_STORE           Must not be persisted in any evidence artifact,
                          even in redacted form — no redaction makes it safe.
    NEVER_DISPLAY         Must never be rendered in a human-facing view.
                          Distinct from NEVER_STORE: a NEVER_DISPLAY value
                          may still exist in a durable record for a narrow
                          non-display purpose (e.g. cryptographic
                          verification).
    """

    SAFE_TO_EXPOSE = "safe_to_expose"
    SAFE_AFTER_REDACTION = "safe_after_redaction"
    REFERENCE_ONLY = "reference_only"
    NEVER_STORE = "never_store"
    NEVER_DISPLAY = "never_display"


class ReasonCode(str):
    """
    A validated, machine-readable reason code token.

    Structural format only — per `basis-schemas` v0.2.0's `reason-code`
    contract, this is deliberately not a closed enum. A string is a
    well-formed `ReasonCode` if and only if it is non-empty and matches
    ``^[a-z][a-z0-9]*(_[a-z0-9]+)*$``: a lowercase letter, followed by
    lowercase letters or digits, optionally repeated groups of a single
    underscore followed by one or more lowercase letters or digits. No
    leading digit, no uppercase, no hyphen, no colon, no leading, trailing,
    or doubled underscore.

    `ReasonCode` is a `str` subclass so it behaves like an ordinary string
    (equality, hashing, sorting, f-string/JSON serialization) while
    guaranteeing every instance in existence has already passed format
    validation — there is no way to construct an invalid `ReasonCode`.

    This class does not define, enumerate, or imply any specific reason-code
    *vocabulary* — that remains this repository's own incremental decision as
    evaluation stages are implemented (see the roadmap plan, Section 3, row
    "reason codes").
    """

    def __new__(cls, value: str) -> ReasonCode:
        if not isinstance(value, str):
            raise TypeError(f"ReasonCode value must be a string, got {type(value).__name__}.")
        if value == "":
            raise ValueError("ReasonCode must not be empty.")
        if not _REASON_CODE_RE.match(value):
            raise ValueError(
                f"ReasonCode {value!r} does not match the required pattern "
                r"'^[a-z][a-z0-9]*(_[a-z0-9]+)*$' (lowercase snake_case, no "
                "leading digit, no hyphen, no colon, no leading/trailing/"
                "doubled underscore)."
            )
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"ReasonCode({str.__str__(self)!r})"
