"""
basis_core.policy.operation_aware — operation-aware policy data models.

This package holds the operation-aware v0.2.0 policy *data* models
(`docs/implementation/basis-core-v0.2-operation-aware-plan.md`, Milestone 4:
"Policy Domain Model and Semantic Validation"). It is a sibling to the
existing v0.1.0 `basis_core.policy` package (`engine.py`, `rules.py`), not a
replacement for it — the v0.1.0 `PolicyEngine`/`PolicyRule` Protocol/rule
implementations are unaffected by anything added here.

Contents
────────
  condition.py   `PolicyCondition` — the operation-aware condition data
                 model published by `basis-schemas` v0.2.0's
                 `policy-condition` contract (PR 12). Inert structural data
                 only: no condition evaluation, no operator registry, no
                 operator whitelist, no field-path resolution.
  rule.py        `OperationAwarePolicyRule`, `OperationAwarePolicyMatch`,
                 `RuleEffect` — the operation-aware rule data model
                 published by `basis-schemas` v0.2.0's `policy-rule`
                 contract (PR 13). Inert structural data only: no rule
                 matching, no condition evaluation, no deny precedence,
                 no bundle-level behavior. Deliberately named
                 `OperationAwarePolicyRule`, not `PolicyRule`, to avoid
                 colliding with the existing v0.1.0 `PolicyRule` Protocol
                 re-exported from `basis_core.policy` — that import
                 remains unchanged.
  bundle.py      `PolicyBundle`, `PolicyBundleScope` — the operation-aware
                 policy bundle data model published by `basis-schemas`
                 v0.2.0's `policy-bundle` contract (PR 14): the unit of
                 policy identity, versioning, ownership, provenance,
                 optional applicability scope, and rule grouping. Inert
                 structural data only: no bundle evaluation and no scope-
                 to-request applicability determination (PR 17). Does not
                 itself reject duplicate `rule_id` values across `rules` —
                 that is `validation.py`'s explicit responsibility. No
                 `validation_status` field exists; see `bundle.py`'s
                 docstring.
  validation.py  `PolicyBundleValidationError`, `StructuralPolicyValidation
                 Error`, `SemanticPolicyValidationError`,
                 `DuplicateRuleIdError`, `DuplicateConditionIdError`,
                 `validate_policy_bundle()` — the explicit `PolicyBundle`
                 structural/semantic validation pipeline (PR 15):
                 structural failures (malformed shape, wrapped from
                 `pydantic.ValidationError` with the original preserved as
                 `__cause__`) are distinguished from semantic failures
                 (duplicate `rule_id` across `bundle.rules`; duplicate
                 `condition_id` within one rule). `validate_policy_bundle`
                 is invoked *before* any evaluation entry point exists, so
                 an invalid bundle can never reach evaluation and can
                 never produce `ALLOW` — see `validation.py`'s own
                 docstring for the full rationale, including how it
                 relates to PR 13's own rule-level `condition_id`
                 uniqueness check. No evaluation, applicability, or
                 evaluation-result concept is implemented here.

These models are policy *data*, not policy *evaluation*. `validation.py`'s
structural/semantic validation pipeline (PR 15) validates policy *data*,
not policy *decisions* — it returns a validated `PolicyBundle`, never an
authorization result.

  selector.py    `evaluate_rule_selectors()`, `select_candidate_rules()` —
                 deterministic structural `match`-criteria evaluation
                 (Milestone 6, PR 19-20). Does not evaluate `conditions`;
                 a rule whose structural match is satisfied but which still
                 carries conditions is reported `not_matched` with
                 `conditions_pending=True`, never a premature `matched`.
  operators.py   `ConditionResult`, `ConditionEvaluation`,
                 `evaluate_condition()` — the approved, finite
                 ten-operator condition registry and standalone
                 `PolicyCondition` evaluation (Milestone 7, PR 22),
                 implementing exactly the `basis-architecture`-approved
                 clarification named in Section 8 of the roadmap plan.
                 Evaluates one condition against one
                 `OperationAwareDecisionRequest` only — rule-level
                 condition-array iteration and aggregation, selector
                 integration, and trace evidence remain PR 23 and later,
                 separately-scoped work.
  condition_eval.py  `RuleConditionResult`, `RuleConditionEvaluation`,
                 `evaluate_rule_conditions()` — rule-level condition
                 evaluation integration (Milestone 7, PR 23): combines
                 `selector.py`'s structural match classification with
                 `operators.py`'s standalone per-condition evaluation into
                 one ordered, bounded, rule-level result. Evaluates every
                 authored condition in array order, in full, for a
                 structurally matched rule with conditions pending; never
                 evaluates conditions for a structurally nonmatching rule.
                 Does not construct `TraceRuleEvidence`, does not import
                 `basis_core.audit`, and does not implement rule effects,
                 deny precedence, or any final authorization outcome —
                 those remain Milestone 8 and Milestone 9 onward,
                 separately-scoped work.

Public API status: internal for now, exactly like every other
operation-aware module added so far (`domain.operation_aware_vocabulary`,
`domain.evidence`, `domain.operation_aware`, `decisions.operation_aware`).
Not re-exported from `basis_core.policy` or any other package
`__init__.py`; see `docs/public-api.md`'s "Open API questions" convention
and Section 6 of the roadmap plan for when operation-aware symbols are
expected to graduate to the stable public API (Milestone 11, PR 35).
"""

from __future__ import annotations
