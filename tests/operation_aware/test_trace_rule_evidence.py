"""
tests/operation_aware/test_trace_rule_evidence.py — tests for
`basis_core.audit.operation_aware.trace_rule_evidence.TraceRuleEvidence`
(Milestone 8, PR 24 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`:
"TraceRuleEvidence model").

Covers `TraceRuleEvidence`/`TraceConditionEvidence`/`TraceRuleEffect`/
`RuleResult`/`TraceConditionResult` construction, validation, immutability,
equality, and serialization round-trip — cross-checked against every
vendored `basis-schemas` v0.2.0 `trace-rule-evidence` contract example (six
valid, twelve invalid) via the existing test-only loader
(`tests/helpers/operation_aware_contracts.py`).

This file tests bounded trace-evidence *shape* only: construction,
validation, immutability, and schema alignment. It does not test, and must
never test, trace assembly, conversion from any internal evaluator result
(`basis_core.policy.operation_aware.condition_eval.RuleConditionEvaluation`
or `basis_core.policy.operation_aware.operators.ConditionEvaluation`),
`EvaluationTrace`, or any evaluation semantics — none of that exists in
this module or this PR. `TestV01Compatibility` is the mandatory,
mechanically-checked proof that `basis_core.audit.trace.RuleEvaluation`
(the existing v0.1.0 type) is unaffected by anything added here.

Does not test any later, not-yet-implemented operation-aware model
(`EvaluationTrace`, `OperationAwareDecisionResponse`, `AuditEvidence`) —
see `tests/operation_aware/README.md`'s scope boundaries.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from basis_core.audit.operation_aware.trace_rule_evidence import (
    RuleResult,
    TraceConditionEvidence,
    TraceRuleEffect,
    TraceRuleEvidence,
)
from tests.helpers.operation_aware_contracts import (
    load_contract,
    require_mapping_field,
    require_sequence_field,
)

# ══════════════════════════════════════════════════════════════════════════
# Fixture loading
# ══════════════════════════════════════════════════════════════════════════


def _trace_rule_evidence_examples() -> tuple[list[object], list[object]]:
    document = load_contract("trace-rule-evidence")
    section = require_mapping_field(document, "trace_rule_evidence", context="trace-rule-evidence")
    examples = require_mapping_field(
        section, "examples", context="trace-rule-evidence.trace_rule_evidence"
    )
    valid = require_sequence_field(examples, "valid", context="trace-rule-evidence.examples")
    invalid = require_sequence_field(examples, "invalid", context="trace-rule-evidence.examples")
    return valid, invalid


_VALID_EXAMPLES, _INVALID_EXAMPLES = _trace_rule_evidence_examples()


def _invalid_example_value(entry: object) -> object:
    if isinstance(entry, dict) and "value" in entry and "reason" in entry:
        return entry["value"]
    return entry


def _invalid_example_reason(entry: object, index: int) -> str:
    if isinstance(entry, dict):
        reason = entry.get("reason")
        if isinstance(reason, str) and reason:
            return reason
    return f"example-{index}"


def _valid_example_id(example: object, index: int) -> str:
    if isinstance(example, dict):
        rule_id = example.get("rule_id")
        if isinstance(rule_id, str) and rule_id:
            return rule_id
    return f"example-{index}"


# A structurally valid record reused across tests that need one but are not
# themselves testing rule_id/effect/rule_result validation.
_VALID_EVIDENCE_KWARGS: dict[str, object] = {
    "rule_id": "rule-operator-read-ahu-telemetry",
    "effect": "allow",
    "rule_result": "matched",
}

_VALID_CONDITION_EVIDENCE_KWARGS: dict[str, object] = {
    "condition_id": "cond-risk-score-high",
    "result": "matched",
}


# ══════════════════════════════════════════════════════════════════════════
# Fixture conformance — every vendored valid/invalid example
# ══════════════════════════════════════════════════════════════════════════


class TestFixtureConformance:
    def test_six_valid_examples_are_vendored(self) -> None:
        # A supplementary count check — the parametrized tests below are
        # the primary completeness mechanism; this only guards against a
        # coincidental simultaneous add+remove in the vendored fixture.
        assert len(_VALID_EXAMPLES) == 6

    def test_twelve_invalid_examples_are_vendored(self) -> None:
        assert len(_INVALID_EXAMPLES) == 12

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_valid_example_constructs(self, example: object) -> None:
        assert isinstance(example, dict)
        evidence = TraceRuleEvidence.model_validate(example)
        assert type(evidence) is TraceRuleEvidence
        if "condition_results" in example:
            assert all(
                type(entry) is TraceConditionEvidence for entry in evidence.condition_results
            )

    @pytest.mark.parametrize(
        "entry",
        _INVALID_EXAMPLES,
        ids=[_invalid_example_reason(ex, i) for i, ex in enumerate(_INVALID_EXAMPLES)],
    )
    def test_invalid_example_is_rejected(self, entry: object) -> None:
        value = _invalid_example_value(entry)
        with pytest.raises(ValidationError):
            TraceRuleEvidence.model_validate(value)

    @pytest.mark.parametrize(
        "example",
        _VALID_EXAMPLES,
        ids=[_valid_example_id(ex, i) for i, ex in enumerate(_VALID_EXAMPLES)],
    )
    def test_all_vendored_valid_examples_round_trip(self, example: object) -> None:
        assert isinstance(example, dict)
        evidence = TraceRuleEvidence.model_validate(example)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        restored = TraceRuleEvidence.model_validate(dumped)
        assert restored == evidence

    def test_matching_allow_example_serializes_expected_shape(self) -> None:
        example = _VALID_EXAMPLES[0]
        assert isinstance(example, dict)
        evidence = TraceRuleEvidence.model_validate(example)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "rule_id": "rule-operator-read-ahu-telemetry",
            "effect": "allow",
            "rule_result": "matched",
            "reason_code": "allow_rule_matched",
            "explanation": "Operator role matched an allow rule for read:ahu.",
        }

    def test_condition_evidence_example_serializes_expected_shape(self) -> None:
        example = _VALID_EXAMPLES[3]
        assert isinstance(example, dict)
        assert example["rule_id"] == "rule-deny-elevated-risk"
        evidence = TraceRuleEvidence.model_validate(example)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "rule_id": "rule-deny-elevated-risk",
            "effect": "deny",
            "rule_result": "matched",
            "condition_results": [
                {
                    "condition_id": "cond-risk-score-high",
                    "result": "matched",
                    "reason_code": "risk_score_above_threshold",
                }
            ],
            "reason_code": "deny_rule_matched",
        }


# ══════════════════════════════════════════════════════════════════════════
# Model configuration
# ══════════════════════════════════════════════════════════════════════════


class TestModelConfiguration:
    def test_evidence_model_is_frozen(self) -> None:
        assert TraceRuleEvidence.model_config.get("frozen") is True

    def test_evidence_model_forbids_extra_fields(self) -> None:
        assert TraceRuleEvidence.model_config.get("extra") == "forbid"

    def test_condition_evidence_model_is_frozen(self) -> None:
        assert TraceConditionEvidence.model_config.get("frozen") is True

    def test_condition_evidence_model_forbids_extra_fields(self) -> None:
        assert TraceConditionEvidence.model_config.get("extra") == "forbid"

    def test_frozen_rejects_attribute_assignment(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        with pytest.raises(ValidationError):
            evidence.rule_id = "other"  # type: ignore[misc]

    def test_only_the_six_published_fields_exist(self) -> None:
        assert set(TraceRuleEvidence.model_fields) == {
            "rule_id",
            "effect",
            "rule_result",
            "condition_results",
            "reason_code",
            "explanation",
        }

    def test_only_the_four_published_condition_fields_exist(self) -> None:
        assert set(TraceConditionEvidence.model_fields) == {
            "condition_id",
            "result",
            "reason_code",
            "explanation",
        }


# ══════════════════════════════════════════════════════════════════════════
# Required fields
# ══════════════════════════════════════════════════════════════════════════


class TestRequiredFields:
    def test_rule_id_effect_rule_result_are_required(self) -> None:
        assert TraceRuleEvidence.model_fields["rule_id"].is_required()
        assert TraceRuleEvidence.model_fields["effect"].is_required()
        assert TraceRuleEvidence.model_fields["rule_result"].is_required()

    def test_condition_results_reason_code_explanation_are_optional(self) -> None:
        for name in ("condition_results", "reason_code", "explanation"):
            assert not TraceRuleEvidence.model_fields[name].is_required(), name

    def test_missing_rule_id_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS)
        del kwargs["rule_id"]
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_missing_effect_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS)
        del kwargs["effect"]
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_missing_rule_result_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS)
        del kwargs["rule_result"]
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_null_rule_id_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS, rule_id=None)
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_null_effect_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS, effect=None)
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_null_rule_result_is_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS, rule_result=None)
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)  # type: ignore[arg-type]

    def test_empty_rule_id_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS, rule_id="")
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)

    def test_whitespace_only_rule_id_rejected(self) -> None:
        kwargs = dict(_VALID_EVIDENCE_KWARGS, rule_id="   ")
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**kwargs)

    def test_missing_condition_id_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceConditionEvidence(result="matched")  # type: ignore[call-arg]

    def test_missing_result_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceConditionEvidence(condition_id="cond-1")  # type: ignore[call-arg]

    def test_empty_condition_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceConditionEvidence(condition_id="", result="matched")


# ══════════════════════════════════════════════════════════════════════════
# effect (TraceRuleEffect)
# ══════════════════════════════════════════════════════════════════════════


class TestRuleEffect:
    @pytest.mark.parametrize("effect", ["allow", "deny"])
    def test_valid_effects_accepted(self, effect: str) -> None:
        evidence = TraceRuleEvidence(rule_id="rule-1", effect=effect, rule_result="matched")
        assert evidence.effect == TraceRuleEffect(effect)

    @pytest.mark.parametrize("effect", ["permit", "reject", "ALLOW", "DENY", "unknown", ""])
    def test_invalid_effects_rejected(self, effect: str) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(rule_id="rule-1", effect=effect, rule_result="matched")

    def test_not_applicable_specifically_rejected_as_bundle_applicability_outcome(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-not-applicable-effect",
                effect="not_applicable",
                rule_result="matched",
            )

    def test_effect_serializes_to_exact_lowercase_contract_value(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        dumped = evidence.model_dump(mode="json")
        assert dumped["effect"] == "allow"
        assert isinstance(dumped["effect"], str)


# ══════════════════════════════════════════════════════════════════════════
# rule_result (RuleResult)
# ══════════════════════════════════════════════════════════════════════════


class TestRuleResult:
    @pytest.mark.parametrize("result", ["matched", "not_matched", "skipped", "error"])
    def test_every_published_value_accepted(self, result: str) -> None:
        evidence = TraceRuleEvidence(rule_id="rule-1", effect="allow", rule_result=result)
        assert evidence.rule_result == RuleResult(result)

    @pytest.mark.parametrize(
        "result", ["passed", "failed", "success", "allow", "deny", "unknown", ""]
    )
    def test_unsupported_values_rejected(self, result: str) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(rule_id="rule-1", effect="allow", rule_result=result)

    @pytest.mark.parametrize("result", ["MATCHED", "Matched", "NOT_MATCHED", "Skipped", "ERROR"])
    def test_case_variants_rejected(self, result: str) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(rule_id="rule-1", effect="allow", rule_result=result)

    def test_rule_result_serializes_exactly(self) -> None:
        evidence = TraceRuleEvidence(rule_id="rule-1", effect="allow", rule_result="skipped")
        dumped = evidence.model_dump(mode="json")
        assert dumped["rule_result"] == "skipped"
        assert isinstance(dumped["rule_result"], str)


# ══════════════════════════════════════════════════════════════════════════
# condition_results
# ══════════════════════════════════════════════════════════════════════════


class TestConditionResults:
    def test_omitted_defaults_to_none(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        assert evidence.condition_results is None

    def test_explicit_null_treated_as_omitted(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, condition_results=None)
        assert evidence.condition_results is None

    def test_explicit_empty_array_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, condition_results=[])

    def test_valid_single_condition_result_accepted(self) -> None:
        evidence = TraceRuleEvidence(
            **_VALID_EVIDENCE_KWARGS, condition_results=[_VALID_CONDITION_EVIDENCE_KWARGS]
        )
        assert len(evidence.condition_results) == 1
        assert type(evidence.condition_results[0]) is TraceConditionEvidence

    def test_invalid_nested_condition_missing_result_rejected(self) -> None:
        malformed = {"condition_id": "cond-missing-result"}
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-1",
                effect="deny",
                rule_result="error",
                condition_results=[malformed],
            )

    def test_unsupported_nested_result_value_rejected(self) -> None:
        malformed = dict(_VALID_CONDITION_EVIDENCE_KWARGS, result="skipped")
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-1", effect="deny", rule_result="error", condition_results=[malformed]
            )

    def test_unknown_nested_field_rejected(self) -> None:
        malformed = dict(_VALID_CONDITION_EVIDENCE_KWARGS, field_path="risk_context.score")
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, condition_results=[malformed])

    def test_multiple_condition_results_preserve_authored_order(self) -> None:
        cond_a = {"condition_id": "cond-a", "result": "matched"}
        cond_b = {"condition_id": "cond-b", "result": "not_matched"}
        cond_c = {"condition_id": "cond-c", "result": "matched"}
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="deny",
            rule_result="not_matched",
            condition_results=[cond_a, cond_b, cond_c],
        )
        assert [c.condition_id for c in evidence.condition_results] == [
            "cond-a",
            "cond-b",
            "cond-c",
        ]

    def test_nested_serialization_matches_published_shape(self) -> None:
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="deny",
            rule_result="matched",
            condition_results=[
                {
                    "condition_id": "cond-a",
                    "result": "matched",
                    "reason_code": "risk_score_above_threshold",
                    "explanation": "Risk score exceeded threshold.",
                }
            ],
        )
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert dumped["condition_results"] == [
            {
                "condition_id": "cond-a",
                "result": "matched",
                "reason_code": "risk_score_above_threshold",
                "explanation": "Risk score exceeded threshold.",
            }
        ]

    def test_condition_id_duplicate_within_one_record_rejected(self) -> None:
        cond_a = {"condition_id": "cond-duplicate", "result": "matched"}
        cond_b = {"condition_id": "cond-duplicate", "result": "not_matched"}
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-1",
                effect="deny",
                rule_result="matched",
                condition_results=[cond_a, cond_b],
            )

    def test_condition_id_unique_across_entries_accepted(self) -> None:
        cond_a = {"condition_id": "cond-a", "result": "matched"}
        cond_b = {"condition_id": "cond-b", "result": "matched"}
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="deny",
            rule_result="matched",
            condition_results=[cond_a, cond_b],
        )
        assert len(evidence.condition_results) == 2

    # No published minimum/maximum item-count bound exists beyond
    # "non-empty when present" (no maxItems is published by the vendored
    # contract) — see this module's docstring; no further bound is tested,
    # per the roadmap's "do not invent stricter behavior than the schema"
    # instruction.


# ══════════════════════════════════════════════════════════════════════════
# condition-error-forces-rule-error invariant
# ══════════════════════════════════════════════════════════════════════════


class TestConditionErrorForcesRuleError:
    def test_condition_error_with_rule_result_error_accepted(self) -> None:
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="deny",
            rule_result="error",
            condition_results=[{"condition_id": "cond-a", "result": "error"}],
        )
        assert evidence.rule_result is RuleResult.ERROR

    def test_condition_error_with_rule_result_matched_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-1",
                effect="deny",
                rule_result="matched",
                condition_results=[{"condition_id": "cond-a", "result": "error"}],
            )

    def test_condition_error_with_rule_result_not_matched_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(
                rule_id="rule-1",
                effect="deny",
                rule_result="not_matched",
                condition_results=[{"condition_id": "cond-a", "result": "error"}],
            )

    def test_no_condition_error_does_not_require_rule_result_error(self) -> None:
        # The inverse relationship is not required by the contract: a rule
        # may be rule_result: error for reasons unrelated to any listed
        # condition_results entry (or with condition_results absent
        # entirely) — this model does not infer or require any such link.
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="deny",
            rule_result="error",
            condition_results=[{"condition_id": "cond-a", "result": "matched"}],
        )
        assert evidence.rule_result is RuleResult.ERROR

    def test_rule_result_skipped_with_condition_results_present_is_not_rejected(self) -> None:
        # The contract does not declare rule_result=skipped combined with a
        # populated condition_results invalid; this model must not invent
        # that cross-field invariant. Trace-assembly honesty about what a
        # given evaluation stage has or has not evaluated is out of this
        # model's scope (Milestone 8's PR 26).
        evidence = TraceRuleEvidence(
            rule_id="rule-1",
            effect="allow",
            rule_result="skipped",
            condition_results=[{"condition_id": "cond-a", "result": "matched"}],
        )
        assert evidence.rule_result is RuleResult.SKIPPED


# ══════════════════════════════════════════════════════════════════════════
# reason_code (rule-level and condition-level)
# ══════════════════════════════════════════════════════════════════════════


class TestReasonCode:
    def test_valid_open_reason_code_accepted(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, reason_code="allow_rule_matched")
        assert evidence.reason_code == "allow_rule_matched"

    def test_structurally_valid_but_not_illustrative_reason_code_accepted(self) -> None:
        # No closed whitelist: any structurally well-formed reason code is
        # accepted, not just the vendored contract's illustrative examples
        # — reason_code is not implemented as a closed enum.
        evidence = TraceRuleEvidence(
            **_VALID_EVIDENCE_KWARGS, reason_code="future_trace_evidence_reason"
        )
        assert evidence.reason_code == "future_trace_evidence_reason"

    def test_malformed_reason_code_uppercase_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, reason_code="ALLOW_RULE_MATCHED")

    def test_malformed_reason_code_hyphenated_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, reason_code="allow-rule-matched")

    def test_missing_reason_code_defaults_to_none(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        assert evidence.reason_code is None

    def test_explicit_null_reason_code_accepted(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, reason_code=None)
        assert evidence.reason_code is None

    def test_condition_level_reason_code_accepts_future_token(self) -> None:
        condition = TraceConditionEvidence(
            condition_id="cond-a", result="matched", reason_code="condition_future_reason"
        )
        assert condition.reason_code == "condition_future_reason"

    def test_condition_level_malformed_reason_code_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceConditionEvidence(condition_id="cond-a", result="matched", reason_code="BAD CODE")


# ══════════════════════════════════════════════════════════════════════════
# explanation (rule-level and condition-level)
# ══════════════════════════════════════════════════════════════════════════


class TestExplanation:
    def test_valid_static_explanation_accepted(self) -> None:
        evidence = TraceRuleEvidence(
            **_VALID_EVIDENCE_KWARGS, explanation="Operators may read AHU telemetry."
        )
        assert evidence.explanation == "Operators may read AHU telemetry."

    def test_empty_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, explanation="")

    def test_whitespace_only_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, explanation="   ")

    def test_missing_explanation_defaults_to_none(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        assert evidence.explanation is None

    def test_explicit_null_explanation_accepted(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, explanation=None)
        assert evidence.explanation is None

    def test_explanation_is_not_template_interpreted(self) -> None:
        # No interpolation mechanism exists; a template-looking string is
        # stored verbatim as opaque text, not executed or substituted.
        text = "Denied because {{subject_id}} lacks clearance."
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, explanation=text)
        assert evidence.explanation == text

    def test_condition_level_explanation_valid(self) -> None:
        condition = TraceConditionEvidence(
            condition_id="cond-a", result="matched", explanation="Risk score exceeded."
        )
        assert condition.explanation == "Risk score exceeded."

    def test_condition_level_empty_explanation_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceConditionEvidence(condition_id="cond-a", result="matched", explanation="")


# ══════════════════════════════════════════════════════════════════════════
# Extra-field rejection and boundedness
# ══════════════════════════════════════════════════════════════════════════


class TestExtraFieldRejectionAndBoundedness:
    def test_unknown_top_level_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, priority=1)  # type: ignore[call-arg]

    def test_unknown_nested_condition_field_rejected(self) -> None:
        malformed = dict(_VALID_CONDITION_EVIDENCE_KWARGS, operator="equals")
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, condition_results=[malformed])

    @pytest.mark.parametrize(
        "field_name",
        [
            "actual_value",
            "expected_value",
            "raw_value",
            "request",
            "rule",
            "match",
            "conditions",
            "claims",
            "token",
            "raw_payload",
            "stack_trace",
        ],
    )
    def test_raw_or_sensitive_field_rejected_as_unknown(self, field_name: str) -> None:
        with pytest.raises(ValidationError):
            TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS, **{field_name: "x"})  # type: ignore[arg-type]

    def test_model_contains_only_published_fields(self) -> None:
        assert set(TraceRuleEvidence.model_fields) == {
            "rule_id",
            "effect",
            "rule_result",
            "condition_results",
            "reason_code",
            "explanation",
        }
        assert set(TraceConditionEvidence.model_fields) == {
            "condition_id",
            "result",
            "reason_code",
            "explanation",
        }


# ══════════════════════════════════════════════════════════════════════════
# Immutability
# ══════════════════════════════════════════════════════════════════════════


class TestImmutability:
    def test_top_level_field_reassignment_rejected(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        with pytest.raises(ValidationError):
            evidence.rule_result = "error"  # type: ignore[misc]

    def test_condition_evidence_field_reassignment_rejected(self) -> None:
        condition = TraceConditionEvidence(**_VALID_CONDITION_EVIDENCE_KWARGS)
        with pytest.raises(ValidationError):
            condition.result = "error"  # type: ignore[misc]


# ══════════════════════════════════════════════════════════════════════════
# v0.1 compatibility — TraceRuleEvidence is separate from RuleEvaluation
# ══════════════════════════════════════════════════════════════════════════


class TestV01Compatibility:
    """Mandatory regression: the existing v0.1.0
    `basis_core.audit.trace.RuleEvaluation` type is untouched by anything
    added in this PR. `TraceRuleEvidence` is a distinct symbol, never
    aliased to `RuleEvaluation`, never a subclass of it, and never exported
    from the same module."""

    def test_rule_evaluation_import_still_resolves(self) -> None:
        from basis_core.audit.trace import RuleEvaluation

        assert RuleEvaluation.__module__ == "basis_core.audit.trace"

    def test_rule_evaluation_fields_unchanged(self) -> None:
        from basis_core.audit.trace import RuleEvaluation

        assert set(RuleEvaluation.model_fields) == {"rule_name", "outcome", "reason"}

    def test_decision_trace_fields_unchanged(self) -> None:
        from basis_core.audit.trace import DecisionTrace

        assert set(DecisionTrace.model_fields) == {
            "final_outcome",
            "evaluated_rules",
            "short_circuited",
        }

    def test_trace_rule_evidence_is_not_rule_evaluation(self) -> None:
        from basis_core.audit.trace import RuleEvaluation

        assert TraceRuleEvidence is not RuleEvaluation
        assert not issubclass(TraceRuleEvidence, RuleEvaluation)
        assert not issubclass(RuleEvaluation, TraceRuleEvidence)

    def test_audit_package_v01_public_symbols_still_present_unchanged(self) -> None:
        """PR 35 (Milestone 11) additively extends `basis_core.audit.__all__`
        with the operation-aware trace/audit-evidence surface; every v0.1.0
        symbol previously asserted here remains present, in the same
        relative order, unremoved and unrenamed. See
        `tests/test_public_api.py::TestAuditPackage::test_v01_inventory_unchanged`
        for the authoritative harness."""
        import basis_core.audit as audit_package

        v01_symbols = [
            "AuditEvent",
            "AuditEventType",
            "AuditOutcome",
            "AUDIT_SCHEMA_VERSION",
            "AuditWriter",
            "NullAuditWriter",
            "LogAuditWriter",
            "DecisionTrace",
            "RuleEvaluation",
        ]
        assert [name for name in audit_package.__all__ if name in v01_symbols] == v01_symbols


# ══════════════════════════════════════════════════════════════════════════
# Public API boundary — TraceRuleEvidence graduated to stable public API by PR 35
# ══════════════════════════════════════════════════════════════════════════


class TestPublicAPIBoundary:
    """As of PR 35 (Milestone 11), `TraceRuleEvidence` and its nested closed
    vocabularies are stabilized as part of `basis_core.audit`'s
    package-level public API. Supersedes the prior "not prematurely public"
    guard, which asserted the pre-PR-35 state."""

    def test_trace_rule_evidence_exported_from_basis_core_audit(self) -> None:
        import basis_core.audit as audit_package
        import basis_core.audit.operation_aware.trace_rule_evidence as concrete

        assert "TraceRuleEvidence" in audit_package.__all__
        assert audit_package.TraceRuleEvidence is concrete.TraceRuleEvidence

    def test_trace_rule_evidence_not_exported_from_operation_aware_package_init(self) -> None:
        """`basis_core.audit.operation_aware` (the internal orchestration
        subpackage's own __init__) remains un-exported from — only the
        top-level `basis_core.audit` package gained the export."""
        import basis_core.audit.operation_aware as oa_audit_package

        assert not hasattr(oa_audit_package, "TraceRuleEvidence")


# ══════════════════════════════════════════════════════════════════════════
# Serialization
# ══════════════════════════════════════════════════════════════════════════


class TestSerialization:
    """The governed round-trip convention for this model is
    `model_dump(mode="json", exclude_none=True)`, matching every other
    operation-aware model in this repository."""

    def test_plain_model_dump_json_names_every_published_field(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        dumped = evidence.model_dump(mode="json")
        assert set(dumped) == {
            "rule_id",
            "effect",
            "rule_result",
            "condition_results",
            "reason_code",
            "explanation",
        }

    def test_exclude_none_omits_unset_top_level_fields(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        assert dumped == {
            "rule_id": "rule-operator-read-ahu-telemetry",
            "effect": "allow",
            "rule_result": "matched",
        }

    def test_plain_model_dump_would_emit_null_by_contrast(self) -> None:
        evidence = TraceRuleEvidence(**_VALID_EVIDENCE_KWARGS)
        plain_dumped = evidence.model_dump(mode="json")
        assert plain_dumped["condition_results"] is None
        assert plain_dumped["reason_code"] is None
        assert plain_dumped["explanation"] is None

    def test_governed_convention_round_trips_for_full_record(self) -> None:
        evidence = TraceRuleEvidence(
            rule_id="rule-deny-elevated-risk",
            effect="deny",
            rule_result="error",
            condition_results=[
                {
                    "condition_id": "cond-risk-score-high",
                    "result": "error",
                    "reason_code": "condition_type_mismatch",
                }
            ],
            reason_code="condition_evaluation_error",
        )
        dumped = evidence.model_dump(mode="json", exclude_none=True)
        restored = TraceRuleEvidence.model_validate(dumped)
        assert restored == evidence
