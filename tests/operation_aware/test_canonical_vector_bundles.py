"""
tests/operation_aware/test_canonical_vector_bundles.py — canonical
policy-bundle conformance tests (Milestone 4, PR 16 of
`docs/implementation/basis-core-v0.2-operation-aware-plan.md`: "Bundle/rule
contract-fixture conformance tests (canonical vectors)").

Objective (per the roadmap plan's PR 16 entry): extend PR 10's contract-
fixture conformance suite (`test_contract_conformance.py`, which validates
each of the 14 vendored contracts' own embedded `examples.valid`/
`examples.invalid` blocks) to also cover all five canonical compatibility
vectors' `policy-bundle.yaml` / `invalid-policy-bundle.yaml` artifacts
under `tests/fixtures/basis-schemas/v0.2.0/compatibility/` — a different,
narrower fixture set than the 14 contracts' own examples.

Four of the five canonical scenarios (`allow-basic`, `deny-precedence`,
`default-deny`, `not-applicable`) vendor a *valid* `policy-bundle.yaml`:
this module proves each one loads through the existing test-only loader
(`tests/helpers/operation_aware_contracts.load_scenario_artifact`),
constructs as the current typed `PolicyBundle` model, preserves its
authored bundle identity and rule content, and passes PR 15's explicit
`validate_policy_bundle()` semantic pipeline unchanged.

The fifth scenario, `invalid-policy-bundle`, vendors an intentionally
invalid `invalid-policy-bundle.yaml`: structurally well-formed (it
constructs as a base `PolicyBundle`), but semantically rejected by
`validate_policy_bundle()` for its one documented defect — a duplicate
`rule_id` (`"allow-duplicate-rule"`) across `bundle.rules`
(`policy-bundle.yaml`'s own `constraints`; see that fixture's file header
and `tests/fixtures/basis-schemas/v0.2.0/compatibility/
invalid-policy-bundle/invalid-policy-bundle.yaml`'s comments for the full
reasoning). This module proves rejection is `DuplicateRuleIdError`
specifically — not merely some `SemanticPolicyValidationError` subclass,
and never `StructuralPolicyValidationError` — and that the raised error
names both the offending `rule_id` and the bundle's own `bundle_id`.

Relationship to PR 15 (`test_policy_validation.py`)
────────────────────────────────────────────────────────────────────────
PR 15's own test suite already proves `validate_policy_bundle`'s general
behavior directly (duplicate-`rule_id` detection, duplicate-`condition_id`
detection, the structural/semantic error hierarchy, purity, and one
direct check of the `invalid-policy-bundle` canonical fixture, per that
PR's own roadmap-mandated completion criterion). This module does not
re-prove any of that: it exists to prove that *all five* canonical
vectors' bundle fixtures — not just the one invalid one PR 15 already
exercises — conform to the current `PolicyBundle` model and validation
pipeline. No duplicate-`condition_id` case, error-hierarchy check, or
purity/mutation check is repeated here; see `test_policy_validation.py`
for that coverage.

Relationship to PR 10 (`test_contract_conformance.py`)
────────────────────────────────────────────────────────────────────────
PR 10's suite validates the 14 contracts' own embedded examples (a
different fixture set, `tests/fixtures/basis-schemas/v0.2.0/schemas/`).
This module targets only the five canonical compatibility-vector
directories under `tests/fixtures/basis-schemas/v0.2.0/compatibility/`,
which PR 10's suite explicitly documents as out of its own scope.

Scope — bundle conformance only, nothing else
────────────────────────────────────────────────────────────────────────
This module does not implement, exercise, or assert: bundle applicability
or scope-to-request matching (PR 17), rule selector matching, condition
operator execution or field-path resolution, candidate-rule selection or
ordering, policy evaluation, `ALLOW`/`DENY`/`NOT_APPLICABLE` outcomes,
deny precedence, default-deny behavior, evaluation traces, trace rule
evidence, operation-aware decision responses, audit evidence, or any
gateway/enforcement behavior. The `deny-precedence` and `not-applicable`
scenario names describe *future* evaluator outcomes their fixtures will
eventually help prove — in this module, each is exercised only as a
canonical *policy-bundle* fixture, exactly like the other three scenarios.

Fixture integrity
────────────────────────────────────────────────────────────────────────
Every fixture is consumed directly via `load_scenario_artifact` (the
existing, safe, boundary-enforced test-only loader) — never copied,
hand-transcribed, or reconstructed as an inline dict. No fixture is
mutated, normalized, or rewritten by this module.
"""

from __future__ import annotations

import pytest

from basis_core.policy.operation_aware.bundle import PolicyBundle
from basis_core.policy.operation_aware.validation import (
    DuplicateRuleIdError,
    PolicyBundleValidationError,
    SemanticPolicyValidationError,
    StructuralPolicyValidationError,
    validate_policy_bundle,
)
from tests.helpers.basis_schemas_snapshot import COMPATIBILITY_SCENARIOS
from tests.helpers.operation_aware_contracts import load_scenario_artifact

# ══════════════════════════════════════════════════════════════════════════
# Canonical scenario inventory
# ══════════════════════════════════════════════════════════════════════════

#: The one canonical scenario whose policy-bundle artifact is intentionally
#: invalid. The other four vendor a valid `policy-bundle.yaml`.
_INVALID_SCENARIO: str = "invalid-policy-bundle"

#: Derived from the shared `COMPATIBILITY_SCENARIOS` inventory (the same
#: source of truth `test_compatibility_fixture_loading.py` uses), rather
#: than a second, hand-typed list of scenario names.
_VALID_SCENARIOS: tuple[str, ...] = tuple(
    scenario for scenario in COMPATIBILITY_SCENARIOS if scenario != _INVALID_SCENARIO
)

#: Each valid scenario's authored `bundle_id`, read directly from its own
#: vendored `policy-bundle.yaml` — used to prove bundle identity is
#: preserved through construction and validation, not merely that
#: construction "succeeds" on some unspecified content.
_EXPECTED_BUNDLE_ID: dict[str, str] = {
    "allow-basic": "bundle-compat-allow",
    "deny-precedence": "bundle-compat-deny-precedence",
    "default-deny": "bundle-compat-default-deny",
    "not-applicable": "bundle-compat-hvac-scope",
}

#: Each valid scenario's authored `{rule_id: effect}` mapping, read
#: directly from its own vendored `policy-bundle.yaml` — used to prove
#: rule *content* (not just count) is preserved, without asserting
#: anything about how that content is later matched or evaluated.
_EXPECTED_RULE_EFFECTS: dict[str, dict[str, str]] = {
    "allow-basic": {"allow-operator-read-ahu": "allow"},
    "deny-precedence": {
        "allow-operator-write-hvac-setpoint": "allow",
        "deny-control-during-interlock": "deny",
    },
    "default-deny": {"allow-operator-read-ahu-telemetry": "allow"},
    "not-applicable": {"allow-operator-hvac-write": "allow"},
}

#: The invalid scenario's documented defect (see this module's docstring
#: and the fixture's own file-header comment): two rules sharing this
#: exact `rule_id`.
_DUPLICATE_RULE_ID: str = "allow-duplicate-rule"
_INVALID_BUNDLE_ID: str = "bundle-compat-invalid-policy"


def _load_bundle_fixture(scenario: str) -> dict[str, object]:
    """Load one canonical scenario's `policy_bundle` artifact via the
    existing test-only loader, asserting only the generic mapping-root
    shape every pinned artifact already has
    (`test_compatibility_fixture_loading.py` proves this broadly for all
    five scenarios and six artifacts; this helper does not re-prove it)."""
    raw = load_scenario_artifact(scenario, "policy_bundle")
    assert isinstance(raw, dict), (
        f"{scenario}: expected the policy-bundle fixture to have a mapping "
        f"root, got {type(raw).__name__}."
    )
    return raw


# ══════════════════════════════════════════════════════════════════════════
# Canonical scenario inventory sanity
# ══════════════════════════════════════════════════════════════════════════


class TestCanonicalScenarioInventory:
    def test_five_canonical_scenarios_are_recognized(self) -> None:
        assert len(COMPATIBILITY_SCENARIOS) == 5

    def test_invalid_scenario_is_among_the_five(self) -> None:
        assert _INVALID_SCENARIO in COMPATIBILITY_SCENARIOS

    def test_four_scenarios_are_treated_as_valid(self) -> None:
        assert len(_VALID_SCENARIOS) == 4
        assert _INVALID_SCENARIO not in _VALID_SCENARIOS

    def test_every_valid_scenario_has_an_expected_bundle_id_and_rule_map(self) -> None:
        assert set(_EXPECTED_BUNDLE_ID) == set(_VALID_SCENARIOS)
        assert set(_EXPECTED_RULE_EFFECTS) == set(_VALID_SCENARIOS)


# ══════════════════════════════════════════════════════════════════════════
# Valid canonical bundles: allow-basic, deny-precedence, default-deny,
# not-applicable
# ══════════════════════════════════════════════════════════════════════════


class TestValidCanonicalBundlesConstructAndValidate:
    """Each of the four canonical scenarios below vendors a valid
    `policy-bundle.yaml`. Only the bundle *fixture* is exercised here — no
    scope-to-request applicability, rule matching, or evaluation outcome
    of any kind. Test IDs are the scenario name itself (pytest's default
    `parametrize` ID for a string parameter), so a failure immediately
    identifies which canonical scenario broke."""

    @pytest.mark.parametrize("scenario", _VALID_SCENARIOS)
    def test_fixture_loads_with_expected_bundle_id(self, scenario: str) -> None:
        raw = _load_bundle_fixture(scenario)
        assert raw.get("bundle_id") == _EXPECTED_BUNDLE_ID[scenario]

    @pytest.mark.parametrize("scenario", _VALID_SCENARIOS)
    def test_fixture_constructs_as_policy_bundle(self, scenario: str) -> None:
        raw = _load_bundle_fixture(scenario)
        bundle = PolicyBundle.model_validate(raw)
        assert type(bundle) is PolicyBundle
        assert bundle.bundle_id == _EXPECTED_BUNDLE_ID[scenario]

    @pytest.mark.parametrize("scenario", _VALID_SCENARIOS)
    def test_fixture_preserves_expected_rule_ids_and_effects(self, scenario: str) -> None:
        raw = _load_bundle_fixture(scenario)
        bundle = PolicyBundle.model_validate(raw)
        actual = {rule.rule_id: rule.effect.value for rule in bundle.rules}
        assert actual == _EXPECTED_RULE_EFFECTS[scenario]

    @pytest.mark.parametrize("scenario", _VALID_SCENARIOS)
    def test_fixture_passes_semantic_validation_pipeline(self, scenario: str) -> None:
        raw = _load_bundle_fixture(scenario)
        result = validate_policy_bundle(raw)
        assert type(result) is PolicyBundle
        assert result.bundle_id == _EXPECTED_BUNDLE_ID[scenario]
        actual = {rule.rule_id: rule.effect.value for rule in result.rules}
        assert actual == _EXPECTED_RULE_EFFECTS[scenario]

    @pytest.mark.parametrize("scenario", _VALID_SCENARIOS)
    def test_validate_policy_bundle_does_not_return_none_or_bool(self, scenario: str) -> None:
        raw = _load_bundle_fixture(scenario)
        result = validate_policy_bundle(raw)
        assert result is not None
        assert not isinstance(result, bool)


# ══════════════════════════════════════════════════════════════════════════
# Invalid canonical bundle: invalid-policy-bundle
# ══════════════════════════════════════════════════════════════════════════


class TestInvalidCanonicalBundleFailsSemanticValidation:
    """`invalid-policy-bundle`'s policy-bundle artifact
    (`invalid-policy-bundle.yaml`) is structurally well-formed but carries
    one intentional defect: two rules sharing `rule_id`
    `"allow-duplicate-rule"` (`policy-bundle.yaml`'s own bundle-level
    `rule_id`-uniqueness constraint). It must construct as a base
    `PolicyBundle` — the structural boundary `bundle.py`/PR 14 currently
    enforces, duplicate-`rule_id` rejection being explicitly deferred to
    PR 15's semantic stage — and be rejected by `validate_policy_bundle`
    for exactly that documented reason, not an incidental or unrelated
    failure."""

    def _load(self) -> dict[str, object]:
        return _load_bundle_fixture(_INVALID_SCENARIO)

    def test_fixture_is_structurally_loadable(self) -> None:
        raw = self._load()
        assert raw.get("bundle_id") == _INVALID_BUNDLE_ID

    def test_fixture_constructs_as_base_policy_bundle(self) -> None:
        # The fixture's only intended defect is semantic (bundle-level
        # duplicate rule_id) — plain PolicyBundle construction, which does
        # not check cross-rule rule_id uniqueness (deferred to PR 15),
        # must succeed. See bundle.py's docstring, "Deferred to PR 15".
        raw = self._load()
        bundle = PolicyBundle.model_validate(raw)
        assert type(bundle) is PolicyBundle
        assert len(bundle.rules) == 2
        assert {rule.rule_id for rule in bundle.rules} == {_DUPLICATE_RULE_ID}

    def test_semantic_validation_pipeline_rejects_the_fixture(self) -> None:
        raw = self._load()
        with pytest.raises(SemanticPolicyValidationError) as exc_info:
            validate_policy_bundle(raw)
        # Never the structural stage: the fixture's shape is well-formed.
        assert not isinstance(exc_info.value, StructuralPolicyValidationError)

    def test_rejection_is_specifically_a_duplicate_rule_id_error(self) -> None:
        # Narrower than "some SemanticPolicyValidationError" — proves the
        # rejection is caused by the intended duplicate-rule_id defect,
        # not an unrelated semantic failure (e.g. DuplicateConditionIdError,
        # this hierarchy's only sibling semantic error type).
        raw = self._load()
        with pytest.raises(DuplicateRuleIdError):
            validate_policy_bundle(raw)

    def test_error_names_the_documented_duplicate_rule_id(self) -> None:
        raw = self._load()
        with pytest.raises(DuplicateRuleIdError, match=_DUPLICATE_RULE_ID):
            validate_policy_bundle(raw)

    def test_error_names_the_bundle_id(self) -> None:
        raw = self._load()
        with pytest.raises(DuplicateRuleIdError, match=_INVALID_BUNDLE_ID):
            validate_policy_bundle(raw)

    def test_rejection_is_a_policy_bundle_validation_error(self) -> None:
        # The stable root type every caller may catch without needing the
        # structural/semantic distinction; see validation.py's docstring.
        raw = self._load()
        with pytest.raises(PolicyBundleValidationError):
            validate_policy_bundle(raw)
