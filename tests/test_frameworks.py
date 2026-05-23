"""Tests for assessment frameworks/profiles (Mythos)."""

import pytest

from znextscan.frameworks import (
    MYTHOS_CONTROLS,
    mythos_scanner_check_ids,
    questionnaire_controls,
)
from znextscan.frameworks.mythos import VALIDATION_METHODS
from znextscan.scanner import CHECK_REGISTRY, get_check_by_id, get_registry


class TestMythosCatalog:
    def test_catalog_size(self) -> None:
        assert len(MYTHOS_CONTROLS) == 42

    def test_composite_controls_multibind(self) -> None:
        # C05 must run all its declared checks, not just the primary.
        c05 = next(c for c in MYTHOS_CONTROLS if c.control_id == "MYT-C05")
        assert set(c05.bound_check_ids) >= {"SCI-001", "SCI-004", "EXT-025", "EXT-015"}

    def test_four_dimensions_present(self) -> None:
        dims = {c.dimension for c in MYTHOS_CONTROLS}
        assert dims == {"R", "C", "V", "X"}

    def test_each_dimension_has_a_p0(self) -> None:
        for dim in ("R", "C", "V", "X"):
            p0 = [c for c in MYTHOS_CONTROLS if c.dimension == dim and c.priority == "P0"]
            assert p0, f"dimension {dim} has no P0 control"

    def test_validation_methods_valid(self) -> None:
        for c in MYTHOS_CONTROLS:
            assert c.validation_method in VALIDATION_METHODS

    def test_ids_unique_and_well_formed(self) -> None:
        ids = [c.control_id for c in MYTHOS_CONTROLS]
        assert len(ids) == len(set(ids))
        for cid in ids:
            assert cid.startswith("MYT-")

    def test_scanner_bindings_resolve_to_real_checks(self) -> None:
        for c in MYTHOS_CONTROLS:
            if c.scanner_check_id is not None:
                assert get_check_by_id(c.scanner_check_id) is not None, c.control_id

    def test_questionnaire_controls_are_non_scriptable_or_pending(self) -> None:
        qc = questionnaire_controls()
        assert qc
        for c in qc:
            assert c.needs_questionnaire
        # A pure scanner-bound control should NOT be in the questionnaire
        bound = next(c for c in MYTHOS_CONTROLS if c.control_id == "MYT-R06")
        assert bound not in qc


class TestProfiles:
    def test_mrra_registry_is_full_legacy_set(self) -> None:
        assert get_registry("mrra") == list(CHECK_REGISTRY)

    def test_mythos_registry_matches_catalog_bindings(self) -> None:
        myt = get_registry("mythos")
        assert myt, "mythos registry is empty"
        assert [c.control_id for c in myt] == mythos_scanner_check_ids()

    def test_mythos_registry_includes_native_checks(self) -> None:
        ids = {c.control_id for c in get_registry("mythos")}
        assert {"MYT-R01", "MYT-V01", "MYT-V02", "MYT-V07", "MYT-X01"}.issubset(ids)

    def test_unknown_profile_raises(self) -> None:
        with pytest.raises(ValueError):
            get_registry("bogus")

    def test_mythos_checks_annotated(self) -> None:
        for cls in get_registry("mythos"):
            assert "mythos" in cls.frameworks
            assert cls.mythos_dimension in {"R", "C", "V", "X"}
