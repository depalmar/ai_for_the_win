"""Tests for scripts/check_ai_model_freshness.py (retired and retiring model IDs)."""

import json
from datetime import date
from pathlib import Path

import pytest

from scripts.check_ai_model_freshness import (
    DEPRECATED_MODELS,
    deprecation_status,
    iter_files,
    scan_file,
    scan_text,
)

PROJECT_ROOT = Path(__file__).parent.parent


def ids(text: str, is_code: bool = True) -> list[tuple[str, str, bool]]:
    """(model_id_as_written, base_id, is_error) for each finding."""
    return [(model_id, base, err) for _, model_id, base, err in scan_text(text, is_code)]


class TestMatching:
    @pytest.mark.parametrize(
        "text, expected_base",
        [
            ('model="claude-sonnet-4-20250514"', "claude-sonnet-4"),
            ('model="claude-sonnet-4-5"', "claude-sonnet-4-5"),
            ('model="claude-sonnet-4-5-20250929"', "claude-sonnet-4-5"),
            ('model="claude-opus-4-1-20250805"', "claude-opus-4-1"),
            ('model="gpt-5"', "gpt-5"),
            ('model="gpt-5-2025-08-07"', "gpt-5"),
            ('model="gpt-5-mini"', "gpt-5-mini"),
            ('GenerativeModel("gemini-2.5-pro")', "gemini-2.5-pro"),
            ('model="claude-sonnet-4-5@20250929"', "claude-sonnet-4-5"),
        ],
    )
    def test_matches_deprecated_ids_and_snapshots(self, text, expected_base):
        assert [base for _, base, _ in ids(text)] == [expected_base]

    @pytest.mark.parametrize(
        "text",
        [
            'model="claude-sonnet-5-5"',
            'model="claude-sonnet-4-6"',
            'model="claude-opus-4-8"',
            'model="claude-haiku-4-5-20251001"',
            'model="gpt-5.2"',
            'model="gpt-6.2-sol"',
            'model="gemini-3.8-flash"',
            'model="gemini-2.5-pro-preview-tts"',
            "foo1 = bar_o1",
        ],
    )
    def test_ignores_current_and_lookalike_ids(self, text):
        assert ids(text) == []

    def test_sentence_ending_period_still_matches_in_prose(self):
        assert ids("Teams still on gpt-5.", is_code=False) == [("gpt-5", "gpt-5", False)]


class TestSeverity:
    def test_quoted_id_in_code_is_error(self):
        assert ids("x = 'claude-sonnet-4-5'") == [("claude-sonnet-4-5", "claude-sonnet-4-5", True)]

    def test_unquoted_id_in_code_comment_is_warning(self):
        assert ids("# was claude-sonnet-4-5 before") == [
            ("claude-sonnet-4-5", "claude-sonnet-4-5", False)
        ]

    def test_quoted_id_in_prose_is_warning(self):
        assert ids('Set `model="gpt-5"`', is_code=False) == [("gpt-5", "gpt-5", False)]

    def test_notebook_code_cell_is_error_markdown_cell_is_warning(self, tmp_path):
        notebook = {
            "cells": [
                {"cell_type": "code", "source": ['    return "anthropic", "claude-sonnet-4.5"\n']},
                {"cell_type": "markdown", "source": ["Sonnet 4.5 (`claude-sonnet-4-5`) retires"]},
            ]
        }
        path = tmp_path / "lab.ipynb"
        path.write_text(json.dumps(notebook, indent=1), encoding="utf-8")

        findings = scan_file(path, tmp_path)

        assert [(f.location, f.model_id, f.is_error) for f in findings] == [
            ("cell 0, line 1", "claude-sonnet-4.5", True),
            ("cell 1, line 1", "claude-sonnet-4-5", False),
        ]


class TestStatus:
    def test_retiring_before_date(self):
        status = deprecation_status("claude-sonnet-4-5", date(2026, 11, 20))
        assert status == "retires 2026-11-30 (in 10 days); use claude-sonnet-5-5"

    def test_retired_on_and_after_date(self):
        assert deprecation_status("claude-sonnet-4-5", date(2026, 11, 30)).startswith("retired")
        assert deprecation_status("claude-sonnet-4", date(2026, 11, 20)).startswith("retired")

    def test_every_entry_has_iso_date_and_replacement(self):
        for model_id, (retire_on, replacement) in DEPRECATED_MODELS.items():
            date.fromisoformat(retire_on)
            assert replacement and replacement not in DEPRECATED_MODELS, model_id


def test_repository_code_uses_no_retired_or_retiring_models():
    """Executable defaults must not point at a retired or retiring model."""
    errors = [
        f"{f.path} ({f.location}): {f.model_id}"
        for path in iter_files(PROJECT_ROOT)
        for f in scan_file(path, PROJECT_ROOT)
        if f.is_error
    ]
    assert errors == [], "Retired or retiring model IDs in code:\n" + "\n".join(errors)
