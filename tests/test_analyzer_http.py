"""Analyzer HTTP contract that does not need the spaCy model."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVE = ROOT / "deploy" / "presidio" / "serve.py"


def _function(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    tree = ast.parse(SERVE.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            continue
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(name)


def test_do_post_catches_errors_and_parses_content_length_inside_the_try():
    do_post = _function("do_POST")
    assert isinstance(do_post.body[0], ast.Try)
    handlers = {getattr(item.type, "id", None) or getattr(item.type, "attr", None) for item in do_post.body[0].handlers}
    assert "Exception" in handlers
    source = ast.get_source_segment(SERVE.read_text(encoding="utf-8"), do_post.body[0]) or ""
    assert "Content-Length" in source
    assert '"internal"' in source


def test_handle_error_logs_only_the_exception_type():
    handle = _function("handle_error")
    source = ast.get_source_segment(SERVE.read_text(encoding="utf-8"), handle) or ""
    assert "type(exc).__name__" in source
    assert "traceback" not in source.lower()
    assert "log_error" not in source


def test_request_cannot_set_entities_threshold_or_ad_hoc_recognizers():
    analyze = _function("_analyze")
    source = ast.get_source_segment(SERVE.read_text(encoding="utf-8"), analyze) or ""
    assert "parsed.entities" not in source
    assert "parsed.ad_hoc_recognizers" not in source or "_pinned_recognizers" in source
    assert "payload.get(\"entities\")" not in source
    assert "payload.get(\"score_threshold\")" not in source
    assert "payload.get(\"ad_hoc_recognizers\")" not in source
    assert "_pinned_recognizers()" in source
    assert "_server_score_threshold()" in source
