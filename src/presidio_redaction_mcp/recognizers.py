"""Synthetic-oriented recognizers shared with the Presidio analyze request."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from presidio_redaction_mcp.errors import ConfigError


@dataclass(frozen=True)
class PatternRule:
    entity: str
    name: str
    regex: re.Pattern[str]
    score: float


@dataclass(frozen=True)
class DenyRule:
    entity: str
    terms: tuple[str, ...]


@dataclass(frozen=True)
class RecognizerSet:
    patterns: tuple[PatternRule, ...]
    deny_lists: tuple[DenyRule, ...]
    ad_hoc: tuple[dict[str, Any], ...]

    def find_spans(self, text: str) -> list[dict[str, Any]]:
        spans: list[dict[str, Any]] = []
        for rule in self.patterns:
            for match in rule.regex.finditer(text):
                spans.append(
                    {
                        "entity_type": rule.entity,
                        "start": match.start(),
                        "end": match.end(),
                        "score": rule.score,
                    }
                )
        lowered = text.lower()
        for rule in self.deny_lists:
            for term in rule.terms:
                start = 0
                needle = term.lower()
                while True:
                    index = lowered.find(needle, start)
                    if index < 0:
                        break
                    spans.append(
                        {
                            "entity_type": rule.entity,
                            "start": index,
                            "end": index + len(term),
                            "score": 0.95,
                        }
                    )
                    start = index + len(needle)
        spans.sort(key=lambda item: (item["start"], -(item["end"] - item["start"])))
        return _drop_overlaps(spans)


def load_recognizers(path: Path) -> RecognizerSet:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ConfigError("recognizers_invalid")
    patterns: list[PatternRule] = []
    ad_hoc: list[dict[str, Any]] = []
    for entry in raw.get("recognizers") or []:
        entity = str(entry["entity"])
        compiled_patterns = []
        for pattern in entry.get("patterns") or []:
            expression = str(pattern["regex"])
            score = float(pattern.get("score", 0.85))
            if score < 0.75:
                raise ConfigError("recognizer_score_below_mask_floor")
            try:
                compiled = re.compile(expression)
            except re.error as exc:
                raise ConfigError("recognizer_regex_invalid") from exc
            name = str(pattern.get("name") or entity)
            patterns.append(PatternRule(entity=entity, name=name, regex=compiled, score=score))
            compiled_patterns.append({"name": name, "regex": expression, "score": score})
        ad_hoc.append(
            {
                "name": str(entry.get("name") or entity),
                "supported_language": "en",
                "supported_entity": entity,
                "patterns": compiled_patterns,
            }
        )
    deny_lists: list[DenyRule] = []
    for entry in raw.get("deny_list") or []:
        terms = tuple(str(term) for term in entry.get("terms") or [])
        if not terms:
            raise ConfigError("deny_list_empty")
        entity = str(entry["entity"])
        deny_lists.append(DenyRule(entity=entity, terms=terms))
        ad_hoc.append(
            {
                "name": f"deny_{entity.lower()}",
                "supported_language": "en",
                "supported_entity": entity,
                "deny_list": list(terms),
            }
        )
    return RecognizerSet(patterns=tuple(patterns), deny_lists=tuple(deny_lists), ad_hoc=tuple(ad_hoc))


def _drop_overlaps(spans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    cursor = -1
    for span in spans:
        if span["start"] < cursor:
            continue
        kept.append(span)
        cursor = span["end"]
    return kept
