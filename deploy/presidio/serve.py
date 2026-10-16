"""Analyzer engine for the local Presidio front.

The HTTP server binds this engine. US_NPI is not in Presidio's default
registry; ``register_us_recognizers`` turns the US predefined set on.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

_DIR = Path(__file__).resolve().parent
if str(_DIR) not in sys.path:
    sys.path.insert(0, str(_DIR))

from us_recognizers import register_us_recognizers


def _engine(role: str, nlp_engine: Any = None) -> Any:
    if role == "anonymizer":
        from presidio_anonymizer import AnonymizerEngine

        return AnonymizerEngine()
    if role != "analyzer":
        raise ValueError(role)
    from presidio_analyzer import AnalyzerEngine

    if nlp_engine is None:
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = os.environ.get("PRESIDIO_SPACY_MODEL", "en_core_web_lg")
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            }
        )
        nlp_engine = provider.create_engine()
    engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    register_us_recognizers(engine)
    return engine
