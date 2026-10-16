"""US predefined recognizers that the stock Presidio registry leaves off.

Presidio 2.2.362 ships ``UsNpiRecognizer`` and ``UsMbiRecognizer`` with
``enabled: false``. The analyzer front has to add them. Recognizers that are
already in the default registry are left as they are.
"""

from __future__ import annotations

from typing import Any

from presidio_analyzer.predefined_recognizers import (
    MedicalLicenseRecognizer,
    UsBankRecognizer,
    UsItinRecognizer,
    UsLicenseRecognizer,
    UsMbiRecognizer,
    UsNpiRecognizer,
    UsPassportRecognizer,
    UsSsnRecognizer,
)

# ABA routing is not in Presidio's default recognizer catalog. Its weak
# pattern promotes any checksum-valid 9-digit run to a high score, so it stays off.
_US_RECOGNIZERS = (
    UsBankRecognizer,
    UsLicenseRecognizer,
    UsItinRecognizer,
    UsPassportRecognizer,
    UsSsnRecognizer,
    MedicalLicenseRecognizer,
    UsMbiRecognizer,
    UsNpiRecognizer,
)


def register_us_recognizers(engine: Any) -> list[str]:
    """Add missing US recognizers. Returns the entity names that were added."""
    loaded = {recognizer.__class__ for recognizer in engine.registry.recognizers}
    added: list[str] = []
    for cls in _US_RECOGNIZERS:
        if cls in loaded:
            continue
        recognizer = cls()
        engine.registry.add_recognizer(recognizer)
        loaded.add(cls)
        added.extend(recognizer.supported_entities)
    return added
