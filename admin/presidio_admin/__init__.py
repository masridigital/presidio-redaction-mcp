"""Admin portal for the Presidio redaction proxy.

The portal is the system of record for upstream tool allowlists, registered
Entra clients, recognizer thresholds, and the Claude verifier switch. The
proxy reads the published version and refuses to serve an invalid document.
"""

__version__ = "0.1.0"
