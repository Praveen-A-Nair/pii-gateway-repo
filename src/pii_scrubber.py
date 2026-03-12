"""
PII Scrubber Module
Provides the PIIScrubber class as a wrapper around EnterprisePIIEngine
for backward compatibility with existing tests and setup scripts
"""

from pii_engine import EnterprisePIIEngine


class PIIScrubber:
    """
    Wrapper around EnterprisePIIEngine for convenient PII scrubbing.
    """
    def __init__(self):
        self.engine = EnterprisePIIEngine()

    def scrub(self, text: str, policy: dict = None):
        """
        Scrub PII from text based on policy.
        Returns tuple of (scrubbed_text, pii_found_dict)
        """
        return self.engine.scrub(text, policy)


# For direct import compatibility
__all__ = ['PIIScrubber']
