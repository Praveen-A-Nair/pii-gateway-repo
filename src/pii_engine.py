"""
Enterprise PII Engine
- Presidio AI + regex patterns
- Department-aware policies
- Configurable actions per PII type
"""

import re
import json
import logging
from typing import Tuple

logger = logging.getLogger("pii-engine")


class EnterprisePIIEngine:
    def __init__(self):
        self.presidio_available = self._init_presidio()
        self.patterns = self._build_patterns()

    def _init_presidio(self) -> bool:
        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_anonymizer import AnonymizerEngine
            self.analyzer  = AnalyzerEngine()
            self.anonymizer = AnonymizerEngine()
            logger.info("✅ Presidio AI engine loaded")
            return True
        except ImportError:
            logger.warning("⚠️  Presidio not found — regex only mode")
            return False

    def _build_patterns(self) -> dict:
        return {
            "EMAIL":          (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "[EMAIL]"),
            "PHONE":          (r'\b(\+\d{1,3}[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b', "[PHONE]"),
            "SSN":            (r'\b\d{3}-\d{2}-\d{4}\b', "[SSN]"),
            "CREDIT_CARD":    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "[CREDIT_CARD]"),
            "AWS_KEY":        (r'\bAKIA[0-9A-Z]{16}\b', "[AWS_KEY]"),
            "API_KEY":        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[A-Za-z0-9_\-]{20,}', "[API_KEY]"),
            "PASSWORD":       (r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+', "[PASSWORD]"),
            "JWT":            (r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b', "[JWT]"),
            "IP_ADDRESS":     (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "[IP]"),
            "BEARER_TOKEN":   (r'(?i)bearer\s+[A-Za-z0-9\-_\.]+', "[BEARER_TOKEN]"),
            "PRIVATE_KEY":    (r'-----BEGIN [\w\s]*PRIVATE KEY-----[\s\S]+?-----END [\w\s]*PRIVATE KEY-----', "[PRIVATE_KEY]"),
            "IBAN":           (r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b', "[IBAN]"),
            "PASSPORT":       (r'\b[A-Z]{1,2}\d{6,9}\b', "[PASSPORT]"),
            "MRN":            (r'\bMRN[-:\s]?\d{6,10}\b', "[MRN]"),
            "DOB":            (r'\b(DOB|Date of Birth)[-:\s]?\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', "[DOB]"),
            "CONNECTION_STR": (r'(?i)(connection[-_]?string|conn[-_]?str)\s*[=:]\s*.+', "[CONN_STRING]"),
        }

    def scrub(self, text: str, policy: dict = None) -> Tuple[str, dict]:
        """
        Scrub PII based on department policy
        policy example:
        {
          "scrub_names": true,
          "scrub_emails": true,
          "block_on_pii": false,
          "allowed_pii_types": ["IP_ADDRESS"]  ← never scrub these
        }
        """
        if not text:
            return text, {}

        policy = policy or {}
        allowed = set(policy.get("allowed_pii_types", []))
        pii_found = {}

        # Handle JSON bodies
        try:
            data = json.loads(text)
            scrubbed_data, pii_found = self._scrub_json(data, policy, allowed)
            return json.dumps(scrubbed_data), pii_found
        except (json.JSONDecodeError, ValueError):
            return self._scrub_text(text, policy, allowed)

    def _scrub_json(self, data, policy, allowed, pii_found=None):
        if pii_found is None:
            pii_found = {}
        if isinstance(data, dict):
            return {k: self._scrub_json(v, policy, allowed, pii_found)[0]
                    for k, v in data.items()}, pii_found
        elif isinstance(data, list):
            return [self._scrub_json(i, policy, allowed, pii_found)[0]
                    for i in data], pii_found
        elif isinstance(data, str):
            s, found = self._scrub_text(data, policy, allowed)
            for k, v in found.items():
                pii_found[k] = pii_found.get(k, 0) + v
            return s, pii_found
        return data, pii_found

    def _scrub_text(self, text: str, policy: dict, allowed: set) -> Tuple[str, dict]:
        pii_found = {}
        scrubbed  = text

        # Presidio AI (catches names, locations, orgs)
        if self.presidio_available and policy.get("scrub_names", True):
            try:
                from presidio_anonymizer.entities import OperatorConfig
                results = self.analyzer.analyze(text=scrubbed, language="en")
                filtered = [r for r in results if r.entity_type not in allowed]
                if filtered:
                    anon = self.anonymizer.anonymize(
                        text=scrubbed,
                        analyzer_results=filtered,
                        operators={
                            "DEFAULT":        OperatorConfig("replace", {"new_value": "[REDACTED]"}),
                            "PERSON":         OperatorConfig("replace", {"new_value": "[NAME]"}),
                            "EMAIL_ADDRESS":  OperatorConfig("replace", {"new_value": "[EMAIL]"}),
                            "PHONE_NUMBER":   OperatorConfig("replace", {"new_value": "[PHONE]"}),
                            "CREDIT_CARD":    OperatorConfig("replace", {"new_value": "[CREDIT_CARD]"}),
                            "US_SSN":         OperatorConfig("replace", {"new_value": "[SSN]"}),
                            "IP_ADDRESS":     OperatorConfig("replace", {"new_value": "[IP]"}),
                            "LOCATION":       OperatorConfig("replace", {"new_value": "[LOCATION]"}),
                        }
                    )
                    scrubbed = anon.text
                    for r in filtered:
                        pii_found[r.entity_type] = pii_found.get(r.entity_type, 0) + 1
            except Exception as e:
                logger.warning(f"Presidio error: {e}")

        # Regex patterns (catches keys, tokens, credentials)
        for pii_type, (pattern, replacement) in self.patterns.items():
            if pii_type in allowed:
                continue
            matches = re.findall(pattern, scrubbed)
            if matches:
                scrubbed = re.sub(pattern, replacement, scrubbed)
                pii_found[pii_type] = pii_found.get(pii_type, 0) + len(matches)

        return scrubbed, pii_found
