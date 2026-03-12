#!/usr/bin/env python3
"""
Quick PII Scrubbing Test
Tests the gateway's PII scrubber against sample data
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from pii_scrubber import PIIScrubber

# Initialize scrubber
scrubber = PIIScrubber()

# Test cases
test_data = [
    "My email is abcd@mycompany.com and my credit card is 556733423",
    "Contact john@company.com or call 555-123-4567",
    "SSN: 123-45-6789",
    "My API key is api_key=sk_live_51234567890ABCDEF",
    '{"email": "user@example.com", "ssn": "987-65-4321", "name": "John Doe"}',
]

print("=" * 70)
print("PII SCRUBBER TEST")
print("=" * 70)

for i, text in enumerate(test_data, 1):
    print(f"\n[Test {i}]")
    print(f"Original: {text}")
    scrubbed, found = scrubber.scrub(text)
    print(f"Scrubbed: {scrubbed}")
    if found:
        print(f"PII Found: {found}")
    print("-" * 70)

print("\n✅ Scrubber test complete!")
