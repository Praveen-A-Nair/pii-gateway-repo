"""
Test script — validate PII scrubbing works correctly
Run: python test_pii.py
"""

import sys
from pathlib import Path

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from pii_scrubber import PIIScrubber

scrubber = PIIScrubber()

# ── Test Cases ─────────────────────────────────────────────────
tests = [
    {
        "name": "Email",
        "input": "Contact john.doe@company.com for details",
        "expect": "[EMAIL]"
    },
    {
        "name": "Phone",
        "input": "Call me at +1 (555) 123-4567 anytime",
        "expect": "[PHONE]"
    },
    {
        "name": "SSN",
        "input": "My SSN is 123-45-6789",
        "expect": "[SSN]"
    },
    {
        "name": "Credit Card",
        "input": "Payment with 4532015112830366",
        "expect": "[CREDIT_CARD]"
    },
    {
        "name": "AWS Key",
        "input": "aws_key = AKIAIOSFODNN7EXAMPLE",
        "expect": "[AWS_KEY]"
    },
    {
        "name": "IP Address",
        "input": "Server IP: 192.168.1.100",
        "expect": "[IP]"
    },
    {
        "name": "API Key in JSON",
        "input": '{"messages": [{"role": "user", "content": "My email is test@test.com and SSN 123-45-6789"}]}',
        "expect": "[EMAIL]"
    },
    {
        "name": "Password in text",
        "input": "password=SuperSecret123!",
        "expect": "[PASSWORD]"
    },
]

print("\n" + "="*60)
print("  🧪 PII SCRUBBER TESTS")
print("="*60)

passed = 0
for test in tests:
    scrubbed, found = scrubber.scrub(test["input"])
    ok = test["expect"] in scrubbed or len(found) > 0
    status = "✅ PASS" if ok else "❌ FAIL"
    if ok:
        passed += 1

    print(f"\n{status} — {test['name']}")
    print(f"  Input:   {test['input'][:60]}")
    print(f"  Output:  {scrubbed[:60]}")
    print(f"  Found:   {found}")

print("\n" + "="*60)
print(f"  Results: {passed}/{len(tests)} passed")
print("="*60 + "\n")
