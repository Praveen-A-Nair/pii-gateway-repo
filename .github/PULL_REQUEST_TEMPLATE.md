## Summary
<!-- What does this PR do? -->

## Type of Change
- [ ] Bug fix
- [ ] New PII pattern added
- [ ] New department policy
- [ ] New LLM endpoint
- [ ] TLS mode change
- [ ] Infrastructure change
- [ ] Documentation update

## PII Changes (if applicable)
- Pattern name:
- Regex / detection method:
- Test case added:

## Security Checklist
- [ ] No real PII/secrets in code or tests
- [ ] `.env` not committed
- [ ] No cert private keys committed
- [ ] Audit logging tested
- [ ] Fail-closed behaviour verified

## Tests
- [ ] Unit tests pass (`pytest tests/ -v -m "not integration"`)
- [ ] Integration tests pass (`pytest tests/ -v -m integration`)
- [ ] Manually tested with curl against `/scrub` endpoint

## Reviewer Notes
<!-- Anything specific for the reviewer to check -->
