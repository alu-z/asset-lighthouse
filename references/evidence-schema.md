# Evidence and Report Model

## Contents

- Principles
- Case record
- Observation record
- Root-cause assessment
- Report template
- Sensitive-data handling

## Principles

- Preserve original evidence and store analysis separately.
- Record the source, time, collection method, and file hash.
- Mark user statements as `user_reported`; do not treat them as verified facts.
- Use stable IDs to link observations, evidence, and findings.
- Do not collect personal data that is not needed for the assessment.

## Case record

```json
{
  "case_id": "CASE-20260827-001",
  "created_at": "2026-08-27T10:00:00+08:00",
  "platform": "windows",
  "scope": ["browser", "wallet-extension"],
  "professional_forensics_required": false
}
```

## Observation record

```json
{
  "id": "OBS-001",
  "type": "observed_fact",
  "category": "clipboard",
  "statement": "The synthetic address changed when pasted into Notepad",
  "source": "synthetic-clipboard-test",
  "observed_at": "2026-08-27T10:10:00+08:00",
  "user_confirmed": true,
  "evidence_ids": ["EV-001"]
}
```

An evidence record should contain at least:

```json
{
  "id": "EV-001",
  "kind": "screenshot",
  "path": "evidence/clipboard-test.png",
  "sha256": "<sha256>",
  "collected_at": "2026-08-27T10:11:00+08:00",
  "redacted": true
}
```

## Root-cause assessment

```json
{
  "id": "FIND-001",
  "hypothesis": "system-level-clipper",
  "confidence": "high",
  "supporting_observations": ["OBS-001", "OBS-004"],
  "contradicting_observations": [],
  "alternatives": ["browser-extension-tampering"],
  "missing_evidence": ["process-or-startup-artifact"],
  "recommended_actions": ["isolate-device", "offline-scan", "retest"]
}
```

## Report template

```markdown
# Asset Lighthouse Investigation Report

## Risk level
## Most likely root cause and confidence
## Confirmed facts
## Evidence list
## Alternative explanations and missing evidence
## Immediate containment
## Next read-only checks
## Remediation advice
## Retest method
## Escalation recommendation
```

## Sensitive-data handling

- Redact addresses, email addresses, phone numbers, hostnames, and account IDs as needed.
- Never write seed phrases, private keys, passwords, cookies, tokens, vault data, or recovery codes to case records.
- If a log unexpectedly contains a secret, record only "suspected credential found"; never repeat the original value in chat or reports.
- Before submitting samples or logs to an external platform, obtain explicit user authorization and re-check for sensitive data.
