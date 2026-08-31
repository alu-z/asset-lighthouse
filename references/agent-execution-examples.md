# End-to-End Agent Invocation Examples

Use this file to verify that a host Agent can complete a safe triage without asking the user to run commands manually. Scripts run on demand only and are not a substitute for continuous monitoring.

## General execution order

1. Ask about the operating system, time of the anomaly, affected scope, and whether credentials were exposed to a suspicious environment.
2. If credentials were entered, remote control, ongoing exfiltration, or account takeover is suspected, provide containment steps first.
3. Explain the collection scope, then call `scripts/collect_local.py --platform auto`; the Agent may run read-only collection directly.
4. Select one to three relevant techniques from `behavior-taxonomy.md`, separating confirmed facts, hypotheses, and checks that were not executed.
5. Request an explicit confirmation before testing the clipboard, then call `clipboard_canary.py` with its built-in synthetic value or a user-provided public address (never a seed phrase or private key).
6. Output the risk level, evidence, alternative explanations, remediation, and next read-only checks.

## Scenario A: Suspected clipboard hijacking

**Example user request**:

> I copy a wallet address on my Mac, but the pasted address sometimes changes. Please investigate.

**The Agent should**:

- Recommend stopping transactions and ask whether a seed phrase or private key was entered on the suspected device.
- Run the read-only collector automatically, focusing on processes, startup items, and browser extensions.
- Explain that the clipboard test temporarily writes a synthetic or user-provided public address and obtain confirmation before running `clipboard_canary.py`.

**Assessment requirements**:

- If replacement reproduces across multiple applications, treat a clipboard clipper as a high-priority hypothesis.
- If only one webpage is affected, retain webpage or extension tampering as an alternative explanation.
- If a script was not run or was permission-denied, mark the check as unverified; do not report "no anomaly found."

## Scenario B: Suspected infostealer after software installation

**Example user request**:

> I downloaded a wallet tool from a search advertisement, and several accounts later reported logins from unknown locations.

**The Agent should**:

- Recommend disconnecting or isolating the device and stop logging in to high-value accounts.
- Run the basic read-only collector automatically; use `--profile network` only when DNS/proxy context is useful and after explaining the additional network metadata collected.
- Do not read browser passwords, cookies, wallet directories, or Keychain contents.

**Assessment requirements**:

- Treat an infostealer or trojanized installer as the primary hypothesis and state evidence gaps.
- On a clean device, rotate passwords, tokens, API keys, and 2FA; if wallet keys may have been exposed, recommend migrating to a new wallet.
- Do not uninstall, clean, or reinstall automatically unless the user separately authorizes it.

## Scenario C: Browser extension or DApp interaction anomaly

**Example user request**:

> Only one wallet website in Chrome shows the wrong recipient address; other applications are normal.

**The Agent should**:

- Route first to malicious extensions, frontend tampering, blind signing, and DNS/proxy anomalies.
- Collect extension-directory metadata automatically and guide the user to verify extension ID, publisher, version, and source.
- Compare with a clean browser profile or an asset-free wallet; do not enter real credentials or sign anything.

**Assessment requirements**:

- Do not classify a system-level malware infection from a single-browser symptom alone.
- If the webpage and wallet confirmation differ, stop signing immediately and preserve page/request evidence.
- Version 1 does not query on-chain approvals, balances, transactions, or fund flows.

## Host capability fallback

- With terminal access: the Agent calls the scripts and parses JSON directly.
- With file access only: the Agent reads redacted results actively exported by the user; do not request secrets.
- Without local capabilities: provide a manual read-only checklist and explicitly state "local collection not executed."

## Acceptance criteria

An end-to-end invocation must satisfy at least the following:

- The user did not copy and paste commands.
- Read-only collection did not request administrator, root, or full-disk access.
- An explicit confirmation appeared before a live clipboard test and the overwrite/non-restore behavior was disclosed.
- The output contains the risk level, evidence, alternatives, containment, and next steps.
- All not-executed, failed, and permission-denied states are recorded truthfully.
