# Remediation and Recovery Playbook

## Contents

- Immediate containment
- Evidence preservation
- Credential and wallet recovery
- Device cleanup
- Account and network recovery
- Retesting

## Immediate containment

- Stop signing, transferring, logging in, or entering sensitive information on the suspected device.
- If remote control, exfiltration, or account changes are ongoing, isolate the network and contact providers from a clean device.
- If an exchange, email, cloud, or SIM is compromised, prioritize freezing withdrawals, APIs, and recovery flows.
- Do not run a "revoke approval," "security upgrade," or support-provided script on the suspected device.

## Evidence preservation

- Record the timeline, symptoms, domains, file paths, extension IDs, account alerts, and reproduction steps.
- Preserve screenshots, logs, samples, and SHA-256 hashes; do not open or run samples.
- If professional forensics may be needed, do not delete files, clear the browser, factory-reset, or reinstall first.

## Credential and wallet recovery

- On a clean device, change email, exchange, password-manager, and cloud-account passwords, then revoke all sessions.
- Revoke API keys, app passwords, OAuth grants, remote access, and old recovery codes; configure independent 2FA again.
- If a seed phrase, private key, or wallet password was exposed, create a new wallet and migrate assets; do not reuse the old seed or copy old wallet data to the new system.
- If the only symptom is address replacement, do not claim that the seed was exposed, but still investigate for an infostealer.

## Device cleanup

- Prefer built-in or enterprise-approved security tools for full and offline scans.
- Record suspicious extensions, applications, startup items, or scheduled tasks before suggesting disablement, removal, or deletion.
- If driver-level bypass, system-process injection, persistent remote control, or an unresolved root cause is found, recommend backing up necessary non-executable files and reinstalling or factory-resetting.
- Do not restore old browser profiles, unknown scripts, wallet files, or suspicious backups directly to a new system.

## Account and network recovery

- Check email forwarding, recovery methods, withdrawal allowlists, cloud-sync devices, MFA, SIM/eSIM, and carrier transfer records.
- Remove unauthorized DNS, Hosts, proxy, VPN, root-certificate, or device-management settings.
- Reinstall browsers, wallets, and meeting tools from official websites or official app stores.

## Retesting

- Repeat the original reproduction steps with the same synthetic data.
- Compare a clean profile, clean user, or safe mode.
- Confirm that suspicious sessions, permissions, and persistence no longer appear.
- Complete a second independent security scan.
- If anomalies or unexplained outbound connections remain, do not declare the device safe; escalate to professional forensics or reinstall.
