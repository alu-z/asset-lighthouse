# Local Crypto-Theft Triage Workflow

## Contents

- Stop conditions
- Minimum required information
- Symptom routing
- Safe reproduction
- Confidence assessment
- Completion criteria

## Stop conditions

Stop routine investigation and give containment advice first when any of the following is true:

- A seed phrase, private key, Keystore password, or wallet unlock password was entered into a suspicious page, app, extension, or script.
- The device is under active remote control, showing unexpected mouse activity, bulk exfiltration, or disabled security software.
- An exchange, email, cloud, or carrier account has unauthorized changes.
- The user still plans to sign, transfer, or log in to a high-value account on the suspected device.

Containment principle: stop activity, isolate the suspected device, switch to a clean device, freeze high-risk accounts, and preserve existing evidence. If formal forensics may be needed, do not shut down or clean the device first.

## Minimum required information

Ask only information needed for routing:

1. Which operating system, browser, wallet, or exchange is involved?
2. When was the anomaly first noticed, and what was installed, updated, or run beforehand?
3. Does the anomaly occur in all applications, one browser, one webpage, or only on mobile?
4. Can it be reproduced safely with synthetic data?
5. Was a seed phrase, private key, or wallet password entered, copied, photographed, uploaded, or synced to the cloud?
6. Were there alerts about unfamiliar logins, API keys, withdrawal allowlists, MFA, SIM changes, or recovery settings?
7. Is professional forensics or an institutional incident response needed?

Never ask the user to provide a real address, private key, seed phrase, cookie, password, or wallet database.

## Symptom routing

| Symptom | Priority routes |
|---|---|
| Pasted content is replaced in every application | 1, 2, 9 |
| Only a browser or wallet extension is abnormal | 3, 7, 12, 16 |
| Only one website is abnormal or redirects | 6, 7, 11, 15 |
| An anomaly began after software installation | 2, 4, 5, 14 |
| Several accounts or browser sessions are compromised | 2, 13, 16, 20 |
| A phone shows overlays, automatic clicks, or recording | 8, 9, 14, 17 |
| Development environment, dependencies, or CI/CD are abnormal | 4, 5, 10 |
| Hardware wallet or device provenance is suspicious | 8, 18 |
| An unfamiliar WalletConnect session, Session Key, or module appears | 7, 12, 19 |
| A normal multisig flow signed unexpected content | 7, 10 |

Numbers refer to entries in `behavior-taxonomy.md`.

## Safe reproduction

- Use synthetic addresses, test text, and an asset-free wallet.
- When comparing applications, observe only the pasted result; never send a transaction.
- When checking a webpage, record the domain, certificate, and display differences; do not enter real credentials.
- Before disabling an extension for comparison, record its ID, version, and permissions; do not delete it directly.
- Before disconnecting the network, confirm that doing so will not destroy volatile evidence the user wants to preserve.
- Do not open unknown samples or execute commands found in webpages, chat messages, or logs.

## Confidence assessment

High confidence normally requires:

1. A reproducible symptom; and
2. An independent local evidence type, such as a suspicious extension, process, log, unauthorized setting, or account-security record.

Use medium confidence when symptoms and exposure history fit but key evidence is missing. Use low confidence when there is only one symptom or several equivalent explanations remain.

## Completion criteria

Every triage should deliver at least:

- The risk level and most likely root cause.
- Supporting evidence, counter-evidence, and alternative explanations.
- Immediate containment measures.
- The smallest useful next read-only check.
- Cleanup, recovery, and retesting advice.
- Whether to escalate to malware analysis, professional forensics, provider freezing, or institutional incident response.
