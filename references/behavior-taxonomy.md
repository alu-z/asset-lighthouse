# Typical Crypto-Theft Technique Rules

## Contents

1. Clipboard hijacking / address replacement
2. Infostealers
3. Malicious browser extensions
4. Supply-chain attacks
5. Malicious development tools
6. Social engineering and phishing
7. Frontend, signing, and address poisoning
8. Seed/private-key storage attacks
9. Mobile attacks
10. Institutional frontend supply-chain compromise
11. DNS, Hosts, proxy, and malicious VPN hijacking
12. WalletConnect, Deep Link, and QR-session hijacking
13. Exchange, email, MFA, and API takeover
14. Remote control, remote desktop, and screen sharing
15. Public Wi-Fi and Evil Twin
16. Password managers, cloud backups, and browser sync
17. MDM, proxy certificates, and device-management policies
18. Physical tampering and fake hardware wallets
19. Smart-wallet modules and Session Keys
20. Social accounts, support recovery, and SIM Swap

Read only the entries relevant to the current symptoms. Each entry includes the technique, indicators, safe checks, and remediation focus.

## 1. Clipboard hijacking / address replacement (Clipper)

**Technique**: A background process monitors the clipboard and replaces cryptocurrency addresses or payment accounts with an attacker-controlled address; variants may use similar prefixes/suffixes or alter webpage DOM content.

**Indicators**: Pasted content differs from the copied value; the replacement is a valid-looking address with similar leading/trailing characters; the behavior reproduces across multiple applications.

**Check**: Use the built-in synthetic value or an explicitly supplied public address, paste it into a text editor and browser address bar, compare character by character, and determine whether all applications or only one webpage is affected. Never use a seed phrase or private key as test input.

**Remediation focus**: Stop transactions and isolate the device; handle assets from a clean device; perform an offline malware scan; if sensitive credentials may have been exposed, create a new wallet.

## 2. Infostealers

**Technique**: Malware scans browser passwords, cookies, autofill data, wallet data, desktop wallets, chat sessions, screenshots, and documents, then quickly packages and exfiltrates them.

**Indicators**: A non-browser process reads browser or wallet directories; an archive is created and an unusual outbound connection occurs shortly afterward; multiple accounts show unfamiliar logins or invalidated sessions.

**Check**: Review when suspicious software ran; inspect security alerts, unusual connections, processes, startup items, scheduled tasks, and recent files; do not open wallet databases to validate a theory.

**Remediation focus**: Isolate the device; from a clean device rotate passwords, tokens, API keys, and 2FA; if wallet keys may be exposed, create a new wallet; reinstall when necessary.

## 3. Malicious browser extensions

**Technique**: An extension impersonates a wallet or security tool, or a developer account is taken over or a legitimate extension is purchased and updated with malicious code. Existing privileges are reused to steal or alter content.

**Indicators**: An unfamiliar extension; an abnormal publisher or version; altered webpage, address, or wallet prompts; symptoms disappear when the extension is disabled.

**Check**: Verify extension ID, publisher, source, version, and permissions; record them before disabling nonessential extensions one at a time; compare with a clean browser profile.

**Remediation focus**: Stop transactions; disable sync; remove the malicious extension and reinstall from the official source; treat any seed, private key, or password entered while it was active as exposed.

## 4. Supply-chain attacks

### 4.1 npm/PyPI and other open-source package poisoning

**Technique**: An attacker compromises a maintainer or project account and injects install scripts, credential theft, or self-replicating code into a dependency.

**Indicators**: Unexpected network access, downloads, child processes, or sensitive-file reads during installation/build; sudden changes to versions, publishers, or lockfiles.

**Check**: Review lockfile and dependency changes and audit install/build scripts; observe behavior in an isolated environment with no secrets.

**Remediation focus**: Stop builds and releases; rotate source-control, package-registry, cloud, and CI/CD credentials; roll back to a trusted version and inspect repositories, workflows, and artifacts.

### 4.2 Fake download sites and trojanized installers

**Technique**: Search ads, lookalike domains, or crack sites distribute modified installers that add credential theft, remote control, or persistence during installation.

**Indicators**: Non-official source; invalid or unexpected digital signature; process injection, startup entries, shortcut arguments, unusual outbound connections, or disabled security software after installation.

**Check**: Verify the domain, digital signature, and official hash; compare processes, services, startup items, and network connections before and after installation.

**Remediation focus**: Isolate the device; uninstall the fake software and run an offline scan; rotate credentials; consider reinstalling when system injection or security bypass is present.

## 5. Malicious development tools: IDE extensions and fake SDKs

**Technique**: A malicious IDE extension, SDK, or CLI steals source code, environment variables, SSH keys, cloud credentials, or wallet configuration when installed, launched, or used to open a workspace.

**Indicators**: An unusual publisher or version; a payload download or unknown process starts after opening a project; reads of `.env`, `.ssh`, cloud, or Kubernetes configuration; obfuscation or hidden Unicode.

**Check**: Verify extension ID, publisher, version, and source; inspect activation scripts; observe file reads, child processes, and connections in an isolated environment without keys.

**Remediation focus**: Stop builds and releases; rotate development, cloud, and CI/CD credentials; clean IDE configuration and reinstall from official sources; inspect repositories and artifacts for tampering.

## 6. Social engineering and phishing: fake support, recruiting, meetings, and security upgrades

**Technique**: An attacker impersonates a recruiter, investor, support agent, or acquaintance and persuades the user to open a fake meeting, download a patch, run a script, paste a command, or grant remote control.

**Indicators**: Lookalike domains; requests to disable protection, run PowerShell/AppleScript/bash, enable screen sharing, or download an unknown file.

**Check**: Verify identity through a second channel; inspect domains, signatures, downloads, and script-execution records; treat any "press Win+R and paste this verification" instruction as high risk.

**Remediation focus**: Stop communicating and isolate the device; terminate remote access; rotate accounts and keys from a clean device; treat an executed script as a high-risk infection.

## 7. Frontend, signing, and address poisoning

### 7.1 Drainers, malicious approvals, Permit, and blind signing

**Technique**: A malicious or compromised DApp persuades the user to sign Permit, Permit2, `setApprovalForAll`, `setOwner`, EIP-7702 delegation, or an unreadable message.

**Indicators**: The signature is unrelated to the current action; the wallet displays only a hash; the spender, operator, owner, deadline, or delegate is unexpected; the webpage differs from the wallet confirmation.

**Check**: Verify the domain and complete signing request; observe with an asset-free wallet and a trusted simulation interface without signing; keep the assessment at the local interaction layer and do not query blockchain data.

**Remediation focus**: Disconnect the suspicious DApp; handle approvals and sessions from a clean device; preserve signing-request and page evidence; create a new wallet if keys were exposed.

### 7.2 Address poisoning

**Technique**: Attackers generate addresses with similar prefixes/suffixes and use zero-value or small transfers and lookalike tokens to pollute transaction history, hoping the victim copies the wrong address.

**Indicators**: Unfamiliar zero-value transfers, dust transfers, or lookalike tokens in history; an address resembles a frequently used address at the beginning and end.

**Check**: Never copy from transaction history; verify the complete address using an address book or a trusted second channel. Version 1 only guides recognition and does not query chain history.

**Remediation focus**: Stop the transfer; flag suspicious historical addresses; use an address book or allowlist; if a transfer was sent, contact the provider immediately and preserve records.

## 8. Seed and private-key storage attacks

**Technique**: A malicious app or trojan steals seed phrases through photo OCR, file scanning, clipboard access, keyboard-cloud sync, cloud notes, screenshots, fake hardware wallets, or physical phishing.

**Indicators**: An unrelated app requests photo, file, or clipboard access; the seed was photographed, screenshotted, copied, or uploaded; hardware-wallet source or initialization is abnormal.

**Check**: Review permissions, cloud sessions, sync settings, and hardware provenance; do not reopen, copy, or export the seed to validate a theory.

**Remediation focus**: Treat any digitization or suspicious input as possible exposure; create a new wallet on a clean device; disable unnecessary permissions and cloud sync; verify or replace the hardware device.

## 9. Mobile attacks

**Technique**: Fake wallets, malicious SDKs, clipboard readers, photo scanners, Android Accessibility abuse, overlays, recording, and remote control steal or operate wallets.

**Indicators**: An unknown app source; unrelated permissions; overlays, automatic clicks, screen sharing, address replacement, or unusual battery/network use.

**Check**: Verify the official link, developer, and package name; inspect Accessibility, device-management, recording, profile, VPN, and photo permissions; never enter a real seed for testing.

**Remediation focus**: Uninstall suspicious apps and revoke permissions; rotate accounts; create a new wallet if credentials may be exposed; if cleanup cannot be confirmed, factory-reset without restoring suspicious backups.

## 10. Institutional frontend supply-chain compromise and blind signing

**Technique**: An attacker compromises a developer endpoint or cloud token, tampers with a hosted frontend, shows a normal interface only to a targeted institution or multisig flow, and constructs a malicious request.

**Indicators**: Anomalies on developer endpoints; unauthorized cloud-token, IAM, MFA, S3, or CDN changes; build-artifact hash mismatch; webpage summary differs from the actual confirmation.

**Check**: Review endpoint, cloud audit, CI/CD, S3/CDN, and build hashes; verify transaction intent through an independent device and channel. Version 1 does not analyze on-chain calldata.

**Remediation focus**: Pause signing, withdrawals, and releases; revoke cloud tokens; isolate developer endpoints; rebuild the frontend from a trusted environment; escalate to institutional incident response.

## 11. DNS, Hosts, proxy, and malicious VPN hijacking

**Technique**: DNS, Hosts, proxy, VPN, or root-certificate settings are altered to redirect users to fake websites or modify communications.

**Indicators**: A correct URL redirects to an unfamiliar domain; certificate warnings; changed configuration; multiple devices on the same network show anomalies.

**Check**: Compare DNS, Hosts, proxy, VPN, and certificates with a trusted device; retest on a trusted network.

**Remediation focus**: Disconnect the suspicious network; remove malicious settings and inspect the router; rotate accounts from a clean network; reinstall or reset if the cause cannot be confirmed.

## 12. WalletConnect, Deep Link, and QR-session hijacking

**Technique**: A malicious DApp, QR code, or Deep Link establishes a long-lived wallet connection that continues to request signatures or launch the wallet.

**Indicators**: An unfamiliar session; requests continue after closing the webpage; an unknown QR source; frequent signing prompts.

**Check**: Review wallet sessions, connected sites, sources, and network context; retest with an asset-free wallet without signing.

**Remediation focus**: Disconnect unfamiliar sessions; handle approvals and accounts from a clean device; create a new wallet if a seed or private key was entered.

## 13. Exchange, email, MFA, and API takeover

**Technique**: An attacker takes over email, a phone number, an exchange account, or an API key and changes withdrawal allowlists, recovery methods, or account actions.

**Indicators**: Unauthorized changes to logins, devices, API keys, withdrawal addresses, MFA, recovery email, or forwarding rules.

**Check**: Review security logs, devices, sessions, API permissions, withdrawal allowlists, and account-change history.

**Remediation focus**: Contact the provider to freeze withdrawals; rotate passwords, API keys, and 2FA from a clean device; remove email rules and recovery changes while preserving logs.

## 14. Remote control, remote desktop, and screen sharing

**Technique**: Remote-control software, system remote desktop, or meeting screen sharing operates the wallet and accounts inside the user's real session.

**Indicators**: Unknown remote-control software, remote logins, abnormal mouse or window activity, clipboard control; symptoms stop after remote access is disabled.

**Check**: Review remote-control applications, services, current sessions, login logs, and security alerts.

**Remediation focus**: Disconnect the network and terminate remote sessions; rotate accounts; remove remote-control software and persistence; reinstall if cleanup cannot be confirmed.

## 15. Public Wi-Fi, Evil Twin, and captive portals

**Technique**: An attacker creates a same-name hotspot and fake authentication page, then uses malicious DNS or pages to solicit account and wallet information.

**Indicators**: A same-name hotspot, forced redirects, certificate anomalies; multiple websites behave abnormally after connecting.

**Check**: Switch to cellular data or a trusted network; verify the Wi-Fi name, authentication-page domain, and certificate.

**Remediation focus**: Disconnect and forget the hotspot; rotate accounts and sessions on a trusted network; never enter wallet secrets on public networks.

## 16. Password managers, cloud backups, and browser sync

**Technique**: An attacker takes over a cloud account, password manager, or browser sync and obtains passwords, wallet backups, cookies, extensions, or autofill data.

**Indicators**: Unknown devices, abnormal sync, backup downloads, shared links, or vault access; extensions reappear automatically.

**Check**: Review login devices, sessions, sync, sharing, recovery methods, and export history; do not open sensitive backup contents.

**Remediation focus**: Change the master password and revoke sessions; remove sharing and recovery codes; create a new wallet if a seed or private key reached the cloud.

## 17. MDM, proxy certificates, and device-management policies

**Technique**: Malicious MDM, profiles, root certificates, VPNs, or enterprise policies force-install extensions, intercept traffic, or control settings.

**Indicators**: Unknown management profiles, root certificates, VPNs, proxies, or non-removable policies; applications and extensions return automatically.

**Check**: Review work/school accounts, profiles, device management, root certificates, and proxies, and verify with a trusted administrator.

**Remediation focus**: Stop using sensitive accounts; have a trusted administrator remove the policy; reset or reinstall if it cannot be confirmed; rotate credentials.

## 18. Physical tampering and fake hardware wallets

**Technique**: An unofficial device, malicious firmware, repair, or giveaway supplies a pre-generated seed or steals keys during initialization.

**Indicators**: Unknown source, abnormal packaging, a seed shown before initialization, inability to initialize randomly, or failed official firmware verification.

**Check**: Verify the seller, serial number, packaging, and official checks; confirm the device generates the seed randomly for the first time rather than accepting one supplied by the seller.

**Remediation focus**: Stop using the device and contact the vendor; replace it; migrate any wallet used with it to a new seed.

## 19. Smart-wallet modules, Session Keys, and automation permissions

**Technique**: A malicious DApp persuades the user to grant a long-lived Session Key, wallet module, or automation permission that can act without a prompt each time.

**Indicators**: An unfamiliar module, session key, authorized device, or automation policy; scope, duration, or limits exceed the task.

**Check**: Review modules, connections, and automation permissions through the wallet's trusted interface; version 1 does not query on-chain state.

**Remediation focus**: Disable unfamiliar permissions and sessions from a clean device; create a new wallet if control cannot be confirmed; preserve authorization pages and prompts.

## 20. Social accounts, support recovery, and SIM Swap

**Technique**: An attacker takes over a phone number, email, social account, or support channel and impersonates the user to reset passwords, unlink devices, withdraw funds, or recover accounts.

**Indicators**: Sudden loss of mobile service; changed SIM/eSIM, recovery information, or account settings; unexpected codes, reset notices, or fake support messages.

**Check**: Ask the carrier to confirm SIM replacement, number porting, and eSIM records; review provider recovery records, devices, sessions, and support tickets.

**Remediation focus**: Freeze porting and recovery flows; rotate accounts and use a hardware security key; contact the exchange to freeze withdrawals; migrate wallet assets if recovery information was exposed.
