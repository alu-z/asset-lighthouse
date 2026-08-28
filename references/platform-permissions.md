# Platform and Permission Checklist

## Contents

- Permission levels
- macOS
- Windows
- Linux
- Mobile
- Failure fallback

## Permission levels

### L0: No extra permission

- User description, timeline, screenshots, and synthetic-data reproduction.
- Extension lists, process lists, network summaries, and security alerts actively exported by the user.
- Official websites, software versions, file hashes, and configuration metadata.

### L1: Ordinary-user read-only (default)

- Processes, application versions, startup items, scheduled tasks, and browser-extension metadata visible to the current user.
- DNS, proxy, VPN, remote-session, and network-connection summaries visible to the current user.
- File names, timestamps, sizes, and hashes in the current user's directories; do not read sensitive file contents.

### L2: One-time, explicit authorization

Request the smallest privilege increase only when symptoms require it and L0/L1 cannot distinguish the root cause. Explain the scope, duration, and revocation method, and provide a manual alternative if authorization is denied.

- macOS: Full Disk Access, security logs, device-management metadata, or network-extension metadata.
- Windows: administrator-visible security logs, services, scheduled tasks, or protected-directory metadata.
- Linux: system services, logs, or network-namespace metadata.

L2 does not authorize reading passwords, Keychain, cookies, tokens, wallet vaults, or private keys.

### L3: Prohibited by default

- Reading or exporting passwords, cookies, session tokens, Keychain items, seed phrases, private keys, Keystore data, or wallet vaults.
- Enabling or using Input Monitoring, Screen Recording, or Accessibility to "observe user activity automatically."
- Bypassing system permissions, disabling security software, injecting processes, or executing unknown samples.

## macOS

Prefer ordinary-user-visible processes, login items, LaunchAgent metadata, application manifests, browser-extension metadata, DNS/proxy/VPN settings, and network-connection summaries. Do not make Full Disk Access or Keychain access prerequisites. For system logs, ask the user to export a redacted excerpt or explicitly authorize a one-time read.

## Windows

Prefer ordinary-user-visible processes, startup items, scheduled tasks, browser extensions, proxy/DNS settings, remote sessions, and Defender alerts. Request administrator access only when protected services or security logs are genuinely necessary.

## Linux

Prefer user processes, systemd user services, Cron, shell configuration, browser extensions, proxies, and network connections. System-level logs require separate authorization. Version 1 does not assume a distribution or desktop environment.

## Mobile

Rely on user self-checks: app source, photo/clipboard/accessibility/screen-recording/device-management/VPN permissions, and account sessions. Do not ask the user to grant remote control, screen recording, or full-backup access for ordinary triage.

## Failure fallback

Keep a "not executed" status when permission is insufficient and provide the smallest manual check. Do not replace missing evidence with higher privileges, and do not describe an unchecked item as "no anomaly found."
