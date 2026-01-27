# CraftedSignal CLI

Command-line tool for managing detection rules as code with bidirectional sync to your CraftedSignal platform.

## Installation

Download from [the GitHub releases](https://github.com/CraftedSignal/cli/releases), [pull the container image](https://github.com/orgs/CraftedSignal/packages?repo_name=cli) or install from source yourself:

```bash
go install github.com/craftedsignal/cli/cmd/csctl@latest
```

## Configuration

Create `.csctl.yaml` in your repository root:

```yaml
# if not using CraftedSignal SaaS, specify your endpoint
url: https://your-craftedsignal-instance.com

# your API token (or use env variable CSCTL_TOKEN)
token: ""

defaults:
  # the directory of your ruleset to sync
  path: detections/
  # default platform to assume for rules
  platform: splunk
```

## Usage

### Push local rules to platform

```bash
csctl push                          # Push all rules
csctl push -m "Deploy Q1 rules"     # With version comment
csctl -dry-run push                 # Preview changes
```

### Pull rules from platform

```bash
csctl pull                          # Pull all rules
csctl pull -group endpoint-threats  # Pull specific group
```

### Sync (bidirectional)

```bash
csctl sync                          # Fails on conflicts (exit code 2)
csctl sync -resolve=local           # Keep local changes on conflict
csctl sync -resolve=remote          # Keep platform changes on conflict
```

### Validate YAML files

```bash
csctl validate
```

### Check authentication

```bash
csctl auth
```

### Initialize project

```bash
csctl init                          # Create example structure
csctl init -from-platform           # Bootstrap from existing rules
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Conflicts detected |

## Rule Format

Detection rules are defined in YAML files. Here's a complete example:

### Splunk Example

```yaml
id: 550e8400-e29b-41d4-a716-446655440000  # Auto-assigned on first push
title: Brute Force SSH Detection
platform: splunk
description: |
  Detects multiple failed SSH login attempts from a single source IP,
  which may indicate a brute force attack against SSH services.

query: |
  index=auth sourcetype=sshd action=failure
  | stats count by src_ip
  | where count > 5


kind: scheduled
severity: high
enabled: true
frequency: 5m
period: 15m
tactics: [credential-access]
techniques: [T1110.001]
tags: [ssh, brute-force]
groups: [endpoint-threats]

tests:
  positive:
    - name: Multiple failed logins from single IP
      description: 6 failed SSH attempts should trigger detection
      data:
        - { src_ip: "10.0.0.50", action: "failure", user: "admin" }
        - { src_ip: "10.0.0.50", action: "failure", user: "root" }
        - { src_ip: "10.0.0.50", action: "failure", user: "admin" }
        - { src_ip: "10.0.0.50", action: "failure", user: "test" }
        - { src_ip: "10.0.0.50", action: "failure", user: "admin" }
        - { src_ip: "10.0.0.50", action: "failure", user: "guest" }
  negative:
    - name: Normal failed login
      description: Single failed login should not trigger
      data:
        - { src_ip: "192.168.1.10", action: "failure", user: "admin" }
    - name: Successful logins
      description: Successful logins should not trigger
      data:
        - { src_ip: "10.0.0.50", action: "success", user: "admin" }
        - { src_ip: "10.0.0.50", action: "success", user: "admin" }
```

### Microsoft Sentinel Example

```yaml
title: Suspicious PowerShell Execution
description: Detects encoded PowerShell commands commonly used by attackers.
platform: sentinel
kind: scheduled
query: |
  SecurityEvent
  | where EventID == 4688
  | where CommandLine contains "-enc" or CommandLine contains "-EncodedCommand"
  | project TimeGenerated, Computer, Account, CommandLine
severity: medium
enabled: true
frequency: 15m
period: 1h
tactics:
  - execution
  - defense-evasion
techniques:
  - T1059.001
  - T1027
tags:
  - powershell
  - living-off-the-land
tests:
  positive:
    - name: Encoded PowerShell command
      description: Base64 encoded command should trigger detection
      data:
        - EventID: 4688
          Computer: "WORKSTATION01"
          Account: "DOMAIN\\user"
          CommandLine: "powershell.exe -enc SGVsbG8gV29ybGQ="
  negative:
    - name: Normal PowerShell
      description: Regular PowerShell without encoding should not trigger
      data:
        - EventID: 4688
          Computer: "WORKSTATION01"
          Account: "DOMAIN\\admin"
          CommandLine: "powershell.exe -File script.ps1"
    - name: Other process
      description: Non-PowerShell process should not trigger
      data:
        - EventID: 4688
          Computer: "WORKSTATION01"
          Account: "DOMAIN\\user"
          CommandLine: "cmd.exe /c dir"
```

### Field Reference

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | UUID assigned on first push (leave empty for new rules) |
| `title` | Yes | Human-readable rule name |
| `description` | No | Detailed explanation of what the rule detects |
| `platform` | Yes | Target SIEM: `splunk`, `sentinel`, `elastic` |
| `kind` | No | Rule type: `scheduled` (default), `realtime`, `correlation` |
| `query` | Yes | Detection query in platform-native syntax |
| `severity` | No | Alert priority: `low`, `medium`, `high`, `critical` |
| `enabled` | Yes | Whether the rule is active |
| `frequency` | No | How often to run (e.g., `5m`, `1h`) |
| `period` | No | Time window to search (e.g., `15m`, `24h`) |
| `tactics` | No | MITRE ATT&CK tactics (lowercase, hyphenated) |
| `techniques` | No | MITRE ATT&CK technique IDs (e.g., `T1059.001`) |
| `tags` | No | Custom labels for filtering/organization |
| `groups` | No | Detection groups for logical organization |
| `tests` | No | Test cases with positive (should match) and negative (should not match) samples |

## Folder Structure

Folder names automatically become groups:

```
detections/
  endpoint-threats/
    brute-force-ssh.yaml    # -> groups: [endpoint-threats]
  network/
    c2-beacon.yaml          # -> groups: [network]
```

## TLS Verification

To skip TLS certificate verification (for self-signed certs):

```bash
csctl -insecure push
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Deploy Detections

on:
  push:
    branches: [main]
    paths:
      - 'detections/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install csctl
        run: |
          curl -sL https://github.com/CraftedSignal/cli/releases/latest/download/csctl_linux_amd64.tar.gz | tar xz
          sudo mv csctl /usr/local/bin/

      - name: Validate
        run: csctl validate detections/

      - name: Sync detections
        run: csctl sync -m "Deploy from ${{ github.sha }}"
        env:
          CSCTL_TOKEN: ${{ secrets.CSCTL_TOKEN }}
```
