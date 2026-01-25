# CraftedSignal CLI

Command-line tool for managing detection rules as code with bidirectional sync to CraftedSignal platform.

## Installation

Download from releases or build from source:

```bash
go install github.com/craftedsignal/cli/cmd/csctl@latest
```

## Configuration

Create `.csctl.yaml` in your repository root:

```yaml
url: https://your-craftedsignal-instance.com

defaults:
  path: detections/
  platform: splunk
```

Set your API token:

```bash
export CSCTL_TOKEN=your-api-token
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

## YAML Format

```yaml
id: 550e8400-e29b-41d4-a716-446655440000  # Auto-assigned on first push
title: Brute Force SSH Detection
platform: splunk
query: |
  index=auth sourcetype=sshd action=failure
  | stats count by src_ip
  | where count > 5
severity: high
enabled: true
frequency: 5m
period: 15m
tactics:
  - credential-access
techniques:
  - T1110.001
tags:
  - ssh
groups:
  - endpoint-threats
```

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
