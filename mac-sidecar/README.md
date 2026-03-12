# 🛡️ PII Sidecar Agent — macOS

Intercepts VS Code Copilot traffic and scrubs PII before it reaches GitHub's servers.

## Requirements

- macOS 12+ (Monterey or later)
- Python 3.10+
- mitmproxy

## Install

```bash
# Install mitmproxy
pip3 install mitmproxy

# Clone or copy sidecar files
mkdir -p /opt/company/piisidecar
cp sidecar_agent.py /opt/company/piisidecar/
```

## First Run (as sudo — needed to trust cert)

```bash
sudo python3 sidecar_agent.py
```

This will:
1. Generate mitmproxy CA cert at `~/.mitmproxy/`
2. Install it into macOS System Keychain automatically
3. Start the proxy on `http://localhost:7777`

## VS Code Settings

Open VS Code → `Cmd+Shift+P` → `Open User Settings JSON` and add:

```json
{
  "http.proxy": "http://localhost:7777",
  "http.proxyStrictSSL": false,
  "http.proxySupport": "override",
  "github.copilot.advanced": {
    "debug.overrideProxyUrl": "http://localhost:7777",
    "debug.testOverrideProxyUrl": "http://localhost:7777"
  }
}
```

Fully quit and reopen VS Code after saving.

## Auto-start on Login (via LaunchAgent)

```bash
# Copy plist to LaunchAgents
cp com.company.piisidecar.plist ~/Library/LaunchAgents/

# Edit plist — update PII_GATEWAY_URL to your company gateway
nano ~/Library/LaunchAgents/com.company.piisidecar.plist

# Load it
launchctl load ~/Library/LaunchAgents/com.company.piisidecar.plist

# Verify it's running
launchctl list | grep piisidecar
```

## View Logs

```bash
# Live log
tail -f ~/Library/Logs/PIISidecar/sidecar.log

# Or
tail -f /var/log/piisidecar/sidecar.log
```

## Deploy via Jamf (Enterprise)

1. Package `sidecar_agent.py` as a `.pkg` installer
2. Upload to Jamf Pro → Packages
3. Create a Jamf Policy to deploy to all Macs
4. Use a Jamf Configuration Profile to push the mitmproxy cert to all devices
5. Use a LaunchAgent script to auto-start on login

## Test PII Scrubbing

After starting the sidecar, open Copilot Chat in VS Code and type:
```
My email is test@company.com and SSN is 123-45-6789. Write hello world.
```

Check the sidecar terminal — you should see:
```
🔴 PII REMOVED | user=yourname | host=api.individual.githubcopilot.com | types=['EMAIL', 'SSN']
```

## Uninstall

```bash
# Stop and remove LaunchAgent
launchctl unload ~/Library/LaunchAgents/com.company.piisidecar.plist
rm ~/Library/LaunchAgents/com.company.piisidecar.plist

# Remove cert from keychain
sudo security delete-certificate -c "mitmproxy" /Library/Keychains/System.keychain

# Remove files
rm -rf /opt/company/piisidecar
```
