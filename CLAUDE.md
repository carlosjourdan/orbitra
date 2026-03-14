# Orbitra Workspace Setup

## Azure CLI

Install via pip (uv tool doesn't work due to namespace package issues):

```bash
pip install --break-system-packages --ignore-installed argcomplete azure-cli
```

## Network Diagnostics

### Local HTTP Proxy (port 18080)

Forwards through the upstream `GLOBAL_AGENT_HTTP_PROXY` with request/response logging.

```bash
python3 http_proxy.py &
```

### Local DNS Server (port 15353)

Resolves via direct UDP (8.8.8.8/8.8.4.4) with fallback to proxy-based resolution.

```bash
python3 dns_server.py &
```

### Logs

```bash
tail -f logs/http_proxy.log logs/dns_server.log
```

## Azure Login

The Claude Code web proxy must have `login.microsoft.com` and `login.microsoftonline.com` in the allowed hosts whitelist. This is configured in the Claude workspace settings and requires a **new session** to take effect (the JWT is fixed per session).

```bash
az login --use-device-code &
```

Then open https://login.microsoft.com/device and enter the code shown in the output.
