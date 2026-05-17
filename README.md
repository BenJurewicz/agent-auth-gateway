# Auth Proxy

A secure credential gate that sits between an AI agent and any service that needs
authentication. Holds all credentials (SSH keys, API tokens, service account keys)
on a dedicated machine and requires explicit Telegram approval before every
privileged operation.

## Architecture

```
 ┌─────────────────────────┐   POST /gate/{svc}/{act}   ┌──────────────────────────┐
 │   AI Agent (remote VM)  │ ─────────────────────────▶  │  Auth Proxy (gate host)  │
 │                         │                            │                          │
 │  - Has no credentials   │  ◀────────────────────────  │  - Holds ALL credentials │
 │  - Delegates to proxy   │   {success, output, ...}   │  - Service plugin system │
 │  - Receives results     │                            │  - Request store + auth  │
 └─────────────────────────┘                            └──────────┬───────────────┘
                                                                   │
                                                    ┌──────────────┴───────────────┐
                                                    │        Telegram Bot          │
                                                    │                              │
                                                    │  "git push to repo/main?     │
                                                    │   [✅ Approve]  [❌ Deny]    │
                                                    │                              │
                                                    │       Authorized User        │
                                                    └──────────────────────────────┘
```

**Key security properties:**

- Credentials **never leave** the gate machine.
- The AI agent cannot bypass approval — it doesn't have the keys.
- Each operation shows enough context to make an informed decision.
- Adding a new service is a single file: subclass `BaseService`, add `@service("name")`.

## Supported Services

| Service | Action   | Description                                      |
|---------|----------|--------------------------------------------------|
| `git`   | `fetch-bundle` | Download a git bundle for local clone/fetch |
| `git`   | `push-bundle`  | Upload a local git bundle and push it       |
| `git`   | `clear-cache`  | Remove all cached bare repos from the gateway |
| `github` | `list-repos` | List repositories visible to the GitHub token |
| `github` | `create-repo` | Create a GitHub repository                  |
| `github` | `create-pr`   | Create a GitHub pull request                |

Only SSH git URLs are allowed (`git@github.com:user/repo.git` or `ssh://`).

## Adding a New Service

Services are plugins in `services/*.py`. To add one:

```python
from services import BaseService, service

@service("my-service")
class MyService(BaseService):

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        """Raise ValueError on bad parameters."""
        pass

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        """Execute the action. Return {success, output, exit_code}."""
        pass

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        """Markdown-formatted Telegram approval message."""
        return "..."
```

The service is auto-discovered via the `@service` decorator. No other registration needed.

## Deployment

The proxy runs on a dedicated machine (Proxmox LXC, dedicated VM, Raspberry Pi, etc.)
with Debian 12 or Ubuntu 22.04+.

### Prerequisites

- Debian 12 or Ubuntu 22.04+ machine (1 CPU core, 512 MB RAM is plenty)
- Internet access (for pip packages and Telegram API)
- A Telegram bot token from [@BotFather](https://t.me/BotFather)
- Your Telegram user ID from [@userinfobot](https://t.me/userinfobot)
- (For git service) An SSH deploy key with access to your repositories

### Quick Setup

```bash
# 1. Install system dependencies
apt update && apt install -y python3 python3-pip python3-venv git openssh-client curl

# 2. Clone the repo and set up venv
cd /opt
git clone https://github.com/BenJurewicz/agent-auth-gateway.git
cd agent-auth-gateway
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Configure
cp config.yaml.example config.yaml
nano config.yaml
```

Required config fields:

```yaml
api:
  auth_token: "generate-a-random-string"    # Shared secret with the AI agent

telegram:
  bot_token: "1234567890:ABC-DEF..."        # From @BotFather
  allowed_user_ids:                          # From @userinfobot
    - 123456789

services:
  git:
    ssh_key_path: "~/.ssh/id_ed25519"       # Deploy key to access repos
```

```bash
# 4. Add an SSH deploy key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
cat ~/.ssh/id_ed25519.pub
# Add the public key to your GitHub account or repo deploy keys

# Accept GitHub's host key
ssh -o StrictHostKeyChecking=accept-new -T git@github.com

# 5. Start the server (foreground test)
source venv/bin/activate
AUTH_PROXY_TOKEN="your-secret" python auth-proxy-server.py
```

### Testing

The server starts on port 8443 by default. Test it from another terminal:

```bash
# Console approval mode (for testing, no Telegram needed)
nano config.yaml  # set approval.mode: console

# Restart the server, then:
python auth-proxy-client.py --proxy-url http://localhost:8443 \
  --auth-token "your-secret" health

# Test a git clone via bundle transport
mkdir -p /tmp/test-proxy
python auth-proxy-client.py --proxy-url http://localhost:8443 \
  --auth-token "your-secret" fetch-bundle \
  --repo git@github.com:github/gitignore.git \
  --target-dir /tmp/test-proxy/gitignore \
  --branch main \
  --details "Testing the proxy"
```

After approving in the server console, verify the clone:

```bash
ls /tmp/test-proxy/gitignore/
```

### Systemd Service (Production)

```bash
# Edit config back to telegram mode
nano config.yaml  # set approval.mode: telegram

# Stop the foreground server (Ctrl+C) and create the service
cat > /etc/systemd/system/agent-auth-gateway.service << 'SERVICE'
[Unit]
Description=Agent Auth Gateway — credential gate with Telegram approval
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/agent-auth-gateway/venv/bin/python /opt/agent-auth-gateway/auth-proxy-server.py
WorkingDirectory=/opt/agent-auth-gateway
Restart=on-failure
RestartSec=5
User=root
Group=root
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable --now agent-auth-gateway
systemctl status agent-auth-gateway

# View logs
journalctl -u agent-auth-gateway -f
```

> **Note:** `PrivateTmp=yes` is intentionally omitted from the service unit.
> It isolates `/tmp` and causes git clone targets to land in a private namespace
> invisible to the client. The agent needs to see the cloned output.

## Configuration

### config.yaml

```yaml
server:
  host: "0.0.0.0"
  port: 8443

api:
  auth_token: "your-random-secret"       # Shared with the AI agent

telegram:
  bot_token: "123456:ABC-DEF..."         # From @BotFather
  allowed_user_ids:
    - 123456789                           # the user's Telegram user ID

approval:
  mode: "telegram"                       # "telegram" | "console" | "auto"
  timeout: 300                           # Seconds before request expires

services:
  git:
    enabled: true
    ssh_key_path: "~/.ssh/id_ed25519"    # the user's GitHub SSH key
    timeout: 120
```

### Environment Variables (override config)

| Variable | Overrides | Description |
|----------|-----------|-------------|
| `AUTH_PROXY_TOKEN` | `api.auth_token` | API auth token |
| `AUTH_PROXY_TELEGRAM` | `telegram.bot_token` | Telegram bot token |
| `AUTH_PROXY_DEBUG` | — | Set to enable `/docs` Swagger UI |

### Approval Modes

| Mode       | Description                                                 |
|------------|-------------------------------------------------------------|
| `telegram` | Sends approval via Telegram with inline buttons (default)   |
| `console`  | Prompts for approval on stdin (useful for testing)          |
| `auto`     | Auto-approves all requests (⚠️ only for trusted environments) |

### Getting Your Telegram User ID

1. Message [@userinfobot](https://t.me/userinfobot) on Telegram
2. It will reply with your numeric user ID
3. Add that ID to `allowed_user_ids` in the config

## Usage

### From the AI Agent (Python library)

```python
from auth_proxy_client import AuthProxyClient

proxy = AuthProxyClient(
    proxy_url="http://auth-proxy.lxc:8443",   # Proxmox LXC IP
    auth_token="your-secret-token",
)

# ── Git bundle transport ──
result = proxy.git_fetch_bundle(
    repo="git@github.com:user/private-repo.git",
    target_dir="/home/agent/projects/private-repo",
    branch="main",
    details="Clone private repo locally",
)
print(result["output"])

result = proxy.git_push_bundle(
    repo="git@github.com:user/my-project.git",
    workdir="/home/agent/projects/my-project",
    branch="main",
    details="Auto-generated feature X",
)

# ── Any service (generic) ──
result = proxy.gate("git", "push-bundle", {
    "repo": "git@github.com:user/my-project.git",
    "branch": "main",
    "bundle_b64": "...",
}, details="Description")

# ── GitHub API ──
repos = proxy.github_list_repos(filter="my-project")
pr = proxy.github_create_pr(
    owner="user",
    repo="my-project",
    title="Add feature",
    head="feature-branch",
    base="main",
)

# ── Health ──
print(proxy.health())
```

### From the Command Line

```bash
# Set credentials once
export AUTH_PROXY_URL="http://auth-proxy.lxc:8443"
export AUTH_PROXY_TOKEN="your-secret-token"

# Git bundle transport
python auth-proxy-client.py fetch-bundle \
    --repo git@github.com:user/private-repo.git \
    --target-dir /home/agent/projects/private-repo \
    --branch main \
    --details "Clone private repo locally"

python auth-proxy-client.py push-bundle \
    --repo git@github.com:user/my-project.git \
    --workdir /home/agent/projects/my-project \
    --branch main \
    --details "Auto-generated feature X"

python auth-proxy-client.py git-clear-cache \
    --details "Remove cached gateway repos"

# GitHub API
python auth-proxy-client.py github-list-repos --filter my-project
python auth-proxy-client.py github-create-pr \
    --owner user --repo my-project \
    --title "Add feature" --head feature-branch --base main

# Health check
python auth-proxy-client.py health
```

### Response Format

```json
{
  "success": true,
  "output": "Everything up-to-date\n",
  "exit_code": 0,
  "approved": true,
  "request_id": "abc123def456...",
  "service": "git",
  "action": "push"
}
```

| Field        | Type   | Description                             |
|--------------|--------|-----------------------------------------|
| `success`    | bool   | Whether the operation succeeded         |
| `output`     | string | Combined stdout + stderr                |
| `exit_code`  | int    | Exit code (-1 if denied/timed out)      |
| `approved`   | bool   | Whether the user approved the request   |
| `request_id` | string | Unique request identifier               |
| `service`    | string | Service name (e.g. "git")               |
| `action`     | string | Action name (e.g. "push")               |

## Approval Flow

When the AI agent sends an operation:

1. **The user receives** a Telegram message with full context:
   - Service and action
   - Operation parameters (repo, branch, refspec, etc.)
   - For git: current branch, recent commits, unpushed changes
   - Custom details from the agent

2. **The user taps** ✅ Approve or ❌ Deny

3. **If approved:** the proxy executes the operation with the stored credential.
   **If denied:** the agent gets an error response.

4. The request expires after 5 minutes (configurable).

## Security

### What the proxy protects against

- **Credential exfiltration:** Keys never leave the Proxmox machine.
- **Unauthorized operations:** Every operation requires Telegram approval.
- **Shell injection:** Parameters are validated against a character blacklist.
- **MITM:** API token sent as Bearer. Run both on the same VLAN/VPN for extra security.
- **Bypass via direct access:** The AI agent doesn't have any keys. Even if the agent is compromised, the attacker can't act without approval.

### What the proxy does NOT protect against

- Compromised proxy machine (root on the proxy has all keys).
- Social engineering of the user (tricked into approving malicious ops).
- Compromised Telegram account (attacker approves from the user's Telegram).

### Recommendations

- Run on its own LXC container with minimal permissions.
- Firewall the proxy port to only the AI agent's IP.
- Place on a private VLAN/VPN.
- Monitor logs: `journalctl -u auth-proxy -f`
- Regularly rotate keys and tokens.

## API Reference

### POST /gate/{service}/{action}

Submit an operation for approval and execution.

**Headers:**
```
Authorization: Bearer <auth_token>
Content-Type: application/json
```

**Request body:**
```json
{
  "params": {
    "repo": "git@github.com:user/my-project.git",
    "branch": "main"
  },
  "details": "Auto-generated code for issue #42"
}
```

**Response:** See [Response Format](#response-format) above.

### GET /health

```json
{
  "status": "ok",
  "version": "1.2.0",
  "pending_requests": 0,
  "services": ["git", "github"]
}
```

## Project Structure

```
auth-proxy/
├── README.md                      # This file
├── requirements.txt               # Python dependencies
├── config.yaml.example            # Configuration template
├── setup-lxc.sh                   # LXC container setup script
├── auth-proxy-server.py           # Server (FastAPI + Telegram bot)
├── auth-proxy-client.py           # Client library and CLI
└── services/
    ├── __init__.py                # Service registry + BaseService
    ├── git.py                     # Git bundle transport service
    ├── github.py                  # GitHub REST API service
    └── calendar.py                # (future) Google Calendar service
```

## Extending

Adding a new service is a single file:

1. Create `services/your-service.py`
2. Import `BaseService` and `service` from `services`
3. Subclass `BaseService` and implement the three required methods
4. Decorate with `@service("your-service-name")`
5. Restart the proxy

Example skeleton:

```python
# services/myservice.py
from services import BaseService, service

@service("myservice")
class MyService(BaseService):

    @classmethod
    def validate(cls, action: str, data: dict) -> None:
        if action not in {"do_thing", "undo_thing"}:
            raise ValueError(f"Unknown action: {action}")
        if "key" not in data:
            raise ValueError("'key' is required")

    @classmethod
    def execute(cls, action: str, data: dict, config: dict) -> dict:
        # Use config.get("services", {}).get("myservice", {}) for service settings
        return {"success": True, "output": "Done!", "exit_code": 0}

    @classmethod
    def approval_text(cls, action: str, data: dict, request_id: str) -> str:
        return f"🔐 *MyService — {action}*\n`{request_id[:16]}…`"
```

No other files need changes. The service registers automatically on import.

## Development

```bash
# Install
pip install -r requirements.txt

# Run in auto-approve mode (no Telegram needed)
AUTH_PROXY_TOKEN=test-token python auth-proxy-server.py

# Test with client
python auth-proxy-client.py health
python auth-proxy-client.py fetch-bundle \
    --repo git@github.com:test/repo.git \
    --target-dir /tmp/test-repo \
    --branch main

# Run with console approval mode
AUTH_PROXY_TOKEN=test-token python auth-proxy-server.py
# (set approval.mode: console in config.yaml)
```

## License

MIT
