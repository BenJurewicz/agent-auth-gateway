# Auth Proxy

A secure credential gate that sits between an AI agent and any service that needs
authentication. Holds all credentials (SSH keys, API tokens, service account keys)
on a Proxmox LXC container and requires explicit Telegram approval before every
privileged operation.

## Architecture

```
 ┌─────────────────────────┐   POST /gate/{svc}/{act}   ┌──────────────────────────┐
 │   AI Agent (remote VM)  │ ─────────────────────────▶  │ Auth Proxy (Proxmox LXC) │
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
                                                    │        the user              │
                                                    └──────────────────────────────┘
```

**Key security properties:**

- Credentials **never leave** the Proxmox machine.
- The AI agent cannot bypass approval — it doesn't have the keys.
- Each operation shows the user enough context to make a decision.
- Adding a new service is a single file: subclass `BaseService`, add `@service("name")`.

## Supported Services

| Service | Action   | Description                                      |
|---------|----------|--------------------------------------------------|
| `git`   | `push`   | Push commits to a remote repository              |
| `git`   | `clone`  | Clone a repository (including private repos)     |
| `git`   | `fetch`  | Fetch updates from a remote                      |
| `git`   | `pull`   | Pull updates from a remote                       |
| —       | —        | _(More services added as needed)_                |

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

## Deployment (Proxmox LXC)

### Prerequisites

- Proxmox VE 7.x or 8.x
- LXC template: Ubuntu 22.04+ or Debian 12+
- GitHub SSH key for the user
- Telegram bot token (from [@BotFather](https://t.me/BotFather))

### Quick Setup

```bash
# 1. Inside your LXC container, as root:
cd /opt
git clone <this-repo> auth-proxy
cd auth-proxy
bash setup-lxc.sh

# 2. Edit the configuration:
nano /opt/auth-proxy/config.yaml

# 3. Add SSH key for GitHub:
cp /path/to/id_ed25519 /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519

# 4. Test SSH access (accept GitHub's host key):
ssh -T git@github.com

# 5. Start the service:
systemctl start auth-proxy
systemctl status auth-proxy
```

### Manual Setup

```bash
# Install dependencies
apt update && apt install -y python3 python3-pip python3-venv git openssh-client
python3 -m venv /opt/auth-proxy/venv
source /opt/auth-proxy/venv/bin/activate
pip install fastapi uvicorn[standard] pyyaml python-telegram-bot pydantic

# Copy files
mkdir -p /opt/auth-proxy/services
cp auth-proxy-server.py /opt/auth-proxy/
cp -r services/ /opt/auth-proxy/
cp config.yaml.example /opt/auth-proxy/config.yaml
find /opt/auth-proxy -name "*.py" -exec chmod +x {} \;

# Configure
nano /opt/auth-proxy/config.yaml

# Add SSH key
cp ~/.ssh/id_ed25519 /root/.ssh/id_ed25519
chmod 600 /root/.ssh/id_ed25519

# Create systemd service and start
cp setup-lxc.sh /opt/auth-proxy/  # or paste the service manually
systemctl enable --now auth-proxy
```

### Systemd Service (from setup-lxc.sh)

```ini
[Unit]
Description=Auth Proxy — Secure credential gate with Telegram approval
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/auth-proxy/venv/bin/python /opt/auth-proxy/auth-proxy-server.py
WorkingDirectory=/opt/auth-proxy
Restart=on-failure
RestartSec=5
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
```

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

# ── Git ──
result = proxy.git_push(
    repo="git@github.com:user/my-project.git",
    workdir="/home/agent/projects/my-project",
    branch="main",
    details="Auto-generated feature X",
)
print(result["output"])

result = proxy.git_clone(
    repo="git@github.com:user/private-repo.git",
    target_dir="/home/agent/projects/private-repo",
)

proxy.git_fetch(repo="git@github.com:user/my-project.git", workdir="/path")
proxy.git_pull(repo="git@github.com:user/my-project.git", workdir="/path")

# ── Any service (generic) ──
result = proxy.gate("git", "push", {
    "repo": "git@github.com:user/my-project.git",
    "workdir": "/path",
    "branch": "main",
}, details="Description")

# ── Health ──
print(proxy.health())
```

### From the Command Line

```bash
# Set credentials once
export AUTH_PROXY_URL="http://auth-proxy.lxc:8443"
export AUTH_PROXY_TOKEN="your-secret-token"

# Git operations
python auth-proxy-client.py gate git push \
    --param repo=git@github.com:user/my-project.git \
    --param workdir=/home/agent/projects/my-project \
    --param branch=main \
    --details "Auto-generated feature X"

python auth-proxy-client.py gate git clone \
    --param repo=git@github.com:user/private-repo.git \
    --param target-dir=/home/agent/output

python auth-proxy-client.py gate git fetch \
    --param repo=git@github.com:user/my-project.git \
    --param workdir=/path

python auth-proxy-client.py gate git pull \
    --param repo=git@github.com:user/my-project.git \
    --param workdir=/path

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

2. **the user taps** ✅ Approve or ❌ Deny

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
  "version": "1.0.0",
  "pending_requests": 0,
  "services": ["git"]
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
    ├── git.py                     # Git/GitHub service
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
python auth-proxy-client.py gate git push \
    --param repo=git@github.com:test/repo.git \
    --param workdir=/tmp/test-repo \
    --param branch=main

# Run with console approval mode
AUTH_PROXY_TOKEN=test-token python auth-proxy-server.py
# (set approval.mode: console in config.yaml)
```

## License

MIT
