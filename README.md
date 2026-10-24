# server-mcp

An MCP server that lets Claude manage Linux servers and Docker. It works over SSH (key or password) or on the local machine. Nothing is installed on the servers.

Every change shows a preview first and waits for your yes.

## What Claude can do

- **Docker:** list, logs, inspect, stats, start, stop, restart, build, run, copy files, Compose stacks, images, volumes, networks, or any docker command with `docker_cli`.
- **System:** info, processes, services (systemd), logs (journal), packages (apt, dnf, apk), reboot and power off.
- **Files:** read, write, edit, move, delete and list on any path. File edits show a diff before they run.
- **Shell:** `server_run`. Safe read commands run at once. Others need approval.
- **sudo:** tools with `as_root` run as root. Root actions always show a preview.

## How approval works

1. Claude calls a tool that changes something.
2. It gets back a preview: the host, the action, the exact command, and a diff for files.
3. You say yes.
4. Claude repeats the same call with `confirm=true`. It runs only if that exact preview was shown in the last 15 minutes. Each preview works once.

Set `SERVER_MCP_READ_ONLY=true` to refuse all changes.

## Secrets

Passwords, tokens and keys are hidden in everything Claude sees. Files such as `.env`, private keys and credential files are never read or written.

## Install

Nothing to install by hand. Add it to your Claude config with `uvx`, as in `claude_desktop_config.example.json`. It downloads the tool from GitHub and runs the `server-mcp` command.

To run from a local copy instead: `pip install .`, then use the command `server-mcp`.

## Settings

All settings are environment variables. The full list is at the top of `server_mcp/server.py`.

| Setting | Meaning |
| --- | --- |
| `SERVER_MCP_HOSTS_NAME` | Your hosts, as `name=address` pairs (or `address=name`). Separate with commas, semicolons or new lines. Every pair is a host. |
| `SERVER_MCP_HOSTS` | Optional. A plain list of hosts without names. Empty and no pairs means this machine. |
| `SERVER_MCP_SSH_USER`, `_SSH_KEY`, `_SSH_PASSWORD`, `_SSH_PORT` | Login for all hosts. Use a key or a password. |
| `SERVER_MCP_SUDO`, `_SUDO_PASSWORD` | Use sudo for docker and root actions. The SSH password is used for sudo too, unless you set a separate sudo password. |
| `SERVER_MCP_<NAME>_...` | Any setting for one host only. |
| `SERVER_MCP_FILE_ROOTS` | Limit the file tools to some folders. |
| `SERVER_MCP_READ_ONLY` | Refuse every change. |

## Safety notes

- Use a dedicated account where you can, and give it only the sudo rights you want Claude to have.
- Passwords in environment variables are stored in your Claude config file. Prefer SSH keys.
- New SSH host keys are trusted on first use, then checked. Use this on networks you trust, or set `SERVER_MCP_SSH_STRICT=true`.

## Tests

```
python tests/test_server.py
```

## License

MIT
