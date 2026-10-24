"""Server MCP tool.

Lets Claude look at and manage Linux servers: Docker (containers, images, volumes,
networks, Compose stacks), files, services, logs, packages and power, with sudo
when you ask for it. Every change shows a preview and waits for your yes.

How it connects: it runs the `docker` command. For a remote host it runs it
over SSH with a key or a password. For the machine it runs on, it runs
`docker` directly. Nothing is installed on the Docker host.

Settings come from environment variables only.

  SERVER_MCP_HOSTS      your hosts, comma separated (a name or an IP address).
                        Optional when SERVER_MCP_HOSTS_NAME has pairs.
                        If both are empty, one host called "local" is used.
  SERVER_MCP_HOSTS_NAME friendly names, as pairs. Each pair is name=address or
                        address=name, for example
                        "web1=192.0.2.50,db1=192.0.2.40".
                        Separate pairs with commas, semicolons, new lines, or write
                        a JSON list inside the string:
                        "[\\"web1=192.0.2.50\\", \\"db1=192.0.2.40\\"]".
                        Every pair is also a host, so SERVER_MCP_HOSTS is not needed.
                        SSH connects to the address. Claude can use the name or the
                        address. The <NAME> in the settings below can be either one.

For each host name (letters, digits; other characters become "_", upper case):

  SERVER_MCP_<NAME>_SSH         user@address for SSH. Leave empty to use local docker.
  SERVER_MCP_<NAME>_SSH_PORT    SSH port (default 22)
  SERVER_MCP_<NAME>_SSH_KEY     path to the private key file to use
  SERVER_MCP_<NAME>_SSH_PASSWORD  SSH password (use this OR a key)
  SERVER_MCP_<NAME>_SUDO        "true" to run docker with sudo
  SERVER_MCP_<NAME>_REMOTE_DOCKER  full path of the docker program on the host, for when sudo
                                cannot find it (some NAS systems: /usr/local/bin/docker)
  SERVER_MCP_<NAME>_SUDO_PASSWORD  sudo password (default: the SSH password)
  SERVER_MCP_<NAME>_STACKS      folder with one sub folder per Compose stack (default /opt/stacks)

Shared settings (used by every host that does not set its own):

  SERVER_MCP_SSH_USER     login name. The host name is then used as the address
                          (user@name), so you only list the names in SERVER_MCP_HOSTS.
  SERVER_MCP_SSH_KEY      one private key for all hosts
  SERVER_MCP_SSH_PASSWORD one SSH password for all hosts (a host's own key or password wins)
  SERVER_MCP_SUDO_PASSWORD  one sudo password for all hosts (default: the SSH password)
  SERVER_MCP_SSH_PORT     SSH port for all hosts
  SERVER_MCP_SUDO         "true" to use `sudo -n` on all hosts
  SERVER_MCP_STACKS       Compose stacks folder for all hosts
  A host's own <NAME> setting always wins over the shared one.

File settings (for the file, copy, build and run tools):

  SERVER_MCP_FILE_ROOTS   limit the file tools to these folders, comma separated.
                          Empty (the default) allows any path. The stacks folder is always
                          allowed. System folders are never deleted as a whole.
  SERVER_MCP_<NAME>_FILE_ROOTS  the same, for one host
  SERVER_MCP_MAX_FILE_KB  biggest file to read or write, in KB (default 1024)
  SERVER_MCP_BUILD_TIMEOUT  seconds for docker build (default 1800)

Other settings:

  SERVER_MCP_READ_ONLY  "true" to refuse every change
  SERVER_MCP_TIMEOUT    seconds to wait for a normal command (default 60)
  SERVER_MCP_LONG_TIMEOUT  seconds for pull, up and update (default 900)
  SERVER_MCP_SSH_STRICT "true" to refuse hosts not already in known_hosts (default: trust a new host once)
  SERVER_MCP_SSH_BIN    ssh program to use (default "ssh")
  SERVER_MCP_DOCKER_BIN docker program for local use (default "docker")

Safety (preview, then confirm):
  read         runs right away
  change       returns a preview first. After the user says yes, repeat the same
               call with confirm=true. Each preview is good for one run.
  destructive  same, and the preview warns that data can be lost
  as_root      tools with this option run with sudo. Root actions always preview.

Secrets (passwords, tokens, keys) are hidden in everything shown to Claude.
The .env files are never read.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import posixpath
import re
import shlex
import subprocess
import time
import functools
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

__version__ = "2026.10.23.02"


class _EnvView:
    """Settings come from SERVER_MCP_* names. The older DOCKER_MCP_* names still work."""

    @staticmethod
    def _old(key: str) -> str | None:
        return "DOCKER_MCP_" + key[len("SERVER_MCP_"):] if key.startswith("SERVER_MCP_") else None

    def __contains__(self, key: str) -> bool:
        old = self._old(key)
        return key in os.environ or bool(old and old in os.environ)

    def __getitem__(self, key: str) -> str:
        if key in os.environ:
            return os.environ[key]
        old = self._old(key)
        if old and old in os.environ:
            return os.environ[old]
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default


ENV = _EnvView()

mcp = FastMCP("server")

# ---------------------------------------------------------------------------
# Names and checks
# ---------------------------------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$")
SINCE_RE = re.compile(r"^(\d{1,6}[smhd]|\d{4}-\d{2}-\d{2}(T[0-9:.+Z-]+)?)$")
COMPOSE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")

# A name with one of these words in it holds a secret. Its value is hidden.
SECRET_WORDS = (
    "PASS", "SECRET", "TOKEN", "KEY", "CRED", "AUTH", "CLAIM", "LICENSE",
    "PRIVATE", "COOKIE", "SESSION", "USER",
)
HIDDEN = "***hidden***"

_LINE = re.compile(
    r"^(?P<pre>\s*(?:-\s*)?[\"']?)(?P<key>[A-Za-z0-9_.-]+)(?P<mid>[\"']?\s*[:=]\s*)(?P<val>\S.*)$"
)
_INLINE = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:pass|passwd|password|secret|token|apikey|api_key)[A-Za-z0-9_]*)=(\S+)"
)


_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_AUTHHDR = re.compile(r"(?i)\b(authorization:\s*)\S.*$")


def _secret_name(name: str) -> bool:
    up = name.upper()
    return any(w in up for w in SECRET_WORDS)


def _redact_text(text: str) -> str:
    """Hide secret values in text (compose files, logs). Best effort."""
    out = []
    for line in text.splitlines():
        m = _LINE.match(line)
        if m and _secret_name(m.group("key")):
            val = m.group("val").strip()
            if not val.startswith("${"):  # a reference like ${PIA_PASSWORD} is fine to show
                line = f"{m.group('pre')}{m.group('key')}{m.group('mid')}{HIDDEN}"
        line = _INLINE.sub(lambda mm: f"{mm.group(1)}={HIDDEN}", line)
        line = _AUTHHDR.sub(lambda mm: mm.group(1) + HIDDEN, line)
        line = _BEARER.sub(lambda mm: f"{mm.group(1)} {HIDDEN}", line)
        out.append(line)
    return "\n".join(out)


def _redact_env(env: list[str] | None) -> list[str]:
    out = []
    for item in env or []:
        key, sep, val = str(item).partition("=")
        out.append(f"{key}={HIDDEN}" if sep and _secret_name(key) and val else str(item))
    return out


# ---------------------------------------------------------------------------
# Hosts
# ---------------------------------------------------------------------------
def _env_key(name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "_", name.upper())


def _truthy(v: str | None) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def _is_ip(x: str) -> bool:
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def _name_items(raw: str) -> list[str]:
    """Split SERVER_MCP_HOSTS_NAME into items. Commas, semicolons, new lines, or a JSON list all work."""
    raw = raw.strip()
    if raw.startswith("["):
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [str(x).strip() for x in data if str(x).strip()]
        except ValueError:
            pass
    return [x.strip().strip('"\'') for x in re.split(r"[,;\n]", raw.strip("[]")) if x.strip().strip('"\'')]


def _parse_names(raw: str) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ([(address, name), ...], plain names). Pairs work both ways: name=ip or ip=name."""
    pairs: list[tuple[str, str]] = []
    plain: list[str] = []
    for item in _name_items(raw):
        if "=" not in item:
            plain.append(item)
            continue
        left, _, right = (x.strip() for x in item.partition("="))
        if not left or not right:
            continue
        if _is_ip(left) and not _is_ip(right):
            pairs.append((left, right))
        elif _is_ip(right) and not _is_ip(left):
            pairs.append((right, left))
        else:
            pairs.append((right, left))  # name=address is the default
    return pairs, plain


def _hosts() -> dict[str, dict[str, Any]]:
    pair_list, plain = _parse_names(ENV.get("SERVER_MCP_HOSTS_NAME", ""))
    pairs = {addr: name for addr, name in pair_list}
    entries = [n.strip() for n in ENV.get("SERVER_MCP_HOSTS", "").split(",") if n.strip()]
    for addr, _name in pair_list:  # every named host is also a host
        if addr not in entries:
            entries.append(addr)
    if not entries:
        entries = ["local"]
    # Shared defaults, used by every host that does not set its own value.
    d_user = ENV.get("SERVER_MCP_SSH_USER", "").strip()
    d_port = ENV.get("SERVER_MCP_SSH_PORT", "").strip()
    d_key = ENV.get("SERVER_MCP_SSH_KEY", "").strip()
    d_pw = ENV.get("SERVER_MCP_SSH_PASSWORD", "")
    d_sudo_pw = ENV.get("SERVER_MCP_SUDO_PASSWORD", "")
    d_remote_docker = ENV.get("SERVER_MCP_REMOTE_DOCKER", "").strip()
    d_sudo = ENV.get("SERVER_MCP_SUDO")
    d_stacks = ENV.get("SERVER_MCP_STACKS", "").strip()
    hosts: dict[str, dict[str, Any]] = {}
    for i, addr in enumerate(entries):
        name = pairs.get(addr) or (plain[i] if i < len(plain) and not pairs else "") or addr  # a blank slot means no name
        if name in hosts:
            name = addr  # two hosts with the same friendly name: keep them apart
        prefixes = [f"SERVER_MCP_{_env_key(name)}_", f"SERVER_MCP_{_env_key(addr)}_"]

        def get(suffix: str) -> str | None:
            for pre in prefixes:
                if pre + suffix in ENV:
                    return ENV[pre + suffix]
            return None

        ssh = (get("SSH") or "").strip()
        if not ssh and d_user and addr.lower() != "local":
            # Shared user: the host entry is the address (name or IP).
            ssh = f"{d_user}@{addr}"
        sudo_raw = get("SUDO")
        stacks = (get("STACKS") or "").strip() or d_stacks or "/opt/stacks"
        own_key = (get("SSH_KEY") or "").strip()
        own_pw = get("SSH_PASSWORD") or ""
        # A host's own key beats the shared password. A host's own password beats the shared key.
        if own_pw:
            pw, key = own_pw, ""
        elif own_key:
            pw, key = "", own_key
        else:
            pw, key = d_pw, d_key
        if pw:
            key = ""
        sudo_pw = (get("SUDO_PASSWORD") or "") or d_sudo_pw or pw
        hosts[name] = {
            "name": name,
            "address": addr,
            "ssh": ssh,
            "port": (get("SSH_PORT") or "").strip() or d_port,
            "key": key,
            "password": pw,
            "sudo_password": sudo_pw,
            "docker_path": (get("REMOTE_DOCKER") or "").strip() or d_remote_docker,
            "sudo": _truthy(sudo_raw if sudo_raw is not None else d_sudo),
            "stacks": stacks.rstrip("/") or "/",
        }
    return hosts


def _pick(host: str) -> tuple[dict[str, Any] | None, str]:
    hs = _hosts()
    listing = ", ".join(f"{h['name']} ({h['address']})" if h["name"] != h["address"] else h["name"] for h in hs.values())
    if not host:
        if len(hs) == 1:
            return next(iter(hs.values())), ""
        return None, "Which host? Choose one of: " + listing
    want = host.strip().lower()
    for h in hs.values():  # friendly name first, then the address
        if h["name"].lower() == want:
            return h, ""
    for h in hs.values():
        if h["address"].lower() == want:
            return h, ""
    return None, f"Unknown host '{host}'. Choose one of: " + listing


def _timeout(long: bool | str = False) -> int:
    if long == "build":
        return int(ENV.get("SERVER_MCP_BUILD_TIMEOUT", "1800"))
    if long:
        return int(ENV.get("SERVER_MCP_LONG_TIMEOUT", "900"))
    return int(ENV.get("SERVER_MCP_TIMEOUT", "60"))


def _ssh_cmd(h: dict[str, Any], argv: list[str], cwd: str | None = None) -> list[str]:
    """Build the ssh command that runs argv on the remote host. Every part is quoted."""
    if h["ssh"].startswith("-"):
        raise ValueError("SSH target must not start with '-'")
    remote = " ".join(shlex.quote(a) for a in argv)
    if cwd:
        remote = f"cd {shlex.quote(cwd)} && {remote}"
    cmd = [ENV.get("SERVER_MCP_SSH_BIN", "ssh"),
           "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if not _truthy(ENV.get("SERVER_MCP_SSH_STRICT")):
        cmd += ["-o", "StrictHostKeyChecking=accept-new"]  # trust a new host once, refuse if it later changes
    if h["port"]:
        cmd += ["-p", h["port"]]
    if h["key"]:
        cmd += ["-i", h["key"], "-o", "IdentitiesOnly=yes"]
    return cmd + ["--", h["ssh"], remote]


import contextvars
_FORCE_ROOT: contextvars.ContextVar[bool] = contextvars.ContextVar("force_root", default=False)


def _rootable(fn: Callable) -> Callable:
    """For tools with an as_root option: every command inside the tool runs with sudo."""
    @functools.wraps(fn)
    def wrapper(*a: Any, **k: Any) -> Any:
        tok = _FORCE_ROOT.set(bool(k.get("as_root")))
        try:
            return fn(*a, **k)
        finally:
            _FORCE_ROOT.reset(tok)
    return wrapper


def _scrub(text: str, h: dict[str, Any]) -> str:
    """Remove the SSH and sudo passwords from any text."""
    for secret in (h.get("password"), h.get("sudo_password")):
        if secret:
            text = text.replace(secret, "********")
    return text


SUDO_SCRIPT = (
    'IFS= read -r p; if sudo -n true 2>/dev/null; then exec sudo -n "$@"; '
    'else { printf "%s\\n" "$p"; cat; } | sudo -S -p "" "$@"; fi'
)


def _sudo_wrap(h: dict[str, Any], argv: list[str], root: bool) -> tuple[list[str], bytes]:
    """Put docker on its full path, and add sudo when asked for (or when docker needs it)."""
    argv = list(argv)
    if not argv:
        return argv, b""
    is_docker = argv[0] == "docker"
    if is_docker:
        if h["ssh"] and h.get("docker_path"):
            argv[0] = h["docker_path"]
        elif not h["ssh"]:
            argv[0] = ENV.get("SERVER_MCP_DOCKER_BIN", "docker")
    if (root or (h["sudo"] and is_docker)) and argv[0] != "sudo":
        if h.get("sudo_password"):
            # The password goes in on stdin (first line). If sudo needs no password, it is
            # dropped, so it can never end up inside a file or command input.
            return ["sh", "-c", SUDO_SCRIPT, "sh"] + argv, (h["sudo_password"] + "\n").encode()
        return ["sudo", "-n"] + argv, b""
    return argv, b""


def _run_password(h: dict[str, Any], argv: list[str], cwd: str | None, timeout: int | None,
                  payload: bytes | None) -> tuple[int, bytes, bytes]:
    """Run a command over SSH with a password (and a key, if one is set), using paramiko."""
    try:
        import paramiko
    except ImportError:
        return 127, b"", b"The paramiko package is missing. Install server-mcp again."
    remote = " ".join(shlex.quote(a) for a in argv)
    if cwd:
        remote = f"cd {shlex.quote(cwd)} && {remote}"
    user, _, addr = h["ssh"].rpartition("@")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # trusted network: accept key on first use
    limit = timeout or _timeout()
    try:
        client.connect(addr, port=int(h["port"] or 22), username=user or None, password=h["password"] or None,
                       key_filename=h["key"] or None, timeout=10, look_for_keys=False, allow_agent=False)
        chan = client.get_transport().open_session()
        chan.settimeout(limit)
        chan.exec_command(remote)
        if payload:
            chan.sendall(payload)
        chan.shutdown_write()
        out, err = bytearray(), bytearray()
        end = time.monotonic() + limit
        while True:
            got = False
            while chan.recv_ready():
                out += chan.recv(65536); got = True
            while chan.recv_stderr_ready():
                err += chan.recv_stderr(65536); got = True
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            if time.monotonic() > end:
                return 124, bytes(out), b"Timed out waiting for the command."
            if not got:
                time.sleep(0.05)
        return chan.recv_exit_status(), bytes(out), bytes(err)
    except paramiko.AuthenticationException:
        return 255, b"", b"Permission denied. The SSH login was not accepted."
    except Exception as exc:  # network, timeout, protocol
        return 255, b"", f"SSH to {h['ssh']} failed: {exc}".encode()
    finally:
        client.close()


def _once(h: dict[str, Any], argv: list[str], cwd: str | None, timeout: int | None,
          data: bytes | None, root: bool) -> tuple[int, bytes, str]:
    """Run one command with one login. Returns (code, stdout bytes, stderr text)."""
    try:
        argv, feed = _sudo_wrap(h, argv, root)
        payload = (feed + (data or b"")) if (feed or data is not None) else None
        if h["ssh"] and h.get("password"):
            rc, out, err = _run_password(h, argv, cwd, timeout, payload)
            return rc, out, _scrub(err.decode("utf-8", "replace"), h)
        if h["ssh"]:
            cmd, kw = _ssh_cmd(h, argv, cwd), {}
        else:
            cmd, kw = argv, {"cwd": cwd}
        if payload is None:
            kw["stdin"] = subprocess.DEVNULL
        else:
            kw["input"] = payload
        p = subprocess.run(cmd, capture_output=True, timeout=timeout or _timeout(), **kw)
        return p.returncode, p.stdout, _scrub(p.stderr.decode("utf-8", "replace"), h)
    except subprocess.TimeoutExpired:
        return 124, b"", "Timed out waiting for the command."
    except (OSError, ValueError) as e:
        return 127, b"", str(e)


def _exec_bytes(h: dict[str, Any], argv: list[str], cwd: str | None = None,
                timeout: int | None = None, data: bytes | None = None,
                root: bool = False) -> tuple[int, bytes, str]:
    """Run a command on the host with exact bytes in and out. root=True runs it with sudo."""
    return _once(h, argv, cwd, timeout, data, root or _FORCE_ROOT.get())


def _exec(h: dict[str, Any], argv: list[str], cwd: str | None = None,
          timeout: int | None = None, root: bool = False) -> tuple[int, str, str]:
    """Run a command on the host. Returns (exit code, stdout, stderr) as text."""
    rc, out, err = _exec_bytes(h, argv, cwd=cwd, timeout=timeout, root=root)
    return rc, _scrub(out.decode("utf-8", "replace").replace("\r\n", "\n"), h), err


def _docker(h: dict[str, Any], args: list[str], cwd: str | None = None,
            long: bool | str = False) -> tuple[int, str, str]:
    return _exec(h, ["docker"] + args, cwd=cwd, timeout=_timeout(long))


def _fail(rc: int, err: str, out: str = "") -> str:
    text = (err or out or "no message").strip()
    hint = ""
    if "permission denied" in text.lower() and "docker.sock" in text.lower():
        hint = " Hint: add the user to the docker group, or set SERVER_MCP_<NAME>_SUDO=true."
    if "a password is required" in text.lower():
        hint = " Hint: sudo needs a password. Use the docker group instead of sudo."
    if "ssh password was not accepted" in text.lower():
        hint = " Hint: check SERVER_MCP_<NAME>_SSH_PASSWORD (or SERVER_MCP_SSH_PASSWORD) and that SSH allows password login."
    if "permission denied (publickey" in text.lower():
        hint = " Hint: SSH key was not accepted. Check SERVER_MCP_<NAME>_SSH and _SSH_KEY."
    return f"ERROR (exit {rc}): {_redact_text(text)[:1500]}{hint}"


def _json_lines(out: str) -> list[Any]:
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
    return rows


def _show(obj: Any, limit: int = 60000) -> str:
    text = json.dumps(obj, indent=1, ensure_ascii=False, default=str)
    if len(text) > limit:
        text = text[:limit] + f"\n... cut at {limit} characters"
    return text


def _safe(fn: Callable[..., str]) -> Callable[..., str]:
    @functools.wraps(fn)
    def wrapper(*a: Any, **k: Any) -> str:
        try:
            return fn(*a, **k)
        except Exception as e:  # never crash the tool; tell Claude what went wrong
            return f"ERROR: {type(e).__name__}: {_redact_text(str(e))[:500]}"
    return wrapper


# ---------------------------------------------------------------------------
# Safety gate
# ---------------------------------------------------------------------------
# Changes the user has been shown. A change only runs if its exact preview came first.
_PREVIEWED: dict[str, float] = {}
_PREVIEW_TTL = 900  # seconds


def _diff(h: dict[str, Any], path: str, new: bytes, limit: int = 60) -> str:
    """A short unified diff of the file on the host against the new content."""
    import difflib
    rc, old, _ = _exec_bytes(h, ["cat", "--", path], root=False)
    if rc:
        rc, old, _ = _exec_bytes(h, ["cat", "--", path], root=True)
    old_t = old.decode("utf-8", "replace") if rc == 0 else ""
    try:
        new_t = new.decode("utf-8")
    except UnicodeDecodeError:
        return "(binary content, no diff)"
    lines = list(difflib.unified_diff(old_t.splitlines(), new_t.splitlines(),
                                      "current" if rc == 0 else "(new file)", "new", lineterm="", n=2))
    lines = [_redact_text(x) for x in lines]
    if len(lines) > limit:
        lines = lines[:limit] + [f"... {len(lines) - limit} more diff lines"]
    return "\n".join(lines) or "(no differences)"


def _gate(h: dict[str, Any], tier: str, what: str, details: str,
          confirm: bool, phrase: str = "", preview: str = "") -> str | None:
    """Preview, then confirm. Returns a message if the action must not run yet, else None.

    First call shows exactly what will happen. The user says yes. The same call with
    confirm=true then runs. Any change to the details needs a new preview.
    """
    if tier == "read":
        return None
    if _truthy(ENV.get("SERVER_MCP_READ_ONLY")):
        return "NOT RUN. Read-only mode is on (SERVER_MCP_READ_ONLY). No changes are allowed."
    import hashlib
    key = hashlib.sha256("\x00".join([h["name"], what, details, preview]).encode()).hexdigest()
    now = time.monotonic()
    for k in [k for k, t in _PREVIEWED.items() if now - t > _PREVIEW_TTL]:
        del _PREVIEWED[k]
    if confirm and key in _PREVIEWED:
        del _PREVIEWED[key]
        return None
    _PREVIEWED[key] = now
    warn = "This can destroy data. " if tier == "destructive" else ""
    why = "" if not confirm else "You used confirm=true, but this exact change was not shown yet. "
    return (
        f"PREVIEW. Nothing ran. {why}{warn}\n"
        f"Host: {h['name']}\nAction: {what}\nDetails: {details}\n"
        + (f"Changes:\n{preview}\n" if preview else "")
        + "Show the user this preview and ask for a clear yes. "
        "After they say yes, call again with the same arguments and confirm=true."
    )


def _check_name(kind: str, value: str, image: bool = False) -> str | None:
    rx = IMAGE_RE if image else NAME_RE
    if not value or not rx.match(value) or ".." in value:
        return f"Bad {kind} name: {value!r}"
    return None


# ---------------------------------------------------------------------------
# Stacks (Compose projects, one folder each)
# ---------------------------------------------------------------------------
def _find_stacks(h: dict[str, Any]) -> tuple[dict[str, str] | None, str]:
    """Return {stack name: compose file path} or (None, error)."""
    root = h["stacks"]
    found: dict[str, str] = {}
    if h["ssh"]:
        argv = ["find", root, "-maxdepth", "2", "-type", "f", "("]
        for i, n in enumerate(COMPOSE_NAMES):
            argv += (["-o"] if i else []) + ["-name", n]
        argv += [")"]
        rc, out, err = _exec(h, argv)
        if rc != 0 and not out.strip():
            return None, _fail(rc, err)
        paths = [p.strip() for p in out.splitlines() if p.strip()]
    else:
        paths = []
        if os.path.isdir(root):
            for d in sorted(os.listdir(root)):
                for n in COMPOSE_NAMES:
                    p = os.path.join(root, d, n)
                    if os.path.isfile(p):
                        paths.append(p.replace("\\", "/"))
                        break
    for p in sorted(paths):
        parts = p.rstrip("/").split("/")
        if len(parts) >= 2 and NAME_RE.match(parts[-2]) and parts[-2] not in found:
            found[parts[-2]] = p
    return found, ""


def _stack(h: dict[str, Any], name: str) -> tuple[tuple[str, str] | None, str]:
    """Return ((folder, compose file), '') or (None, error)."""
    bad = _check_name("stack", name)
    if bad:
        return None, bad
    stacks, err = _find_stacks(h)
    if stacks is None:
        return None, err
    if name not in stacks:
        return None, f"No stack '{name}' under {h['stacks']}. Found: " + (", ".join(stacks) or "none")
    path = stacks[name]
    return (path.rsplit("/", 1)[0], path), ""


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------
@mcp.tool()
@_safe
def server_hosts() -> str:
    """List the Docker hosts this tool knows and test the connection to each."""
    rows = []
    for h in _hosts().values():
        rc0, _, err0 = _exec(h, ["true"])
        rc, out, err = _docker(h, ["version", "--format", "{{.Server.Version}}"]) if rc0 == 0 else (rc0, "", err0)
        row: dict[str, Any] = {
            "host": h["name"], "address": h["address"], "via": f"ssh {h['ssh']}" if h["ssh"] else "local docker",
            "sudo": h["sudo"], "stacks_folder": h["stacks"],
            "login": "password" if h.get("password") else ("key" if h.get("key") else "default ssh key"),
        }
        if rc == 0:
            row["docker"] = out.strip()
            rc2, out2, _ = _docker(h, ["compose", "version", "--short"])
            row["compose"] = out2.strip() if rc2 == 0 else "not found"
        elif rc0 == 0:
            row["connection"] = "ok"
            row["docker"] = "not installed or not reachable" if "not found" in err else _fail(rc, err)
        else:
            row["error"] = _fail(rc, err)
        rows.append(row)
    return _show(rows)


@mcp.tool()
@_safe
def docker_ps(host: str = "", all: bool = True, name_contains: str = "") -> str:
    """List containers: name, image, state, status, ports, networks.

    all=true includes stopped containers. name_contains filters by name.
    """
    h, err = _pick(host)
    if not h:
        return err
    args = ["ps", "--format", "{{json .}}"] + (["-a"] if all else [])
    rc, out, e = _docker(h, args)
    if rc != 0:
        return _fail(rc, e)
    rows = []
    for r in _json_lines(out):
        if name_contains and name_contains.lower() not in str(r.get("Names", "")).lower():
            continue
        rows.append({
            "name": r.get("Names"), "image": r.get("Image"), "state": r.get("State"),
            "status": r.get("Status"), "ports": r.get("Ports"), "networks": r.get("Networks"),
        })
    return _show(rows) if rows else "No containers."


@mcp.tool()
@_safe
def docker_logs(container: str, host: str = "", tail: int = 100, since: str = "") -> str:
    """Show the last lines of a container's log. since like 10m, 2h, or 2026-10-11.

    Secrets that look like password or token values are hidden.
    """
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("container", container)
    if bad:
        return bad
    args = ["logs", "--timestamps", "--tail", str(max(1, min(int(tail), 1000)))]
    if since:
        if not SINCE_RE.match(since):
            return f"Bad since value: {since!r}. Use 10m, 2h, 1d, or 2026-10-11."
        args += ["--since", since]
    rc, out, e = _docker(h, args + [container])
    if rc != 0:
        return _fail(rc, e)
    text = _redact_text((out + e).strip())
    return text[-30000:] if text else "(no log lines)"


def _inspect_container(d: dict[str, Any]) -> dict[str, Any]:
    cfg, st, hc = d.get("Config") or {}, d.get("State") or {}, d.get("HostConfig") or {}
    nets = {k: v.get("IPAddress") for k, v in ((d.get("NetworkSettings") or {}).get("Networks") or {}).items()}
    labels = cfg.get("Labels") or {}
    return {
        "name": str(d.get("Name", "")).lstrip("/"),
        "image": cfg.get("Image"),
        "state": {k: st.get(k) for k in ("Status", "Running", "ExitCode", "StartedAt", "FinishedAt", "OOMKilled")},
        "health": (st.get("Health") or {}).get("Status"),
        "restart_count": d.get("RestartCount"),
        "restart_policy": (hc.get("RestartPolicy") or {}).get("Name"),
        "network_mode": hc.get("NetworkMode"),
        "networks": nets,
        "ports": hc.get("PortBindings"),
        "user": cfg.get("User"),
        "cmd": [_redact_text(str(c)) for c in (cfg.get("Cmd") or [])],
        "env": _redact_env(cfg.get("Env")),
        "mounts": [
            {"type": m.get("Type"), "source": m.get("Name") or m.get("Source"),
             "target": m.get("Destination"), "rw": m.get("RW")}
            for m in d.get("Mounts") or []
        ],
        "compose": {k.split(".")[-1]: v for k, v in labels.items() if k.startswith("com.docker.compose.project") or k == "com.docker.compose.service"},
    }


@mcp.tool()
@_safe
def docker_inspect(name: str, kind: str = "container", host: str = "") -> str:
    """Show details of a container, volume, network or image (kind).

    For a volume this shows its driver and options, such as the NFS address.
    Secret values in environment variables are hidden.
    """
    h, err = _pick(host)
    if not h:
        return err
    if kind not in ("container", "volume", "network", "image"):
        return "kind must be container, volume, network or image."
    bad = _check_name(kind, name, image=(kind == "image"))
    if bad:
        return bad
    if kind in ("container", "image"):
        args = ["inspect", "--type", kind, name]
    else:
        args = [kind, "inspect", name]
    rc, out, e = _docker(h, args)
    if rc != 0:
        return _fail(rc, e)
    try:
        data = json.loads(out)[0]
    except (ValueError, IndexError):
        return "Could not read the answer from docker."
    if kind == "container":
        return _show(_inspect_container(data))
    if kind == "image":
        cfg = data.get("Config") or {}
        return _show({
            "id": data.get("Id"), "tags": data.get("RepoTags"), "created": data.get("Created"),
            "size": data.get("Size"), "env": _redact_env(cfg.get("Env")),
            "user": cfg.get("User"), "ports": list((cfg.get("ExposedPorts") or {})),
        })
    if kind == "volume":
        return _show({k: data.get(k) for k in ("Name", "Driver", "Options", "Mountpoint", "Labels", "CreatedAt")})
    return _show({k: data.get(k) for k in ("Name", "Driver", "Scope", "Options", "IPAM", "Labels")}
                 | {"containers": {v.get("Name"): v.get("IPv4Address") for v in (data.get("Containers") or {}).values()}})


@mcp.tool()
@_safe
def docker_stats(host: str = "") -> str:
    """Show CPU, memory and network use of running containers right now."""
    h, err = _pick(host)
    if not h:
        return err
    rc, out, e = _docker(h, ["stats", "--no-stream", "--format", "{{json .}}"])
    if rc != 0:
        return _fail(rc, e)
    rows = [{"name": r.get("Name"), "cpu": r.get("CPUPerc"), "memory": r.get("MemUsage"),
             "mem_percent": r.get("MemPerc"), "network": r.get("NetIO"), "block_io": r.get("BlockIO")}
            for r in _json_lines(out)]
    return _show(rows) if rows else "No running containers."


@mcp.tool()
@_safe
def docker_images(host: str = "") -> str:
    """List images: name, tag, size, age."""
    h, err = _pick(host)
    if not h:
        return err
    rc, out, e = _docker(h, ["images", "--format", "{{json .}}"])
    if rc != 0:
        return _fail(rc, e)
    rows = [{"image": f"{r.get('Repository')}:{r.get('Tag')}", "id": r.get("ID"),
             "size": r.get("Size"), "created": r.get("CreatedSince")} for r in _json_lines(out)]
    return _show(rows) if rows else "No images."


@mcp.tool()
@_safe
def docker_volumes(host: str = "") -> str:
    """List volumes: name and driver."""
    h, err = _pick(host)
    if not h:
        return err
    rc, out, e = _docker(h, ["volume", "ls", "--format", "{{json .}}"])
    if rc != 0:
        return _fail(rc, e)
    rows = [{"name": r.get("Name"), "driver": r.get("Driver")} for r in _json_lines(out)]
    return _show(rows) if rows else "No volumes."


@mcp.tool()
@_safe
def docker_networks(host: str = "") -> str:
    """List networks: name, driver, scope."""
    h, err = _pick(host)
    if not h:
        return err
    rc, out, e = _docker(h, ["network", "ls", "--format", "{{json .}}"])
    if rc != 0:
        return _fail(rc, e)
    rows = [{"name": r.get("Name"), "driver": r.get("Driver"), "scope": r.get("Scope")} for r in _json_lines(out)]
    return _show(rows) if rows else "No networks."


@mcp.tool()
@_safe
def docker_disk_usage(host: str = "") -> str:
    """Show how much disk space images, containers, volumes and build cache use."""
    h, err = _pick(host)
    if not h:
        return err
    rc, out, e = _docker(h, ["system", "df", "--format", "{{json .}}"])
    if rc != 0:
        return _fail(rc, e)
    return _show(_json_lines(out))


@mcp.tool()
@_safe
def docker_stacks(host: str = "") -> str:
    """List Compose stacks (one folder each under the stacks folder) and whether they are running."""
    h, err = _pick(host)
    if not h:
        return err
    stacks, e = _find_stacks(h)
    if stacks is None:
        return e
    running: list[dict[str, Any]] = []
    rc, out, _ = _docker(h, ["compose", "ls", "--all", "--format", "json"])
    if rc == 0:
        try:
            running = json.loads(out) if out.strip() else []
        except ValueError:
            running = []
    rows = []
    for name, path in sorted(stacks.items()):
        match = next((p for p in running if path in str(p.get("ConfigFiles", ""))), None)
        rows.append({"stack": name, "file": path, "status": match.get("Status") if match else "not created yet"})
    return _show(rows) if rows else f"No stacks found under {h['stacks']}."


@mcp.tool()
@_safe
def docker_stack_status(stack: str, host: str = "") -> str:
    """Show the containers of one stack and their state."""
    h, err = _pick(host)
    if not h:
        return err
    st, e = _stack(h, stack)
    if not st:
        return e
    rc, out, er = _docker(h, ["compose", "ps", "--all", "--format", "json"], cwd=st[0])
    if rc != 0:
        return _fail(rc, er)
    rows = []
    for line in out.strip().splitlines():
        try:
            r = json.loads(line)
        except ValueError:
            continue
        for x in (r if isinstance(r, list) else [r]):
            rows.append({"service": x.get("Service"), "name": x.get("Name"), "image": x.get("Image"),
                         "state": x.get("State"), "health": x.get("Health"), "status": x.get("Status"),
                         "ports": x.get("Publishers") and [f"{p.get('PublishedPort')}->{p.get('TargetPort')}" for p in x["Publishers"] if p.get("PublishedPort")]})
    return _show(rows) if rows else "No containers created for this stack."


@mcp.tool()
@_safe
def docker_stack_file(stack: str, host: str = "") -> str:
    """Show the compose file of a stack. Secret values are hidden. The .env file is never shown."""
    h, err = _pick(host)
    if not h:
        return err
    st, e = _stack(h, stack)
    if not st:
        return e
    if h["ssh"]:
        rc, out, er = _exec(h, ["cat", "--", st[1]])
        if rc != 0:
            return _fail(rc, er)
    else:
        with open(st[1], encoding="utf-8", errors="replace") as f:
            out = f.read()
    return _redact_text(out)[:60000]


@mcp.tool()
@_safe
def docker_stack_config(stack: str, host: str = "") -> str:
    """Check a stack and show the final compose file with all variables filled in.

    Good for finding a missing or wrong value in the .env file. Secret values are hidden.
    """
    h, err = _pick(host)
    if not h:
        return err
    st, e = _stack(h, stack)
    if not st:
        return e
    rc, out, er = _docker(h, ["compose", "config"], cwd=st[0])
    if rc != 0:
        return _fail(rc, er)
    return _redact_text(out)[:60000]


# ---------------------------------------------------------------------------
# Change tools
# ---------------------------------------------------------------------------
@mcp.tool()
@_safe
def docker_container_action(container: str, action: str, host: str = "",
                            confirm: bool = False) -> str:
    """Start, stop, restart, pause or unpause one container. Needs confirm=true."""
    h, err = _pick(host)
    if not h:
        return err
    if action not in ("start", "stop", "restart", "pause", "unpause"):
        return "action must be start, stop, restart, pause or unpause."
    bad = _check_name("container", container)
    if bad:
        return bad
    stop = _gate(h, "change", f"{action} container {container}", f"docker {action} {container}", confirm)
    if stop:
        return stop
    rc, out, e = _docker(h, [action, container], long=True)
    return _fail(rc, e, out) if rc else f"Done: {action} {container}"


@mcp.tool()
@_safe
def docker_stack_action(stack: str, action: str, host: str = "",
                        confirm: bool = False) -> str:
    """Run a Compose action on one stack.

    action: up (create/start, same as docker compose up -d), pull (get new images),
    update (pull then up), start, stop, restart, build (build the images the
    compose file builds itself), build_no_cache, up_build (build then up),
    recreate (up with --force-recreate).
    These need confirm=true.
    down (removes the containers and network, keeps volumes) and
    down_volumes (also removes the stack's volumes) are destructive and also
    """
    h, err = _pick(host)
    if not h:
        return err
    plans = {
        "up": [["compose", "up", "-d"]],
        "pull": [["compose", "pull"]],
        "update": [["compose", "pull"], ["compose", "up", "-d"]],
        "start": [["compose", "start"]],
        "stop": [["compose", "stop"]],
        "restart": [["compose", "restart"]],
        "build": [["compose", "build"]],
        "build_no_cache": [["compose", "build", "--no-cache"]],
        "up_build": [["compose", "up", "-d", "--build"]],
        "recreate": [["compose", "up", "-d", "--force-recreate"]],
        "down": [["compose", "down"]],
        "down_volumes": [["compose", "down", "--volumes"]],
    }
    if action not in plans:
        return "action must be one of: " + ", ".join(plans)
    st, e = _stack(h, stack)
    if not st:
        return e
    tier = "destructive" if action.startswith("down") else "change"
    stop = _gate(h, tier, f"stack {stack} {action}", " then ".join("docker " + " ".join(p) for p in plans[action]), confirm)
    if stop:
        return stop
    log = []
    for cmd in plans[action]:
        rc, out, er = _docker(h, cmd, cwd=st[0], long="build" if "build" in action else True)
        text = _redact_text((out + er).strip())[-3000:]
        if rc:
            return _fail(rc, er, out)
        log.append(text)
    return f"Done: {action} {stack}\n" + "\n".join(x for x in log if x)


@mcp.tool()
@_safe
def docker_pull_image(image: str, host: str = "", confirm: bool = False) -> str:
    """Download an image, for example ghcr.io/example/app:latest. Needs confirm=true."""
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("image", image, image=True)
    if bad:
        return bad
    stop = _gate(h, "change", f"pull image {image}", f"docker pull {image}", confirm, "")
    if stop:
        return stop
    rc, out, e = _docker(h, ["pull", image], long=True)
    return _fail(rc, e, out) if rc else f"Done: pulled {image}\n{out.strip()[-500:]}"


# ---------------------------------------------------------------------------
# Destructive tools
# ---------------------------------------------------------------------------
@mcp.tool()
@_safe
def docker_remove(kind: str, name: str, host: str = "",
                  confirm: bool = False) -> str:
    """Delete one container, image, volume or network (kind).

    Destructive. Shows a preview first. Run again with confirm=true after the user says yes.
    A running container is not removed. Stop it first. Removing a volume
    deletes the data inside it. A volume with an NFS setting only holds the
    setting, not the files on the NAS.
    """
    h, err = _pick(host)
    if not h:
        return err
    cmds = {"container": ["rm"], "image": ["rmi"], "volume": ["volume", "rm"], "network": ["network", "rm"]}
    if kind not in cmds:
        return "kind must be container, image, volume or network."
    bad = _check_name(kind, name, image=(kind == "image"))
    if bad:
        return bad
    stop = _gate(h, "destructive", f"remove {kind} {name}", f"docker {' '.join(cmds[kind])} {name}", confirm)
    if stop:
        return stop
    rc, out, e = _docker(h, cmds[kind] + [name])
    return _fail(rc, e, out) if rc else f"Done: removed {kind} {name}"


@mcp.tool()
@_safe
def docker_prune(what: str, host: str = "", confirm: bool = False) -> str:
    """Clean up unused things. what: containers (stopped), images (unused, untagged only),
    networks (unused), volumes (not used by any container), builder (build cache).

    Destructive. Shows a preview first. Run again with confirm=true after the user says yes.
    """
    h, err = _pick(host)
    if not h:
        return err
    if what not in ("containers", "images", "networks", "volumes", "builder"):
        return "what must be containers, images, networks, volumes or builder."
    sub = {"containers": "container", "images": "image", "networks": "network", "volumes": "volume", "builder": "builder"}[what]
    stop = _gate(h, "destructive", f"prune {what}", f"docker {sub} prune -f", confirm)
    if stop:
        return stop
    rc, out, e = _docker(h, [sub, "prune", "-f"])
    return _fail(rc, e, out) if rc else f"Done: prune {what}\n{out.strip()[-1000:]}"


@mcp.tool()
@_safe
def docker_exec(container: str, command: str, host: str = "", shell: bool = False,
                workdir: str = "", user: str = "",
                confirm: bool = False) -> str:
    """Run one command inside a running container (no terminal, no input).

    Destructive, because the command can do anything inside the container.
    Shows a preview first. Run again with confirm=true after the user says yes.
    By default the command is split like a shell would, but no shell is used
    (no pipes). Set shell=true to run it with `sh -c` (pipes, &&, redirects).
    workdir sets the folder inside the container. user sets the user.
    """
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("container", container)
    if bad:
        return bad
    try:
        parts = ["sh", "-c", command] if shell else shlex.split(command)
    except ValueError as e:
        return f"Bad command: {e}"
    if not command.strip() or not parts:
        return "command is empty."
    opts: list[str] = []
    if workdir:
        if not _container_path_ok(workdir):
            return f"Bad workdir: {workdir!r}"
        opts += ["-w", workdir]
    if user:
        if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})?$", user):
            return f"Bad user: {user!r}"
        opts += ["-u", user]
    stop = _gate(h, "destructive", f"exec {container}", f"{command}", confirm)
    if stop:
        return stop
    rc, out, e = _docker(h, ["exec"] + opts + [container] + parts)
    text = _redact_text((out + e).strip())[-8000:]
    return f"ERROR (exit {rc}): {text}" if rc else (text or "(no output)")


# ---------------------------------------------------------------------------
# Files on the host (stacks folder and any extra allowed folders)
# ---------------------------------------------------------------------------
SECRET_FILE_RE = re.compile(
    r"(^\.env|\.env$|\.(pem|key|p12|pfx|kdbx)$|^id_(rsa|dsa|ecdsa|ed25519)$|^authorized_keys$"
    r"|^shadow$|^\.htpasswd$|credentials?$|^\.git-credentials$)", re.I)
PORT_RE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}:)?\d{1,5}(-\d{1,5})?:\d{1,5}(-\d{1,5})?(/(tcp|udp))?$")
KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
MODE_RE = re.compile(r"^[0-7]{3,4}$")
GIT_URL_RE = re.compile(r"^https://[A-Za-z0-9.-]+/[A-Za-z0-9._~%/-]+(#[A-Za-z0-9._/:-]+)?$")
RESTART_RE = re.compile(r"^(no|always|unless-stopped|on-failure(:\d{1,3})?)$")
HIDDEN_MSG = (
    "Refusing: the text contains ***hidden*** (a hidden secret). Writing it would "
    "destroy the real value. Use server_file_edit on the other lines, or use ${VAR} references."
)


def _max_bytes() -> int:
    return int(ENV.get("SERVER_MCP_MAX_FILE_KB", "1024")) * 1024


def _roots(h: dict[str, Any]) -> list[str]:
    raw = ENV.get(f"SERVER_MCP_{_env_key(h['name'])}_FILE_ROOTS")
    if raw is None:
        raw = ENV.get("SERVER_MCP_FILE_ROOTS", "")
    if not raw.strip():
        return ["/"]  # any path, unless SERVER_MCP_FILE_ROOTS limits it
    roots = [h["stacks"]]
    for x in raw.split(","):
        x = x.strip()
        if x.startswith("/"):
            x = posixpath.normpath(x)
            if x not in roots:
                roots.append(x)
    return roots


# Folders that are never deleted or replaced as a whole.
PROTECTED = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root",
             "/run", "/sbin", "/srv", "/sys", "/usr", "/var", "/mnt", "/media", "/volume1"}


def _protected(p: str) -> bool:
    return posixpath.normpath(p) in PROTECTED


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


def _path(h: dict[str, Any], raw: str) -> tuple[str | None, str]:
    """Check a host path. It must be inside an allowed folder, also after symlinks."""
    raw = (raw or "").strip()
    if not raw or any(c in raw for c in "\0\n\r"):
        return None, f"Bad path: {raw!r}"
    if not raw.startswith("/"):
        raw = h["stacks"] + "/" + raw  # relative paths start in the stacks folder
    p = posixpath.normpath(raw)
    if p.startswith("//"):
        p = "/" + p.lstrip("/")
    roots = _roots(h)
    if not any(_under(p, r) for r in roots):
        return None, (f"Path {p} is outside the allowed folders: {', '.join(roots)}. "
                      "More can be allowed with SERVER_MCP_FILE_ROOTS.")
    rc, out, err = _exec(h, ["realpath", "-m", "--"] + roots + [p])
    if rc != 0:
        return None, _fail(rc, err)
    lines = out.splitlines()
    if len(lines) != len(roots) + 1:
        return None, "Could not check the path."
    if not any(_under(lines[-1], r) for r in lines[:-1]):
        return None, f"Path {p} leads outside the allowed folders (symlink). Refused."
    return p, ""


def _secret_file(p: str) -> bool:
    return bool(SECRET_FILE_RE.search(posixpath.basename(p)))


def _container_path_ok(p: str) -> bool:
    return (bool(p) and p.startswith("/") and len(p) < 1024 and not any(c in p for c in "\0\n\r")
            and ".." not in p.split("/"))


def _exists(h: dict[str, Any], p: str, flag: str = "-e") -> bool:
    rc, _, _ = _exec(h, ["test", flag, p])
    return rc == 0


WRITE_SCRIPT = r'''set -e
f="$1"; mode="$2"; bak="$3"; mk="$4"
d=$(dirname -- "$f")
if [ "$mk" = 1 ]; then mkdir -p -- "$d"; fi
if [ ! -d "$d" ]; then echo "folder does not exist: $d" >&2; exit 3; fi
if [ -d "$f" ]; then echo "that path is a folder: $f" >&2; exit 3; fi
t="$f.mcp-tmp.$$"
trap 'rm -f -- "$t"' EXIT
cat > "$t"
if [ -e "$f" ]; then
  if [ "$bak" = 1 ]; then cp -p -- "$f" "$f.bak"; fi
  chmod --reference="$f" -- "$t" 2>/dev/null || true
  chown --reference="$f" -- "$t" 2>/dev/null || true
fi
if [ -n "$mode" ]; then chmod "$mode" -- "$t"; fi
mv -f -- "$t" "$f"
trap - EXIT
'''


def _write_file(h: dict[str, Any], p: str, data: bytes, make_dirs: bool = True,
                backup: bool = True, mode: str = "") -> tuple[int, str]:
    rc, _, err = _exec_bytes(
        h, ["sh", "-c", WRITE_SCRIPT, "sh", p, mode, "1" if backup else "0", "1" if make_dirs else "0"],
        data=data)
    return rc, err


def _read_file(h: dict[str, Any], p: str, limit: int) -> tuple[bytes | None, str, bool]:
    """Return (bytes, error, cut). Reads at most limit bytes; cut=true if the file is longer."""
    rc, out, err = _exec_bytes(h, ["head", "-c", str(limit + 1), "--", p])
    if rc != 0:
        return None, _fail(rc, err), False
    return out[:limit], "", len(out) > limit


def _as_text(data: bytes) -> str | None:
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


@mcp.tool()
@_safe
@_rootable
def server_file_list(path: str = "", host: str = "", depth: int = 1, as_root: bool = False) -> str:
    """List files and folders on the Docker host (type, mode, owner, size, date, path).

    Any path works. SERVER_MCP_FILE_ROOTS can limit it to some folders. as_root=true uses sudo.
    An empty path means the stacks folder. A path without a leading / starts there too.
    depth is how many folder levels to show (1 to 4).
    """
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path or h["stacks"])
    if not p:
        return e
    depth = max(1, min(int(depth), 4))
    rc, out, er = _exec(h, ["find", p, "-maxdepth", str(depth), "-printf", "%y %m %u:%g %s %TY-%Tm-%Td_%TH:%TM %p\\n"])
    if rc != 0 and not out.strip():
        return _fail(rc, er)
    lines = sorted(out.splitlines(), key=lambda x: x.split(" ", 5)[-1])
    cut = f"\n... showing 500 of {len(lines)}" if len(lines) > 500 else ""
    return "\n".join(lines[:500]) + cut


@mcp.tool()
@_safe
@_rootable
def server_file_read(path: str, host: str = "", as_root: bool = False) -> str:
    """Read a text file on the Docker host. Secret values are hidden.

    Files that hold secrets (.env, *.env, keys, credentials) are never shown.
    Big files are cut (SERVER_MCP_MAX_FILE_KB, default 1024 KB).
    """
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path)
    if not p:
        return e
    if _secret_file(p):
        return f"Refusing to show {posixpath.basename(p)}: it holds secrets. You can still write or edit it."
    data, e, cut = _read_file(h, p, _max_bytes())
    if data is None:
        return e
    text = _as_text(data)
    if text is None:
        return "That file is not UTF-8 text (binary). Not shown."
    shown = _redact_text(text)
    note = "\n[note: secret values were hidden]" if shown != text.rstrip("\n") and HIDDEN in shown else ""
    return shown + ("\n... file cut here" if cut else "") + note


@mcp.tool()
@_safe
@_rootable
def server_file_write(path: str, content: str, host: str = "", make_dirs: bool = True,
                      backup: bool = True, mode: str = "", encoding: str = "text", as_root: bool = False, confirm: bool = False) -> str:
    """Create a file, or replace a whole file, on the Docker host. Needs confirm=true.

    make_dirs creates missing folders. backup keeps the old file as <name>.bak.
    mode is an optional octal mode such as 644 or 755 (for scripts). An existing
    file keeps its mode and owner. encoding is text, or base64 for binary files.
    For a small change to an existing file use server_file_edit instead: it never
    touches hidden secret lines.
    """
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path)
    if not p:
        return e
    if encoding not in ("text", "base64"):
        return "encoding must be text or base64."
    if mode and not MODE_RE.match(mode):
        return "mode must be octal like 644 or 755."
    if HIDDEN in content:
        return HIDDEN_MSG
    try:
        data = base64.b64decode(content, validate=True) if encoding == "base64" else content.encode("utf-8")
    except ValueError:
        return "content is not valid base64."
    if len(data) > _max_bytes():
        return f"Too big ({len(data)} bytes). Limit is {_max_bytes()} (SERVER_MCP_MAX_FILE_KB)."
    exists = _exists(h, p)
    stop = _gate(h, "change", f"write file {p}",
                 f"{'replace' if exists else 'create'} {p} ({len(data)} bytes)"
                 + (f"; old file kept as {p}.bak" if exists and backup else ""), confirm, "",
                 preview=_diff(h, p, data))
    if stop:
        return stop
    rc, er = _write_file(h, p, data, make_dirs, backup, mode)
    if rc:
        return _fail(rc, er)
    return f"Done: wrote {len(data)} bytes to {p}" + (f" (old file kept as {p}.bak)" if exists and backup else "")


@mcp.tool()
@_safe
@_rootable
def server_file_edit(path: str, old_string: str, new_string: str, host: str = "",
                     replace_all: bool = False, backup: bool = True, as_root: bool = False, confirm: bool = False) -> str:
    """Change part of a text file: replace old_string with new_string. Needs confirm=true.

    old_string must match the file exactly and must be unique, unless replace_all=true.
    Works on files Claude can read. Lines with hidden secrets cannot be matched.
    """
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path)
    if not p:
        return e
    if _secret_file(p):
        return f"Refusing to edit {posixpath.basename(p)}: it holds secrets. Use server_file_write for the whole file."
    if HIDDEN in old_string or HIDDEN in new_string:
        return HIDDEN_MSG
    if not old_string:
        return "old_string is empty. Use server_file_write to create a file."
    if old_string == new_string:
        return "old_string and new_string are the same. Nothing to do."
    data, e, cut = _read_file(h, p, _max_bytes())
    if data is None:
        return e
    if cut:
        return "File is too big to edit this way."
    text = _as_text(data)
    if text is None:
        return "That file is not UTF-8 text. Cannot edit."
    n = text.count(old_string)
    if n == 0:
        hint = " The file uses Windows line endings (\\r\\n)." if "\r\n" in text and "\r\n" not in old_string else ""
        return f"old_string was not found.{hint} Read the file again and copy the text exactly."
    if n > 1 and not replace_all:
        return f"old_string was found {n} times. Add more text around it to make it unique, or set replace_all=true."
    new_text = text.replace(old_string, new_string) if replace_all else text.replace(old_string, new_string, 1)
    stop = _gate(h, "change", f"edit file {p}",
                 f"replace {n if replace_all else 1} place(s) in {p}: {_redact_text(old_string)[:200]!r} -> {_redact_text(new_string)[:200]!r}",
                 confirm, "", preview=_diff(h, p, new_text.encode("utf-8")))
    if stop:
        return stop
    rc, er = _write_file(h, p, new_text.encode("utf-8"), False, backup)
    if rc:
        return _fail(rc, er)
    return f"Done: changed {n if replace_all else 1} place(s) in {p}" + (f" (old file kept as {p}.bak)" if backup else "")


@mcp.tool()
@_safe
@_rootable
def server_file_mkdir(path: str, host: str = "", as_root: bool = False, confirm: bool = False) -> str:
    """Make a folder (and missing parent folders) on the Docker host. Needs confirm=true."""
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path)
    if not p:
        return e
    stop = _gate(h, "change", f"mkdir {p}", f"mkdir -p {p}", confirm, "")
    if stop:
        return stop
    rc, out, er = _exec(h, ["mkdir", "-p", "--", p])
    return _fail(rc, er, out) if rc else f"Done: folder {p} exists"


@mcp.tool()
@_safe
@_rootable
def server_file_move(source: str, destination: str, host: str = "", overwrite: bool = False, as_root: bool = False, confirm: bool = False) -> str:
    """Move or rename a file or folder on the Docker host. Needs confirm=true.

    Without overwrite=true an existing destination is left alone.
    """
    h, err = _pick(host)
    if not h:
        return err
    s_, e = _path(h, source)
    if not s_:
        return e
    d_, e = _path(h, destination)
    if not d_:
        return e
    if s_ in _roots(h):
        return "Refusing to move an allowed root folder."
    stop = _gate(h, "change", f"move {s_}", f"mv {s_} -> {d_}" + (" (overwrite)" if overwrite else ""), confirm, "")
    if stop:
        return stop
    rc, out, er = _exec(h, ["mv", "-f" if overwrite else "-n", "--", s_, d_])
    return _fail(rc, er, out) if rc else f"Done: moved {s_} to {d_}"


@mcp.tool()
@_safe
@_rootable
def server_file_delete(path: str, host: str = "", recursive: bool = False, as_root: bool = False, confirm: bool = False) -> str:
    """Delete a file or an empty folder on the Docker host. Destructive.

    Destructive. Shows a preview first. Run again with confirm=true after the user says yes.
    recursive=true also deletes a folder with everything in it. Never forced.
    """
    h, err = _pick(host)
    if not h:
        return err
    p, e = _path(h, path)
    if not p:
        return e
    if p in _roots(h) or _protected(p):
        return "Refusing to delete a protected system folder."
    stop = _gate(h, "destructive", f"delete {p}", f"{'rm -r' if recursive else 'rm'} {p}", confirm)
    if stop:
        return stop
    if recursive:
        argv = ["rm", "-r", "--", p]
    else:
        argv = ["sh", "-c", 'if [ -d "$1" ] && [ ! -L "$1" ]; then rmdir -- "$1"; else rm -- "$1"; fi', "sh", p]
    rc, out, er = _exec(h, argv)
    return _fail(rc, er, out) if rc else f"Done: deleted {p}"


@mcp.tool()
@_safe
def docker_copy(container: str, container_path: str, host_path: str, direction: str,
                host: str = "", keep_owner: bool = False, confirm: bool = False) -> str:
    """Copy files between a container and the Docker host (docker cp). Needs confirm=true.

    direction: to_container (host_path -> container_path) or from_container
    (container_path -> host_path). host_path must be in an allowed folder.
    Existing files at the destination are overwritten. keep_owner uses docker cp -a.
    """
    h, err = _pick(host)
    if not h:
        return err
    if direction not in ("to_container", "from_container"):
        return "direction must be to_container or from_container."
    bad = _check_name("container", container)
    if bad:
        return bad
    if not _container_path_ok(container_path):
        return f"Bad container_path: {container_path!r}. Use an absolute path without '..'."
    hp, e = _path(h, host_path)
    if not hp:
        return e
    remote = f"{container}:{container_path}"
    src, dst = (hp, remote) if direction == "to_container" else (remote, hp)
    stop = _gate(h, "change", f"copy {direction} {container}", f"docker cp {src} {dst}", confirm, "")
    if stop:
        return stop
    rc, out, er = _docker(h, ["cp"] + (["-a"] if keep_owner else []) + [src, dst], long=True)
    return _fail(rc, er, out) if rc else f"Done: copied {src} to {dst}"


# ---------------------------------------------------------------------------
# Stack files, build, run, create
# ---------------------------------------------------------------------------
@mcp.tool()
@_safe
def docker_stack_write(stack: str, content: str, host: str = "", confirm: bool = False) -> str:
    """Create a new stack, or replace the compose file of one, then check it. Needs confirm=true.

    The file goes to <stacks folder>/<stack>/compose.yaml (an existing compose file keeps its name).
    The result is checked with `docker compose config`. If the check fails, the old file is put back
    (or the new file removed) and the error is shown. Nothing is started: use docker_stack_action up.
    Secret values should be ${VARIABLES} that live in the .env file (write that with server_file_write).
    """
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("stack", stack)
    if bad:
        return bad
    if HIDDEN in content:
        return HIDDEN_MSG
    data = content.encode("utf-8")
    if len(data) > _max_bytes():
        return f"Too big ({len(data)} bytes)."
    stacks, e = _find_stacks(h)
    if stacks is None:
        return e
    target = stacks.get(stack) or f"{h['stacks']}/{stack}/compose.yaml"
    p, e = _path(h, target)
    if not p:
        return e
    existed = stack in stacks
    stop = _gate(h, "change", f"write stack {stack}",
                 f"{'replace' if existed else 'create'} {p} ({len(data)} bytes), then check it", confirm, "",
                 preview=_diff(h, p, data))
    if stop:
        return stop
    rc, er = _write_file(h, p, data, True, True)
    if rc:
        return _fail(rc, er)
    folder = p.rsplit("/", 1)[0]
    rc, out, er = _docker(h, ["compose", "config", "-q"], cwd=folder)
    if rc:
        if existed:
            _exec(h, ["mv", "-f", "--", p + ".bak", p])
        else:
            _exec(h, ["rm", "-f", "--", p])
        return "The compose file did not pass the check, so the " + (
            "old file was put back." if existed else "new file was removed.") + "\n" + _fail(rc, er, out)
    return f"Done: {p} written and checked ({'replaced' if existed else 'new stack'}). Not started yet."


@mcp.tool()
@_safe
def docker_stack_logs(stack: str, host: str = "", service: str = "", tail: int = 100, since: str = "") -> str:
    """Show the last log lines of a whole stack, or one service of it. since like 10m, 2h, 2026-10-22."""
    h, err = _pick(host)
    if not h:
        return err
    st, e = _stack(h, stack)
    if not st:
        return e
    args = ["compose", "logs", "--no-color", "--timestamps", "--tail", str(max(1, min(int(tail), 1000)))]
    if since:
        if not SINCE_RE.match(since):
            return f"Bad since value: {since!r}."
        args += ["--since", since]
    if service:
        bad = _check_name("service", service)
        if bad:
            return bad
        args.append(service)
    rc, out, er = _docker(h, args, cwd=st[0])
    if rc:
        return _fail(rc, er, out)
    text = _redact_text((out + er).strip())
    return text[-30000:] if text else "(no log lines)"


@mcp.tool()
@_safe
def docker_build(context: str, tag: str, host: str = "", dockerfile: str = "",
                 build_args: dict[str, str] | None = None, target: str = "", platform: str = "",
                 no_cache: bool = False, pull: bool = False, confirm: bool = False) -> str:
    """Build an image with docker build. Needs confirm=true.

    context is a folder on the host (in an allowed folder) or an https git URL
    such as https://github.com/example/repo.git#main. tag is the image name,
    for example myapp:latest. dockerfile is a path inside the context.
    Build args are visible in the image history: do not put real secrets in them.
    """
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("image", tag, image=True)
    if bad:
        return bad
    if GIT_URL_RE.match(context):
        ctx = context
    elif "://" in context or context.startswith(("git@", "-")):
        return "Bad context: use a folder on the host or an https git URL."
    else:
        ctx, e = _path(h, context)
        if not ctx:
            return e
    args = ["build", "--progress=plain", "-t", tag]
    if dockerfile:
        if not re.match(r"^[A-Za-z0-9._][A-Za-z0-9._/-]*$", dockerfile) or ".." in dockerfile.split("/"):
            return f"Bad dockerfile: {dockerfile!r}. Use a path inside the context."
        args += ["-f", dockerfile if ctx.startswith("https://") else f"{ctx}/{dockerfile}"]
    shown = []
    for k, v in (build_args or {}).items():
        if not KEY_RE.match(k) or "\n" in str(v):
            return f"Bad build arg: {k!r}"
        args += ["--build-arg", f"{k}={v}"]
        shown.append(f"{k}={HIDDEN if _secret_name(k) else v}")
    if target:
        if not NAME_RE.match(target):
            return f"Bad target: {target!r}"
        args += ["--target", target]
    if platform:
        if not re.match(r"^[a-z0-9]+/[a-z0-9]+(/v[0-9]+)?$", platform):
            return f"Bad platform: {platform!r}. Use linux/amd64 for example."
        args += ["--platform", platform]
    if no_cache:
        args.append("--no-cache")
    if pull:
        args.append("--pull")
    args.append(ctx)
    stop = _gate(h, "change", f"build image {tag}", f"docker build {ctx} -> {tag}" + (f" args: {', '.join(shown)}" if shown else ""), confirm, "")
    if stop:
        return stop
    rc, out, er = _docker(h, args, long="build")
    text = _redact_text((out + er).strip())
    if rc:
        return f"BUILD FAILED (exit {rc}). Last lines:\n{text[-4000:]}"
    return f"Done: built {tag}\n{text[-1200:]}"


@mcp.tool()
@_safe
def docker_tag_image(source: str, target: str, host: str = "", confirm: bool = False) -> str:
    """Give an image a second name (docker tag). Needs confirm=true."""
    h, err = _pick(host)
    if not h:
        return err
    for v in (source, target):
        bad = _check_name("image", v, image=True)
        if bad:
            return bad
    stop = _gate(h, "change", f"tag {source}", f"docker tag {source} {target}", confirm, "")
    if stop:
        return stop
    rc, out, er = _docker(h, ["tag", source, target])
    return _fail(rc, er, out) if rc else f"Done: {source} is now also {target}"


@mcp.tool()
@_safe
def docker_run(image: str, host: str = "", name: str = "", ports: list[str] | None = None,
               env: dict[str, str] | None = None, volumes: list[str] | None = None,
               network: str = "", restart: str = "unless-stopped", command: str = "",
               user: str = "", workdir: str = "", confirm: bool = False) -> str:
    """Start a new container in the background (docker run -d). Needs confirm=true.

    For anything that should stay, a compose stack (docker_stack_write) is better.
    ports like "8080:80" or "127.0.0.1:8080:80/tcp". volumes like "myvol:/data" or
    "/opt/stacks/app/data:/data:ro" (a host folder must be in an allowed folder).
    Not possible here: privileged mode, devices, the docker socket.
    """
    h, err = _pick(host)
    if not h:
        return err
    bad = _check_name("image", image, image=True)
    if bad:
        return bad
    args = ["run", "-d"]
    if name:
        bad = _check_name("container", name)
        if bad:
            return bad
        args += ["--name", name]
    if not RESTART_RE.match(restart):
        return "restart must be no, always, unless-stopped or on-failure[:N]."
    args += ["--restart", restart]
    if network:
        bad = _check_name("network", network)
        if bad:
            return bad
        args += ["--network", network]
    for pt in ports or []:
        if not PORT_RE.match(pt):
            return f"Bad port: {pt!r}"
        args += ["-p", pt]
    env_list = []
    for k, v in (env or {}).items():
        if not KEY_RE.match(k) or "\n" in str(v):
            return f"Bad env name: {k!r}"
        args += ["-e", f"{k}={v}"]
        env_list.append(f"{k}={v}")
    for vol in volumes or []:
        parts = vol.split(":")
        if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] not in ("ro", "rw", "z", "Z", "ro,z", "ro,Z")):
            return f"Bad volume: {vol!r}. Use source:target or source:target:ro"
        src = parts[0]
        if src.startswith("/"):
            src, e = _path(h, src)
            if not src:
                return e
        elif not NAME_RE.match(src):
            return f"Bad volume source: {src!r}"
        if not _container_path_ok(parts[1]):
            return f"Bad volume target: {parts[1]!r}"
        args += ["-v", ":".join([src] + parts[1:])]
    if user:
        if not re.match(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,63})?$", user):
            return f"Bad user: {user!r}"
        args += ["-u", user]
    if workdir:
        if not _container_path_ok(workdir):
            return f"Bad workdir: {workdir!r}"
        args += ["-w", workdir]
    try:
        cmd_parts = shlex.split(command) if command else []
    except ValueError as e:
        return f"Bad command: {e}"
    args += [image] + cmd_parts
    details = f"docker run -d {image}" + (f" name={name}" if name else "") + f" ports={ports or []} volumes={volumes or []} env={_redact_env(env_list)} network={network or 'default'}"
    stop = _gate(h, "change", f"run {image}", details, confirm, "")
    if stop:
        return stop
    rc, out, er = _docker(h, args, long=True)
    return _fail(rc, er, out) if rc else f"Done: started {name or image}\nid: {out.strip()[:64]}"


@mcp.tool()
@_safe
def docker_create(kind: str, name: str, host: str = "", driver: str = "", subnet: str = "",
                  gateway: str = "", ip_range: str = "", parent: str = "", internal: bool = False,
                  options: dict[str, str] | None = None, confirm: bool = False) -> str:
    """Create a network or a volume. Needs confirm=true.

    kind: network or volume.
    Network: driver (bridge, macvlan ...), subnet, gateway, ip_range, parent (the host
    interface for macvlan, for example eth0.20), internal.
    Volume: driver (default local) and options, for example an NFS volume:
    options {"type": "nfs", "o": "addr=192.0.2.10,nfsvers=3,hard", "device": ":/export/share"}.
    """
    h, err = _pick(host)
    if not h:
        return err
    if kind not in ("network", "volume"):
        return "kind must be network or volume."
    bad = _check_name(kind, name)
    if bad:
        return bad
    if driver and not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", driver):
        return f"Bad driver: {driver!r}"
    args = [kind, "create"] + (["--driver", driver] if driver else [])
    if kind == "network":
        try:
            if subnet:
                ipaddress.ip_network(subnet, strict=False)
                args += ["--subnet", subnet]
            if ip_range:
                ipaddress.ip_network(ip_range, strict=False)
                args += ["--ip-range", ip_range]
            if gateway:
                ipaddress.ip_address(gateway)
                args += ["--gateway", gateway]
        except ValueError as e:
            return f"Bad address: {e}"
        if parent:
            if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$", parent):
                return f"Bad parent: {parent!r}"
            args += ["-o", f"parent={parent}"]
        if internal:
            args.append("--internal")
    flag = "-o" if kind == "network" else "--opt"
    for k, v in (options or {}).items():
        if not KEY_RE.match(k) or "\n" in str(v):
            return f"Bad option: {k!r}"
        args += [flag, f"{k}={v}"]
    stop = _gate(h, "change", f"create {kind} {name}", "docker " + " ".join(args) + f" {name}", confirm, "")
    if stop:
        return stop
    rc, out, er = _docker(h, args + [name])
    return _fail(rc, er, out) if rc else f"Done: created {kind} {name}"


# ---------------------------------------------------------------------------
# Host command (like pikvm_ssh): safe reads run, the rest needs a yes
# ---------------------------------------------------------------------------
READ_CMDS = {"ls", "cat", "head", "tail", "wc", "grep", "find", "stat", "du", "df", "free", "uptime",
             "pwd", "whoami", "id", "uname", "date", "hostname", "file", "ps", "ss", "lsblk", "which",
             "echo", "sort", "uniq", "cut", "tr", "diff", "readlink", "realpath", "basename", "dirname", "ip",
             "lsof"}
READ_GIT = {"status", "log", "diff", "show", "branch", "remote", "rev-parse"}
RISKY_CMDS = {"rm", "rmdir", "mv", "dd", "mkfs", "shutdown", "reboot", "poweroff", "halt", "kill", "killall",
              "pkill", "chmod", "chown", "chattr", "passwd", "usermod", "userdel", "systemctl", "service",
              "apt", "apt-get", "dpkg", "yum", "dnf", "pacman", "iptables", "ufw", "mount", "umount", "fdisk",
              "parted", "crontab", "sudo", "su", "truncate", "shred", "wipefs"}
SHELL_BAD = re.compile(r"(>|<|`|\$\(|;|&&|\|\||\n|&)")


def _classify(command: str) -> str:
    """read, change, destructive, or blocked. Errs on the side of asking."""
    cmd = command.strip()
    if not cmd or "\0" in cmd:
        return "blocked"
    if re.search(r"(\.env\b|id_(rsa|ed25519|ecdsa|dsa)|authorized_keys|/etc/shadow|\.pem\b|\.key\b|credentials)", cmd, re.I):
        return "blocked"
    if any(w in RISKY_CMDS for w in re.findall(r"[A-Za-z0-9_.+-]+", cmd)):
        return "destructive"
    if SHELL_BAD.search(cmd):
        return "change"
    for seg in cmd.split("|"):
        parts = seg.split()
        if not parts:
            return "change"
        c = parts[0].rsplit("/", 1)[-1]
        if c == "git":
            if len(parts) < 2 or parts[1] not in READ_GIT:
                return "change"
        elif c == "find":
            if re.search(r"\s-(exec|execdir|delete|ok|fprint|fprintf)\b", seg):
                return "change"
        elif c not in READ_CMDS:
            return "change"
    return "read"


@mcp.tool()
@_safe
def server_run(command: str, host: str = "", timeout: int = 60, as_root: bool = False,
               confirm: bool = False) -> str:
    """Run one shell command on the Docker host itself (not inside a container).

    It starts in the stacks folder. Safe read-only commands (ls, cat, head, tail, grep, find,
    df, free, uptime, git status/log/diff, ps, ss, ip, and pipes between them) run right away.
    Anything else needs confirm=true after the user says yes. Risky ones (rm, mv, dd, chmod,
    chown, kill, systemctl, apt, reboot, sudo ...) are marked destructive in the preview.
    as_root=true runs it with sudo. Root commands always show a preview first.
    Files with passwords or keys (.env, keys, credentials) are blocked.
    For files, prefer server_file_read, server_file_write and server_file_edit.
    """
    h, err = _pick(host)
    if not h:
        return err
    tier = _classify(command)
    if tier == "blocked":
        return "ERROR: that command is empty or touches a file with passwords or keys. It is blocked."
    first = command.strip().split()[0].rsplit("/", 1)[-1]
    if as_root and tier == "read":
        tier = "change"
    stop = _gate(h, tier, f"{'sudo ' if as_root else ''}run {first}", command, confirm)
    if stop:
        return stop
    return _sh(h, command, as_root, timeout)


def _sh(h: dict[str, Any], command: str, root: bool = False, timeout: int = 60, cwd: str | None = None) -> str:
    """Run a shell command and return redacted output."""
    # Start in the stacks folder if the host has one, otherwise in the login folder.
    start = cwd or h["stacks"]
    script = f"cd {shlex.quote(start)} 2>/dev/null || cd \"$HOME\" 2>/dev/null || cd /; {command}"
    rc, out, er = _exec(h, ["sh", "-c", script], timeout=max(5, min(int(timeout), 900)), root=root)
    text = _redact_text((out + (("\n" + er) if er.strip() else "")).strip())[-12000:]
    return f"ERROR (exit {rc}): {text}" if rc else (text or "(no output)")


_UNIT = re.compile(r"^[A-Za-z0-9@_.:\\-]{1,120}$")
_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+_.:=~-]{0,100}$")


@mcp.tool()
def server_info(host: str = "") -> str:
    """Show the system: OS, kernel, uptime, CPU, memory, disks and network. Read only."""
    h, err = _pick(host)
    if not h:
        return err
    return _sh(h, "(cat /etc/os-release | head -3; uname -srm; uptime; echo; free -h; echo; df -hT -x tmpfs -x devtmpfs; "
                  "echo; ip -brief addr) 2>&1")


@mcp.tool()
def server_service(unit: str, action: str = "status", host: str = "", as_root: bool = True,
                   confirm: bool = False) -> str:
    """Manage a systemd service. action: status, start, stop, restart, reload, enable, disable.

    status is read only and runs right away. The others show a preview first.
    """
    h, err = _pick(host)
    if not h:
        return err
    if not _UNIT.match(unit):
        return "Bad unit name."
    if action not in {"status", "start", "stop", "restart", "reload", "enable", "disable"}:
        return "action must be status, start, stop, restart, reload, enable or disable."
    if action == "status":
        return _sh(h, f"systemctl status --no-pager -l {shlex.quote(unit)} 2>&1 | head -40")
    stop = _gate(h, "destructive" if action in {"stop", "disable"} else "change",
                 f"service {action} {unit}", f"systemctl {action} {unit}", confirm)
    return stop or _sh(h, f"systemctl {action} {shlex.quote(unit)} 2>&1 && echo done", as_root)


@mcp.tool()
def server_journal(unit: str = "", lines: int = 100, since: str = "", grep: str = "", host: str = "",
                   as_root: bool = False) -> str:
    """Read the system log (journalctl). Optional unit, line count, since ("1 hour ago") and grep. Read only."""
    h, err = _pick(host)
    if not h:
        return err
    cmd = f"journalctl --no-pager -n {max(1, min(int(lines), 2000))}"
    if unit:
        if not _UNIT.match(unit):
            return "Bad unit name."
        cmd += f" -u {shlex.quote(unit)}"
    if since:
        cmd += f" --since {shlex.quote(since)}"
    if grep:
        cmd += f" | grep -i -- {shlex.quote(grep)}"
    return _sh(h, cmd + " 2>&1", as_root)


@mcp.tool()
def server_packages(action: str, packages: str = "", host: str = "", confirm: bool = False) -> str:
    """Manage system packages (apt, dnf or apk, found automatically).

    action: list_updates and search are read only. update (refresh lists), install, remove
    and upgrade show a preview first. packages is a space separated list.
    """
    h, err = _pick(host)
    if not h:
        return err
    names = packages.split()
    if any(not _PKG.match(n) for n in names):
        return "Bad package name."
    mgr = _sh(h, "for m in apt-get dnf apk; do command -v $m >/dev/null && echo $m && break; done").strip().split()[-1:]
    if not mgr or mgr[0] not in {"apt-get", "dnf", "apk"}:
        return "No supported package manager (apt, dnf, apk) found."
    m, q = mgr[0], " ".join(shlex.quote(n) for n in names)
    table = {
        "apt-get": {"list_updates": "apt list --upgradable 2>/dev/null", "search": f"apt-cache search {q}",
                    "update": "apt-get update", "install": f"apt-get install -y {q}",
                    "remove": f"apt-get remove -y {q}", "upgrade": "apt-get upgrade -y"},
        "dnf": {"list_updates": "dnf check-update", "search": f"dnf search {q}", "update": "dnf makecache",
                "install": f"dnf install -y {q}", "remove": f"dnf remove -y {q}", "upgrade": "dnf upgrade -y"},
        "apk": {"list_updates": "apk version -l '<'", "search": f"apk search {q}", "update": "apk update",
                "install": f"apk add {q}", "remove": f"apk del {q}", "upgrade": "apk upgrade"},
    }[m]
    if action not in table:
        return "action must be list_updates, search, update, install, remove or upgrade."
    if action in {"install", "remove", "search"} and not names:
        return "packages is needed for this action."
    if action in {"list_updates", "search"}:
        return _sh(h, table[action] + " 2>&1 | head -200")
    stop = _gate(h, "destructive" if action in {"remove", "upgrade"} else "change",
                 f"packages {action}", table[action], confirm)
    return stop or _sh(h, "DEBIAN_FRONTEND=noninteractive " + table[action] + " 2>&1", True, 900)


@mcp.tool()
def server_processes(sort: str = "cpu", limit: int = 15, host: str = "") -> str:
    """Show the busiest processes. sort: cpu or mem. Read only."""
    h, err = _pick(host)
    if not h:
        return err
    key = "-%mem" if sort == "mem" else "-%cpu"
    return _sh(h, f"ps -eo pid,user,%cpu,%mem,etime,comm --sort={key} | head -{max(2, min(int(limit), 100)) + 1}")


@mcp.tool()
def server_power(action: str, host: str = "", confirm: bool = False) -> str:
    """Reboot or power off the host. action: reboot or poweroff. Always shows a preview first.

    The SSH link drops when it runs. That is normal.
    """
    h, err = _pick(host)
    if not h:
        return err
    if action not in {"reboot", "poweroff"}:
        return "action must be reboot or poweroff."
    stop = _gate(h, "destructive", f"power {action}", f"systemctl {action}. Running containers stop.", confirm)
    if stop:
        return stop
    _exec(h, ["sh", "-c", f"nohup sh -c 'sleep 2; systemctl {action}' >/dev/null 2>&1 &"], root=True)
    return f"{action} started. The host will drop off the network for a bit."


@mcp.tool()
def docker_cli(args: str, host: str = "", as_root: bool = False, confirm: bool = False) -> str:
    """Run any docker command, for things the other docker tools do not cover.

    Give the arguments after "docker", for example: "system df" or "compose -p demo ps".
    Read commands (ps, images, inspect, logs, info, version, stats --no-stream, network ls ...)
    run right away. Anything else shows a preview first.
    """
    h, err = _pick(host)
    if not h:
        return err
    try:
        argv = shlex.split(args)
    except ValueError as e:
        return f"Bad arguments: {e}"
    if not argv:
        return "Give some arguments."
    reads = {"ps", "images", "inspect", "logs", "info", "version", "top", "port", "diff", "history", "events"}
    sub = argv[0]
    safe = sub in reads or (len(argv) > 1 and argv[1] in {"ls", "ps", "inspect", "config", "logs", "df", "version"}
                            and sub in {"network", "volume", "compose", "system", "image", "container"})
    stop = None if safe and not as_root else _gate(h, "change", f"docker {sub}", "docker " + shlex.join(argv), confirm)
    if stop:
        return stop
    rc, out, er = _exec(h, ["docker"] + argv, cwd=h["stacks"], timeout=_timeout("long"), root=as_root)
    text = _redact_text((out + (("\n" + er) if er.strip() else "")).strip())[-12000:]
    return f"ERROR (exit {rc}): {text}" if rc else (text or "(no output)")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
