"""Tests for server-mcp. Plain Python, no test framework needed:  python tests/test_server.py

Everything runs on the local machine with a fake `docker`. No real servers are touched.
"""
import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp()
LOG = os.path.join(TMP, "calls.log")
FAKE = os.path.join(TMP, "fake_docker")
shutil.copy(ROOT / "tests" / "fake_docker", FAKE)
os.chmod(FAKE, 0o755)
STACKS = os.path.join(TMP, "stacks")
os.makedirs(os.path.join(STACKS, "demo"))
Path(STACKS, "demo", "compose.yaml").write_text("services:\n  svc:\n    image: example/svc\n")
os.environ.update({"SERVER_MCP_DOCKER_BIN": FAKE, "FAKE_DOCKER_LOG": LOG, "SERVER_MCP_HOSTS": "local",
                   "SERVER_MCP_LOCAL_STACKS": STACKS})

import server_mcp.server as s  # noqa: E402

RESULTS = []


def check(label, cond, detail=""):
    RESULTS.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + label + ("" if cond else f"  -> {str(detail)[:400]}"))


def tools():
    return {t.name: t for t in asyncio.run(s.mcp.list_tools())}


def docker_calls():
    if not Path(LOG).exists():
        return []
    return [json.loads(x)["args"] for x in Path(LOG).read_text().splitlines() if x.strip()]


# ---------------------------------------------------------------- tools exist
t = tools()
for name in ["server_hosts", "server_run", "server_info", "server_service", "server_journal", "server_packages",
             "server_processes", "server_power", "server_file_read", "server_file_write", "server_file_edit",
             "server_file_delete", "docker_cli", "docker_ps", "docker_stack_write"]:
    check(f"tool {name} exists", name in t)
check("no old confirm_phrase option left", all("confirm_phrase" not in x.inputSchema["properties"] for x in t.values()))
for name in ["server_run", "server_file_write", "server_file_edit", "server_file_delete", "docker_cli"]:
    check(f"{name} has as_root", "as_root" in t[name].inputSchema["properties"])

# ---------------------------------------------------------------- preview then confirm
f = os.path.join(TMP, "note.txt")
out = s.server_file_write(f, "hello\n")
check("write first shows a preview", out.startswith("PREVIEW") and "+hello" in out, out)
check("preview did not write", not os.path.exists(f))
out = s.server_file_write(f, "different\n", confirm=True)
check("confirm without the same preview is refused", out.startswith("PREVIEW") and not os.path.exists(f), out)
s.server_file_write(f, "hello\n")
out = s.server_file_write(f, "hello\n", confirm=True)
check("same call with confirm runs", out.startswith("Done") and Path(f).read_text() == "hello\n", out)
out = s.server_file_write(f, "hello\n", confirm=True)
check("a preview works only once", out.startswith("PREVIEW"), out)

s.server_file_edit(f, "hello", "bye")
out = s.server_file_edit(f, "hello", "bye", confirm=True)
check("edit shows diff then runs", Path(f).read_text() == "bye\n" and Path(f + ".bak").exists(), out)

out = s.server_file_read(f)
check("read runs right away", "bye" in out, out)

# ---------------------------------------------------------------- secrets stay hidden
sec = os.path.join(TMP, "app.env")
Path(sec).write_text("PASSWORD=hunter2\n")
check("secret file is refused", "hunter2" not in s.server_file_read(sec))
out = s.server_run("echo token=abc123 password=hunter2")
check("run output hides secrets", "hunter2" not in out, out)

# ---------------------------------------------------------------- delete safety
s.server_file_delete(f)
out = s.server_file_delete(f, confirm=True)
check("delete works after preview", not os.path.exists(f), out)
check("system folder is never deleted", "protected" in s.server_file_delete("/etc", recursive=True, confirm=True).lower())

# ---------------------------------------------------------------- shell classification
check("ls is read", s._classify("ls -la /tmp") == "read")
check("rm is destructive", s._classify("rm -rf /tmp/x") == "destructive")
check("unknown command is a change", s._classify("mytool --go") == "change")
check("key file is blocked", s._classify("cat ~/.ssh/id_ed25519") == "blocked")
check("root run always previews", s.server_run("ls", as_root=True).startswith("PREVIEW"))
check("read-only mode blocks changes", (lambda: (os.environ.__setitem__("SERVER_MCP_READ_ONLY", "1"),
      s.server_run("touch x", confirm=True))[1])().startswith("NOT RUN"))
os.environ.pop("SERVER_MCP_READ_ONLY")

# ---------------------------------------------------------------- system tools
check("info runs", "Linux" in s.server_info())
os.environ["SERVER_MCP_LOCAL_STACKS"] = "/no/such/folder"
check("info works when the stacks folder is missing", "Linux" in s.server_info(), s.server_info())
os.environ["SERVER_MCP_LOCAL_STACKS"] = STACKS
check("processes runs", "PID" in s.server_processes())
check("bad unit name refused", s.server_service("a;b") == "Bad unit name.")
check("service stop previews", s.server_service("demo.service", "stop").startswith("PREVIEW"))
check("bad package refused", s.server_packages("install", "x;y") == "Bad package name.")
check("power previews", s.server_power("reboot").startswith("PREVIEW"))

# ---------------------------------------------------------------- docker tools
check("docker ps works", "web" in s.docker_ps(), s.docker_ps())
check("docker_cli reads run", "27.3.1" in s.docker_cli("version --format x") or "27.3.1" in s.docker_cli("version"))
check("docker_cli change previews", s.docker_cli("rm thing").startswith("PREVIEW"))
before = len(docker_calls())
s.docker_stack_action("demo", "restart")
check("stack action previews, no call", len(docker_calls()) == before)
out = s.docker_stack_action("demo", "restart", confirm=True)
check("stack action runs after preview", any(c[:2] == ["compose", "restart"] or "restart" in c for c in docker_calls()[before:]), out)

# ---------------------------------------------------------------- sudo and docker path
h = {"name": "x", "ssh": "u@h", "docker_path": "/usr/local/bin/docker", "sudo": True, "sudo_password": "", "password": "", "key": "", "port": ""}
check("docker gets full path and sudo -n", s._sudo_wrap(h, ["docker", "ps"], False)[0] == ["sudo", "-n", "/usr/local/bin/docker", "ps"])
h2 = {**h, "sudo": False}
check("plain command stays plain", s._sudo_wrap(h2, ["ls"], False)[0] == ["ls"])
check("root adds sudo", s._sudo_wrap(h2, ["ls"], True)[0] == ["sudo", "-n", "ls"])
h3 = {**h2, "sudo_password": "pw"}
argv, feed = s._sudo_wrap(h3, ["ls"], True)
check("sudo password goes through stdin only", feed == b"pw\n" and "pw" not in " ".join(argv) and argv[-1] == "ls")

# ---------------------------------------------------------------- ssh options
hh = {"name": "x", "ssh": "u@h", "port": "", "key": ""}
check("ssh trusts a new host once", "StrictHostKeyChecking=accept-new" in s._ssh_cmd(hh, ["ls"]))
os.environ["SERVER_MCP_SSH_STRICT"] = "true"
check("strict mode turns that off", "StrictHostKeyChecking=accept-new" not in s._ssh_cmd(hh, ["ls"]))
del os.environ["SERVER_MCP_SSH_STRICT"]

# ---------------------------------------------------------------- host names
def names(raw):
    os.environ["SERVER_MCP_HOSTS_NAME"] = raw
    os.environ.pop("SERVER_MCP_HOSTS", None)
    return {k: v["address"] for k, v in s._hosts().items()}


want = {"web1": "192.0.2.50", "db1": "192.0.2.40"}
check("name=ip pairs", names("web1=192.0.2.50,db1=192.0.2.40") == want)
check("ip=name pairs", names("192.0.2.50=web1,192.0.2.40=db1") == want)
check("new lines", names("web1=192.0.2.50\ndb1=192.0.2.40") == want)
check("json list in a string", names('["web1=192.0.2.50", "db1=192.0.2.40"]') == want)
check("semicolons and spaces", names(" web1 = 192.0.2.50 ; db1 = 192.0.2.40 ") == want)
check("name with a host name address", names("web1=web1.example.org") == {"web1": "web1.example.org"})
os.environ["SERVER_MCP_HOSTS_NAME"] = "app=192.0.2.60"
os.environ["SERVER_MCP_HOST_2"] = "db1=192.0.2.40"
os.environ["SERVER_MCP_HOST_1"] = "web1=192.0.2.50"
os.environ.pop("SERVER_MCP_HOSTS", None)
got = {k: v["address"] for k, v in s._hosts().items()}
check("one pair per setting (HOST_1, HOST_2) adds to the list, in order", got == {"app": "192.0.2.60", "web1": "192.0.2.50", "db1": "192.0.2.40"} and list(got) == ["app", "web1", "db1"], got)
for k in ("SERVER_MCP_HOST_1", "SERVER_MCP_HOST_2", "SERVER_MCP_HOSTS_NAME"):
    del os.environ[k]

# ---------------------------------------------------------------- sudo password from the SSH password
os.environ.update({"SERVER_MCP_HOSTS": "192.0.2.10", "SERVER_MCP_SSH_USER": "main", "SERVER_MCP_SSH_PASSWORD": "pw123"})
hh = list(s._hosts().values())[0]
check("SSH password is also the sudo password", hh["sudo_password"] == "pw123")
os.environ["SERVER_MCP_SUDO_PASSWORD"] = "other"
check("a separate sudo password wins", list(s._hosts().values())[0]["sudo_password"] == "other")
del os.environ["SERVER_MCP_SUDO_PASSWORD"]
check("password is scrubbed", "pw123" not in s._scrub("x pw123 y", hh))
check("no fallback settings left", "fb_user" not in hh)

# real run of the sudo wrapper against a fake sudo (asks for a password, or does not)
import subprocess  # noqa: E402
bindir = os.path.join(TMP, "bin")
os.makedirs(bindir)
Path(bindir, "sudo").write_text("""#!/bin/sh
if [ "$1" = "-n" ]; then
  shift
  [ "$1" = "true" ] && [ -z "$NOPW" ] && exit 1
  exec "$@"
fi
if [ "$1" = "-S" ]; then
  shift; shift; shift
  IFS= read -r p; [ "$p" = "pw123" ] || { echo "bad password" >&2; exit 1; }
  exec "$@"
fi
exit 9
""")
os.chmod(os.path.join(bindir, "sudo"), 0o755)
hs = {"name": "x", "ssh": "", "docker_path": "", "sudo": False, "sudo_password": "pw123", "password": "", "key": "", "port": ""}
for nopw in ("", "1"):
    argv, feed = s._sudo_wrap(hs, ["cat"], True)
    env = {**os.environ, "PATH": bindir + os.pathsep + os.environ["PATH"], "NOPW": nopw}
    r = subprocess.run(argv, input=feed + b"file data\n", capture_output=True, env=env)
    label = "no password needed" if nopw else "password needed"
    check(f"sudo wrapper, {label}: command gets only its own data", r.stdout == b"file data\n" and r.returncode == 0, r)
for k in ("SERVER_MCP_SSH_PASSWORD", "SERVER_MCP_SSH_USER"):
    del os.environ[k]

# ---------------------------------------------------------------- no personal data in the source
src = (ROOT / "server_mcp" / "server.py").read_text()
import re  # noqa: E402
check("no private addresses in the source", not re.search(r"\b(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d+\.\d+\.\d+\b", src))

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
