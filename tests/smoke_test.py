"""CI smoke test for gpcert.py: everything that works without a firewall or Let's Encrypt.

Runs from a copy in a folder whose name contains a space, to catch quoting bugs in the
schedule and launchers. Exits non-zero on the first failed check.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.path.join(tempfile.gettempdir(), "gp cert smoke")
IS_WIN = os.name == "nt"
DOMAIN = "example.duckdns.org"


def check(cond, what):
    print(("PASS  " if cond else "FAIL  ") + what)
    if not cond:
        sys.exit(1)


def run(*args, stdin=""):
    p = subprocess.run([sys.executable, os.path.join(WORK, "gpcert.py")] + list(args), input=stdin,
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    out = p.stdout + p.stderr
    print("---- gpcert.py %s (exit %d)\n%s----" % (" ".join(args), p.returncode, out))
    return p.returncode, out


def make_test_cert(crt, key):
    """Self-signed cert standing in for a Let's Encrypt one (issued now, so not due for renewal)."""
    candidates = [shutil.which("openssl"), r"C:\Program Files\Git\usr\bin\openssl.exe",
                  r"C:\Program Files\Git\mingw64\bin\openssl.exe"]
    exe = next((c for c in candidates if c and os.path.exists(c)), None)
    check(exe is not None, "openssl available to make a test certificate")
    subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90", "-subj", "/CN=" + DOMAIN,
                    "-keyout", key, "-out", crt], check=True, capture_output=True)


shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(WORK)
for name in os.listdir(ROOT):
    if name == "gpcert.py" or name.endswith((".bat", ".command")):
        shutil.copy(os.path.join(ROOT, name), WORK)
sys.path.insert(0, WORK)
import gpcert as g  # noqa: E402

print("Python %s on %s, working in %r" % (sys.version.split()[0], sys.platform, WORK))

# 1. Before setup
rc, out = run("status")
check(rc == 1 and "Not set up yet" in out, "status before setup says 'Not set up yet'")

# 2. Setup validates answers and stops cleanly when input ends
rc, out = run("setup", stdin="no-such-host-gpcert-ci-%d\n" % int(time.time()))
check("doesn't resolve" in out, "setup rejects a hostname that doesn't resolve")
check("setup cancelled" in out and "Traceback" not in out, "setup stops cleanly when input ends")

# 3. lego download for this OS/CPU, checksum-verified
g.install_lego()
check(os.path.exists(g.LEGO_EXE), "lego downloaded to %s" % g.LEGO_EXE)
v = subprocess.run([g.LEGO_EXE, "--version"], capture_output=True, text=True)
check(v.returncode == 0 and "lego version" in v.stdout, "lego runs: %s" % v.stdout.strip())

# 4. Configured, with a firewall that can't be reached (TEST-NET address)
g.save_json(g.CONFIG_FILE, {"domain": DOMAIN, "duckdns_token": "x", "fw_host": "192.0.2.1", "fw_user": "ci",
                            "fw_key": "x", "cert_name": "gp-letsencrypt", "renew_days": 14,
                            "portal_host": "192.0.2.1"})
crt, key = g.cert_paths(DOMAIN)
os.makedirs(os.path.dirname(crt), exist_ok=True)
make_test_cert(crt, key)
check(not g.is_test_cert(crt), "staging guard leaves a non-staging certificate alone")

rc, out = run("renew")
check(rc == 1 and "unreachable" in out and "Traceback" not in out, "renew reports the unreachable firewall")
state = g.load_json(g.STATE_FILE, {})
check(state.get("last_status", "").startswith("FAILED"), "renew records the failure for status")
check(not os.path.exists(g.LOCK_FILE), "renew removes its lock file")

rc, out = run("status")
check(rc == 0 and "Traceback" not in out, "status runs when configured")
check("not reachable from here" in out, "status skips firewall checks when the firewall is unreachable")

# 5. Schedule install / inspect / remove (CI machines only: it would replace a real schedule)
if not os.environ.get("CI"):
    print("\nSkipping the schedule checks outside CI.")
    sys.exit(0)
desc = g.install_schedule()
print("schedule: " + desc)
check(g.schedule_installed(), "schedule is installed")
if IS_WIN:
    xml = subprocess.run(["schtasks", "/Query", "/TN", g.TASK, "/XML"], capture_output=True,
                         text=True, errors="replace").stdout
    print(xml)
    check("<CalendarTrigger>" in xml and "<LogonTrigger>" in xml, "task runs daily and at logon")
    check("<StartWhenAvailable>true</StartWhenAvailable>" in xml, "task runs as soon as possible if missed")
    check("pythonw.exe" in xml.lower() or "python.exe" in xml.lower(), "task runs Python")
    check('"%s" renew' % os.path.join(WORK, "gpcert.py") in xml.replace("&quot;", '"'),
          "task quotes the script path (folder name has a space)")
rc, out = run("status")
check("Schedule:      on" in out, "status shows the schedule as on")
g.uninstall()
check(not g.schedule_installed(), "uninstall removes the schedule")

# 6. Double-click launcher (Windows): runs Status and waits for a key
if IS_WIN:
    p = subprocess.run(["cmd", "/c", "Check Status.bat"], cwd=WORK, input="\n", capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=300)
    print(p.stdout + p.stderr)
    check("GlobalProtect certificate for " + DOMAIN in p.stdout, "Check Status.bat launches gpcert.py status")
    check("\u2718" in p.stdout and "\u00e2\u0153" not in p.stdout, "Check Status.bat shows status symbols correctly (UTF-8)")

print("\nAll checks passed.")
