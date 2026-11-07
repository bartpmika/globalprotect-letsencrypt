#!/usr/bin/env python3
"""Free public certificate and management for Palo Alto GlobalProtect.

Gets a Let's Encrypt certificate for a DuckDNS hostname (DNS-01 challenge via lego),
installs it on a PAN-OS firewall with a partial commit, and keeps it renewed.
Works on macOS, Linux and Windows with Python 3.8+ and no extra packages.

Usage:  gpcert.py setup | renew [--force] | status | uninstall
"""
import datetime as dt
import getpass
import hashlib
import io
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile
from xml.sax.saxutils import escape as xml_escape

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
LOGS = os.path.join(BASE, "logs")
BIN = os.path.join(BASE, "bin")
CONFIG_FILE = os.path.join(DATA, "config.json")
STATE_FILE = os.path.join(DATA, "state.json")
LOCK_FILE = os.path.join(DATA, "renew.lock")
LEGO_DIR = os.path.join(DATA, "lego")
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"
LEGO_EXE = os.path.join(BIN, "lego.exe" if IS_WIN else "lego")
TASK = "globalprotect-letsencrypt"  # schedule name on every OS
MAC_LABEL = "local." + TASK
DDNS_DOCS = "https://docs.paloaltonetworks.com/ngfw/networking/ddns/configure-dynamic-dns-for-firewall-interfaces"
KEY_DOCS = "https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/generate-api-key"

# ----------------------------------------------------------------------------- output

if IS_WIN:
    os.system("")  # turns on ANSI colors in the Windows console
for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass
COLOR = sys.stdout.isatty()


def paint(code, text):
    return "\033[%sm%s\033[0m" % (code, text) if COLOR else text


def ok(msg):
    print("  " + paint("32", "✔") + " " + msg)


def bad(msg):
    print("  " + paint("31", "✘") + " " + msg)


def warn(msg):
    print("  " + paint("33", "⚠") + " " + msg)


def step(msg):
    print("\n" + paint("1", "==> " + msg))


def log(msg):
    line = "[%s] %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    os.makedirs(LOGS, exist_ok=True)
    with open(os.path.join(LOGS, "renew.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def notify(msg):
    """Best-effort desktop notification for failures of the scheduled run."""
    try:
        if IS_MAC:
            subprocess.run(["osascript", "-e", 'display notification %s with title "GlobalProtect certificate"'
                            % json.dumps(msg)], timeout=10, capture_output=True)
        elif not IS_WIN:
            subprocess.run(["notify-send", "GlobalProtect certificate", msg], timeout=10, capture_output=True)
    except (OSError, subprocess.SubprocessError):
        pass


class Fail(Exception):
    pass

# ----------------------------------------------------------------------------- files


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def cert_paths(domain):
    base = os.path.join(LEGO_DIR, "certificates", domain)
    return base + ".crt", base + ".key"

# ----------------------------------------------------------------------------- network helpers


def tls_context(verify=True):
    ctx = ssl.create_default_context()
    if not verify:  # firewall management and portal checks: self-signed or not-yet-switched certs
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif IS_MAC and os.path.exists("/etc/ssl/cert.pem"):
        ctx.load_verify_locations("/etc/ssl/cert.pem")  # python.org builds ship without CA certs
    return ctx


def http_get(url, timeout=20, headers=None):
    req = urllib.request.Request(url, headers=dict({"User-Agent": TASK}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as r:
        return r.read()


def resolve(name):
    """Public DNS answer for name (DNS-over-HTTPS avoids split-DNS answers from the LAN)."""
    try:
        data = json.loads(http_get("https://cloudflare-dns.com/dns-query?type=A&name=" + name,
                                   headers={"Accept": "application/dns-json"}))
        ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
        if ips:
            return ips[-1]
    except (OSError, ValueError):
        pass
    try:
        return socket.gethostbyname(name)
    except OSError:
        return None


def duckdns_token_ok(domain, token):
    # The TXT form of the update call never touches the IP the firewall registered
    sub = domain[: -len(".duckdns.org")]
    url = "https://www.duckdns.org/update?" + urllib.parse.urlencode(
        {"domains": sub, "token": token, "txt": "check", "clear": "true"})
    return http_get(url).decode().strip() == "OK"


def served_fingerprint(host, sni, timeout=6):
    """SHA-256 of the certificate a TLS server presents, or None if unreachable."""
    try:
        with socket.create_connection((host, 443), timeout=timeout) as raw:
            with tls_context(verify=False).wrap_socket(raw, server_hostname=sni) as s:
                return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
    except (OSError, ssl.SSLError):
        return None

# ----------------------------------------------------------------------------- certificates


def pem_certs(text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text or "", re.S)


def fingerprint(pem):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def cert_dates(path):
    """(not_before, not_after) as epoch seconds for the first certificate in a PEM file."""
    info = ssl._ssl._test_decode_cert(path)  # stdlib parser, no extra packages needed
    return ssl.cert_time_to_seconds(info["notBefore"]), ssl.cert_time_to_seconds(info["notAfter"])


def is_test_cert(path):
    """True for certificates from Let's Encrypt's staging CA, which no device trusts."""
    issuer = dict(x[0] for x in ssl._ssl._test_decode_cert(path)["issuer"]).get("commonName", "")
    return "STAGING" in issuer.upper() or "FAKE" in issuer.upper()


def fmt_date(epoch):
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d")

# ----------------------------------------------------------------------------- firewall


class Firewall:
    def __init__(self, cfg):
        self.host = cfg["fw_host"]
        self.user = cfg.get("fw_user", "")
        self.password = cfg.get("fw_password") or ""
        self.key = cfg.get("fw_key") or ""

    def call(self, params, upload=None, timeout=60):
        url = "https://%s/api/" % self.host
        if upload:
            boundary = uuid.uuid4().hex
            body = b""
            for k, v in params.items():
                body += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n' % (boundary, k, v)).encode()
            name, content = upload
            body += ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
                     'Content-Type: application/octet-stream\r\n\r\n' % (boundary, name)).encode()
            body += content + ("\r\n--%s--\r\n" % boundary).encode()
            ctype = "multipart/form-data; boundary=" + boundary
        else:
            body = urllib.parse.urlencode(params).encode()
            ctype = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype, "User-Agent": TASK})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=tls_context(verify=False)) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:  # PAN-OS answers bad credentials with 403 + XML
            raw = e.read()
        except OSError as e:
            raise Fail("can't reach the firewall at %s (%s)" % (self.host, getattr(e, "reason", e)))
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            raise Fail("unexpected answer from the firewall: %r" % raw[:200])
        if root.get("status") != "success":
            msg = " ".join(t.strip() for t in root.itertext() if t.strip()) or "error"
            raise Fail("firewall said: " + msg)
        return root

    def reachable(self):
        try:
            urllib.request.urlopen("https://%s/" % self.host, timeout=10, context=tls_context(verify=False))
            return True
        except urllib.error.HTTPError:
            return True
        except OSError:
            return False

    def keygen(self, password):
        key = self.call({"type": "keygen", "user": self.user, "password": password}).findtext("result/key")
        if not key:
            raise Fail("the firewall didn't return an API key")
        return key

    def login(self):
        if not self.key:
            self.key = self.keygen(self.password)

    def op(self, cmd, timeout=60):
        self.login()
        return self.call({"type": "op", "cmd": cmd, "key": self.key}, timeout=timeout)

    def running(self, xpath):
        """Running-config subtree via an operational command, so the XML API 'Configuration'
        permission isn't needed. A missing section comes back empty."""
        try:
            return self.op("<show><config><running><xpath>%s</xpath></running></config></show>" % xpath)
        except Fail as e:
            if "No such node" in str(e):
                return ET.Element("response")
            raise

    def system_info(self):
        r = self.op("<show><system><info></info></system></show>")
        return r.findtext(".//model") or "?", r.findtext(".//sw-version") or "?", r.findtext(".//hostname") or "?"

    def pending_changes(self):
        return (self.op("<check><pending-changes></pending-changes></check>").findtext("result") or "").strip() == "yes"

    def import_cert(self, name, crt, key):
        self.login()
        base = {"key": self.key, "certificate-name": name, "format": "pem"}
        self.call(dict(base, type="import", category="certificate"), upload=(name + ".crt", crt))
        # PAN-OS requires a passphrase field even for an unencrypted key
        self.call(dict(base, type="import", category="private-key", passphrase="unused"), upload=(name + ".key", key))

    def commit_partial(self):
        """Commits only this admin's changes and waits for the result."""
        cmd = "<commit><partial><admin><member>%s</member></admin></partial></commit>" % xml_escape(self.user)
        r = self.call({"type": "commit", "action": "partial", "cmd": cmd, "key": self.key})
        job = r.findtext("result/job")
        if not job:
            return " ".join(r.itertext()).strip()  # e.g. "There are no changes to commit"
        for _ in range(120):
            time.sleep(5)
            j = self.op("<show><jobs><id>%s</id></jobs></show>" % job)
            if j.findtext(".//job/status") == "FIN":
                result = j.findtext(".//job/result")
                details = " ".join(t.strip() for t in j.find(".//job/details").itertext() if t.strip()) \
                    if j.find(".//job/details") is not None else ""
                if result != "OK":
                    raise Fail("commit job %s failed: %s" % (job, details or result))
                return "commit job %s OK" % job
        raise Fail("commit job %s didn't finish within 10 minutes" % job)

    def cert_fingerprint(self, name):
        r = self.running("shared/certificate/entry[@name='%s']" % name)
        certs = pem_certs(r.findtext(".//public-key"))
        return fingerprint(certs[0]) if certs else None

    def ddns_entries(self):
        """Every DDNS setting on every interface, subinterface, AE, VLAN, loopback and tunnel."""
        root = self.running("devices/entry/network/interface")
        parent = {child: p for p in root.iter() for child in p}
        interfaces = {e.get("name") for e in root.iter("entry")
                      if re.match(r"^(ethernet|ae|vlan|loopback|tunnel)", e.get("name") or "")}
        found = []
        for cfg in root.iter("ddns-config"):
            node, name = cfg, None
            while node in parent:  # nearest enclosing <entry> is the interface or subinterface
                node = parent[node]
                if node.tag == "entry":
                    name = node.get("name")
                    break
            found.append({
                "interface": name,
                "hostname": (cfg.findtext("ddns-hostname") or "").strip().lower(),
                "vendor": cfg.findtext("ddns-vendor") or "",
                "enabled": (cfg.findtext("ddns-enabled") or "") == "yes",
                "ip_sources": [m.text or "" for m in cfg.findall("ddns-ip/member")],
            })
        return len(interfaces), found

    def interface_ip(self, ifname, sources):
        for src in sources:
            if src.upper() == "DHCP":
                ip = self.op("<show><dhcp><client><state>%s</state></client></dhcp></show>" % ifname).findtext(".//ip")
                if ip and ip != "0.0.0.0":
                    return ip
            elif re.match(r"^\d+\.\d+\.\d+\.\d+", src):
                return src.split("/")[0]
        r = self.op("<show><interface>%s</interface></show>" % ifname)
        for e in r.iter():
            m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)(/\d+)?", (e.text or "").strip())
            if m and m.group(1) != "0.0.0.0":
                return m.group(1)
        return None

    def last_ddns_log(self, domain):
        """Newest DDNS system-log line for domain, or None (needs the XML API 'Log' permission)."""
        self.login()
        r = self.call({"type": "log", "log-type": "system", "nlogs": "50", "query": "(subtype eq ddns)", "key": self.key})
        job = r.findtext("result/job")
        for _ in range(15):
            time.sleep(1)
            r = self.call({"type": "log", "action": "get", "job-id": job, "key": self.key})
            if r.findtext(".//job/status") == "FIN":
                break
        for e in r.iter("entry"):
            text = e.findtext("opaque") or ""
            if domain in text.lower():
                return e.findtext("time_generated"), text.strip()
        return None

    def gp_objects(self):
        """Every GlobalProtect portal and gateway in every vsys:
        kind, vsys, name, bound interface (or None), SSL/TLS profile and that profile's certificate."""
        shared = {e.get("name"): e.findtext("certificate")
                  for c in self.running("shared/ssl-tls-service-profile").iter("ssl-tls-service-profile")
                  for e in c.findall("entry")}
        vsys_list = self.running("devices/entry/vsys").find("result/vsys")
        result = []
        for v in (vsys_list.findall("entry") if vsys_list is not None else []):
            local = {e.get("name"): e.findtext("certificate")
                     for c in v.findall("ssl-tls-service-profile") for e in c.findall("entry")}
            for kind in ("portal", "gateway"):
                for c in v.iter("global-protect-" + kind):
                    for e in c.findall("entry"):
                        cfg = e.find("portal-config") if kind == "portal" else e
                        cfg = cfg if cfg is not None else e
                        prof = cfg.findtext("ssl-tls-service-profile")
                        result.append({"kind": kind, "vsys": v.get("name"), "name": e.get("name"),
                                       "interface": cfg.findtext("local-address/interface"), "profile": prof,
                                       "certificate": local.get(prof, shared.get(prof))})
        return result

    def set_config(self, xpath, element):
        self.login()
        self.call({"type": "config", "action": "set", "xpath": xpath, "element": element, "key": self.key})

    def revert_own_changes(self):
        cmd = "<revert><config><partial><admin><member>%s</member></admin></partial></config></revert>" % xml_escape(self.user)
        self.op(cmd)

    def use_certificate(self, targets, cert_name):
        """Points the given portals/gateways at a dedicated SSL/TLS profile named after the certificate.
        The existing profile is left alone (other services may share it); its TLS settings are copied."""
        if self.pending_changes():
            raise Fail("the firewall has uncommitted changes; commit or revert them first")
        proto = None
        base = next((t["profile"] for t in targets if t["profile"]), None)
        for xp in ("shared/ssl-tls-service-profile/entry[@name='%s']/protocol-settings" % base,
                   "devices/entry/vsys/entry/ssl-tls-service-profile/entry[@name='%s']/protocol-settings" % base):
            node = self.running(xp).find(".//protocol-settings") if base else None
            if node is not None:
                node.tail = None
                proto = ET.tostring(node, encoding="unicode")
                break
        proto = proto or "<protocol-settings><min-version>tls1-2</min-version><max-version>max</max-version></protocol-settings>"
        name = xml_escape(cert_name)
        try:
            self.set_config("/config/shared/ssl-tls-service-profile",
                            '<entry name="%s">%s<certificate>%s</certificate></entry>' % (name, proto, name))
            for t in targets:
                xp = ("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='%s']"
                      "/global-protect/global-protect-%s/entry[@name='%s']" % (t["vsys"], t["kind"], t["name"]))
                if t["kind"] == "portal":
                    xp += "/portal-config"
                self.set_config(xp, "<ssl-tls-service-profile>%s</ssl-tls-service-profile>" % name)
            return self.commit_partial()
        except Fail:
            try:
                self.revert_own_changes()  # never leave half-made changes in the candidate config
            except Fail:
                pass
            raise


def gp_targets(objects, interface):
    """Portals/gateways bound to the DDNS interface, plus unbound ones sharing a profile with them."""
    bound = [o for o in objects if interface and o["interface"] == interface]
    profiles = {o["profile"] for o in bound}
    return bound + [o for o in objects if o not in bound and not o["interface"] and o["profile"] in profiles]

# ----------------------------------------------------------------------------- lego (ACME client)


def install_lego():
    if os.path.exists(LEGO_EXE):
        return
    osname = {"darwin": "darwin", "win32": "windows"}.get(sys.platform, "linux")
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64",
            "armv7l": "armv7", "armv6l": "armv6", "i386": "386", "i686": "386", "x86": "386"}.get(machine)
    if not arch:
        raise Fail("unsupported CPU type %r" % machine)
    ext = "zip" if IS_WIN else "tar.gz"
    rel = json.loads(http_get("https://api.github.com/repos/go-acme/lego/releases/latest"))
    assets = {a["name"]: a["browser_download_url"] for a in rel["assets"]}
    pkg = next((n for n in assets if n.endswith("_%s_%s.%s" % (osname, arch, ext))), None)
    sums = next((n for n in assets if n.endswith("_checksums.txt")), None)
    if not pkg or not sums:
        raise Fail("no lego download for %s/%s in release %s" % (osname, arch, rel["tag_name"]))
    data = http_get(assets[pkg], timeout=120)
    expected = dict(reversed(line.split()) for line in http_get(assets[sums]).decode().splitlines() if line.strip())
    if hashlib.sha256(data).hexdigest() != expected.get(pkg):
        raise Fail("lego download failed its checksum check")
    exe = "lego.exe" if IS_WIN else "lego"
    if IS_WIN:
        blob = zipfile.ZipFile(io.BytesIO(data)).read(exe)
    else:
        blob = tarfile.open(fileobj=io.BytesIO(data)).extractfile(exe).read()
    os.makedirs(BIN, exist_ok=True)
    with open(LEGO_EXE, "wb") as f:
        f.write(blob)
    os.chmod(LEGO_EXE, 0o755)
    print("  lego %s installed" % rel["tag_name"])


def run_lego(cfg, renew):
    args = [LEGO_EXE, "--log.format", "text", "run", "--path", LEGO_DIR, "--accept-tos",
            "--domains", cfg["domain"], "--dns", "duckdns", "--key-type", "RSA2048", "--no-random-sleep"]
    if renew:
        args.append("--renew-force")  # this tool decides when to renew (every renew_days)
    env = dict(os.environ, DUCKDNS_TOKEN=cfg["duckdns_token"])
    p = subprocess.run(args, env=env, capture_output=True, text=True, timeout=900)
    for line in (p.stdout + p.stderr).splitlines():
        if line.strip():
            log("  lego: " + line.strip())
    if p.returncode != 0:
        raise Fail("Let's Encrypt request failed (see the lego lines above)")

# ----------------------------------------------------------------------------- renew


def acquire_lock():
    os.makedirs(DATA, exist_ok=True)
    try:
        if time.time() - os.path.getmtime(LOCK_FILE) > 3 * 3600:
            os.remove(LOCK_FILE)  # left behind by a crashed run
    except OSError:
        pass
    try:
        os.close(os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        return True
    except FileExistsError:
        return False


def renew(force=False, interactive=False):
    cfg = load_json(CONFIG_FILE, None)
    if not cfg:
        raise Fail("not set up yet: run Setup first")
    if not acquire_lock():
        log("Another run is in progress, exiting.")
        return
    state = load_json(STATE_FILE, {})
    try:
        _renew(cfg, state, force, interactive)
        state["last_status"] = "OK %s" % dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        log("=== Finished OK ===")
    except Fail as e:
        state["last_status"] = "FAILED %s: %s" % (dt.datetime.now().strftime("%Y-%m-%d %H:%M"), e)
        log("ERROR: %s" % e)
        if not interactive:
            notify(str(e))
        raise
    finally:
        save_json(STATE_FILE, state)
        try:
            os.remove(LOCK_FILE)
        except OSError:
            pass


def _renew(cfg, state, force, interactive):
    domain = cfg["domain"]
    crt_path, key_path = cert_paths(domain)
    log("=== Run for %s ===" % domain)
    install_lego()

    # 1. New certificate when there is none, it's renew_days old, or less than 30 days are left
    if not os.path.exists(crt_path):
        log("No certificate yet, requesting one from Let's Encrypt")
        run_lego(cfg, renew=False)
    else:
        issued, expires = cert_dates(crt_path)
        due = issued + int(cfg["renew_days"]) * 86400 - 2 * 3600
        if force or time.time() >= due or expires - time.time() < 30 * 86400:
            log("Renewing the certificate")
            run_lego(cfg, renew=True)
        else:
            log("Certificate not due for renewal until %s" % fmt_date(due))

    with open(crt_path, "rb") as f:
        crt = f.read()
    with open(key_path, "rb") as f:
        key = f.read()
    local_fp = fingerprint(pem_certs(crt.decode())[0])
    log("Certificate expires %s" % fmt_date(cert_dates(crt_path)[1]))

    # 2. Install on the firewall when it doesn't have this certificate yet
    if state.get("deployed_fingerprint") == local_fp:
        log("Firewall already has this certificate")
        return
    fw = Firewall(cfg)
    if not fw.reachable():
        raise Fail("firewall %s unreachable (not on the home network?); will retry next run" % fw.host)
    if fw.pending_changes():
        # the partial commit includes everything this admin changed, so never commit over unfinished edits
        raise Fail("the firewall has uncommitted changes; commit or revert them, will retry next run")
    if is_test_cert(crt_path):
        raise Fail("refusing to install a Let's Encrypt test (staging) certificate on the firewall")
    log("Installing on %s as '%s'" % (fw.host, cfg["cert_name"]))
    fw.import_cert(cfg["cert_name"], crt, key)
    log("Committing: " + fw.commit_partial())
    if fw.cert_fingerprint(cfg["cert_name"]) != local_fp:
        raise Fail("after the commit the firewall still has a different certificate as '%s'" % cfg["cert_name"])
    state["deployed_fingerprint"] = local_fp
    log("Firewall is using the new certificate")

# ----------------------------------------------------------------------------- schedule


def python_for_schedule():
    exe = sys.executable
    if IS_WIN:
        w = os.path.join(os.path.dirname(exe), "pythonw.exe")  # no console window
        if os.path.exists(w):
            return w
    return exe


def have(cmd):
    return shutil.which(cmd) is not None


def install_schedule():
    script = os.path.abspath(__file__)
    py = python_for_schedule()
    if IS_MAC:
        plist = os.path.expanduser("~/Library/LaunchAgents/%s.plist" % MAC_LABEL)
        os.makedirs(os.path.dirname(plist), exist_ok=True)
        with open(plist, "w") as f:
            f.write("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array><string>%s</string><string>%s</string><string>renew</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>10</integer><key>Minute</key><integer>23</integer></dict>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>%s</string>
  <key>StandardErrorPath</key><string>%s</string>
</dict>
</plist>
""" % (MAC_LABEL, py, script, os.path.join(LOGS, "schedule.log"), os.path.join(LOGS, "schedule.log")))
        uid = str(os.getuid())
        subprocess.run(["launchctl", "bootout", "gui/%s/%s" % (uid, MAC_LABEL)], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", "gui/" + uid, plist], check=True, capture_output=True)
        return "daily 10:23, at login, and on wake if 10:23 was missed"
    if IS_WIN:
        ps = (
            "$a = New-ScheduledTaskAction -Execute '%s' -Argument '\"%s\" renew' -WorkingDirectory '%s';"
            "$t = @((New-ScheduledTaskTrigger -Daily -At 10:23), (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME));"
            "$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;"
            "Register-ScheduledTask -TaskName '%s' -Action $a -Trigger $t -Settings $s -Force | Out-Null"
        ) % (py.replace("'", "''"), script.replace("'", "''"), BASE.replace("'", "''"), TASK)
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                       check=True, capture_output=True)
        return "daily 10:23, at logon, and as soon as possible if 10:23 was missed"
    # Linux: systemd user timer (Persistent catches up after sleep/power-off), cron as fallback
    if have("systemctl") and subprocess.run(["systemctl", "--user", "show-environment"],
                                            capture_output=True).returncode == 0:
        unit_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(unit_dir, exist_ok=True)
        with open(os.path.join(unit_dir, TASK + ".service"), "w") as f:
            f.write("[Unit]\nDescription=GlobalProtect certificate renewal\n\n[Service]\nType=oneshot\n"
                    "ExecStart=%s %s renew\n" % (py, script))
        with open(os.path.join(unit_dir, TASK + ".timer"), "w") as f:
            f.write("[Unit]\nDescription=Daily GlobalProtect certificate check\n\n[Timer]\n"
                    "OnCalendar=*-*-* 10:23:00\nOnStartupSec=5min\nPersistent=true\n\n"
                    "[Install]\nWantedBy=timers.target\n")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", TASK + ".timer"], check=True, capture_output=True)
        return "daily 10:23 and at startup if missed (systemd user timer; run 'loginctl enable-linger' " \
               "to keep it running while you're logged out)"
    if not have("crontab"):
        raise Fail("no scheduler found: install cron (e.g. 'sudo apt install cron') or use systemd, then run Setup again")
    line = "%s %s renew  # %s" % (py, script, TASK)
    old = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout
    keep = [l for l in old.splitlines() if TASK not in l]
    new = "\n".join(keep + ["23 10 * * * " + line, "@reboot sleep 300; " + line]) + "\n"
    subprocess.run(["crontab", "-"], input=new, text=True, check=True)
    return "daily 10:23 and at boot (cron)"


def schedule_installed():
    if IS_MAC:
        return subprocess.run(["launchctl", "print", "gui/%s/%s" % (os.getuid(), MAC_LABEL)],
                              capture_output=True).returncode == 0
    if IS_WIN:
        return subprocess.run(["schtasks", "/Query", "/TN", TASK], capture_output=True).returncode == 0
    if have("systemctl") and subprocess.run(["systemctl", "--user", "is-enabled", TASK + ".timer"],
                                            capture_output=True).returncode == 0:
        return True
    return have("crontab") and TASK in subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout


def uninstall():
    if IS_MAC:
        subprocess.run(["launchctl", "bootout", "gui/%s/%s" % (os.getuid(), MAC_LABEL)], capture_output=True)
        try:
            os.remove(os.path.expanduser("~/Library/LaunchAgents/%s.plist" % MAC_LABEL))
        except OSError:
            pass
    elif IS_WIN:
        subprocess.run(["schtasks", "/Delete", "/TN", TASK, "/F"], capture_output=True)
    else:
        if have("systemctl"):
            subprocess.run(["systemctl", "--user", "disable", "--now", TASK + ".timer"], capture_output=True)
        for ext in (".service", ".timer"):
            try:
                os.remove(os.path.expanduser("~/.config/systemd/user/" + TASK + ext))
            except OSError:
                pass
        old = subprocess.run(["crontab", "-l"], capture_output=True, text=True) if have("crontab") else None
        if old and old.returncode == 0 and TASK in old.stdout:
            keep = "\n".join(l for l in old.stdout.splitlines() if TASK not in l) + "\n"
            subprocess.run(["crontab", "-"], input=keep, text=True)
    print("Automatic renewal is off. Your certificate and the firewall are unchanged.")

# ----------------------------------------------------------------------------- status


def portal_report(cfg, state, fw):
    """Prints how the portal looks: from the firewall's own config, and over the network."""
    crt_path, _ = cert_paths(cfg["domain"])
    local_fp = fingerprint(pem_certs(open(crt_path).read())[0])
    if fw is not None:
        objects = fw.gp_objects()
        if not objects:
            warn("No GlobalProtect portal or gateway found on the firewall")
        for o in objects:
            if o["certificate"] == cfg["cert_name"]:
                ok("GlobalProtect %s '%s' uses '%s' (profile '%s')" % (o["kind"], o["name"], o["certificate"], o["profile"]))
            else:
                bad("GlobalProtect %s '%s' uses certificate '%s' (profile '%s'), not '%s'"
                    % (o["kind"], o["name"], o["certificate"], o["profile"], cfg["cert_name"]))
    served = served_fingerprint(cfg["portal_host"], cfg["domain"])
    if served == local_fp:
        ok("Portal %s:443 is serving the current certificate" % cfg["portal_host"])
    elif served:
        bad("Portal %s:443 is serving a different certificate" % cfg["portal_host"])
    elif state.get("portal_reachable_at_setup") is False:
        warn("Can't reach the portal at %s:443 from this network, and couldn't during setup either. "
             "That's normal from inside without a U-turn/no-NAT rule, so this check is inconclusive; "
             "the firewall checks above are what count." % cfg["portal_host"])
    else:
        bad("Can't reach the portal at %s:443, although it was reachable during setup" % cfg["portal_host"])


def status():
    cfg = load_json(CONFIG_FILE, None)
    if not cfg:
        print("Not set up yet. Run Setup.")
        return 1
    state = load_json(STATE_FILE, {})
    print("GlobalProtect certificate for %s" % cfg["domain"])
    last = state.get("last_status", "never ran")
    (ok if last.startswith("OK") else bad)("Last run:      " + last)
    crt_path, _ = cert_paths(cfg["domain"])
    if not os.path.exists(crt_path):
        bad("No certificate yet. Run Setup.")
        return 1
    issued, expires = cert_dates(crt_path)
    (ok if expires - time.time() > 21 * 86400 else bad)("Expires:       " + fmt_date(expires))
    ok("Next renewal:  " + fmt_date(issued + int(cfg["renew_days"]) * 86400))
    if schedule_installed():
        ok("Schedule:      on")
    else:
        bad("Schedule:      off. Run Setup.")
    fw = Firewall(cfg)
    if not fw.reachable():
        warn("Firewall %s not reachable from here (away from home?); skipping firewall checks" % fw.host)
        fw = None
    else:
        try:
            if fw.cert_fingerprint(cfg["cert_name"]) == fingerprint(pem_certs(open(crt_path).read())[0]):
                ok("Firewall has the current certificate as '%s'" % cfg["cert_name"])
            else:
                bad("Firewall's '%s' is not the current certificate" % cfg["cert_name"])
        except Fail as e:
            bad("Firewall check failed: %s" % e)
            fw = None
    portal_report(cfg, state, fw)
    return 0

# ----------------------------------------------------------------------------- setup


def ask(prompt, default=None, secret=False, validate=None, mask_default=False):
    while True:
        shown = " [%s]" % ("keep current" if secret or mask_default else default) if default else ""
        try:
            raw = getpass.getpass("  %s%s: " % (prompt, shown)) if secret else input("  %s%s: " % (prompt, shown))
        except EOFError:
            raise Fail("setup cancelled")
        value = raw.strip() or (default or "")
        if not value:
            print("    Please enter a value.")
            continue
        if validate:
            err = validate(value)
            if err:
                print("    " + paint("31", err))
                continue
        return value


def choose(prompt, options, default="1"):
    print("  " + prompt)
    for i, text in enumerate(options, 1):
        print("    %d) %s" % (i, text))
    return int(ask("Choose", default, validate=lambda v: None if v.isdigit() and 1 <= int(v) <= len(options)
                   else "Type a number from the list"))


def pause(msg):
    warn(msg)
    try:
        input("    Press Enter to continue anyway, or Ctrl+C to stop and fix it first. ")
    except EOFError:
        pass


def manual_switch(cfg, objects):
    by_profile = {}
    for o in objects:
        by_profile.setdefault(o["profile"], []).append("%s '%s'" % (o["kind"], o["name"]))
    print("\n  " + paint("1", "One manual step on the firewall (only needed once):"))
    print("    Device > Certificate Management > SSL/TLS Service Profile")
    for prof, users in by_profile.items():
        print("      - profile '%s' (used by %s): set Certificate to '%s'" % (prof, ", ".join(users), cfg["cert_name"]))
    print("    Then Commit. '%s' already includes the full certificate chain." % cfg["cert_name"])
    try:
        input("    Press Enter when you've committed (or Ctrl+C to do it later). ")
    except EOFError:
        pass


def setup():
    print(paint("1", "GlobalProtect free public certificate: setup"))
    print("Press Enter to keep the value in [brackets]. Ctrl+C stops at any time.")
    if IS_MAC:
        home = os.path.expanduser("~")
        for blocked in ("Desktop", "Documents", "Downloads", "Library/Mobile Documents"):
            if BASE.startswith(os.path.join(home, blocked)):
                raise Fail("macOS blocks scheduled jobs in %s. Move this folder into your home folder (%s) "
                           "and run Setup again." % (blocked, home))
    old = load_json(CONFIG_FILE, {})
    state = load_json(STATE_FILE, {})
    cfg = dict(old)

    step("1/7  DuckDNS hostname")
    def check_domain(v):
        v = v.lower().strip(".")
        if not v.endswith(".duckdns.org"):
            v += ".duckdns.org"
        cfg["domain"] = v
        cfg["_ip"] = resolve(v)
        return None if cfg["_ip"] else "%s doesn't resolve. Check the name at duckdns.org." % v
    ask("DuckDNS hostname (e.g. yourname.duckdns.org)", old.get("domain"), validate=check_domain)
    ok("%s points to %s" % (cfg["domain"], cfg["_ip"]))

    def check_token(v):
        try:
            return None if duckdns_token_ok(cfg["domain"], v) else "DuckDNS rejected this token for %s." % cfg["domain"]
        except OSError as e:
            return "Couldn't reach DuckDNS: %s" % e
    cfg["duckdns_token"] = ask("DuckDNS token (top of the page at duckdns.org)", old.get("duckdns_token"),
                               validate=check_token, mask_default=True)
    ok("DuckDNS token works")

    step("2/7  Firewall connection")
    def check_host(v):
        cfg["fw_host"] = v
        return None if Firewall(cfg).reachable() else "Can't reach https://%s from this computer." % v
    ask("Firewall management IP or hostname", old.get("fw_host"), validate=check_host)
    ok("Firewall answers at https://%s" % cfg["fw_host"])
    cfg["fw_user"] = ask("Firewall admin username for this tool", old.get("fw_user"))

    while True:
        options = ["Generate an API key now from the password (recommended; the password isn't stored)",
                   "Use an API key I already have",
                   "Store the password (a key is generated on every run)"]
        auth = choose("How should the tool log in?", options, "1")
        cfg.pop("fw_password", None)
        cfg.pop("fw_key", None)
        try:
            fw = Firewall(cfg)
            if auth == 1:
                fw.key = cfg["fw_key"] = fw.keygen(ask("Password for %s" % cfg["fw_user"], secret=True))
                warn("Remember: this API key stops working when %s's password changes. "
                     "After a password change, run Setup again." % cfg["fw_user"])
            elif auth == 2:
                print("    How to get one: " + KEY_DOCS)
                fw.key = cfg["fw_key"] = ask("API key", old.get("fw_key"), secret=True)
            else:
                fw.password = cfg["fw_password"] = ask("Password for %s" % cfg["fw_user"], old.get("fw_password"),
                                                       secret=True)
            model, version, hostname = fw.system_info()
            fw.pending_changes()
            ok("Logged in to %s (%s, PAN-OS %s)" % (hostname, model, version))
            break
        except Fail as e:
            bad("Login failed: %s" % e)
            print("    The admin needs XML API permissions: Import, Commit, Operational Requests.")

    step("3/7  Checking the firewall keeps DuckDNS up to date")
    try:
        count, entries = fw.ddns_entries()
        print("  Scanned %d interfaces" % count)
        mine = [e for e in entries if e["hostname"] == cfg["domain"]]
        if not mine:
            others = ", ".join("%s on %s" % (e["hostname"], e["interface"]) for e in entries) or "none"
            pause("No interface on the firewall updates %s with Dynamic DNS (other DDNS hostnames: %s). "
                  "Without it the hostname stops working when your IP changes. How to set it up: %s"
                  % (cfg["domain"], others, DDNS_DOCS))
        else:
            e = next((x for x in mine if x["enabled"]), mine[0])
            cfg["ddns_interface"] = e["interface"]
            if not e["enabled"] or "duckdns" not in e["vendor"].lower():
                pause("Dynamic DNS for %s on %s is %s (vendor '%s'). It should be enabled with vendor DuckDNS. "
                      "See %s" % (cfg["domain"], e["interface"], "enabled" if e["enabled"] else "disabled",
                                  e["vendor"], DDNS_DOCS))
            else:
                ok("%s updates %s via DuckDNS" % (e["interface"], cfg["domain"]))
            wan_ip = fw.interface_ip(e["interface"], e["ip_sources"])
            if wan_ip and wan_ip == cfg["_ip"]:
                ok("%s's IP %s matches DuckDNS" % (e["interface"], wan_ip))
            else:
                private = wan_ip and re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)", wan_ip)
                pause("%s has IP %s but DuckDNS points to %s, so the firewall's updates aren't working.%s "
                      "Check Monitor > Logs > System (filter: subtype eq ddns)."
                      % (e["interface"], wan_ip or "unknown", cfg["_ip"],
                         " That IP is private: the firewall seems to be behind another router." if private else ""))
            try:
                last = fw.last_ddns_log(cfg["domain"])
                if last and ("successful" in last[1].lower() or "server response: ok" in last[1].lower()):
                    ok("Last DDNS update %s: successful" % last[0])
                elif last:
                    pause("Last DDNS update %s didn't succeed: %s" % last)
                else:
                    warn("No recent DDNS log entries for %s" % cfg["domain"])
            except Fail:
                print("    (Skipped the DDNS log check: the admin has no XML API 'Log' permission.)")
    except Fail as e:
        pause("Couldn't check the firewall's Dynamic DNS settings: %s" % e)

    step("4/7  Options")
    cfg["cert_name"] = ask("Certificate name on the firewall", old.get("cert_name", "gp-letsencrypt"),
                           validate=lambda v: None if re.fullmatch(r"[\w.\-]{1,31}", v) else
                           "Use up to 31 letters, digits, dots, dashes or underscores")
    cfg["renew_days"] = int(ask("Get a fresh certificate every N days (they're valid for 90)",
                                str(old.get("renew_days", 14)),
                                validate=lambda v: None if v.isdigit() and 1 <= int(v) <= 60 else "Enter 1 to 60"))
    cfg["portal_host"] = old.get("portal_host", cfg["domain"])

    # Remember whether the portal is reachable from here before anything changes, so later
    # "can't connect" results can be told apart from real problems
    reachable = served_fingerprint(cfg["portal_host"], cfg["domain"]) is not None
    state["portal_reachable_at_setup"] = reachable
    if reachable:
        ok("The portal at %s:443 is reachable from this computer" % cfg["portal_host"])
    else:
        warn("The portal at %s:443 isn't reachable from this computer. That's common from inside your network "
             "(it needs a U-turn/no-NAT rule). The tool will check the firewall's configuration instead."
             % cfg["portal_host"])

    cfg.pop("_ip", None)
    save_json(CONFIG_FILE, cfg)
    save_json(STATE_FILE, state)

    step("5/7  Getting the certificate and installing it on the firewall")
    renew(interactive=True)

    step("6/7  Pointing GlobalProtect at the certificate")
    objects = fw.gp_objects()
    targets = gp_targets(objects, cfg.get("ddns_interface"))
    todo = [o for o in targets if o["certificate"] != cfg["cert_name"]]
    if not objects:
        warn("No GlobalProtect portal or gateway found on the firewall")
    elif not targets:
        warn("No GlobalProtect portal or gateway is bound to the DuckDNS interface %s"
             % (cfg.get("ddns_interface") or "(none found)"))
        manual_switch(cfg, [o for o in objects if o["certificate"] != cfg["cert_name"]])
    elif not todo:
        for o in targets:
            ok("%s '%s' already uses '%s'" % (o["kind"].capitalize(), o["name"], cfg["cert_name"]))
    else:
        print("  These use the DuckDNS interface %s but not the new certificate yet:" % cfg["ddns_interface"])
        for o in todo:
            print("    - %s '%s' (vsys %s, SSL/TLS profile '%s', certificate '%s')"
                  % (o["kind"], o["name"], o["vsys"], o["profile"], o["certificate"]))
        print("  Switching creates an SSL/TLS profile '%s' with the same TLS settings, points these at it, "
              "and commits. Your existing profiles stay unchanged." % cfg["cert_name"])
        answer = ask("Switch them automatically? (y/n)", "y",
                     validate=lambda v: None if v.lower() in ("y", "yes", "n", "no") else "Type y or n")
        if answer.lower().startswith("y"):
            try:
                ok("Switched and committed (%s)" % fw.use_certificate(todo, cfg["cert_name"]))
            except Fail as e:
                bad("Couldn't switch automatically: %s" % e)
                print("    (Automatic switching needs the XML API 'Configuration' permission.)")
                manual_switch(cfg, todo)
        else:
            manual_switch(cfg, todo)

    step("7/7  Turning on automatic renewal")
    ok("Schedule: " + install_schedule())

    print("\n" + paint("1", "Status"))
    portal_report(cfg, load_json(STATE_FILE, {}), fw)
    print("\n" + paint("32", "Setup complete.") + " Run Check Status any time.")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    try:
        if cmd == "setup":
            setup()
        elif cmd == "renew":
            renew(force="--force" in sys.argv)
        elif cmd == "status":
            return status()
        elif cmd == "uninstall":
            uninstall()
        else:
            print(__doc__)
            return 2
    except Fail as e:
        print("\n" + paint("31", "ERROR: ") + str(e))
        return 1
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
