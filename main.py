#!/usr/bin/env python3
"""kirkware-py-inspector — infrastructure inspector with a small web UI.

Stdlib only. Reports OS, container, platform (Cloud Foundry / Kubernetes),
networking, resources, and version info at every layer it can observe.
Designed to run under python_buildpack on CF *or* in a Kubernetes Pod.
"""

import base64
import binascii
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_VERSION = "1.0.0"
START_TIME = time.time()
HOST = os.environ.get("BIND", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))


def _sh(cmd, timeout=5):
    """Run a command, return stripped stdout or None."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() or None
    except Exception:
        return None


def _read(path):
    try:
        return Path(path).read_text().strip()
    except Exception:
        return None


def _read_bytes(path):
    try:
        return Path(path).read_bytes()
    except Exception:
        return None


# ---------------------------------------------------------------- OS layer

def os_release():
    fields = {}
    text = _read("/etc/os-release") or ""
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            fields[k.strip()] = v.strip().strip('"')
    return fields


def glibc_version():
    try:
        import ctypes
        lib = ctypes.CDLL("libc.so.6")
        if hasattr(lib, "gnu_get_libc_version"):
            lib.gnu_get_libc_version.restype = ctypes.c_char_p
            v = lib.gnu_get_libc_version()
            return v.decode() if isinstance(v, bytes) else str(v)
    except Exception:
        pass
    return None


def os_info():
    rel = os_release()
    cpu_model = None
    for line in (_read("/proc/cpuinfo") or "").splitlines():
        if line.startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
    meminfo = {}
    for line in (_read("/proc/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        meminfo[k.strip()] = v.strip()
    try:
        total_mb = int(meminfo.get("MemTotal", "0").split()[0]) // 1024
    except Exception:
        total_mb = None
    try:
        avail_mb = int(meminfo.get("MemAvailable", "0").split()[0]) // 1024
    except Exception:
        avail_mb = None
    disk = {}
    for mount in ("/", "/home/vcap" if Path("/home/vcap").exists() else "/"):
        try:
            du = shutil.disk_usage(mount)
            disk[mount] = {
                "total_gb": round(du.total / 2**30, 1),
                "used_gb": round(du.used / 2**30, 1),
                "free_gb": round(du.free / 2**30, 1),
            }
        except Exception:
            pass
    return {
        "distribution": rel.get("PRETTY_NAME"),
        "os_release": rel,
        "kernel": platform.release(),
        "uname": platform.uname().release + " " + platform.uname().machine,
        "glibc": glibc_version(),
        "arch": platform.machine(),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "memory_total_mb": total_mb,
        "memory_available_mb": avail_mb,
        "disk": disk,
    }


# ---------------------------------------------------------- container layer

def _parse_fib_trie():
    """IPv4 addresses from /proc/net/fib_trie (fallback when `ip` is absent)."""
    addrs = {}
    current_ip = None
    for raw in (_read("/proc/net/fib_trie") or "").splitlines():
        line = raw.rstrip()
        m = re.match(r"^\s+\|--\s+(\d+\.\d+\.\d+\.\d+)", line)
        if m:
            current_ip = m.group(1)
            continue
        if current_ip and re.match(r"^\s+/(\d+)\s+host LOCAL", line):
            prefix = re.match(r"^\s+/(\d+)", line).group(1)
            addrs.setdefault(current_ip, prefix)
            current_ip = None
    return addrs


def _parse_proc_net_route():
    """Default route + interface gateways from /proc/net/route."""
    default, routes = None, []
    try:
        lines = _read("/proc/net/route").splitlines()[1:]
        for line in lines:
            parts = line.split()
            iface, dest, gw = parts[0], int(parts[1], 16), int(parts[2], 16)

            def hex_to_ip(h):
                return ".".join(str((h >> (i * 8)) & 0xFF) for i in range(4))

            if dest == 0:
                default = {"interface": iface, "gateway": hex_to_ip(gw)}
            routes.append({"interface": iface, "dest": hex_to_ip(dest), "gateway": hex_to_ip(gw)})
    except Exception:
        pass
    return default, routes


def listening_sockets():
    """LISTEN sockets from /proc/net/tcp{,6}."""
    out = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in (_read(path) or "").splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":  # 0A = LISTEN
                continue
            addr_hex, port_hex = parts[1].rsplit(":", 1)
            port = int(port_hex, 16)
            if len(addr_hex) == 8:  # v4
                addr = ".".join(str(int(addr_hex[i:i + 2], 16)) for i in range(6, -2, -2))
            else:
                addr = "ipv6"
            out.append({"address": addr, "port": port})
    # de-duplicate (same port shows in tcp + tcp6 and per-socket)
    seen = set()
    deduped = []
    for s in out:
        key = (s["address"], s["port"])
        if key not in seen:
            seen.add(key)
            deduped.append(s)
    return deduped


def network_info():
    ifaces = []
    try:
        names = sorted(p.name for p in Path("/sys/class/net").iterdir())
    except Exception:
        names = []
    fib = _parse_fib_trie()
    for name in names:
        base = f"/sys/class/net/{name}"
        info = {
            "name": name,
            "mac": _read(f"{base}/address"),
            "mtu": _read(f"{base}/mtu"),
            "state": _read(f"{base}/operstate"),
            "ipv4": [],
        }
        for ip, prefix in fib.items():
            # naive ownership: attribute via /proc or interface match is not
            # reliable from fib_trie alone; collect below with `ip` if present
            info["ipv4"].append(ip + "/" + prefix)
        # prefer `ip` output for accurate per-interface attribution
        ip_json = _sh(["ip", "-o", "-j", "addr", "show", name], timeout=3)
        if ip_json:
            try:
                data = json.loads(ip_json)
                if data:
                    v4 = []
                    for a in data[0].get("addr_info", []):
                        if a.get("family") == "inet":
                            v4.append(a["local"])
                    if v4:
                        info["ipv4"] = v4
            except Exception:
                pass
        ifaces.append(info)
    default, routes = _parse_proc_net_route()
    try:
        hostname = socket.gethostname()
        resolved = socket.gethostbyname_ex(hostname)[2]
    except Exception:
        hostname, resolved = "unknown", []
    return {
        "interfaces": ifaces,
        "default_route": default,
        "routes": routes[:12],
        "dns": {
            "nameservers": [l.split()[1] for l in (_read("/etc/resolv.conf") or "").splitlines()
                            if l.startswith("nameserver")],
            "search_domains": [l.split()[1:] for l in (_read("/etc/resolv.conf") or "").splitlines()
                               if l.startswith("search")],
        },
        "hostname": hostname,
        "hostname_resolves_to": resolved,
        "listening_sockets": listening_sockets(),
    }


def container_info():
    cgroups = (_read("/proc/1/cgroup") or "").splitlines()
    unified = _read("/proc/self/cgroup")
    pid1_comm = _read("/proc/1/comm")
    pid1_cmd = (_read("/proc/1/cmdline") or "").replace("\x00", " ").strip() if _read("/proc/1/cmdline") else None
    cf_file = _read("/.cf")
    try:
        cf_parsed = json.loads(cf_file) if cf_file else None
    except Exception:
        cf_parsed = None
    markers = {
        "/.cf": cf_file is not None,
        "/.dockerenv": Path("/.dockerenv").exists(),
        "/run/.containerenv": Path("/run/.containerenv").exists(),
        "/run/containerd": Path("/run/containerd").exists(),
    }
    return {
        "hostname": socket.gethostname(),
        "pid1": {"comm": pid1_comm, "cmdline": pid1_cmd},
        "cgroups": cgroups[:12],
        "cgroup_unified": unified,
        "cf_droplet_file": cf_parsed,
        "runtime_markers": markers,
    }


# ------------------------------------------------------------- CF detection

def cf_info():
    app = None
    raw = os.environ.get("VCAP_APPLICATION")
    if raw:
        try:
            app = json.loads(raw)
        except Exception:
            app = {"raw": raw[:500]}
    services = []
    raw = os.environ.get("VCAP_SERVICES")
    if raw:
        try:
            for _label, entries in json.loads(raw).items():
                for e in entries:
                    services.append({
                        "name": e.get("name"),
                        "label": e.get("label"),
                        "plan": e.get("plan"),
                        "tags": e.get("tags", []),
                    })
        except Exception:
            pass
    deps = []
    base = Path("/home/vcap/deps")
    if base.exists():
        for d in sorted(base.iterdir()):
            if d.is_dir():
                bin_dir = d / "bin"
                tools = sorted(p.name for p in bin_dir.iterdir())[:10] if bin_dir.exists() else []
                deps.append({"layer": str(d), "tools": tools})
    droplet_env = {k: os.environ.get(k) for k in ("VCAP_APP_HOST", "VCAP_APP_PORT") if os.environ.get(k)}
    return {
        "detected": bool(app or droplet_env or base.exists()),
        "application": app,
        "services": services,
        "buildpack_dep_layers": deps,
        "vcap_env": droplet_env,
    }


# ---------------------------------------------------------- K8s detection

def _jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return None


def k8s_info():
    sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    token = _read(f"{sa_dir}/token")
    namespace = _read(f"{sa_dir}/namespace")
    payload = _jwt_payload(token) if token else None
    sub = (payload or {}).get("sub")
    sa_name = None
    if sub and "system:serviceaccount:" in sub:
        sa_name = sub.rsplit(":", 1)[-1]
    k8s_env = {}
    for k, v in os.environ.items():
        if re.match(r"^(KUBERNETES_|POD_|NODE_|MY_)|NAMESPACE", k):
            k8s_env[k] = v
    mounts = [l for l in (_read("/proc/mounts") or "").splitlines() if "kubernetes" in l or "kubelet" in l]
    return {
        "detected": bool(os.environ.get("KUBERNETES_SERVICE_HOST") or token),
        "api_server": {
            "host": os.environ.get("KUBERNETES_SERVICE_HOST"),
            "port": os.environ.get("KUBERNETES_SERVICE_PORT"),
        },
        "service_account": {
            "name": sa_name,
            "namespace": namespace or (payload or {}).get("namespace"),
            "jwt_sub": sub,
            "jwt_iss": (payload or {}).get("iss"),
            "jwt_exp": (payload or {}).get("exp"),
            "ca_cert_present": Path(f"{sa_dir}/ca.crt").exists(),
            "token_present": bool(token),
        },
        "env": k8s_env,
        "kubernetes_mounts": mounts[:6],
    }


# -------------------------------------------------------------- env + misc

SECRET_RE = re.compile(r"(TOKEN|SECRET|PASSW|CRED|KEY|AUTH|PRIVATE)", re.I)


def env_info():
    out = []
    for k in sorted(os.environ):
        v = os.environ[k]
        if k == "VCAP_SERVICES":
            v = "<structured — see Platform / Cloud Foundry>"
        elif SECRET_RE.search(k) and len(v) > 4:
            v = f"*** ({len(v)} chars)"
        elif len(v) > 200:
            v = v[:200] + "…"
        out.append({"name": k, "value": v})
    return out


def version_info():
    versions = {
        "python": {
            "version": platform.python_version(),
            "full": sys.version,
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
    }
    for name, cmd in [
        ("pip", [sys.executable, "-m", "pip", "--version"]),
        ("setuptools", [sys.executable, "-m", "setuptools", "--version"]),
        ("cf_cli", ["cf", "--version"]),
        ("node", ["node", "--version"]),
        ("git", ["git", "--version"]),
        ("java", ["java", "-version"]),
        ("go", ["go", "version"]),
    ]:
        out = _sh(cmd)
        if out is None and name == "java":
            out = _sh(cmd, timeout=5)  # java prints to stderr; tolerate
        versions[name] = out if out else "not installed"
    return versions


def collect_info():
    now = time.time()
    cf = cf_info()
    k8s = k8s_info()
    if cf["detected"]:
        runtime = "Cloud Foundry"
    elif k8s["detected"]:
        runtime = "Kubernetes"
    else:
        runtime = "Bare / other"
    return {
        "app": {
            "name": "kirkware-py-inspector",
            "version": APP_VERSION,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(START_TIME)),
            "uptime_seconds": round(now - START_TIME, 1),
        },
        "runtime_environment": runtime,
        "os": os_info(),
        "container": container_info(),
        "platform": {"cloud_foundry": cf, "kubernetes": k8s},
        "network": network_info(),
        "versions": version_info(),
        "environment_variables": env_info(),
    }


# --------------------------------------------------------------------- UI

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kirkware-py-inspector</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --panel2: #1c2330;
    --border: #2d333b; --text: #e6edf3; --dim: #8b949e;
    --accent: #58a6ff; --ok: #3fb950; --warn: #d29922; --k8s: #64b5f6; --cf: #ffd358;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  header { position: sticky; top: 0; z-index: 5; display: flex; align-items: center;
           gap: 14px; padding: 14px 24px; background: rgba(13,17,23,.92);
           backdrop-filter: blur(6px); border-bottom: 1px solid var(--border); }
  header h1 { font-size: 16px; margin: 0; font-weight: 600; letter-spacing: .2px; }
  header h1 .ver { color: var(--dim); font-weight: 400; font-size: 12px; margin-left: 8px; }
  .badge { padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight: 600;
           border: 1px solid var(--border); }
  .badge.cf { color: var(--cf); border-color: var(--cf); }
  .badge.k8s { color: var(--k8s); border-color: var(--k8s); }
  .badge.other { color: var(--dim); }
  .spacer { flex: 1; }
  button { background: var(--panel2); color: var(--text); border: 1px solid var(--border);
           border-radius: 6px; padding: 6px 12px; font-size: 12px; cursor: pointer; }
  button:hover { border-color: var(--accent); }
  main { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(460px, 1fr)); gap: 16px; }
  section.card { background: var(--panel); border: 1px solid var(--border);
                 border-radius: 10px; overflow: hidden; }
  section.card > h2 { margin: 0; padding: 12px 16px; font-size: 13px; font-weight: 600;
                      text-transform: uppercase; letter-spacing: .8px; color: var(--dim);
                      border-bottom: 1px solid var(--border);
                      display: flex; justify-content: space-between; align-items: center; }
  section.card > h2 .pill { font-size: 11px; color: var(--ok); text-transform: none; letter-spacing: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { padding: 7px 16px; text-align: left; vertical-align: top;
           border-bottom: 1px solid rgba(45,51,59,.5); }
  tr:last-child td { border-bottom: none; }
  td.k { color: var(--dim); white-space: nowrap; width: 34%; }
  td.v { font-family: var(--mono); font-size: 12.5px; word-break: break-all; }
  pre { margin: 0; padding: 12px 16px; overflow-x: auto; font: 12px/1.5 var(--mono);
        white-space: pre-wrap; word-break: break-all; }
  .hint { color: var(--dim); font-size: 12px; padding: 10px 16px; }
  .muted { color: var(--dim); }
  footer { text-align: center; color: var(--dim); font-size: 12px; padding: 24px; }
  @media (max-width: 560px) { .grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<header>
  <h1>kirkware-py-inspector<span class="ver" id="ver"></span></h1>
  <span class="badge" id="runtime">…</span>
  <span class="spacer"></span>
  <button onclick="load()">↻ Refresh</button>
  <button onclick="copyJson()">Copy JSON</button>
  <button onclick="window.location='/api/info'">Download JSON</button>
</header>
<main class="grid" id="grid"><div class="hint">Loading infrastructure data…</div></main>
<footer>collected live from the process environment · no external calls · secrets masked</footer>
<script>
let DATA = null;
const esc = s => String(s ?? "—").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kv = (rows) => rows.map(([k, v]) =>
  `<tr><td class="k">${esc(k)}</td><td class="v">${v === null || v === undefined || v === '' ? '<span class="muted">not detected</span>' : esc(v)}</td></tr>`).join('');

function card(title, pill, body) {
  return `<section class="card"><h2>${esc(title)}${pill ? `<span class="pill">${esc(pill)}</span>` : ''}</h2>${body}</section>`;
}

function render(d) {
  const g = document.getElementById('grid');
  const cards = [];
  document.getElementById('ver').textContent = 'v' + d.app.version + ' · up ' + Math.round(d.app.uptime_seconds) + 's';
  const rt = document.getElementById('runtime');
  rt.textContent = d.runtime_environment;
  rt.className = 'badge ' + (d.runtime_environment.includes('Cloud') ? 'cf' : d.runtime_environment.includes('Kubernetes') ? 'k8s' : 'other');

  // Runtime / detection
  const det = [];
  const cf = d.platform.cloud_foundry, k8s = d.platform.kubernetes;
  if (cf.application) {
    det.push(['CF app', cf.application.application_name + ' (' + cf.application.application_id + ')']);
    det.push(['CF URIs', (cf.application.application_uris || []).join(', ')]);
    det.push(['CF process', (cf.application.application_uris || []).length ? cf.application.process_type : null]);
  }
  det.push(['CF VCAP_APPLICATION', cf.application ? 'present' : null]);
  det.push(['K8s API server', k8s.api_server.host ? k8s.api_server.host + ':' + k8s.api_server.port : null]);
  det.push(['K8s service account', k8s.service_account.name ? k8s.service_account.name + ' @ ' + (k8s.service_account.namespace || '?') : null]);
  cards.push(card('Runtime Detection', d.runtime_environment, `<table>${kv(det)}</table>`));

  // OS
  const o = d.os;
  cards.push(card('Operating System', null, `<table>${kv([
    ['Distro', o.distribution],
    ['OS release', o.os_release ? (o.os_release.VERSION + ' (' + (o.os_release.ID || '') + ' ' + (o.os_release.ID_LIKE || '') + ')') : null],
    ['Kernel', o.kernel],
    ['glibc', o.glibc],
    ['Architecture', o.arch],
    ['CPU', o.cpu_count + ' × ' + o.cpu_model],
    ['Memory', o.memory_total_mb ? o.memory_total_mb + ' MB total / ' + o.memory_available_mb + ' MB available' : null],
    ['Disk', o.disk ? Object.entries(o.disk).map(([m, x]) => m + ': ' + x.used_gb + '/' + x.total_gb + ' GB').join('  ') : null],
  ])}</table>`));

  // Container
  const c = d.container;
  const markers = Object.entries(c.runtime_markers).filter(([_, v]) => v).map(([k]) => k);
  cards.push(card('Container', markers.length ? markers.join(', ') : 'no markers', `<table>${kv([
    ['PID 1', c.pid1.comm + (c.pid1.cmdline ? ' — ' + c.pid1.cmdline : '')],
    ['Cgroup (PID 1)', c.cgroups && c.cgroups.length ? c.cgroups[0] : (c.cgroup_unified || null)],
    ['All cgroups', null],
    ['CF droplet /.cf', c.cf_droplet_file ? JSON.stringify(c.cf_droplet_file).slice(0, 300) : null],
  ])}</table>` + (c.cgroups && c.cgroups.length > 1 ? `<pre>${esc(c.cgroups.join('\\n'))}</pre>` : '')));

  // CF
  if (cf.detected) {
    const rows = [['App ID', cf.application && cf.application.application_id],
                  ['Uris', cf.application && (cf.application.application_uris || []).join(', ')],
                  ['Version', cf.application && cf.application.version],
                  ['Build', cf.application && cf.application.build],
                  ['Services', cf.services.map(s => s.name + ' [' + s.label + ':' + s.plan + ']').join(', ') || null],
                  ['Buildpack dep layers', cf.buildpack_dep_layers.map(l => l.layer + ' (' + l.tools.join(', ') + ')').join('  ') || null]];
    cards.push(card('Cloud Foundry', 'detected', `<table>${kv(rows)}</table>` +
      (cf.application ? `<details><summary class="hint">VCAP_APPLICATION raw</summary><pre>${esc(JSON.stringify(cf.application, null, 2))}</pre></details>` : '')));
  }

  // K8s
  cards.push(card('Kubernetes', k8s.detected ? 'detected' : 'not detected', `<table>${kv([
    ['API server', k8s.api_server.host ? k8s.api_server.host + ':' + k8s.api_server.port : null],
    ['Service account', k8s.service_account.name],
    ['Namespace', k8s.service_account.namespace],
    ['JWT subject', k8s.service_account.jwt_sub],
    ['JWT issuer', k8s.service_account.jwt_iss],
    ['Token / CA present', (k8s.service_account.token_present ? 'token ' : '') + (k8s.service_account.ca_cert_present ? 'ca.crt' : '') || null],
    ['K8s env vars', Object.keys(k8s.env).length ? Object.entries(k8s.env).map(([k, v]) => k + '=' + v).join('; ') : null],
  ])}</table>`));

  // Network
  const n = d.network;
  cards.push(card('Networking', null, `<table>${kv([
    ['Hostname', n.hostname + (n.hostname_resolves_to.length ? ' → ' + n.hostname_resolves_to.join(', ') : '')],
    ['Default route', n.default_route ? 'via ' + n.default_route.gateway + ' on ' + n.default_route.interface : null],
    ['DNS servers', n.dns.nameservers.join(', ') || null],
    ['DNS search', (n.dns.search_domains[0] || []).join(' ') || null],
    ['Listening', n.listening_sockets.map(s => s.address + ':' + s.port).join(', ') || 'none'],
  ])}</table>` + n.interfaces.map(i =>
    `<details><summary class="hint">iface ${esc(i.name)} — ${esc(i.state || '?')}, mtu ${esc(i.mtu)}, ${esc(i.mac)}</summary><pre>${esc((i.ipv4 || []).join('\\n') || 'no addresses')}</pre></details>`).join('')));

  // Versions
  const v = d.versions;
  cards.push(card('Versions — every layer', null, `<table>${kv([
    ['Python', v.python.version + ' (' + v.python.implementation + ')'],
    ['Python build', (v.python.full || '').split('\\n')[0]],
    ['Python executable', v.python.executable],
    ['pip', v.pip],
    ['setuptools', v.setuptools],
    ['cf CLI', v.cf_cli],
    ['node', v.node],
    ['java', v.java],
    ['git', v.git],
    ['go', v.go],
  ])}</table>`));

  // Buildpack dep layers (CF droplet toolchain)
  if (cf.buildpack_dep_layers.length) {
    cards.push(card('Droplet Toolchain Layers', null, `<table>${kv(cf.buildpack_dep_layers.map(l => [l.layer, l.tools.join(', ') || 'no bin/ tools']))}</table>`));
  }

  // Env
  const rows = d.environment_variables.map(e => [e.name, e.value]);
  cards.push(card('Environment Variables', d.environment_variables.length + ' vars · secrets masked',
    `<table>${kv(rows)}</table>`));

  g.innerHTML = cards.join('');
}

async function load() {
  const r = await fetch('/api/info');
  DATA = await r.json();
  render(DATA);
}
function copyJson() {
  navigator.clipboard.writeText(JSON.stringify(DATA, null, 2)).then(
    () => alert('JSON copied to clipboard'), () => alert('Copy failed'));
}
load();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "py-inspector/" + APP_VERSION

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
        elif path == "/api/info":
            body = json.dumps(collect_info(), indent=2).encode()
            self._send(200, "application/json", body)
        elif path in ("/healthz", "/health"):
            self._send(200, "text/plain", b"ok")
        else:
            self._send(404, "text/plain", b"not found")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


def main():
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    sys.stderr.write("kirkware-py-inspector %s listening on %s:%d\n" % (APP_VERSION, HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
