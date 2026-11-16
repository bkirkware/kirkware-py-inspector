#!/usr/bin/env python3
"""kirkware-py-inspector — infrastructure inspector with a small web UI.

Stdlib only. Reports OS, container, platform (Cloud Foundry / Kubernetes),
networking, resources, and version info at every layer it can observe.
Designed to run under python_buildpack on CF *or* in a Kubernetes Pod.

UI sections (top to bottom, one panel per row):
  1. Container Instance
  2. Security (Application Layer / Dependencies / Buildpack runtime /
     Stack root filesystem / Container platform)
  3. Networking
  4. Environment Variables
"""

import base64
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

APP_NAME = "kirkware-py-inspector"
APP_VERSION = "1.0.1"
START_TIME = time.time()
HOST = os.environ.get("BIND", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

# ---------------------------------------------------------------- helpers


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


def _read_json(path):
    raw = _read(path)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return raw  # keep raw text so the UI can still show it


def human_duration(seconds):
    """2d 3h 14m / 42m 7s / 12s — drop trailing zero units."""
    s = int(max(0, seconds))
    parts = []
    for unit, div in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        n = s // div
        s %= div
        if n or parts:
            parts.append(f"{n}{unit}")
        if len(parts) == 2:
            break
    return " ".join(parts) or "0s"


def parse_git_repo(app_dir):
    """Repo origin + commit from an app dir's .git, if any."""
    out = {"origin": None, "commit": None}
    cfg = _read(os.path.join(app_dir, ".git", "config"))
    if cfg:
        m = re.search(r'url\s*=\s*(\S+)', cfg)
        if m:
            out["origin"] = m.group(1)
    if out["origin"] is None:
        out["origin"] = _sh(["git", "-C", app_dir, "config", "--get",
                             "remote.origin.url"], timeout=3)
    out["commit"] = _sh(["git", "-C", app_dir, "rev-parse", "HEAD"], timeout=3)
    return out


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
        "cf_stack_file": _read("/etc/cf-stack"),
    }


def hardening_info():
    """Container hardening posture from /proc/1/status (pid 1 = container scope)."""
    out = {"seccomp_mode": None, "no_new_privs": None, "cap_eff": None,
           "apparmor": None, "summary": []}
    for line in (_read("/proc/1/status") or "").splitlines():
        if line.startswith("Seccomp:"):
            mode = line.split(":", 1)[1].strip()
            out["seccomp_mode"] = mode
            out["summary"].append(
                "Seccomp: " + {"0": "disabled", "1": "filter", "2": "filter (active)"}
                .get(mode, mode))
        elif line.startswith("NoNewPrivs:"):
            v = line.split(":", 1)[1].strip()
            out["no_new_privs"] = v
            out["summary"].append("NoNewPrivs: " + ("set" if v == "1" else "not set"))
        elif line.startswith("CapEff:"):
            cap = line.split(":", 1)[1].strip()
            out["cap_eff"] = cap
            out["summary"].append("Capabilities: " +
                                  ("none (all dropped)" if cap == "0" * 16 else
                                   f"effective 0x{cap}"))
    # AppArmor profile (if the securityfs is mounted and readable)
    aa = _read("/sys/kernel/security/apparmor/current")
    if aa:
        out["apparmor"] = aa
        out["summary"].append("AppArmor: " + aa)
    else:
        out["summary"].append("AppArmor: not visible from container")
    return out


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
            addrs.setdefault(current_ip, re.match(r"^\s+/(\d+)", line).group(1))
            current_ip = None
    return addrs


def _hex_to_ip(h):
    return ".".join(str((h >> (i * 8)) & 0xFF) for i in range(4))


def _parse_proc_net_route():
    """Default route + interface gateways from /proc/net/route."""
    default, routes = None, []
    try:
        for line in _read("/proc/net/route").splitlines()[1:]:
            parts = line.split()
            iface, dest, gw = parts[0], int(parts[1], 16), int(parts[2], 16)
            if dest == 0:
                default = {"interface": iface, "gateway": _hex_to_ip(gw)}
            routes.append({"interface": iface, "dest": _hex_to_ip(dest),
                           "gateway": _hex_to_ip(gw)})
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
    seen, deduped = set(), []
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
            "ipv4": [ip + "/" + prefix for ip, prefix in fib.items()],
        }
        ip_json = _sh(["ip", "-o", "-j", "addr", "show", name], timeout=3)
        if ip_json:
            try:
                data = json.loads(ip_json)
                if data:
                    v4 = [a["local"] for a in data[0].get("addr_info", [])
                          if a.get("family") == "inet"]
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
        "routes": routes[:16],
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
    raw_cmd = _read("/proc/1/cmdline")
    pid1_cmd = raw_cmd.replace("\x00", " ").strip() if raw_cmd else None
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
        "k8s_entrypoint_config": _read_json("/home/vcap/.cf/k8s-app-entrypoint-config.json"),
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
    for k, v in sorted(os.environ.items()):
        if re.match(r"^(KUBERNETES_|POD_|NODE_|MY_)|NAMESPACE", k):
            k8s_env[k] = v
    mounts = [l for l in (_read("/proc/mounts") or "").splitlines()
              if "kubernetes" in l or "kubelet" in l]
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
        "namespace_env": os.environ.get("NAMESPACE"),
        "env": k8s_env,
        "kubernetes_mounts": mounts[:6],
    }


# ------------------------------------------------------ app layer + deps


def app_layer_info():
    """Security > Application Layer: what the app is and where it came from."""
    app = None
    raw = os.environ.get("VCAP_APPLICATION")
    if raw:
        try:
            app = json.loads(raw)
        except Exception:
            app = None
    app = app or {}
    git = parse_git_repo(os.getcwd())
    # CF droplets drop .git, so probe local first then fall back to deploy-time
    # env (set in manifest.yml). This is the honest "where the app is stored".
    if not git["origin"]:
        git["origin"] = os.environ.get("GIT_REPO_URL")
    if not git["commit"]:
        git["commit"] = os.environ.get("GIT_COMMIT")
    return {
        "application": {
            "name": (app or {}).get("application_name") or APP_NAME,
            "id": (app or {}).get("application_id"),
            "uris": (app or {}).get("application_uris") or [],
            "organization": (app or {}).get("organization_name"),
            "space": (app or {}).get("space_name"),
            "cf_api": (app or {}).get("cf_api"),
            "process_type": (app or {}).get("process_type"),
            "build_id": (app or {}).get("application_version")
            or (app or {}).get("build"),
            "app_version": APP_VERSION,
        },
        "repository": git,
        "working_directory": os.getcwd(),
    }


def dependency_info():
    """Security > Application Dependencies: direct + transitive packages."""
    # Direct deps: requirements.txt / pyproject from the app dir
    direct = []
    req_path = os.path.join(os.getcwd(), "requirements.txt")
    req_text = _read(req_path)
    if req_text:
        for line in req_text.splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                direct.append(line)
    try:
        from importlib.metadata import distributions
        dists = {}
        for search in (["/home/vcap/deps/0"], ["/usr/local/lib", "/usr/lib/python3"]):
            try:
                for d in distributions(path=search):
                    name = (d.metadata["Name"] or "").strip()
                    if name and name not in dists:
                        dists[name] = d
            except Exception:
                pass
        try:
            for d in distributions():
                name = (d.metadata["Name"] or "").strip()
                if name and name not in dists:
                    dists[name] = d
        except Exception:
            pass
    except Exception:
        dists = {}
    direct_names = set(re.match(r"([A-Za-z0-9._-]+)", x).group(1).lower()
                       for x in direct if re.match(r"[A-Za-z0-9._-]+", x))
    packages = []
    for name, d in sorted(dists.items(), key=lambda kv: kv[0].lower()):
        reqs = []
        try:
            for r in (d.requires or []):
                reqs.append(re.split(r"[;<]", r, 1)[0].strip())
        except Exception:
            pass
        packages.append({
            "name": name,
            "version": d.version,
            "requires": sorted(set(reqs)),
            "direct": name.lower() in direct_names,
        })
    return {
        "manifest": "requirements.txt" if req_text else None,
        "direct": direct,
        "packages": packages,
        "total": len(packages),
        "direct_count": sum(1 for p in packages if p["direct"]),
        "transitive_count": sum(1 for p in packages if not p["direct"]),
    }


def buildpack_runtime_info():
    """Security > Buildpack (runtime): Python runtime + buildpack toolchain."""
    deps = []
    base = Path("/home/vcap/deps")
    if base.exists():
        for d in sorted(base.iterdir()):
            if d.is_dir():
                bin_dir = d / "bin"
                tools = sorted(p.name for p in bin_dir.iterdir()) if bin_dir.exists() else []
                cfg = _read_json(str(d / "config.yml"))
                deps.append({"layer": str(d), "tools": tools, "config": cfg})
    py = platform.python_version()
    py_ver = platform.python_version_tuple()
    return {
        "python": {
            "version": py,
            "version_tuple": ".".join(py_ver),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "full": sys.version.split("\n")[0],
            "compile_flags": sys.flags,
        },
        "packages": {
            "pip": _sh([sys.executable, "-m", "pip", "--version"]),
            "setuptools": _sh([sys.executable, "-m", "setuptools", "--version"]),
        },
        "buildpack_dep_layers": deps,
    }


# ---------------------------------------------------------- platform info

def platform_info():
    """Security > Container platform: CF and/or Kubernetes facts."""
    k8s = k8s_info()
    cf = cf_info()
    return {"cloud_foundry": cf, "kubernetes": k8s}


# -------------------------------------------------------------- env + misc

SECRET_RE = re.compile(r"(TOKEN|SECRET|PASSW|CRED|KEY|AUTH|PRIVATE)", re.I)


def env_info():
    out = []
    for k in sorted(os.environ):
        v = os.environ[k]
        if k == "VCAP_SERVICES":
            v = "<structured — see Security / Container platform>"
        elif SECRET_RE.search(k) and len(v) > 4:
            v = f"*** ({len(v)} chars)"
        elif len(v) > 200:
            v = v[:200] + "…"
        out.append({"name": k, "value": v})
    return out


def instance_info():
    """Section 1: container instance number + identity."""
    app = None
    raw = os.environ.get("VCAP_APPLICATION")
    if raw:
        try:
            app = json.loads(raw)
        except Exception:
            app = None
    app = app or {}
    idx = app.get("instance_index")
    if idx is None:
        idx = os.environ.get("CF_INSTANCE_INDEX", os.environ.get("INSTANCE_INDEX"))
    guid = (app.get("instance_id") or os.environ.get("CF_INSTANCE_GUID")
            or os.environ.get("INSTANCE_GUID"))
    return {
        "index": idx,
        "guid": guid,
        "hostname": socket.gethostname(),
        "internal_ip": os.environ.get("CF_INSTANCE_INTERNAL_IP"),
        "ip": os.environ.get("CF_INSTANCE_IP"),
    }


def collect_info():
    now = time.time()
    pi = platform_info()
    cf, k8s = pi["cloud_foundry"], pi["kubernetes"]
    # Kubernetes wins the label: CF-style env also exists on CF-on-K8s (VKS);
    # the header should name the *container platform* actually running.
    if k8s["detected"]:
        runtime = "Kubernetes"
    elif cf["detected"]:
        runtime = "Cloud Foundry"
    else:
        runtime = "Bare / other"
    return {
        "app": {
            "name": APP_NAME,
            "version": APP_VERSION,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(START_TIME)),
            "uptime_seconds": round(now - START_TIME, 1),
            "uptime": human_duration(now - START_TIME),
        },
        "runtime_environment": runtime,
        "instance": instance_info(),
        "security": {
            "application_layer": app_layer_info(),
            "dependencies": dependency_info(),
            "buildpack_runtime": buildpack_runtime_info(),
            "os_stack": {**os_info(), "hardening": hardening_info()},
            "container": container_info(),
            "platform": pi,
        },
        "network": network_info(),
        "environment_variables": env_info(),
        "versions": {
            "python": platform.python_version(),
            "cf_cli": _sh(["cf", "--version"]),
            "node": _sh(["node", "--version"]),
            "git": _sh(["git", "--version"]),
        },
    }


# --------------------------------------------------------------------- UI

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Runtime Inspector</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --panel2: #1c2330;
    --border: #2d333b; --text: #e6edf3; --dim: #8b949e;
    --accent: #58a6ff; --ok: #3fb950; --warn: #d29922;
    --k8s: #64b5f6; --cf: #ffd358; --py: #6fa8dc; --ubuntu: #e95420;
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
           border: 1px solid var(--border); display: inline-flex; align-items: center; gap: 6px; }
  .badge.cf { color: var(--cf); border-color: var(--cf); }
  .badge.k8s { color: var(--k8s); border-color: var(--k8s); }
  .badge.other { color: var(--dim); }
  .spacer { flex: 1; }
  button { background: var(--panel2); color: var(--text); border: 1px solid var(--border);
           border-radius: 6px; padding: 6px 12px; font-size: 12px; cursor: pointer; }
  button:hover { border-color: var(--accent); }
  main { max-width: 960px; margin: 0 auto; padding: 24px; }
  .stack { display: grid; grid-template-columns: 1fr; gap: 16px; }
  section.card { background: var(--panel); border: 1px solid var(--border);
                 border-radius: 10px; overflow: hidden; }
  section.card > h2 { margin: 0; padding: 12px 16px; font-size: 13px; font-weight: 600;
                      text-transform: uppercase; letter-spacing: .8px; color: var(--dim);
                      border-bottom: 1px solid var(--border);
                      display: flex; gap: 10px; align-items: center; }
  section.card > h2 .title { display: flex; gap: 8px; align-items: center;
                             text-transform: none; letter-spacing: .2px; }
  section.card > h2 .pill { margin-left: auto; font-size: 11px; color: var(--ok);
                            text-transform: none; letter-spacing: 0; }
  .icon { width: 18px; height: 18px; flex: none; display: block; }
  .icon text { font-family: var(--mono); font-weight: 700; }
  .group { border: 1px solid var(--border); border-radius: 12px; padding: 14px;
           background: rgba(28,35,48,.35); }
  .group > h2 { margin: 0 0 12px; padding: 0; font-size: 15px; font-weight: 700;
                display: flex; gap: 10px; align-items: center; }
  .group .stack { gap: 12px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  td, th { padding: 7px 16px; text-align: left; vertical-align: top;
           border-bottom: 1px solid rgba(45,51,59,.5); }
  tr:last-child td { border-bottom: none; }
  td.k { color: var(--dim); white-space: nowrap; width: 34%; }
  td.v { font-family: var(--mono); font-size: 12.5px; word-break: break-all; }
  pre { margin: 0; padding: 12px 16px; overflow-x: auto; font: 12px/1.5 var(--mono);
        white-space: pre-wrap; word-break: break-all; }
  .hint { color: var(--dim); font-size: 12px; padding: 10px 16px; cursor: pointer; }
  details[open] .hint { border-bottom: 1px solid var(--border); }
  .muted { color: var(--dim); }
  .pkg { display: flex; gap: 10px; align-items: baseline; padding: 6px 16px;
         border-bottom: 1px solid rgba(45,51,59,.5); font-size: 13px; }
  .pkg:last-child { border-bottom: none; }
  .pkg .pname { font-weight: 600; font-family: var(--mono); font-size: 12.5px; }
  .pkg .pver { font-family: var(--mono); font-size: 12px; color: var(--dim); }
  .tag { font-size: 10px; font-weight: 700; padding: 1px 7px; border-radius: 999px;
         border: 1px solid var(--border); color: var(--dim); letter-spacing: .5px; }
  .tag.direct { color: var(--ok); border-color: var(--ok); }
  footer { text-align: center; color: var(--dim); font-size: 12px; padding: 24px; }
</style>
</head>
<body>
<header>
  <h1>Runtime Inspector<span class="ver" id="ver"></span></h1>
  <span class="badge" id="runtime">…</span>
  <span class="spacer"></span>
  <button onclick="load()">↻ Refresh</button>
  <button onclick="copyJson()">Copy JSON</button>
  <button onclick="window.location='/api/info'">Download JSON</button>
</header>
<main class="stack" id="grid"><div class="hint">Loading infrastructure data…</div></main>
<footer>collected live from the process environment · no external calls · secrets masked</footer>
<script>
let DATA = null;
const esc = s => String(s ?? "—").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kv = (rows) => rows.map(([k, v]) =>
  `<tr><td class="k">${esc(k)}</td><td class="v">${v === null || v === undefined || v === '' ? '<span class="muted">not detected</span>' : esc(v)}</td></tr>`).join('');

// ---- text-based SVG icons -------------------------------------------------
const ICONS = {
  k8s: '<svg class="icon" viewBox="0 0 20 20"><polygon points="10,1 17.2,4.7 17.2,13.4 10,17 2.8,13.4 2.8,4.7" fill="none" stroke="#64b5f6" stroke-width="1.4"/><text x="10" y="13" font-size="6" fill="#64b5f6" text-anchor="middle">k8s</text></svg>',
  cf: '<svg class="icon" viewBox="0 0 20 20"><rect x="1.5" y="1.5" width="17" height="17" rx="4" fill="none" stroke="#ffd358" stroke-width="1.4"/><text x="10" y="13.5" font-size="7" fill="#ffd358" text-anchor="middle">CF</text></svg>',
  python: '<svg class="icon" viewBox="0 0 20 20"><ellipse cx="10" cy="10" rx="8.4" ry="5.6" fill="none" stroke="#6fa8dc" stroke-width="1.3" transform="rotate(-24 10 10)"/><ellipse cx="10" cy="10" rx="8.4" ry="5.6" fill="none" stroke="#6fa8dc" stroke-width="1.3" transform="rotate(24 10 10)"/></svg>',
  ubuntu: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="none" stroke="#e95420" stroke-width="1.4"/><circle cx="10" cy="4.6" r="1.7" fill="#e95420"/><circle cx="5.3" cy="13" r="1.7" fill="#e95420"/><circle cx="14.7" cy="13" r="1.7" fill="#e95420"/></svg>',
  shield: '<svg class="icon" viewBox="0 0 20 20"><path d="M10 1.5 L16.5 4 V9.5 C16.5 13.8 13.7 16.9 10 18.5 C6.3 16.9 3.5 13.8 3.5 9.5 V4 Z" fill="none" stroke="#8b949e" stroke-width="1.4"/><text x="10" y="13" font-size="7" fill="#8b949e" text-anchor="middle">S</text></svg>',
  box: '<svg class="icon" viewBox="0 0 20 20"><rect x="2.5" y="2.5" width="15" height="15" rx="2.5" fill="none" stroke="#8b949e" stroke-width="1.4"/><text x="10" y="13" font-size="6.5" fill="#8b949e" text-anchor="middle">#0</text></svg>',
  net: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="none" stroke="#58a6ff" stroke-width="1.3"/><ellipse cx="10" cy="10" rx="3.6" ry="8" fill="none" stroke="#58a6ff" stroke-width="1.1"/><line x1="2" y1="10" x2="18" y2="10" stroke="#58a6ff" stroke-width="1.1"/><line x1="3.4" y1="6" x2="16.6" y2="6" stroke="#58a6ff" stroke-width="1.1"/><line x1="3.4" y1="14" x2="16.6" y2="14" stroke="#58a6ff" stroke-width="1.1"/></svg>',
  env: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="7.5" fill="none" stroke="#8b949e" stroke-width="1.3"/><path d="M10 5.5 V10 L13 12" stroke="#8b949e" stroke-width="1.3" fill="none" stroke-linecap="round"/></svg>',
  layer: '<svg class="icon" viewBox="0 0 20 20"><path d="M10 2.5 L17.5 6.5 L10 10.5 L2.5 6.5 Z" fill="none" stroke="#8b949e" stroke-width="1.3"/><path d="M2.5 10 L10 14 L17.5 10" fill="none" stroke="#8b949e" stroke-width="1.3"/><path d="M2.5 13.5 L10 17.5 L17.5 13.5" fill="none" stroke="#8b949e" stroke-width="1.3"/></svg>',
};

function card(title, icon, pill, body) {
  return `<section class="card"><h2><span class="title">${ICONS[icon] || ''}${esc(title)}</span>${pill ? `<span class="pill">${pill}</span>` : ''}</h2>${body}</section>`;
}

function render(d) {
  const g = document.getElementById('grid');
  const panels = [];
  document.getElementById('ver').textContent = 'v' + d.app.version + ' · up ' + d.app.uptime;
  const rt = document.getElementById('runtime');
  rt.innerHTML = '';
  const rtClass = d.runtime_environment.includes('Kubernetes') ? 'k8s' : d.runtime_environment.includes('Cloud') ? 'cf' : 'other';
  rt.className = 'badge ' + rtClass;
  if (rtClass === 'k8s') rt.appendChild(Object.assign(document.createElement('span'), {innerHTML: ICONS.k8s}).firstElementChild);
  if (rtClass === 'cf') rt.appendChild(Object.assign(document.createElement('span'), {innerHTML: ICONS.cf}).firstElementChild);
  rt.appendChild(document.createTextNode(d.runtime_environment));

  const sec = d.security;
  const inst = d.instance;
  const cf = sec.platform.cloud_foundry, k8s = sec.platform.kubernetes;
  const os = sec.os_stack, ct = sec.container;

  // ---- 1. Container Instance ----
  panels.push(card('Container Instance', 'box', d.runtime_environment, `<table>${kv([
    ['Instance number', inst.index !== null && inst.index !== undefined ? '#' + inst.index : null],
    ['Instance GUID', inst.guid],
    ['Hostname', inst.hostname],
    ['Internal IP', inst.internal_ip],
    ['External IP', inst.ip],
    ['Started', d.app.started_at + ' (up ' + d.app.uptime + ')'],
    ['PID 1', ct.pid1.comm + (ct.pid1.cmdline ? ' — ' + ct.pid1.cmdline : '')],
    ['Cgroup', ct.cgroups && ct.cgroups.length ? ct.cgroups[0] : (ct.cgroup_unified || null)],
  ])}</table>`));

  // ---- 2. Security (group of sub-panels) ----
  const secPanels = [];

  // 2.1 Application Layer
  const app = sec.application_layer, rep = app.repository;
  secPanels.push(card('Application Layer', 'layer', null, `<table>${kv([
    ['Application', app.application.name + ' — v' + app.application.app_version],
    ['App ID', app.application.id],
    ['Routes', (app.application.uris || []).join(', ') || null],
    ['Org / Space', app.application.organization ? app.application.organization + ' / ' + app.application.space : null],
    ['CF API', app.application.cf_api],
    ['Process type', app.application.process_type],
    ['Build ID', app.application.build_id],
    ['Git repository', rep.origin || null],
    ['Git commit', rep.commit || null],
    ['Working directory', app.working_directory],
  ])}</table>`));

  // 2.2 Application Dependencies
  const dep = sec.dependencies;
  const depBody = dep.total
    ? dep.packages.map(p =>
        `<div class="pkg"><span class="pname">${esc(p.name)}</span><span class="pver">${esc(p.version)}</span>` +
        `<span class="tag${p.direct ? ' direct' : ''}">${p.direct ? 'DIRECT' : 'TRANSITIVE'}</span>` +
        (p.requires.length ? `<span class="muted" style="font-size:11px">← ${esc(p.requires.join(', '))}</span>` : '') +
        `</div>`).join('')
    : '<div class="hint">No third-party packages detected — stdlib-only app.</div>' +
      (dep.direct.length ? `<pre>${esc(dep.direct.join('\\n'))}</pre>` : '');
  secPanels.push(card('Application Dependencies', 'layer',
    dep.total ? dep.direct_count + ' direct · ' + dep.transitive_count + ' transitive' : 'stdlib only',
    depBody));

  // 2.3 Buildpack (runtime)
  const br = sec.buildpack_runtime;
  const bpRows = [
    ['Python runtime', br.python.version + ' (' + br.python.implementation + ')'],
    ['Python build', br.python.full],
    ['Python executable', br.python.executable],
    ['pip', br.packages.pip],
    ['setuptools', br.packages.setuptools],
  ];
  let bpBody = `<table>${kv(bpRows)}</table>`;
  if (br.buildpack_dep_layers.length) {
    bpBody += br.buildpack_dep_layers.map(l =>
      `<details><summary class="hint">buildpack layer ${esc(l.layer)} — ${l.tools.length} tools</summary><pre>${esc(l.tools.join('\\n') || 'no bin/ tools')}</pre></details>`).join('');
  }
  secPanels.push(card('Buildpack (runtime)', 'python', 'python_buildpack', bpBody));

  // 2.4 Stack (root filesystem)
  const h = os.hardening;
  const stackRows = [
    ['Distribution', os.distribution],
    ['OS release', os.os_release ? (os.os_release.VERSION + ' (' + (os.os_release.ID || '') + ' ' + (os.os_release.ID_LIKE || '') + ')') : null],
    ['CF stack', os.cf_stack_file],
    ['Kernel', os.kernel + ' (' + os.arch + ')'],
    ['glibc', os.glibc],
    ['CPU', os.cpu_count + ' × ' + os.cpu_model],
    ['Memory', os.memory_total_mb ? os.memory_total_mb + ' MB total / ' + os.memory_available_mb + ' MB available' : null],
    ['Disk', os.disk ? Object.entries(os.disk).map(([m, x]) => m + ': ' + x.used_gb + '/' + x.total_gb + ' GB').join('  ') : null],
    ['Hardening', h ? h.summary.join(' · ') : null],
    ['Stemcell', 'node-level fact — not visible from inside the container'],
  ];
  secPanels.push(card('Stack (root filesystem)', 'ubuntu', os.distribution,
    `<table>${kv(stackRows)}</table>` +
    (ct.cgroups && ct.cgroups.length > 1 ? `<details><summary class="hint">all cgroups</summary><pre>${esc(ct.cgroups.join('\\n'))}</pre></details>` : '')));

  // 2.5 Container platform
  const k8sRows = [
    ['API server', k8s.api_server.host ? k8s.api_server.host + ':' + k8s.api_server.port : null],
    ['Namespace', k8s.service_account.namespace || k8s.namespace_env || null],
    ['Service account', k8s.service_account.name],
    ['SA token', k8s.service_account.token_present ? 'mounted' : (k8s.api_server.host ? 'not mounted (no API access from container)' : null)],
    ['ca.crt', k8s.service_account.ca_cert_present ? 'present' : null],
    ['JWT subject', k8s.service_account.jwt_sub],
    ['K8s env vars', Object.keys(k8s.env).length ? Object.entries(k8s.env).map(([k, v]) => k + '=' + v).join('; ') : null],
    ['k8s-app-entrypoint', ct.k8s_entrypoint_config ? 'present' : null],
  ];
  let platBody, platPill;
  if (k8s.detected) {
    platBody = `<table>${kv(k8sRows)}</table>`;
    if (ct.k8s_entrypoint_config) {
      platBody += `<details><summary class="hint">k8s-app-entrypoint-config.json</summary><pre>${esc(JSON.stringify(ct.k8s_entrypoint_config, null, 2))}</pre></details>`;
    }
    if (cf.detected) {
      platBody += `<details><summary class="hint">CF overlay on this Kubernetes cluster (VKS)</summary><pre>${esc(JSON.stringify(cf.application, null, 2))}</pre></details>`;
    }
    platPill = k8s.api_server.host ? k8s.api_server.host : 'detected';
  } else {
    const cfRows = [
      ['App ID', cf.application && cf.application.application_id],
      ['Uris', cf.application && (cf.application.application_uris || []).join(', ')],
      ['Build', cf.application && cf.application.build],
      ['Services', cf.services.map(s => s.name + ' [' + s.label + ':' + s.plan + ']').join(', ') || null],
      ['Buildpack dep layers', cf.buildpack_dep_layers.map(l => l.layer + ' (' + l.tools.length + ' tools)').join('  ') || null],
    ];
    platBody = `<table>${kv(cfRows)}</table>`;
    if (cf.application) {
      platBody += `<details><summary class="hint">VCAP_APPLICATION raw</summary><pre>${esc(JSON.stringify(cf.application, null, 2))}</pre></details>`;
    }
    platPill = 'detected';
  }
  secPanels.push(card('Container platform', k8s.detected ? 'k8s' : 'cf', platPill, platBody));

  panels.push(`<div class="group"><h2>${ICONS.shield}Security</h2><div class="stack">${secPanels.join('')}</div></div>`);

  // ---- 3. Networking ----
  const n = d.network;
  panels.push(card('Networking', 'net', null, `<table>${kv([
    ['Hostname', n.hostname + (n.hostname_resolves_to.length ? ' → ' + n.hostname_resolves_to.join(', ') : '')],
    ['Default route', n.default_route ? 'via ' + n.default_route.gateway + ' on ' + n.default_route.interface : null],
    ['DNS servers', n.dns.nameservers.join(', ') || null],
    ['DNS search', (n.dns.search_domains[0] || []).join(' ') || null],
    ['Listening', n.listening_sockets.map(s => s.address + ':' + s.port).join(', ') || 'none'],
  ])}</table>` + n.interfaces.map(i =>
    `<details><summary class="hint">iface ${esc(i.name)} — ${esc(i.state || '?')}, mtu ${esc(i.mtu)}, ${esc(i.mac)}</summary><pre>${esc((i.ipv4 || []).join('\\n') || 'no addresses')}</pre></details>`).join('') +
    (n.routes && n.routes.length ? `<details><summary class="hint">routes</summary><pre>${esc(n.routes.map(r => r.dest + ' via ' + r.gateway + ' dev ' + r.interface).join('\\n'))}</pre></details>` : '')));

  // ---- 4. Environment Variables ----
  const envRows = d.environment_variables.map(e => [e.name, e.value]);
  panels.push(card('Environment Variables', 'env', d.environment_variables.length + ' vars · secrets masked',
    `<table>${kv(envRows)}</table>`));

  g.innerHTML = panels.join('');
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
    sys.stderr.write("%s %s listening on %s:%d\n" % (APP_NAME, APP_VERSION, HOST, PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
