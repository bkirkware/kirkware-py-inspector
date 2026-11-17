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
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP_NAME = "kirkware-py-inspector"
APP_VERSION = "1.0.12"
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
        # Stack name: env is authoritative (stamped by deploy.sh at push
        # time); /etc/cf-stack is the in-droplet fallback when present.
        "stack": os.environ.get("APP_STACK") or _read("/etc/cf-stack"),
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
        # Which buildpack built this app — not visible from inside the
        # droplet, so it's stamped into the environment by deploy.sh at
        # push time (name + the org-resolved version).
        "buildpack": {
            "name": os.environ.get("BUILDPACK_NAME"),
            "version": os.environ.get("BUILDPACK_VERSION"),
        },
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


# ------------------------------------------------- Tanzu Hub CVE enrichment
#
# Credentials come from a bound credhub service instance (label "credhub")
# named `pyi-creds` (see the manifests' `services:` + README). Hub uses an
# OAuth2 client_credentials grant for auth and a single GraphQL endpoint for
# data. We identify *this* app in Hub by its CF app name, read the foundation
# its VRN carries, and pull component vulnerabilities for that foundation —
# the buildpack, the stack, and the platform runtime tile this app runs on.

HUB_CACHE_TTL = int(os.environ.get("HUB_CACHE_TTL", "300"))  # 5 min
HUB_PAGE_SIZE = 100

# Triage states to include. Hub tracks each CVE's disposition; the default
# "affected" states are EXPLOITABLE + UNKNOWN (not yet dispositioned) and
# IN_TRIAGE. FALSE_POSITIVE / NOT_AFFECTED / RESOLVED / RESOLVED_WITH_PEDIGREE
# are excluded so the counts reflect real exposure.
HUB_TRIAGE_STATES = ["EXPLOITABLE", "IN_TRIAGE", "UNKNOWN"]

# Platform runtime tile, per container runtime. Kubernetes is not modeled in
# the TAS Hub vulnerability catalog yet (future work) -> "N/A".
HUB_RUNTIME_TILE = os.environ.get("HUB_RUNTIME_TILE", "")

# GraphQL: look this app up by name -> its VRN (which names its foundation).
_GQL_APP = """
query($first: Int, $names: [String!]) {
  entityQuery {
    queryEntities(entityName: $names, first: $first) {
      edges { node { entityName entityId } }
    }
  }
}
"""

# GraphQL: component vulnerabilities for one EDS type, scoped to a foundation,
# with the per-severity CVE lists. `entityName` is a prefix filter upstream, so
# we match exact name + version client-side below.
_GQL_COMP = """
query($f: ComponentFilterInput, $after: String, $first: Int) {
  vulnerabilityQuery {
    queryComponentVulnerabilities(componentFilter: $f, first: $first, after: $after) {
      edges { node {
        entityName currentVersion entityEdsType foundationName
        criticalCveCount highCveCount latestPatchVersion
        criticalCveList { cveId }
        highCveList { cveId }
      } }
      pageInfo { hasNextPage endCursor }
    }
  }
}
"""

_hub_lock = threading.Lock()
_hub_token = {"value": None, "expires": 0.0}
_hub_cache = {"value": None, "expires": 0.0}


def _hub_creds():
    """Tanzu Hub credentials from the bound `pyi-creds` credhub service."""
    raw = os.environ.get("VCAP_SERVICES")
    if not raw:
        return None
    try:
        for entries in json.loads(raw).values():
            for e in entries:
                if e.get("label") == "credhub":
                    c = e.get("credentials", {})
                    if c.get("TANZU_HUB_URL") and c.get("TANZU_HUB_SERVICE_ACCOUNT_ID"):
                        return c
    except Exception:
        pass
    return None


def _hub_token_locked(creds):
    base = creds["TANZU_HUB_URL"].rstrip("/")
    now = time.time()
    if _hub_token["value"] and now < _hub_token["expires"] - 60:
        return _hub_token["value"]
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": creds["TANZU_HUB_SERVICE_ACCOUNT_ID"],
        "client_secret": creds["TANZU_HUB_SERVICE_ACCOUNT_SECRET"],
    }).encode()
    req = urllib.request.Request(
        base + "/auth/z/default/oauth/token", data=body, method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"})
    r = urllib.request.urlopen(req, timeout=30)
    data = json.loads(r.read())
    _hub_token["value"] = data["access_token"]
    _hub_token["expires"] = now + int(data.get("expires_in", 1800))
    return _hub_token["value"]


def _hub_gql(base, token, query, variables=None, timeout=30):
    """POST a GraphQL query to the Hub's /hub/graphql endpoint. `base` is the
    Hub origin (https://hub...); an optional HUB_URL_OVERRIDE replaces it (tests)."""
    root = os.environ.get("HUB_URL_OVERRIDE") or base
    req = urllib.request.Request(
        root.rstrip("/") + "/hub/graphql",
        data=json.dumps({"query": query, "variables": variables or {}}).encode(),
        method="POST",
        headers={"content-type": "application/json", "authorization": "Bearer " + token})
    r = urllib.request.urlopen(req, timeout=timeout)
    return json.loads(r.read())


def _hub_component_cves(creds, base, token, foundation_id, eds_types, name_filter):
    """All component-vulnerability rows for the given EDS types + foundation,
    deduped by (name, version) and kept only when `name_filter(name, version)`
    is true. Handles cursor pagination up to a bounded page count."""
    filt = {"entityEdsType": eds_types, "foundationId": [foundation_id],
            "triageState": HUB_TRIAGE_STATES}
    nodes, after, pages = [], None, 0
    while pages < 10:
        pages += 1
        r = _hub_gql(base, token, _GQL_COMP, {"f": filt, "after": after, "first": HUB_PAGE_SIZE})
        if "errors" in r:
            raise RuntimeError(r["errors"][0].get("message", "graphql error"))
        p = r["data"]["vulnerabilityQuery"]["queryComponentVulnerabilities"]
        nodes.extend(n["node"] for n in p["edges"])
        if not p["pageInfo"]["hasNextPage"]:
            break
        after = p["pageInfo"]["endCursor"]
    out, seen = [], set()
    for n in nodes:
        key = (n["entityName"], n["currentVersion"])
        if key in seen:
            continue
        seen.add(key)
        if name_filter and not name_filter(n["entityName"], n["currentVersion"]):
            continue
        out.append(n)
    return out


def _cve_ids(row, severity):
    return [c.get("cveId") for c in (row.get(severity) or []) if c.get("cveId")]


def _hub_build_cves(creds):
    """Build the CVE payload for the buildpack / stack / runtime tile."""
    app = {}
    raw = os.environ.get("VCAP_APPLICATION")
    if raw:
        try:
            app = json.loads(raw)
        except Exception:
            app = {}
    app_name = app.get("application_name") or APP_NAME
    stack = os.environ.get("APP_STACK") or _read("/etc/cf-stack")
    buildpack_name = os.environ.get("BUILDPACK_NAME")
    buildpack_version = os.environ.get("BUILDPACK_VERSION")
    base = creds["TANZU_HUB_URL"].rstrip("/")

    with _hub_lock:
        token = _hub_token_locked(creds)

        # 1) look *this* app up by name -> VRN -> foundation instance id
        r = _hub_gql(base, token, _GQL_APP, {"first": 10, "names": [app_name]})
        edges = (r.get("data", {}).get("entityQuery", {})
                 .get("queryEntities", {}).get("edges", []))
        vrn = None
        for e in edges:
            if e["node"]["entityName"] == app_name:
                vrn = e["node"]["entityId"]
                break
        if vrn is None and edges:
            vrn = edges[0]["node"]["entityId"]
        if not vrn or "instance:" not in vrn:
            return {"ok": False, "reason": "app not found in Hub",
                    "app_name": app_name, "components": {}}
        instance = vrn.split("instance:")[1].split("/")[0]
        foundation_id = "vrn/provider:TAS/instance:%s/Foundation:%s" % (instance, instance)

        # 2) buildpack CVEs for the buildpack that built this app
        buildpack = {"ok": True, "name": buildpack_name, "version": buildpack_version,
                     "matched": None}
        if buildpack_name:
            try:
                rows = _hub_component_cves(creds, base, token, foundation_id,
                                           ["Tanzu.TAS.Buildpack"],
                                           lambda n, v: n == buildpack_name)
                if rows:
                    rows.sort(key=lambda n: 0 if n["currentVersion"] == buildpack_version else 1)
                    buildpack["matched"] = _cve_row_summary(rows[0])
                else:
                    buildpack["ok"] = True
            except Exception as e:
                buildpack = {"ok": False, "name": buildpack_name, "reason": str(e)}

        # 3) stack CVEs
        stack_row = {"ok": True, "name": stack, "version": None, "matched": None}
        if stack:
            try:
                rows = _hub_component_cves(creds, base, token, foundation_id,
                                           ["Tanzu.TAS.Stack"],
                                           lambda n, v: n == stack)
                if rows:
                    stack_row["matched"] = _cve_row_summary(rows[0])
            except Exception as e:
                stack_row = {"ok": False, "name": stack, "reason": str(e)}

        # 4) platform runtime tile CVEs
        runtime = {"ok": True, "name": HUB_RUNTIME_TILE or None, "matched": None}
        if HUB_RUNTIME_TILE == "N/A" or not HUB_RUNTIME_TILE:
            runtime = {"ok": True, "name": HUB_RUNTIME_TILE or "not set",
                       "matched": None, "na": True}
        else:
            try:
                rows = _hub_component_cves(creds, base, token, foundation_id,
                                           ["Tanzu.TAS.Tile"],
                                           lambda n, v: n == HUB_RUNTIME_TILE)
                if rows:
                    runtime["matched"] = _cve_row_summary(rows[0])
            except Exception as e:
                runtime = {"ok": False, "name": HUB_RUNTIME_TILE, "reason": str(e)}

        return {
            "ok": True,
            "app_name": app_name,
            "app_vrn": vrn,
            "foundation_instance": instance,
            "foundation_id": foundation_id,
            "hub_url": base,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "components": {
                "buildpack": buildpack,
                "stack": stack_row,
                "runtime": runtime,
            },
        }


def _cve_row_summary(row):
    """Shape one component-vulnerability row into the UI payload.

    Hub exposes CVE *lists* only for critical + high severity (moderate/low
    exist as counts on the raw engine fields, not as per-CVE lists)."""
    return {
        "name": row["entityName"],
        "version": row["currentVersion"],
        "latest_patch_version": row.get("latestPatchVersion"),
        "foundation": row.get("foundationName"),
        "counts": {
            "critical": row.get("criticalCveCount", 0),
            "high": row.get("highCveCount", 0),
        },
        "cves": {
            "critical": _cve_ids(row, "criticalCveList"),
            "high": _cve_ids(row, "highCveList"),
        },
    }


def hub_cve_info():
    """Tanzu Hub CVE enrichment, cached for HUB_CACHE_TTL seconds.

    Never raises: any failure (no creds, network, GraphQL) returns a
    structured {ok: false, reason} so the UI can show why.
    """
    now = time.time()
    with _hub_lock:
        if _hub_cache["value"] and now < _hub_cache["expires"]:
            return _hub_cache["value"]
    creds = _hub_creds()
    if not creds:
        return {"ok": False, "detected": False,
                "reason": "no pyi-creds (credhub) service bound"}
    try:
        result = _hub_build_cves(creds)
    except Exception as e:
        result = {"ok": False, "reason": str(e)}
    result["detected"] = True
    with _hub_lock:
        _hub_cache["value"] = result
        _hub_cache["expires"] = now + HUB_CACHE_TTL
    return result


def _hub_warm():
    """Background thread: warm the CVE cache at startup so the first UI load
    doesn't pay the Hub round-trips."""
    try:
        hub_cve_info()
    except Exception:
        pass


# ------------------------------------------------- OSV kernel CVE lookup
# The stemcell itself is a node-level fact (not visible from inside the
# container), but the host kernel we run on IS visible (/proc/version), and
# its CVEs are tracked by the public OSV API. OSV indexes Ubuntu kernels by
# SOURCE package (linux) + FULL Debian version (X.Y.Z-abi.upload, e.g.
# 5.15.0-202.212) under the ecosystem string "Ubuntu:<VERSION_ID>:LTS".
# `uname -r` alone (5.15.0-202-generic) is NOT queryable — it lacks the
# upload number; the full version comes from /proc/version_signature.
# Full pagination for a jammy 5.15 kernel is ~45 pages (~5 min), so the
# lookup is a warm background thread behind a long cache (OSV_CACHE_TTL).
OSV_API_URL = os.environ.get("OSV_API_URL", "https://api.osv.dev/v1/query")
OSV_CACHE_TTL = int(os.environ.get("OSV_CACHE_TTL", "1800"))  # 30 min
OSV_MAX_PAGES = int(os.environ.get("OSV_MAX_PAGES", "120"))
OSV_PAGE_TIMEOUT = 60

_osv_lock = threading.Lock()
_osv_state = {
    "value": None,        # finished payload (or None)
    "expires": 0.0,
    "building": False,
    "count": 0,           # unique CVEs found so far (warming progress)
}

_OS_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2,
                     "negligible": 1, "unknown": 0}


def _osv_kernel_query():
    """OSV kernel-query inputs, or (None, reason) when not applicable.

    Applicable only on Ubuntu-based stacks with a readable
    /proc/version_signature (present on all modern Ubuntu/Debian kernels).
    The distro for the OSV ecosystem comes from the KERNEL's own revision
    (e.g. `~24.04.1`), not the container image's VERSION_ID — a VKS pod can
    run a 24.04 kernel inside a 22.04 image, and OSV keys kernel data by the
    kernel's distro. OSV labels LTS releases `Ubuntu:<distro>:LTS` and
    interim releases `Ubuntu:<distro>` (no suffix)."""
    rel = os_release()
    if rel.get("ID") != "ubuntu":
        return None, "not applicable (OSV kernel lookup covers Ubuntu stacks; this stack is %s)" % (rel.get("PRETTY_NAME") or "unknown")
    sig = _read("/proc/version_signature") or ""
    # Full Debian kernel version, optionally carrying a `~<year>.<minor>.<point>`
    # distro revision (e.g. `6.17.0-29.29~24.04.1`). The `-generic` suffix is
    # adjacent to the version (no space).
    m = re.match(
        r"Ubuntu\s+(\d+\.\d+\.\d+-\d+\.\d+(?:~[\d.]+)?)(?:-generic)?", sig)
    if not m:
        return None, "no /proc/version_signature on this kernel — full Debian kernel version unknown"
    version = m.group(1)
    dm = re.search(r"~(\d+\.\d+)\.\d+$", version)
    if dm:
        distro = dm.group(1)
    else:
        distro = rel.get("VERSION_ID") or ""
    pm = re.match(r"(\d+)\.(\d+)", distro)
    year, minor = (int(pm.group(1)), int(pm.group(2))) if pm else (0, 0)
    if not distro:
        return None, "could not determine the kernel distro revision"
    lts = (year % 2 == 0 and minor == 4)
    eco = "Ubuntu:%s%s" % (distro, ":LTS" if lts else "")
    return {"ecosystem": eco, "name": "linux", "version": version}, None


def _osv_max_severity(record):
    best = 0
    for s in record.get("severity") or []:
        if isinstance(s, dict) and s.get("type") == "Ubuntu":
            best = max(best, _OS_SEVERITY_RANK.get(str(s.get("score")).lower(), 0))
    return best


def _osv_slim(obj):
    """JSON object_hook: drop the fields the kernel CVE lookup never uses.

    OSV kernel records carry huge `affected[].versions` lists (tens of MB
    per page — the whole kernel CVE universe) plus `ranges`, `details`,
    `references`. The query already filtered by version, so we only need
    id/severity/upstream/aliases/related. Trimming during parse keeps the
    build's peak RSS ~278MB (measured, vs 827MB raw) instead of OOM'ing a
    small instance. The fix-published set is resolved in a second, targeted
    pass over the (rare) USN records — see _osv_build."""
    for k in ("versions", "ranges", "affected", "details", "references"):
        obj.pop(k, None)
    return obj


def _osv_build():
    q, reason = _osv_kernel_query()
    if q is None:
        with _osv_lock:
            _osv_state.update(value={"ok": False, "reason": reason,
                                     "status": "not_applicable"},
                              building=False, count=0,
                              expires=time.time() + OSV_CACHE_TTL)
        return
    found = {}   # cve_id -> max severity rank
    pages = 0
    token = None
    try:
        while pages < OSV_MAX_PAGES:
            pages += 1
            body = {"package": {"ecosystem": q["ecosystem"], "name": q["name"]},
                    "version": q["version"]}
            if token:
                body["page_token"] = token
            req = urllib.request.Request(OSV_API_URL,
                                         data=json.dumps(body).encode(),
                                         method="POST",
                                         headers={"content-type": "application/json"})
            r = json.loads(urllib.request.urlopen(req, timeout=OSV_PAGE_TIMEOUT).read(),
                           object_hook=_osv_slim)
            for v in r.get("vulns") or []:
                rank = _osv_max_severity(v)
                # USN / UBUNTU-CVE records carry the CVE ids in `id` or
                # `upstream` (and sometimes `aliases`/`related`); collect all.
                ids = {v.get("id")} | set(v.get("upstream") or []) \
                    | set(v.get("aliases") or []) | set(v.get("related") or [])
                for i in ids:
                    for c in re.findall(r"CVE-\d{4}-\d+", str(i or "")):
                        cur = found.get(c)
                        if cur is None or rank > cur:
                            found[c] = rank
            token = r.get("next_page_token")
            if not token:
                break
            with _osv_lock:
                _osv_state["count"] = len(found)
    except Exception as e:
        with _osv_lock:
            _osv_state.update(value={"ok": False, "reason": str(e),
                                     "status": "error", "pages": pages},
                              building=False,
                              expires=time.time() + 300)  # retry in 5 min
        return
    # Keep only critical + high: the row lists those (and the user doesn't
    # want medium/low/negligible surfaced, nor a fix-published split).
    sev_rank = {_OS_SEVERITY_RANK[k]: k for k in _OS_SEVERITY_RANK}
    cves = {"critical": [], "high": []}
    for c, rank in found.items():
        name = sev_rank.get(rank)
        if name in cves:
            cves[name].append(c)
    for k in cves:
        cves[k].sort()
    value = {
        "ok": True,
        "status": "ok" if not token else "partial",
        "source": "OSV (api.osv.dev)",
        "ecosystem": q["ecosystem"],
        "package": q["name"],
        "version": q["version"],
        "pages": pages,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cves": cves,
    }
    with _osv_lock:
        _osv_state.update(value=value, expires=time.time() + OSV_CACHE_TTL,
                          building=False, count=len(found))


def kernel_cve_info():
    """Kernel CVE enrichment via the public OSV API.

    Never blocks on the (slow) full pagination: the first caller starts a
    daemon builder thread and immediately returns a live 'warming' snapshot
    with the running count; later callers read the cached result."""
    now = time.time()
    with _osv_lock:
        if _osv_state["value"] and now < _osv_state["expires"]:
            return _osv_state["value"]
        if _osv_state["building"]:
            return {"ok": False, "status": "warming", "count": _osv_state["count"],
                    "reason": "querying OSV"}
        _osv_state["building"] = True
        _osv_state["count"] = 0
        threading.Thread(target=_osv_build, daemon=True).start()
        return {"ok": False, "status": "warming", "count": 0,
                "reason": "querying OSV"}


def _osv_warm():
    """Background thread: warm the OSV kernel-CVE cache at startup.

    Runs AFTER the Hub CVE warm: both warmers parse large JSON payloads, and
    starting them concurrently pushed a 128M app instance over its limit
    (exit 137 / OOM). Serializing the two keeps the startup memory peak flat.
    """
    try:
        hub_cve_info()   # block until the Hub warm is done (it caches)
        kernel_cve_info()
    except Exception:
        pass


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
        "cve": hub_cve_info(),
        "kernel_cve": kernel_cve_info(),
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
  /* ---- Clarity design tokens (vmware-clarity/core, light theme) ----------
     Colors converted from the token HSL values in projects/core/build/tokens.ts
     (construction 25..1100, blue/green/ochre/red status families). Spacing
     from the component space scale (base 20px, 1 unit = 1px). */
  :root {
    --cds-global-space-3: 4px; --cds-global-space-4: 6px; --cds-global-space-5: 8px;
    --cds-global-space-6: 12px; --cds-global-space-7: 16px; --cds-global-space-8: 18px;
    --cds-global-space-9: 24px; --cds-global-space-10: 32px; --cds-global-space-12: 48px;
    --cds-color-blue-50: #e5f7ff; --cds-color-blue-100: #bdebff; --cds-color-blue-700: #0079ad;
    --cds-color-blue-800: #00608a; --cds-color-blue-900: #004b6b;
    --cds-color-green-50: #eefce3; --cds-color-green-700: #42810e; --cds-color-green-800: #366a0c;
    --cds-color-ochre-50: #fff9eb; --cds-color-ochre-100: #fff2d6; --cds-color-ochre-500: #ffb92e;
    --cds-color-ochre-800: #a36500;
    --cds-color-red-50: #fff2f0; --cds-color-red-700: #e02200;
    --cds-color-construction-25: #fcfdfd; --cds-color-construction-50: #f1f6f8;
    --cds-color-construction-100: #e3eaed; --cds-color-construction-200: #cbd4d8;
    --cds-color-construction-300: #aeb8bc; --cds-color-construction-400: #859399;
    --cds-color-construction-500: #6a7a81; --cds-color-construction-600: #4f6169;
    --cds-color-construction-700: #3a4d55; --cds-color-construction-800: #2d4048;
    --cds-color-construction-900: #21333b; --cds-color-construction-1000: #1b2b32;
    --cds-color-k8s: #326CE5; --cds-color-cf: #0C9ED5;
    --cds-alias-object-background: var(--cds-color-construction-25);
    --cds-alias-container-background: #ffffff;
    --cds-alias-border-color: var(--cds-color-construction-200);
    --cds-alias-border-subtle: var(--cds-color-construction-100);
    --cds-alias-border-radius: 4px;
    --cds-alias-shadow: 0 1px 3px 0 hsla(198, 30%, 15%, 0.5);
    --cds-alias-status-info: var(--cds-color-blue-700);
    --cds-alias-status-info-tint: var(--cds-color-blue-50);
    --cds-alias-status-success: var(--cds-color-green-700);
    --cds-alias-status-success-tint: var(--cds-color-green-50);
    --cds-alias-status-warning-tint: var(--cds-color-ochre-50);
    --cds-alias-status-neutral: var(--cds-color-construction-600);
    --cds-alias-status-neutral-tint: var(--cds-color-construction-50);
    --cds-font: 'Clarity City', 'Avenir Next', 'Segoe UI', Helvetica, Arial, sans-serif;
    --cds-font-mono: ui-monospace, Consolas, Menlo, Monaco, monospace;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--cds-alias-object-background); color: #000;
         font: 400 14px/1.4285714em var(--cds-font); }
  a { color: var(--cds-alias-status-info); text-decoration: none; }
  a:hover { color: var(--cds-color-blue-800); text-decoration: underline; }

  /* ---- app header (dark slate, VMware app-bar style) ---- */
  header.app { position: sticky; top: 0; z-index: 5; display: flex; align-items: center;
               gap: 16px; padding: 0 var(--cds-global-space-9); height: 48px;
               background: var(--cds-color-construction-1000); }
  .brand { display: flex; align-items: center; gap: 10px; color: #fff;
           font-size: 16px; font-weight: 500; letter-spacing: -0.0125em; }
  .brand .icon { width: 22px; height: 22px; }
  .ver { font-size: 11px; font-weight: 500; letter-spacing: 0.05em;
         color: var(--cds-color-construction-300); }
  .spacer { flex: 1; }
  button.btn { font: 500 13px/1 var(--cds-font); padding: 7px 12px; border-radius: var(--cds-alias-border-radius);
               cursor: pointer; border: 1px solid transparent; }
  button.btn.ghost { background: transparent; color: #fff; border-color: rgba(255,255,255,.4); }
  button.btn.ghost:hover { background: rgba(255,255,255,.12); border-color: rgba(255,255,255,.7); }
  button.btn.primary { background: var(--cds-color-blue-700); color: #fff; }
  button.btn.primary:hover { background: var(--cds-color-blue-800); }

  /* ---- content ---- */
  main { max-width: 1080px; margin: 0 auto; padding: var(--cds-global-space-9); }
  .crumbs { font-size: 13px; color: var(--cds-color-construction-500); margin-bottom: var(--cds-global-space-7); }
  .crumbs .here { color: var(--cds-color-construction-700); font-weight: 500; }
  .stack { display: grid; grid-template-columns: 1fr; gap: var(--cds-global-space-7); }

  /* ---- Clarity card ---- */
  section.card { background: var(--cds-alias-container-background);
                 border: 1px solid var(--cds-alias-border-color);
                 border-radius: var(--cds-alias-border-radius);
                 box-shadow: var(--cds-alias-shadow); overflow: hidden; }
  section.card > h2 { margin: 0; padding: 12px var(--cds-global-space-8); font-size: 16px;
                      font-weight: 500; letter-spacing: -0.0125em;
                      border-bottom: 1px solid var(--cds-alias-border-subtle);
                      display: flex; gap: 10px; align-items: center; }
  section.card > h2 .title { display: flex; gap: 10px; align-items: center; }
  .icon { width: 20px; height: 20px; flex: none; display: block; }

  /* ---- Clarity tag (pill) ---- */
  .tag { margin-left: auto; font-size: 11px; font-weight: 500; letter-spacing: 0.05em;
         padding: 3px 8px; border-radius: var(--cds-alias-border-radius); white-space: nowrap;
         display: inline-flex; align-items: center; gap: 5px; }
  .tag .icon { width: 13px; height: 13px; }
  .tag.info   { background: var(--cds-alias-status-info-tint); color: var(--cds-alias-status-info); }
  .tag.success{ background: var(--cds-alias-status-success-tint); color: var(--cds-alias-status-success); }
  .tag.warning{ background: var(--cds-alias-status-warning-tint); color: var(--cds-color-ochre-800); }
  .tag.neutral{ background: var(--cds-alias-status-neutral-tint); color: var(--cds-alias-status-neutral); }
  .tag.off    { background: var(--cds-color-construction-100); color: var(--cds-color-construction-500); }
  .tag.k8s    { background: #e9effd; color: var(--cds-color-k8s); }

  /* ---- key/value table (Clarity detail rows) ---- */
  table.kv { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.kv td { padding: 7px var(--cds-global-space-8); vertical-align: top;
                border-bottom: 1px solid var(--cds-alias-border-subtle); }
  table.kv tr:last-child td { border-bottom: none; }
  table.kv tr:hover td { background: var(--cds-color-construction-50); }
  td.k { width: 240px; color: var(--cds-color-construction-600); }
  td.v { font-family: var(--cds-font-mono); font-size: 12.5px; word-break: break-all; color: #000; }
  .muted { color: var(--cds-color-construction-400); }

  /* ---- Clarity accordion (pull-downs) ---- */
  .acc { border-top: 1px solid var(--cds-alias-border-subtle); }
  .acc-hd { width: 100%; display: flex; align-items: center; gap: 8px; padding: 8px var(--cds-global-space-8);
            background: none; border: none; cursor: pointer; font: 500 13px/1.4 var(--cds-font);
            color: var(--cds-alias-status-info); text-align: left; }
  .acc-hd:hover { background: var(--cds-color-construction-50); }
  .acc-caret { display: inline-block; font-size: 10px; transition: transform 0.15s; }
  .acc.open .acc-caret { transform: rotate(90deg); }
  .acc-bd { display: none; padding: 0 0 8px; }
  .acc.open .acc-bd { display: block; }

  pre { margin: 8px var(--cds-global-space-8) 16px; padding: 12px 16px; overflow-x: auto;
        background: var(--cds-color-construction-50); border: 1px solid var(--cds-alias-border-subtle);
        border-radius: var(--cds-alias-border-radius);
        font: 12px/1.5 var(--cds-font-mono); white-space: pre-wrap; word-break: break-all; }
  .acc pre { margin-left: var(--cds-global-space-8); margin-right: var(--cds-global-space-8); }

  /* ---- package list (dependencies) ---- */
  .pkg { display: flex; gap: 10px; align-items: baseline; padding: 7px var(--cds-global-space-8);
         border-bottom: 1px solid var(--cds-alias-border-subtle); font-size: 13px; }
  .pkg:last-child { border-bottom: none; }
  .pkg:hover { background: var(--cds-color-construction-50); }
  .pkg .pname { font-weight: 500; }
  .pkg .pver { font-family: var(--cds-font-mono); font-size: 12px; color: var(--cds-color-construction-600); }
  .pkg .reqs { font-size: 11px; color: var(--cds-color-construction-400); }
  .pkg .tag { margin-left: 0; }

  /* ---- instance hero (Clarity display type: 40px/1.1em, 500) ---- */
  .hero { display: grid; grid-template-columns: auto 1fr; gap: var(--cds-global-space-10);
          padding: var(--cds-global-space-8) var(--cds-global-space-8) var(--cds-global-space-6); }
  .hero-label { font-size: 11px; font-weight: 500; letter-spacing: 0.05em; text-transform: uppercase;
                color: var(--cds-color-construction-500); }
  .hero-num { font-size: 40px; font-weight: 500; line-height: 1.1em; letter-spacing: -0.0125em;
              color: var(--cds-color-construction-900); font-family: var(--cds-font-mono); }
  .hero-sub { font-size: 13px; color: var(--cds-color-construction-600);
              font-family: var(--cds-font-mono); word-break: break-all; margin-top: 2px; }
  .hero table.kv { margin: 0; border: 1px solid var(--cds-alias-border-subtle); border-radius: var(--cds-alias-border-radius); }
  /* Started/Uptime: key column minimal, values take the rest */
  .hero table.kv td.k { width: 1%; white-space: nowrap; }

  /* ---- security group heading (Clarity section type: 20px/1.2em, 500) ---- */
  .sec-group { margin-top: var(--cds-global-space-3); }
  .sec-group > h2 { display: flex; align-items: center; gap: 10px; margin: 0 0 var(--cds-global-space-7);
                    font-size: 20px; font-weight: 500; letter-spacing: -0.01em;
                    color: var(--cds-color-construction-900); }

  footer { text-align: center; color: var(--cds-color-construction-500); font-size: 12px;
           padding: var(--cds-global-space-10) 24px; }
  @media (max-width: 700px) { .hero { grid-template-columns: 1fr; } td.k { width: 38%; } }
</style>
</head>
<body>
<header class="app">
  <div class="brand"><span class="mark" id="brandicon"></span>Runtime Inspector<span class="ver" id="ver"></span></div>
  <span class="spacer"></span>
  <span class="tag" id="hub" title="Tanzu Hub credential binding">…</span>
  <span class="tag" id="runtime">…</span>
  <button class="btn ghost" onclick="load()">↻ Refresh</button>
  <button class="btn ghost" onclick="copyJson()">Copy JSON</button>
  <button class="btn primary" onclick="window.location='/api/info'">Download JSON</button>
</header>
<main>
  <nav class="crumbs"><a href="#">Home</a><span> / </span><span class="here">Runtime Inspector</span></nav>
  <div class="stack" id="grid"><div class="muted" style="padding:24px">Loading infrastructure data…</div></div>
</main>
<footer>collected live from the process environment · CVEs from Tanzu Hub · secrets masked · design: VMware Clarity (light)</footer>
<script>
let DATA = null;
const esc = s => String(s ?? "—").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kv = (rows) => rows.map(([k, v]) =>
  `<tr><td class="k">${esc(k)}</td><td class="v">${v === null || v === undefined || v === '' ? '<span class="muted">not detected</span>' : esc(v)}</td></tr>`).join('');

// ---- SVG icons -------------------------------------------------------------
// Kubernetes + Cloud Foundry: official brand marks (Simple Icons, CC0).
const ICONS = {
  k8s: '<svg class="icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#326CE5"><path d="M10.204 14.35l.007.01-.999 2.413a5.171 5.171 0 0 1-2.075-2.597l2.578-.437.004.005a.44.44 0 0 1 .484.606zm-.833-2.129a.44.44 0 0 0 .173-.756l.002-.011L7.585 9.7a5.143 5.143 0 0 0-.73 3.255l2.514-.725.002-.009zm1.145-1.98a.44.44 0 0 0 .699-.337l.01-.005.15-2.62a5.144 5.144 0 0 0-3.01 1.442l2.147 1.523.004-.002zm.76 2.75l.723.349.722-.347.18-.78-.5-.623h-.804l-.5.623.179.779zm1.5-3.095a.44.44 0 0 0 .7.336l.008.003 2.134-1.513a5.188 5.188 0 0 0-2.992-1.442l.148 2.615.002.001zm10.876 5.97l-5.773 7.181a1.6 1.6 0 0 1-1.248.594l-9.261.003a1.6 1.6 0 0 1-1.247-.596l-5.776-7.18a1.583 1.583 0 0 1-.307-1.34L2.1 5.573c.108-.47.425-.864.863-1.073L11.305.513a1.606 1.606 0 0 1 1.385 0l8.345 3.985c.438.209.755.604.863 1.073l2.062 8.955c.108.47-.005.963-.308 1.34zm-3.289-2.057c-.042-.01-.103-.026-.145-.034-.174-.033-.315-.025-.479-.038-.35-.037-.638-.067-.895-.148-.105-.04-.18-.165-.216-.216l-.201-.059a6.45 6.45 0 0 0-.105-2.332 6.465 6.465 0 0 0-.936-2.163c.052-.047.15-.133.177-.159.008-.09.001-.183.094-.282.197-.185.444-.338.743-.522.142-.084.273-.137.415-.242.032-.024.076-.062.11-.089.24-.191.295-.52.123-.736-.172-.216-.506-.236-.745-.045-.034.027-.08.062-.111.088-.134.116-.217.23-.33.35-.246.25-.45.458-.673.609-.097.056-.239.037-.303.033l-.19.135a6.545 6.545 0 0 0-4.146-2.003l-.012-.223c-.065-.062-.143-.115-.163-.25-.022-.268.015-.557.057-.905.023-.163.061-.298.068-.475.001-.04-.001-.099-.001-.142 0-.306-.224-.555-.5-.555-.275 0-.499.249-.499.555l.001.014c0 .041-.002.092 0 .128.006.177.044.312.067.475.042.348.078.637.056.906a.545.545 0 0 1-.162.258l-.012.211a6.424 6.424 0 0 0-4.166 2.003 8.373 8.373 0 0 1-.18-.128c-.09.012-.18.04-.297-.029-.223-.15-.427-.358-.673-.608-.113-.12-.195-.234-.329-.349-.03-.026-.077-.062-.111-.088a.594.594 0 0 0-.348-.132.481.481 0 0 0-.398.176c-.172.216-.117.546.123.737l.007.005.104.083c.142.105.272.159.414.242.299.185.546.338.743.522.076.082.09.226.1.288l.16.143a6.462 6.462 0 0 0-1.02 4.506l-.208.06c-.055.072-.133.184-.215.217-.257.081-.546.11-.895.147-.164.014-.305.006-.48.039-.037.007-.09.02-.133.03l-.004.002-.007.002c-.295.071-.484.342-.423.608.061.267.349.429.645.365l.007-.001.01-.003.129-.029c.17-.046.294-.113.448-.172.33-.118.604-.217.87-.256.112-.009.23.069.288.101l.217-.037a6.5 6.5 0 0 0 2.88 3.596l-.09.218c.033.084.069.199.044.282-.097.252-.263.517-.452.813-.091.136-.185.242-.268.399-.02.037-.045.095-.064.134-.128.275-.034.591.213.71.248.12.556-.007.69-.282v-.002c.02-.039.046-.09.062-.127.07-.162.094-.301.144-.458.132-.332.205-.68.387-.897.05-.06.13-.082.215-.105l.113-.205a6.453 6.453 0 0 0 4.609.012l.106.192c.086.028.18.042.256.155.136.232.229.507.342.84.05.156.074.295.145.457.016.037.043.09.062.129.133.276.442.402.69.282.247-.118.341-.435.213-.71-.02-.039-.045-.096-.065-.134-.083-.156-.177-.261-.268-.398-.19-.296-.346-.541-.443-.793-.04-.13.007-.21.038-.294-.018-.022-.059-.144-.083-.202a6.499 6.499 0 0 0 2.88-3.622c.064.01.176.03.213.038.075-.05.144-.114.28-.104.266.039.54.138.87.256.154.06.277.128.448.173.036.01.088.019.13.028l.009.003.007.001c.297.064.584-.098.645-.365.06-.266-.128-.537-.423-.608zM16.4 9.701l-1.95 1.746v.005a.44.44 0 0 0 .173.757l.003.01 2.526.728a5.199 5.199 0 0 0-.108-1.674A5.208 5.208 0 0 0 16.4 9.7zm-4.013 5.325a.437.437 0 0 0-.404-.232.44.44 0 0 0-.372.233h-.002l-1.268 2.292a5.164 5.164 0 0 0 3.326.003l-1.27-2.296h-.01zm1.888-1.293a.44.44 0 0 0-.27.036.44.44 0 0 0-.214.572l-.003.004 1.01 2.438a5.15 5.15 0 0 0 2.081-2.615l-2.6-.44-.004.005z"/></svg>',
  cf: '<svg class="icon" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#0C9ED5"><path d="M12.854 13.537c-.048 1.79.074 3.862.149 4.917.96.136 1.633.456 1.633.83 0 .497-1.193 1.07-2.665 1.07s-2.665-.573-2.665-1.07c0-.374.673-.694 1.633-.83.075-1.055.197-3.127.15-4.917-.044-1.613-.779-3.091-1.676-3.821-.725-.59-1.174-1.427-1.166-2.354.016-1.765 1.683-3.186 3.724-3.186s3.708 1.42 3.723 3.186c.008.927-.44 1.763-1.165 2.354-.897.73-1.632 2.208-1.675 3.821zm6.214 6.596c.287-.115.612-.177.951-.19-.007-.24-.166-.672-.303-.877-.56-.1-1.276-.313-1.658-.682a.48.48 0 0 1-.186-.41c.026-.146.133-.253.278-.329a8.115 8.115 0 0 0-1.08-.515 4.6 4.6 0 0 1-1.697-.124c-.303-.09-.764-.24-.82-.549-.16-.03-.54-.083-.766-.112a4.048 4.048 0 0 0-.07.31.815.815 0 0 0 .56.956c1 .291 1.756.77 1.974 1.359.44 1.19-1.413 2.353-4.231 2.353-2.82 0-4.673-1.163-4.233-2.353.213-.574.94-1.044 1.903-1.337a.863.863 0 0 0 .589-1.005l-.06-.283c-.291.03-.779.101-1.031.148-.019.313-.476.466-.76.564a4.65 4.65 0 0 1-1.708.147 7.82 7.82 0 0 0-1.052.535c.544.23.316.736-.09.97-.407.253-.842.409-1.38.51-.051.088-.111.298-.163.438-.016.136-.063.367-.053.459.645.02 1.268.152 1.62.605.281.508-.024.976-.51 1.364.392.316.986.673 1.45.868a4.82 4.82 0 0 1 2.715-.269c.718.16 1.506.581 1.742 1.289.635.042 1.895.04 2.528-.041.182-.731.907-1.147 1.606-1.326a4.803 4.803 0 0 1 2.712.193c.356-.18 1.03-.602 1.306-.9-.474-.358-.873-.794-.63-1.325.085-.19.301-.33.547-.44zm-9.54-5.848s.418-1.586-1.4-3.632A4.99 4.99 0 0 1 6.88 7.346a5.05 5.05 0 0 1 5.047-5.04c2.822-.065 5.168 2.218 5.164 5.04a4.984 4.984 0 0 1-1.248 3.306c-1.614 1.616-1.4 3.633-1.4 3.633a7.352 7.352 0 0 0 4.956-6.898c.035-4.021-3.39-7.47-7.414-7.385-4.027-.083-7.447 3.364-7.413 7.385a7.352 7.352 0 0 0 4.956 6.898z"/></svg>',
  python: '<svg class="icon" viewBox="0 0 20 20"><ellipse cx="10" cy="10" rx="8.4" ry="5.6" fill="none" stroke="#3776ab" stroke-width="1.3" transform="rotate(-24 10 10)"/><ellipse cx="10" cy="10" rx="8.4" ry="5.6" fill="none" stroke="#3776ab" stroke-width="1.3" transform="rotate(24 10 10)"/></svg>',
  ubuntu: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="none" stroke="#e95420" stroke-width="1.4"/><circle cx="10" cy="4.6" r="1.7" fill="#e95420"/><circle cx="5.3" cy="13" r="1.7" fill="#e95420"/><circle cx="14.7" cy="13" r="1.7" fill="#e95420"/></svg>',
  shield: '<svg class="icon" viewBox="0 0 20 20"><path d="M10 1.5 L16.5 4 V9.5 C16.5 13.8 13.7 16.9 10 18.5 C6.3 16.9 3.5 13.8 3.5 9.5 V4 Z" fill="none" stroke="#4f6169" stroke-width="1.4"/></svg>',
  box: '<svg class="icon" viewBox="0 0 20 20"><rect x="2.5" y="2.5" width="15" height="15" rx="2" fill="none" stroke="#4f6169" stroke-width="1.4"/><path d="M2.5 8 H17.5" stroke="#4f6169" stroke-width="1.1"/><circle cx="5.2" cy="5.2" r=".9" fill="#4f6169"/><circle cx="7.6" cy="5.2" r=".9" fill="#4f6169"/></svg>',
  net: '<svg class="icon" viewBox="0 0 20 20"><circle cx="10" cy="10" r="8" fill="none" stroke="#4f6169" stroke-width="1.3"/><ellipse cx="10" cy="10" rx="3.6" ry="8" fill="none" stroke="#4f6169" stroke-width="1.1"/><line x1="2" y1="10" x2="18" y2="10" stroke="#4f6169" stroke-width="1.1"/><line x1="3.4" y1="6" x2="16.6" y2="6" stroke="#4f6169" stroke-width="1.1"/><line x1="3.4" y1="14" x2="16.6" y2="14" stroke="#4f6169" stroke-width="1.1"/></svg>',
  layer: '<svg class="icon" viewBox="0 0 20 20"><path d="M10 2.5 L17.5 6.5 L10 10.5 L2.5 6.5 Z" fill="none" stroke="#4f6169" stroke-width="1.3"/><path d="M2.5 10 L10 14 L17.5 10" fill="none" stroke="#4f6169" stroke-width="1.3"/><path d="M2.5 13.5 L10 17.5 L17.5 13.5" fill="none" stroke="#4f6169" stroke-width="1.3"/></svg>',
};

function tag(text, cls) {
  return text ? `<span class="tag ${cls || 'neutral'}">${esc(text)}</span>` : '';
}
function card(title, icon, tagText, tagCls, body) {
  return `<section class="card"><h2><span class="title">${ICONS[icon] || ''}${esc(title)}</span>${tag(tagText, tagCls)}</h2>${body}</section>`;
}
function acc(label, inner) {
  return `<div class="acc"><button class="acc-hd" type="button" onclick="this.parentElement.classList.toggle('open')"><span class="acc-caret">▸</span>${esc(label)}</button><div class="acc-bd">${inner}</div></div>`;
}
// Tanzu Hub CVE accordion. `comp` = {ok, name, matched:{name,version,counts,cves,latest_patch_version}, na}.
// `cve` = top-level hub result; when !cve.ok we surface the reason.
function cveBlock(label, comp, cve, naMsg) {
  if (!cve || cve.detected === false) {
    return acc(label + ' — CVEs (Tanzu Hub)',
      `<div class="muted" style="padding:10px 18px">Tanzu Hub not configured — bind the <span style="font-family:var(--cds-font-mono)">pyi-creds</span> credhub service (with the Hub service-account credentials) to enable CVE data.</div>`);
  }
  if (!cve.ok) {
    return acc(label + ' — CVEs (Tanzu Hub)',
      `<div class="muted" style="padding:10px 18px">unavailable — ${esc(cve.reason || 'unknown error')}</div>`);
  }
  comp = comp || {};
  const m = comp.matched;
  let header = label + ' — CVEs (Tanzu Hub)';
  if (comp.na) header += ' — N/A';
  else if (m) header += ' — ' + m.name + ' ' + (m.version || '') + ' · ' + m.counts.critical + ' critical · ' + m.counts.high + ' high';
  let body;
  if (comp.na) {
    body = `<div class="muted" style="padding:10px 18px">${esc(naMsg || 'Not applicable for this runtime.')}</div>`;
  } else if (!m) {
    body = `<div class="muted" style="padding:10px 18px">No CVEs reported for ${esc(comp.name || 'this component')} in Tanzu Hub.</div>`;
  } else {
    const parts = [];
    for (const [key, tagcls] of [['critical','warning'],['high','info']]) {
      const list = (m.cves && m.cves[key]) || [];
      if (list.length) parts.push(`<div style="margin:6px 0"><span class="tag ${tagcls}">${key} · ${list.length}</span><pre>${esc(list.join('\\n'))}</pre></div>`);
    }
    body = parts.length ? parts.join('') : `<div class="muted" style="padding:10px 18px">No open CVEs.</div>`;
    if (m.latest_patch_version) body += `<div class="muted" style="padding:0 18px">latest patch version: <span style="font-family:var(--cds-font-mono)">${esc(m.latest_patch_version)}</span></div>`;
  }
  return acc(header, body);
}

// Stemcell - CVEs (OSV) accordion. The stemcell itself is a node-level fact
// (invisible from inside the container), but its *kernel* is — so this row
// looks up Linux kernel CVEs for the running kernel via the public OSV API
// (Ubuntu `linux` source package, full Debian version). `k` = kernel_cve.
function osvBlock(k) {
  const label = 'Stemcell - CVEs (OSV)';
  if (!k) return acc(label,
    `<div class="muted" style="padding:10px 18px">no data</div>`);
  if (k.status === 'warming') {
    const n = k.count || 0;
    return acc(label + ' — querying OSV…',
      `<div class="muted" style="padding:10px 18px">First load: querying the public OSV API for this kernel's CVEs (this can take a few minutes). ${n ? 'Found ' + n + ' CVEs so far.' : 'Fetching page 1…'}<br>Refresh the page once the warm-up completes (result is then cached).</div>`);
  }
  if (!k.ok) {
    return acc(label,
      `<div class="muted" style="padding:10px 18px">${esc(k.reason || 'unavailable')}</div>`);
  }
  const cves = k.cves || {};
  const nCrit = (cves.critical || []).length;
  const nHigh = (cves.high || []).length;
  const sevSummary = `${nCrit} critical · ${nHigh} high`;
  let body = `<div class="muted" style="padding:10px 18px 4px">${sevSummary} kernel CVEs for ${esc(k.version)} (source pkg <span style="font-family:var(--cds-font-mono)">${esc(k.package)}</span> on ${esc(k.ecosystem)}, via ${esc(k.source)}; medium and below are not shown)${k.status === 'partial' ? ' — <em>partial: page cap reached</em>' : ''}</div>`;
  const parts = [];
  for (const [key, tagcls] of [['critical', 'warning'], ['high', 'info']]) {
    const list = cves[key] || [];
    if (list.length) parts.push(`<div style="margin:6px 0"><span class="tag ${tagcls}">${key} · ${list.length}</span><pre>${esc(list.join('\\n'))}</pre></div>`);
  }
  body += parts.length ? parts.join('') : `<div class="muted" style="padding:6px 18px">No critical or high-severity kernel CVEs.</div>`;
  body += `<div class="muted" style="padding:0 18px 10px">Fetched ${esc(k.fetched_at)}.</div>`;
  return acc(label + ' — ' + (k.version || '') + ' · ' + sevSummary, body);
}

function render(d) {
  const g = document.getElementById('grid');
  const panels = [];
  document.getElementById('ver').textContent = 'v' + d.app.version;
  const rt = document.getElementById('runtime');
  rt.className = 'tag ' + (d.runtime_environment.includes('Kubernetes') ? 'k8s' : 'info');
  rt.innerHTML = (d.runtime_environment.includes('Kubernetes') ? ICONS.k8s : ICONS.cf) + esc(d.runtime_environment);
  document.getElementById('brandicon').innerHTML = d.runtime_environment.includes('Kubernetes') ? ICONS.k8s : ICONS.cf;

  const sec = d.security;
  const inst = d.instance;
  const cve = d.cve || {ok:false, reason:'no data'};
  const kernel = d.kernel_cve || {ok:false, reason:'no data'};
  const cf = sec.platform.cloud_foundry, k8s = sec.platform.kubernetes;
  const os = sec.os_stack, ct = sec.container;
  const app = sec.application_layer, br = sec.buildpack_runtime || {};
  br.buildpack = br.buildpack || {};
  br.buildpack_dep_layers = br.buildpack_dep_layers || [];
  // Tanzu Hub detection: on when the pyi-creds binding (Hub service-account
  // credentials) is present, off otherwise.
  const hubEl = document.getElementById('hub');
  if (cve && cve.detected) {
    hubEl.className = 'tag success';
    hubEl.title = 'Tanzu Hub: ' + (cve.foundation_id || 'connected');
    hubEl.innerHTML = ICONS.shield + 'Tanzu Hub';
  } else {
    hubEl.className = 'tag off';
    hubEl.title = 'No Tanzu Hub credential binding (pyi-creds)';
    hubEl.innerHTML = ICONS.shield + 'Tanzu Hub off';
  }

  // ---- 1. Summary (group: Container Instance + Layer Summary) ----
  const idxLabel = inst.index !== null && inst.index !== undefined ? '#' + inst.index : '—';
  const osRelease = os.os_release ? (os.os_release.VERSION + ' (' + (os.os_release.ID || '') + ' ' + (os.os_release.ID_LIKE || '') + ')') : null;
  const instCard = card('Container Instance', 'box', d.runtime_environment,
    d.runtime_environment.includes('Kubernetes') ? 'k8s' : 'info',
    `<div class="hero"><div>
        <div class="hero-label">instance number</div>
        <div class="hero-num">${esc(idxLabel)}</div>
        <div class="hero-sub">${inst.guid ? 'instance ' + esc(inst.guid) : ''}</div>
      </div>
      <table class="kv">${kv([
        ['Started', d.app.started_at],
        ['Uptime', d.app.uptime],
      ])}</table></div>`);
  const layerCard = card('Layer Summary', 'layer', null, null,
    `<table class="kv">${kv([
      ['Application Layer', app.application.name + ' — v' + app.application.app_version],
      ['App Runtime', br.python ? br.python.version + ' (' + br.python.implementation + ')' : 'unknown'],
      ['Buildpack', (br.buildpack.name || 'unknown') + ' — v' + (br.buildpack.version || 'unknown')],
      ['Stack', os.stack || 'unknown'],
      ['OS release', osRelease],
      ['OS Kernel', os.kernel + ' (' + os.arch + ')'],
    ])}</table>`);
  panels.push(`<div class="sec-group"><h2>${ICONS.layer}Summary</h2><div class="stack">${instCard + layerCard}</div></div>`);

  // ---- 2. Security (group) ----
  const secPanels = [];

  // 2.1 Application Layer (env vars as accordion)
  const rep = app.repository;
  const envRows = d.environment_variables.map(e => [e.name, e.value]);
  const envAcc = acc('environment variables — ' + d.environment_variables.length + ' vars · secrets masked',
    `<table class="kv">${kv(envRows)}</table>`);
  secPanels.push(card('Application Layer', 'layer', 'v' + app.application.app_version, 'neutral',
    `<table class="kv">${kv([
      ['Application', app.application.name + ' — v' + app.application.app_version],
      ['Routes', (app.application.uris || []).join(', ') || null],
      ['Process type', app.application.process_type],
      ['Git repository', rep.origin || null],
      ['Git commit', rep.commit || null],
      ['Working directory', app.working_directory],
    ])}</table>` + envAcc));

  // 2.2 Application Dependencies
  const dep = sec.dependencies;
  const depBody = dep.total
    ? dep.packages.map(p =>
        `<div class="pkg"><span class="pname">${esc(p.name)}</span><span class="pver">${esc(p.version)}</span>` +
        `<span class="tag ${p.direct ? 'success' : 'neutral'}">${p.direct ? 'DIRECT' : 'TRANSITIVE'}</span>` +
        (p.requires.length ? `<span class="reqs">requires ${esc(p.requires.join(', '))}</span>` : '') +
        `</div>`).join('')
    : '<div class="muted" style="padding:12px 18px">No third-party packages detected — stdlib-only app.</div>' +
      (dep.direct.length ? `<pre>${esc(dep.direct.join('\\n'))}</pre>` : '');
  secPanels.push(card('Application Dependencies', 'layer',
    dep.total ? dep.direct_count + ' direct · ' + dep.transitive_count + ' transitive' : 'stdlib only', 'neutral',
    depBody));

  // 2.3 Buildpack (runtime)
  let bpBody = `<table class="kv">${kv([
    ['Buildpack', br.buildpack.name ? br.buildpack.name + ' — v' + (br.buildpack.version || 'unknown') : 'not detected'],
    ['Python runtime', br.python.version + ' (' + br.python.implementation + ')'],
    ['Python build', br.python.full],
    ['Python executable', br.python.executable],
    ['pip', br.packages.pip],
    ['setuptools', br.packages.setuptools],
  ])}</table>`;
  if (br.buildpack_dep_layers.length) {
    bpBody += br.buildpack_dep_layers.map(l =>
      acc('buildpack layer ' + l.layer + ' — ' + l.tools.length + ' tools',
        `<pre>${esc(l.tools.join('\\n') || 'no bin/ tools')}</pre>`)).join('');
  }
  bpBody += cveBlock('Buildpack', (cve.components && cve.components.buildpack) || {}, cve);
  secPanels.push(card('Buildpack (runtime)', 'python', 'python_buildpack', 'neutral', bpBody));

  // 2.4 Stack (root filesystem)
  const h = os.hardening;
  let stackBody = `<table class="kv">${kv([
    ['Stack', os.stack],
    ['Distribution', os.distribution],
    ['OS release', osRelease],
    ['Kernel', os.kernel + ' (' + os.arch + ')'],
    ['glibc', os.glibc],
    ['Hardening', h ? h.summary.join(' · ') : null],
  ])}</table>`;
  if (ct.cgroups && ct.cgroups.length > 1) {
    stackBody += acc('all cgroups', `<pre>${esc(ct.cgroups.join('\\n'))}</pre>`);
  }
  stackBody += cveBlock('Stack', (cve.components && cve.components.stack) || {}, cve);
  // Stemcell - CVEs (OSV): the stemcell is a node-level fact we can't see from
  // inside the container, but its kernel is. Look up Linux kernel CVEs for the
  // running kernel via the public OSV API (Ubuntu linux source package).
  stackBody += osvBlock(kernel);
  secPanels.push(card('Stack (root filesystem)', 'ubuntu', os.distribution, 'neutral', stackBody));

  // 2.5 Container platform
  const containerRows = [
    ['Hostname', ct.hostname],
    ['PID 1', ct.pid1.comm + (ct.pid1.cmdline ? ' — ' + ct.pid1.cmdline : '')],
    ['Cgroup', ct.cgroups && ct.cgroups.length ? ct.cgroups[0] : (ct.cgroup_unified || null)],
  ];
  const k8sRows = [
    ['API server', k8s.api_server.host ? k8s.api_server.host + ':' + k8s.api_server.port : null],
    ['SA token', k8s.service_account.token_present ? 'mounted' : (k8s.api_server.host ? 'not mounted (no API access from container)' : null)],
    ['K8s env vars', Object.keys(k8s.env).length ? Object.entries(k8s.env).map(([k, v]) => k + '=' + v).join('; ') : null],
    ['k8s-app-entrypoint', ct.k8s_entrypoint_config ? 'present' : null],
    ['Org / Space', app.application.organization ? app.application.organization + ' / ' + app.application.space : null],
    ['CF API', app.application.cf_api],
    ['Build ID', app.application.build_id],
  ].concat(containerRows);
  let platBody, platTag, platCls;
  if (k8s.detected) {
    platBody = `<table class="kv">${kv(k8sRows)}</table>`;
    if (ct.k8s_entrypoint_config) {
      platBody += acc('k8s-app-entrypoint-config.json', `<pre>${esc(JSON.stringify(ct.k8s_entrypoint_config, null, 2))}</pre>`);
    }
    if (cf.detected) {
      platBody += acc('CF overlay on this Kubernetes cluster (VKS)', `<pre>${esc(JSON.stringify(cf.application, null, 2))}</pre>`);
    }
    platTag = k8s.api_server.host ? k8s.api_server.host : 'detected';
    platCls = 'k8s';
  } else {
    platBody = `<table class="kv">${kv([
      ['App ID', cf.application && cf.application.application_id],
      ['Org / Space', app.application.organization ? app.application.organization + ' / ' + app.application.space : null],
      ['Uris', cf.application && (cf.application.application_uris || []).join(', ')],
      ['CF API', cf.application && cf.application.cf_api],
      ['Build ID', cf.application && cf.application.build_id],
      ['Services', cf.services.map(s => s.name + ' [' + s.label + ':' + s.plan + ']').join(', ') || null],
      ['Buildpack dep layers', cf.buildpack_dep_layers.map(l => l.layer + ' (' + l.tools.length + ' tools)').join('  ') || null],
    ].concat(containerRows))}</table>`;
    if (cf.application) {
      platBody += acc('VCAP_APPLICATION raw', `<pre>${esc(JSON.stringify(cf.application, null, 2))}</pre>`);
    }
    platTag = 'detected';
    platCls = 'info';
  }
  // Platform runtime tile CVEs (Tanzu Hub) live in this panel, not a separate one.
  const rtComp = (cve.components && cve.components.runtime) || {};
  platBody += cveBlock('Container Runtime', rtComp, cve,
    'Platform runtime CVEs are not tracked for Kubernetes in Tanzu Hub yet.');
  secPanels.push(card('Container platform', k8s.detected ? 'k8s' : 'cf', platTag, platCls, platBody));

  panels.push(`<div class="sec-group"><h2>${ICONS.shield}Security</h2><div class="stack">${secPanels.join('')}</div></div>`);

  // ---- 3. Networking ----
  const n = d.network;
  let netBody = `<table class="kv">${kv([
    ['Internal IP', inst.internal_ip],
    ['External IP', inst.ip],
    ['Hostname', n.hostname + (n.hostname_resolves_to.length ? ' → ' + n.hostname_resolves_to.join(', ') : '')],
    ['Default route', n.default_route ? 'via ' + n.default_route.gateway + ' on ' + n.default_route.interface : null],
    ['DNS servers', n.dns.nameservers.join(', ') || null],
    ['DNS search', (n.dns.search_domains[0] || []).join(' ') || null],
    ['Listening', n.listening_sockets.map(s => s.address + ':' + s.port).join(', ') || 'none'],
  ])}</table>` + n.interfaces.map(i =>
    acc('iface ' + i.name + ' — ' + (i.state || '?') + ', mtu ' + i.mtu + ', ' + i.mac,
      `<pre>${esc((i.ipv4 || []).join('\\n') || 'no addresses')}</pre>`)).join('');
  if (n.routes && n.routes.length) {
    netBody += acc('routes', `<pre>${esc(n.routes.map(r => r.dest + ' via ' + r.gateway + ' dev ' + r.interface).join('\\n'))}</pre>`);
  }
  panels.push(card('Networking', 'net', null, null, netBody));

  // ---- 4. Infrastructure ----
  panels.push(card('Infrastructure', 'net', null, null, `<table class="kv">${kv([
    ['CPU', os.cpu_count + ' × ' + os.cpu_model],
    ['Memory', os.memory_total_mb ? os.memory_total_mb + ' MB total / ' + os.memory_available_mb + ' MB available' : null],
    ['Disk', os.disk ? Object.entries(os.disk).map(([m, x]) => m + ': ' + x.used_gb + '/' + x.total_gb + ' GB').join('  ') : null],
  ])}</table>`));

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
    # Warm the Tanzu Hub CVE cache in the background so the first page load
    # isn't blocked on the Hub round-trips. The OSV kernel-CVE warm runs in
    # parallel (its own thread, ~5 min of pagination, cached 30 min).
    threading.Thread(target=_hub_warm, daemon=True).start()
    threading.Thread(target=_osv_warm, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
