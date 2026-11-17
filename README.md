# kirkware-py-inspector

Infrastructure inspector: a small stdlib-only Python web app that reports
everything it can observe about the environment it runs in — built to run on
**both Cloud Foundry (python_buildpack) and Kubernetes** (including
CF-on-K8s / VKS, where both are detected and Kubernetes is labeled first).

## What it reports

UI sections, one panel per row:

1. **Container Instance** — the instance number as a large hero display,
   plus instance GUID, hostname, internal/external IP, started-at +
   human-friendly uptime, PID 1, cgroup.
2. **Security** — a group of sub-panels:
   - *Application Layer* — app name/version, app id, routes, org/space,
     CF API, process type, build ID, git repository origin + commit;
     **Environment Variables folded in as a collapsible pull-down**
     (secrets masked).
   - *Application Dependencies* — every package in the app's environment
     (direct vs transitive, with the requirement edges that pulled each in).
   - *Buildpack (runtime)* — Python runtime (version, implementation,
     executable, build string), pip/setuptools, buildpack dependency layers
     and the tools each provides, plus a **CVE row** listing the CVEs
     Tanzu Hub reports for the buildpack that built this app.
   - *Stack (root filesystem)* — distribution, OS release, CF stack, kernel,
     glibc, container hardening posture (seccomp, NoNewPrivs, capabilities,
     AppArmor visibility). Includes a **CVE row** for the stack's root
     filesystem and a **`Stemcell - CVEs (OSV)`** row: the stemcell itself is a
     node-level fact not observable from inside the container, but its *kernel*
     is — this row looks up Linux kernel CVEs for the running kernel via the
     public OSV API (Ubuntu `linux` source package, full Debian version from
     `/proc/version_signature`). The full kernel CVE history is large (~5 min
     of pagination), so the lookup warms in a background thread and the row
     shows "querying OSV…" with a running count until it's cached.
   - *Container platform* — Cloud Foundry (app id, uris, build, services,
     buildpack layers) and/or Kubernetes (API server, SA-token presence,
     k8s-app-entrypoint config). On CF-on-K8s the
     Kubernetes facts lead and the CF overlay is shown in a collapsible. This
     panel also carries a **Container Runtime CVE row** for the platform
     runtime tile this app runs on (per space): `Small Footprint Elastic
     Application Runtime` (cody), `Resource Segment` (cody-older-stemcell), or
     `N/A` (cody-k8s — Kubernetes runtime is not in the TAS Hub catalog yet).
3. **Networking** — hostname + resolution, default route, DNS, listening
   sockets, per-interface detail (MAC/MTU/state/addresses), routes.
4. **Infrastructure** — node-level resources: CPU (count × model), memory
   (total/available), disk usage per mount.

The header shows the detected container platform (Kubernetes wins over
Cloud Foundry when both are present) with the official brand icon
(Kubernetes and Cloud Foundry marks are the Simple Icons CC0 paths in their
official colors), a **Tanzu Hub detection badge** (green "Tanzu Hub" when the
`pyi-creds` credhub binding with the Hub service-account credentials is
present, muted "Tanzu Hub off" otherwise), and app uptime in human form
(e.g. `2d 3h 14m`).

- **UI:** `GET /` — dark dashboard, "Runtime Inspector"
- **API:** `GET /api/info` — full JSON
- **Health:** `GET /healthz`

No third-party dependencies; everything is read from `/proc`, `/sys`, `/etc`,
and the process environment. The outbound calls are: to **Tanzu Hub** for
Buildpack/Stack/Container-Runtime CVE enrichment (only when the `pyi-creds`
credhub service is bound — see below), and to the **public OSV API**
(`api.osv.dev`, no auth) for the kernel CVE lookup in the Stack panel. With no
bound `pyi-creds` service the Tanzu Hub CVE rows simply show "not configured".

## Tanzu Hub CVE enrichment — fresh deploy

The Buildpack, Stack, and Container Runtime panels each show the CVEs Tanzu
Hub reports for that component. To make this work you need a **`pyi-creds`
credhub service instance in every space you deploy to** — the app reads the
Hub credentials from that bound service (it does not take them from env).

1. **Target the foundation API endpoint** and log in with a space operator:

   ```sh
   cf api https://api.sys.tanzu.kirkware.net --skip-ssl-validation
   cf login -u <space-operator> -p <password>
   cf target -o kirkware-devs -s cody
   ```

2. **Create the credential params file** (kept in `hidden/`, git-ignored). The
   values are your Tanzu Hub service account credentials:

   ```sh
   mkdir -p hidden
   cat > hidden/pyi-creds.json <<'JSON'
   {
     "TANZU_HUB_URL": "https://hub.tanzu.kirkware.net",
     "TANZU_HUB_SERVICE_ACCOUNT_ID": "<service_account_id>",
     "TANZU_HUB_SERVICE_ACCOUNT_SECRET": "<service_account_secret>",
     "TANZU_HUB_CLIENT_SECRET": "<client_secret>"
   }
   JSON
   ```

3. **Create the `pyi-creds` credhub service in each space** (one per space; do
   not use the cross-foundation plan — target the foundation endpoint as in
   step 1 so `credhub default` resolves per-foundation):

   ```sh
   for SPACE in cody cody-k8s cody-older-stemcell; do
     cf target -o kirkware-devs -s "$SPACE"
     cf create-service credhub default pyi-creds -c hidden/pyi-creds.json
   done
   ```

4. **Deploy.** Every manifest declares `services: [pyi-creds]`, so `cf push`
   (or `./deploy.sh`) binds the service on push — the app picks the
   credentials up from `VCAP_SERVICES` and needs no further configuration.

Notes:
- `TANZU_HUB_CLIENT_SECRET` is the `key_…` client-assertion JWT from your
  service account; only the ID + secret are used for the `client_credentials`
  token grant (see the service account details from your Hub admin).
- The app identifies *itself* in Hub by its CF app name, resolves the
  foundation its VRN carries, and scopes buildpack/stack/runtime CVEs to that
  foundation. Results are cached for 5 minutes (tune with `HUB_CACHE_TTL`).
- The platform runtime tile is stamped per space by `deploy.sh`
  (`HUB_RUNTIME_TILE`): cody → `Small Footprint Elastic Application Runtime`,
  cody-older-stemcell → `Resource Segment`, cody-k8s → `N/A`.

## Kernel CVE lookup (OSV) — no setup

The Stack panel's **`Stemcell - CVEs (OSV)`** row looks up Linux kernel CVEs
for the *running* kernel via the public [OSV API](https://api.osv.dev/) — no
credentials and no service binding needed. OSV indexes Ubuntu kernels by the
**source package** `linux` and the **full Debian version** `X.Y.Z-<abi>.<upload>`
(e.g. `5.15.0-202.212`) under the ecosystem string `Ubuntu:<distro>:LTS`. The
app reads that full version from `/proc/version_signature` (present on all
modern Ubuntu/Debian kernels); the plain `uname -r` string
(`5.15.0-202-generic`) is not queryable because it omits the upload number.
Only the `Ubuntu` severity score is used.

**Reading the counts.** OSV's Ubuntu data is tracker-driven: a `UBUNTU-CVE-*`
record matches every kernel the CVE ever touched (unbounded `introduced 0`
range), so the raw total (~2.5k for a jammy 5.15 kernel) is *"CVEs tracked
against this kernel version"*, not open exposure. To keep the row simple the
app lists only **critical- and high-severity** CVE IDs — medium, low and
negligible are counted during the lookup but not shown. The lookup warms in a
background thread on startup (serialised behind the Hub CVE fetch to keep
memory flat), is cached for 30 minutes (`OSV_CACHE_TTL`), and trims the huge
`versions`/`ranges`/`affected` fields during JSON parse so the build peaks
well under a 512M instance. The row shows "querying OSV…" with a running count
until it completes. Non-Ubuntu stacks show "not applicable". Tunables:
`OSV_MAX_PAGES` (page cap, default 120), `OSV_PAGE_TIMEOUT`, `OSV_API_URL`
(override for tests).

## Run locally

```sh
python3 main.py          # PORT env honored (default 8080)
```

## Deploy to Cloud Foundry

```sh
cf push kirkware-py-inspector -f manifest.yml
```

## Deployment matrix (concurrent)

`manifests/` holds one manifest per deployment. Each runs **3 instances** at
**128M** (the app idles ~25–35M RSS). `deploy.sh SPACE MANIFEST` targets the
space, stamps the live git origin/commit plus the manifest's stack and
org-resolved buildpack name/version, and pushes (app name = manifest
basename). All nine run concurrently, across all three spaces:

| App | Space | Stack | Buildpack | Route |
|---|---|---|---|---|
| `pyi-fs4` | cody (VM) | cflinuxfs4 | python_buildpack (1.8.119) | pyi-fs4.apps.tanzu.kirkware.net |
| `pyi-fs1` | cody (VM) | tanzucflinuxfs1 | python_buildpack (1.8.119) | pyi-fs1.apps.tanzu.kirkware.net |
| `pyi-fs4-old` | cody (VM) | cflinuxfs4 | python_buildpack_1_8_102 | pyi-fs4-old.apps.tanzu.kirkware.net |
| `pyi-fs4-k8s` | cody-k8s (VKS) | cflinuxfs4 | python_buildpack (1.8.119) | pyi-fs4-k8s.apps.tanzu.kirkware.net |
| `pyi-fs1-k8s` | cody-k8s (VKS) | tanzucflinuxfs1 | python_buildpack (1.8.119) | pyi-fs1-k8s.apps.tanzu.kirkware.net |
| `pyi-fs4-old-k8s` | cody-k8s (VKS) | cflinuxfs4 | python_buildpack_1_8_102 | pyi-fs4-old-k8s.apps.tanzu.kirkware.net |
| `pyi-fs4-oldstem` | cody-older-stemcell (VM) | cflinuxfs4 | python_buildpack (1.8.119) | pyi-fs4-oldstem.apps.tanzu.kirkware.net |
| `pyi-fs1-oldstem` | cody-older-stemcell (VM) | tanzucflinuxfs1 | python_buildpack (1.8.119) | pyi-fs1-oldstem.apps.tanzu.kirkware.net |
| `pyi-fs4-old-oldstem` | cody-older-stemcell (VM) | cflinuxfs4 | python_buildpack_1_8_102 | pyi-fs4-old-oldstem.apps.tanzu.kirkware.net |

Note: `cflinuxfs4` = Ubuntu 22.04, `tanzucflinuxfs1` = Ubuntu 26.04 — the two
`*-fs1*` apps run a materially newer root filesystem. `python_buildpack_1_8_102`
is a version-pinned buildpack (the `*-fs4-old*` apps build against 1.8.102 while
the rest use the current 1.8.119). `cody-older-stemcell` runs on nodes with an
older stemcell; its `-oldstem` apps compare node-age against `cody`'s.

Development deployments (1 instance, `manifests/pyi-clarity-dev*.yml`):
- `pyi-clarity-dev` in `cody` → pyi-clarity.apps.tanzu.kirkware.net
- `pyi-clarity-dev-k8s` in `cody-k8s` → pyi-clarity-k8s.apps.tanzu.kirkware.net
- `pyi-clarity-dev-oldstem` in `cody-older-stemcell` → pyi-clarity-oldstem.apps.tanzu.kirkware.net

Test matrix used for this app:
- VM-based Diego cells → org `kirkware-devs`, space `cody`
- Kubernetes (VKS) → org `kirkware-devs`, space `cody-k8s`
- Older-stemcell Diego cells → org `kirkware-devs`, space `cody-older-stemcell`
- cf CLI against the Hub endpoint (`https://hub.tanzu.kirkware.net`)
- `./deploy.sh SPACE MANIFEST` targets the space and pushes, stamping the live
  `remote.origin.url` + `HEAD` plus the manifest's `stack` and the org-resolved
  buildpack name/version (from `cf buildpacks`) into the generated manifest so
  the running app can report its repository, commit, buildpack, and stack.
- Pushing to GitHub: `git push https://bkirkware:$BKIRKWARE_GIT_TOKEN@github.com/bkirkware/kirkware-py-inspector.git main`
  (the `KIRKWARE_GIT_TOKEN`/`kirkware` pair gets 403 on this repo).

## Deploy to Kubernetes

Any image that runs `python3 main.py` (or just a slim python image plus the
file). The app reads `$PORT` (default 8080); a Service exposing that port is
all it needs. K8s specifics are read from the service-account mount and
environment, so a default ServiceAccount is enough for the basic report.

## Versioning

Patch (third octet) increments ship with each change; minor/major only when
instructed. Current: see `APP_VERSION` in `main.py` and the package version.
