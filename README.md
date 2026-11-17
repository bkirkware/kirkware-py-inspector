# py-inspector

A small **stdlib-only** Python web app that reports everything it can observe
about the environment it runs in. Built to run on **both Cloud Foundry
(python_buildpack) and Kubernetes** — including CF-on-K8s / VKS, where both are
detected and Kubernetes is labeled first. No third-party dependencies;
everything is read from `/proc`, `/sys`, `/etc`, and the process environment.

- **UI:** `GET /` — a dark "Runtime Inspector" dashboard
- **API:** `GET /api/info` — the full report as JSON
- **Health:** `GET /healthz`

There are two optional outbound data sources, both degrade gracefully when
unavailable:

| Source | What it adds | Setup |
|---|---|---|
| **Tanzu Hub** | Buildpack / Stack / Container-Runtime CVE rows | a bound `credhub` service (see [Tanzu Hub CVE enrichment](#tanzu-hub-cve-enrichment)) |
| **OSV** (`api.osv.dev`) | Kernel CVE lookup for the running kernel | none — public API, no auth |

With neither configured the app still reports everything local; the CVE rows
simply read "not configured".

## What it reports

UI sections, one panel per row:

1. **Container Instance** — the instance number as a large hero display, plus
   instance GUID, hostname, internal/external IP, started-at + human-friendly
   uptime, PID 1, cgroup.
2. **Security** — a group of sub-panels:
   - *Application Layer* — app name/version, app id, routes, org/space, CF API,
     process type, build id, git repository origin + commit; **Environment
     Variables folded in as a collapsible pull-down** (secrets masked).
   - *Application Dependencies* — every package in the app's environment
     (direct vs transitive, with the requirement edges that pulled each in).
   - *Buildpack (runtime)* — Python runtime (version, implementation,
     executable, build string), pip/setuptools, buildpack dependency layers and
     the tools each provides, plus a **CVE row** for the buildpack that built
     this app (from Tanzu Hub, when configured).
   - *Stack (root filesystem)* — distribution, OS release, CF stack, kernel,
     glibc, container hardening posture (seccomp, NoNewPrivs, capabilities,
     AppArmor visibility). Includes a **CVE row** for the stack's root
     filesystem (from Tanzu Hub) and a **`Stemcell - CVEs (OSV)`** row — the
     stemcell itself is a node-level fact not observable from inside the
     container, but its *kernel* is, so this row looks up Linux kernel CVEs for
     the running kernel via the public [OSV API](https://api.osv.dev/) (see
     [Kernel CVE lookup](#kernel-cve-lookup-osv-no-setup)).
   - *Container platform* — Cloud Foundry (app id, uris, build, services,
     buildpack layers) and/or Kubernetes (API server, SA-token presence,
     k8s-app-entrypoint config). On CF-on-K8s the Kubernetes facts lead and the
     CF overlay is shown in a collapsible. This panel also carries a
     **Container Runtime CVE row** for the platform runtime tile you name via
     the `HUB_RUNTIME_TILE` env var (see [Configuration](#configuration)).
3. **Networking** — hostname + resolution, default route, DNS, listening
   sockets, per-interface detail (MAC/MTU/state/addresses), routes.
4. **Infrastructure** — node-level resources: CPU (count × model), memory
   (total/available), disk usage per mount.

The header shows the detected container platform (Kubernetes wins over Cloud
Foundry when both are present) with the official brand icon (Kubernetes and
Cloud Foundry marks are the Simple Icons CC0 paths in their official colors), a
**Tanzu Hub detection badge** (green "Tanzu Hub" when a credhub binding with
Hub credentials is present, muted "Tanzu Hub off" otherwise), and app uptime in
human form (e.g. `2d 3h 14m`).

## Run locally

```sh
python3 main.py          # honors $PORT (default 8080) and $BIND (default 0.0.0.0)
```

## Deploy to Cloud Foundry

```sh
cf push py-inspector -f manifest.yml
```

The app runs on `python_buildpack`. The root `manifest.yml` deploys 3 instances
at 512M and declares `services: [pyi-creds]` so a Hub-cred service is bound on
push (see below — if you don't have one yet, remove that line and the app runs
without the Hub CVE rows).

## Deploy to Kubernetes

Any image that runs `python3 main.py` (or a slim Python image plus the file).
The app reads `$PORT` (default 8080); a Service exposing that port is all it
needs. Kubernetes specifics are read from the service-account mount and
environment, so a default ServiceAccount is enough for the basic report. On
Kubernetes there is no `VCAP_SERVICES`, so the Tanzu Hub CVE rows show "not
configured" unless you inject the credentials as a bound service the app can
see (see below).

## Tanzu Hub CVE enrichment

The Buildpack, Stack, and Container-Runtime panels each show the CVEs Tanzu Hub
reports for that component. To enable this, bind a **`credhub`** service whose
credentials carry the Hub service-account credentials — the app finds it by
scanning `VCAP_SERVICES` for an entry with `label: credhub` that has
`TANZU_HUB_URL` and `TANZU_HUB_SERVICE_ACCOUNT_ID`. The service can have any
name; this repo's manifests bind one named **`pyi-creds`** (so its `services:`
line references that name).

**Required credential keys:**

```json
{
  "TANZU_HUB_URL": "https://hub.tanzu.<your-org>",
  "TANZU_HUB_SERVICE_ACCOUNT_ID": "<service account id>",
  "TANZU_HUB_SERVICE_ACCOUNT_SECRET": "<service account secret>"
}
```

- `TANZU_HUB_URL` — origin of your Tanzu Hub (e.g. `https://hub.tanzu...`).
- `TANZU_HUB_SERVICE_ACCOUNT_ID` — the Hub service-account **ID**; used as the
  OAuth `client_id`.
- `TANZU_HUB_SERVICE_ACCOUNT_SECRET` — the short service-account **secret**;
  used as the OAuth `client_secret`. The app exchanges these for a token via
  `POST {HUB_URL}/auth/z/default/oauth/token` (`client_credentials`) and caches
  it for ~30 min.
- (Optional) `TANZU_HUB_CLIENT_SECRET` — a `key_…` client-assertion JWT. The
  app does **not** use it for the token grant; you can include it if your
  credhub entry already carries it, but it is not required.

**Creating the service** (on the **foundation** CF API endpoint, logged in as a
space operator — target that endpoint, not the Hub endpoint, so `credhub
default` resolves per-foundation):

```sh
cf api <foundation-api-endpoint>
cf login -u <space-operator> -p <password>
cf target -o <org> -s <space>

cat > pyi-creds.json <<'JSON'
{
  "TANZU_HUB_URL": "https://hub.tanzu.<your-org>",
  "TANZU_HUB_SERVICE_ACCOUNT_ID": "<id>",
  "TANZU_HUB_SERVICE_ACCOUNT_SECRET": "<secret>"
}
JSON

cf create-service credhub default pyi-creds -c pyi-creds.json
```

Create one per space you deploy to. The repo's `manifests/` all declare
`services: [pyi-creds]`, so `cf push` binds it on push — the app reads the
credentials from `VCAP_SERVICES` and needs no further configuration. After
binding, the header badge turns green "Tanzu Hub" and the three CVE rows
populate.

The app identifies *itself* in Hub by its CF app name, resolves the foundation
its VRN carries, and scopes buildpack/stack/runtime CVEs to that foundation.
Results are cached for 5 minutes (tune with `HUB_CACHE_TTL`).

## Kernel CVE lookup (OSV) — no setup

The Stack panel's **`Stemcell - CVEs (OSV)`** row looks up Linux kernel CVEs for
the *running* kernel via the public [OSV API](https://api.osv.dev/) — no
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
background thread on startup (serialised behind the Hub CVE fetch to keep memory
flat), is cached for 30 minutes (`OSV_CACHE_TTL`), and trims the huge
`versions`/`ranges`/`affected` fields during JSON parse so the build peaks well
under a 512M instance. The row shows "querying OSV…" with a running count until
it completes. Non-Ubuntu stacks show "not applicable". Tunables: `OSV_MAX_PAGES`
(page cap, default 120), `OSV_PAGE_TIMEOUT`, `OSV_API_URL` (override for tests).

## Configuration

Environment variables (all optional; the app runs with none of them set):

| Var | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `BIND` | `0.0.0.0` | HTTP bind address |
| `HUB_CACHE_TTL` | `300` | Seconds to cache the Hub CVE payload |
| `HUB_RUNTIME_TILE` | *(empty)* | Platform runtime tile name (exact, as it appears in your Hub catalog) for the Container-Runtime CVE row. Set to `N/A` to show "N/A" without querying; leave empty to show "not set". |
| `HUB_URL_OVERRIDE` | *(empty)* | Override the Hub origin (tests). |
| `OSV_API_URL` | `https://api.osv.dev/v1/query` | OSV query endpoint (tests). |
| `OSV_CACHE_TTL` | `1800` | Seconds to cache the OSV kernel-CVE build. |
| `OSV_MAX_PAGES` | `120` | Page cap for the OSV pagination. |
| `OSV_PAGE_TIMEOUT` | `60` | Per-page timeout (seconds). |
| `GIT_REPO_URL`, `GIT_COMMIT` | *(empty)* | Repository origin + commit shown in the report. CF droplets drop `.git`, so these are the in-app source; stamp them at push time if you want the UI to show them. |
| `BUILDPACK_NAME`, `BUILDPACK_VERSION`, `APP_STACK` | *(empty)* | Stamped at push time so the app can report its buildpack/stack and resolve the matching Hub CVE rows (CF droplets can't see their own buildpack name/version or `/etc/cf-stack`). |

## Versioning

Patch (third octet) increments ship with each change; minor/major only when
intended. Current version: see `APP_VERSION` in `main.py`.
