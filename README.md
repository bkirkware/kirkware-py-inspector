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
2. **Security** — a group of five sub-panels:
   - *Application Layer* — app name/version, app ID, routes, org/space,
     CF API, process type, build ID, git repository origin + commit;
     **Environment Variables folded in as a collapsible pull-down**
     (secrets masked).
   - *Application Dependencies* — every package in the app's environment
     (direct vs transitive, with the requirement edges that pulled each in).
   - *Buildpack (runtime)* — Python runtime (version, implementation,
     executable, build string), pip/setuptools, buildpack dependency layers
     and the tools each provides.
   - *Stack (root filesystem)* — distribution, OS release, CF stack, kernel,
     glibc, container hardening posture (seccomp, NoNewPrivs, capabilities,
     AppArmor visibility). Stemcell is a node-level fact and is not
     observable from inside the container — the panel says so.
   - *Container platform* — Cloud Foundry (app id, uris, build, services,
     buildpack layers) and/or Kubernetes (API server, service account,
     namespace, JWT claims, k8s-app-entrypoint config). On CF-on-K8s the
     Kubernetes facts lead and the CF overlay is shown in a collapsible.
3. **Networking** — hostname + resolution, default route, DNS, listening
   sockets, per-interface detail (MAC/MTU/state/addresses), routes.
4. **Infrastructure** — node-level resources: CPU (count × model), memory
   (total/available), disk usage per mount.

The header shows the detected container platform (Kubernetes wins over
Cloud Foundry when both are present) with the official brand icon
(Kubernetes and Cloud Foundry marks are the Simple Icons CC0 paths in their
official colors), and app uptime in human form (e.g. `2d 3h 14m`).

- **UI:** `GET /` — dark dashboard, "Runtime Inspector"
- **API:** `GET /api/info` — full JSON
- **Health:** `GET /healthz`

No third-party dependencies; everything is read from `/proc`, `/sys`,
`/etc`, and the process environment. No outbound network calls.

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
