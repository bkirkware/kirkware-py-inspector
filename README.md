# kirkware-py-inspector

Infrastructure inspector: a small stdlib-only Python web app that reports
everything it can observe about the environment it runs in — built to run on
**both Cloud Foundry (python_buildpack) and Kubernetes**.

## What it reports

| Layer | Details |
|---|---|
| Runtime detection | CF (`VCAP_APPLICATION`, `/.cf`, `/home/vcap/deps`) vs K8s (service-account token, `KUBERNETES_SERVICE_HOST`) vs bare |
| Cloud Foundry | app id/uris/version/build, bound services, buildpack dep layers + tools |
| Kubernetes | API server, service account name/namespace, JWT subject/issuer, K8s env vars, kubelet mounts |
| OS | distro from `/etc/os-release`, kernel, glibc, arch, CPU model/count, memory, disk usage |
| Container | PID 1, cgroups, runtime markers (`/.cf`, `/.dockerenv`, `/.containerenv`, `/run/containerd`) |
| Networking | per-interface MAC/MTU/state/IPv4, default route, routes, DNS, hostname resolution, listening sockets |
| Versions | python (runtime, full build string, executable), pip, setuptools, cf CLI, node, java, git, go |
| Environment | all env vars, secrets masked |

- **UI:** `GET /` — dark dashboard, one card per layer
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

## Deploy to Kubernetes

Any image that runs `python3 main.py` (or just a slim python image plus the
file). The app reads `$PORT` (default 8080); a Service exposing that port is
all it needs. K8s specifics are read from the service-account mount and
environment, so a default ServiceAccount is enough for the basic report.
