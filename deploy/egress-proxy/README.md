# Egress proxy (egress.mode: proxy)

Kubernetes NetworkPolicy cannot filter by hostname, so a runner class with persistent
subscription credentials must not run with unrestricted egress: the credential is readable by
the CLI (and therefore by anything the agent runs). Such classes must set `egress.mode: proxy`
and the controller **rejects the run otherwise** (override for local development only with
`ACP_RUNNER_ALLOW_DIRECT_CREDENTIAL_EGRESS=true`).

## What the proxy enforces

`acp-egress-proxy` (in this repo, `bins/acp-egress-proxy`) is an HTTP `CONNECT` proxy:

* **CONNECT only** — plain-HTTP proxy requests are refused, so every tunnel is end-to-end TLS
  chosen by the client; the proxy never sees plaintext and never terminates TLS.
* **hostname allowlist** — `api.anthropic.com` (exact) or `.openai.com` (domain + subdomains);
  IP-literal targets are refused.
* **port allowlist** — 443 by default.
* **no private destinations** — a name that resolves to any loopback / RFC1918 / CGNAT /
  link-local (incl. the `169.254.169.254` metadata endpoint) / ULA / multicast address is
  refused, so DNS cannot be used to reach cluster-internal services through the proxy.
* one JSON log line per decision (host, port, decision, reason, byte counts) — never payload.

It does **not** distinguish a legitimate provider request from data sent to the same provider,
and it does not see DNS queries; see README "Network model and its guarantees".

## Deploy

```bash
kubectl apply -f deploy/egress-proxy/proxy.yaml     # namespace, allowlist ConfigMap, Deployment, Service, NetworkPolicy
kubectl label namespace acp-agents acp-runner.dev/agents=true --overwrite
```

Then set the proxy on the runner class:

```yaml
spec:
  egress:
    mode: proxy
    httpsProxy: http://acp-egress-proxy.acp-egress.svc:3128
    noProxy: acp-runner-ingest.acp-runner-system.svc,localhost,127.0.0.1
```

runnerd exports `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` to the agent CLI and to its own
`git fetch`; runnerd's ingest traffic never uses the proxy. Edit the allowlist in the
`acp-egress-allowlist` ConfigMap — **verify the exact hosts your pinned CLI versions contact**
(run the live smoke tests through the proxy and read its log) before relying on it. A
TLS-intercepting proxy is not used and not required; if you deploy one, its CA goes to
`ACP_RUNNER_EXTRA_CA_FILE` (runnerd) and `NODE_EXTRA_CA_CERTS` (already set for agents).
