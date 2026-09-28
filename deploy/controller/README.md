# acp-runner controller deployment

## Deploy order

1. `deploy/egress-proxy/proxy.yaml` first (namespace, allowlist ConfigMap,
   proxy Deployment, proxy NetworkPolicy). The controller refreshes Codex
   tokens through this proxy (`ACP_RUNNER_CODEX_REFRESH_PROXY` in
   `controller.yaml`); without it, every provider refresh fails under the
   egress policy below.
2. `deploy/controller/` (namespace, RBAC, controller, policies).
3. Add your kube-apiserver destination (next section) before the controller
   can watch anything.

Operator overrides: set `ACP_RUNNER_CODEX_REFRESH_PROXY` to another proxy,
or unset it to refresh directly (only with a CNI FQDN rule for
`auth.openai.com:443`, otherwise the egress policy blocks it). Set
`ACP_RUNNER_CODEX_REFRESH=false` to disable verifying write-back entirely
(chatgpt write-backs are then rejected fail-closed).

## Required controller egress (no general internet)

`networkpolicy.yaml` (`acp-runner-controller-egress`) restricts controller
egress to exactly four destinations. There is deliberately **no `0.0.0.0/0`
rule**: standard Kubernetes NetworkPolicy has no FQDN selector (see below).

| Destination | Rule | Why |
|---|---|---|
| kube-dns (kube-system) | UDP/TCP 53 | name resolution |
| PostgreSQL (`acp-runner-postgres`) | TCP 5432 | journal |
| egress proxy (`acp-egress-proxy.acp-egress`) | TCP 3128 | V1a Codex token refresh via `ACP_RUNNER_CODEX_REFRESH_PROXY=http://acp-egress-proxy.acp-egress:3128`; the proxy allowlist (`.openai.com`) plus the controller's pinned endpoint check (`https://auth.openai.com/oauth/token`) constrain the destination |
| kube-apiserver (**you must add this**) | TCP 443 to your cluster's API IP/CIDR | watching `ACPRun` / `AgentEnvironment` objects |

## Before applying: add your API-server destination

Applying the egress policy as-is blocks the controller's Kubernetes watches.
Add your cluster's API-server IP/CIDR first. Find it with:

```bash
kubectl cluster-info | head -2            # the control-plane address
# or
kubectl get endpoints kubernetes -o jsonpath='{.subsets[*].addresses[*].ip}'
```

k3s default is `10.43.0.1/32`. Append to the
`acp-runner-controller-egress` policy in `networkpolicy.yaml`:

```yaml
    - to:
        - ipBlock: {cidr: 10.43.0.1/32}   # replace with YOUR api-server IP/CIDR
      ports: [{protocol: TCP, port: 443}]
```

## FQDN limitation (CNI-specific)

"auth.openai.com-only" cannot be expressed in a standard NetworkPolicy.
Enforcement is layered instead:

1. The egress proxy allowlists the destination hostname (`.openai.com`).
2. The controller validates the refresh endpoint is exactly
   `https://auth.openai.com/oauth/token` at startup and on every refresh
   (`codex_refresh::check_trusted_endpoint`).
3. This NetworkPolicy denies the controller any direct public egress, so the
   proxy hop cannot be bypassed.

Clusters whose CNI offers FQDN egress rules should add an
`auth.openai.com:443` rule there and may then drop the proxy hop (unset
`ACP_RUNNER_CODEX_REFRESH_PROXY`).

## AgentEnvironment management (V10)

The controller reconciles `AgentEnvironment` objects (status, `lifecycle:
finish|cancel`, finalizer) and creates one gateway Service + ingress
NetworkPolicy per environment in the object's namespace. All state lives in
PostgreSQL, so `finish`/`cancel`/`destroy` survive restarts and replicas need
no leader election. Disable with `ACP_RUNNER_MANAGE_ENVIRONMENTS=false` for
run-only controllers.

Connection tickets require a shared master key: apply `ticket-key-secret.yaml`
with real key material (see the file header) before scaling past 1 replica.
Rotation is two-key: put the old key in `acp-runner-ticket-key-prev` and set
`ACP_RUNNER_TICKET_KEY_PREV_FILE` + mount (mirroring `controller.yaml`);
environments created under the old key stay connectable until they end.
