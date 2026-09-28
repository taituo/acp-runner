#!/usr/bin/env bash
# Start a bare Kubernetes control plane (etcd + kube-apiserver, no kubelet, no
# controller-manager) for deterministic controller tests without KIND/Docker.
#
# Binaries: the controller-runtime "envtest" bundle (kube-apiserver, etcd, kubectl), e.g.
#   https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-v1.37.0/envtest-v1.37.0-linux-amd64.tar.gz
#
# Usage:
#   ENVTEST_BIN=/path/to/envtest/bin scripts/envtest-up.sh        # prints KUBECONFIG path
#   scripts/envtest-down.sh
set -euo pipefail

BIN=${ENVTEST_BIN:?set ENVTEST_BIN to a directory containing kube-apiserver, etcd, kubectl}
DIR=${ENVTEST_DIR:-${TMPDIR:-/tmp}/acp-runner-envtest}
API_PORT=${ENVTEST_API_PORT:-16443}
ETCD_PORT=${ENVTEST_ETCD_PORT:-12379}
PEER_PORT=$((ETCD_PORT + 1))

mkdir -p "$DIR/pki" "$DIR/etcd"
cd "$DIR/pki"
if [ ! -f ca.crt ]; then
  # all certificates are X.509 v3 (rustls rejects v1 certificates)
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 7 -subj "/CN=acp-envtest-ca" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=kube-apiserver" 2>/dev/null
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n" > san.ext
  printf "extendedKeyUsage=clientAuth\n" > client.ext
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 7 -extfile san.ext 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -keyout admin.key -out admin.csr -subj "/CN=envtest-admin/O=system:masters" 2>/dev/null
  openssl x509 -req -in admin.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out admin.crt -days 7 -extfile client.ext 2>/dev/null
  openssl genrsa -out sa.key 2048 2>/dev/null
  openssl rsa -in sa.key -pubout -out sa.pub 2>/dev/null
fi

"$BIN/etcd" --data-dir "$DIR/etcd" \
  --listen-client-urls "http://127.0.0.1:$ETCD_PORT" --advertise-client-urls "http://127.0.0.1:$ETCD_PORT" \
  --listen-peer-urls "http://127.0.0.1:$PEER_PORT" --initial-advertise-peer-urls "http://127.0.0.1:$PEER_PORT" \
  --initial-cluster "default=http://127.0.0.1:$PEER_PORT" --unsafe-no-fsync >"$DIR/etcd.log" 2>&1 &
echo $! > "$DIR/etcd.pid"

"$BIN/kube-apiserver" \
  --etcd-servers "http://127.0.0.1:$ETCD_PORT" \
  --bind-address 127.0.0.1 --secure-port "$API_PORT" \
  --tls-cert-file "$DIR/pki/server.crt" --tls-private-key-file "$DIR/pki/server.key" \
  --client-ca-file "$DIR/pki/ca.crt" \
  --service-account-issuer https://kubernetes.default.svc.cluster.local \
  --service-account-key-file "$DIR/pki/sa.pub" --service-account-signing-key-file "$DIR/pki/sa.key" \
  --service-cluster-ip-range 10.96.0.0/16 \
  --authorization-mode RBAC \
  --allow-privileged=true >"$DIR/apiserver.log" 2>&1 &
echo $! > "$DIR/apiserver.pid"

cat > "$DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: envtest
  cluster:
    server: https://127.0.0.1:$API_PORT
    certificate-authority: $DIR/pki/ca.crt
users:
- name: admin
  user:
    client-certificate: $DIR/pki/admin.crt
    client-key: $DIR/pki/admin.key
contexts:
- name: envtest
  context: {cluster: envtest, user: admin}
current-context: envtest
EOF

for _ in $(seq 1 120); do
  if KUBECONFIG="$DIR/kubeconfig" "$BIN/kubectl" get --raw /readyz >/dev/null 2>&1; then
    echo "$DIR/kubeconfig"
    exit 0
  fi
  sleep 0.5
done
echo "kube-apiserver did not become ready; see $DIR/apiserver.log" >&2
exit 1
