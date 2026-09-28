//! Deploy guardrails (no cluster needed): the controller must never gain
//! general public egress. V1a routes the Codex token refresh through the
//! allowlisting egress proxy; these tests pin that shape so a future edit
//! cannot silently open 0.0.0.0/0.

use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;

fn load_docs(rel: &str) -> Vec<Value> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy").join(rel);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml::Deserializer::from_str(&text)
        .map(|d| Value::deserialize(d).expect("valid yaml doc"))
        .collect::<Vec<_>>()
        .into_iter()
        .filter(|v| !v.is_null())
        .collect()
}

fn walk_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Array(a) => a.iter().for_each(|x| walk_strings(x, out)),
        Value::Object(m) => m.values().for_each(|x| walk_strings(x, out)),
        _ => {}
    }
}

fn policy<'a>(docs: &'a [Value], name: &str) -> &'a Value {
    docs.iter()
        .find(|d| d.get("kind").and_then(|k| k.as_str()) == Some("NetworkPolicy") && d.pointer("/metadata/name").and_then(|n| n.as_str()) == Some(name))
        .unwrap_or_else(|| panic!("NetworkPolicy {name} not found"))
}

#[test]
fn controller_has_no_public_egress_cidr() {
    let docs = load_docs("controller/networkpolicy.yaml");
    let egress = policy(&docs, "acp-runner-controller-egress");
    let mut strings = vec![];
    walk_strings(egress, &mut strings);
    for bad in ["0.0.0.0/0", "::/0"] {
        assert!(!strings.iter().any(|s| s == bad), "controller egress allows public {bad}");
    }
    // Egress is exactly DNS + postgres + proxy:3128 (plus comments).
    let ports: HashSet<String> = egress
        .pointer("/spec/egress")
        .and_then(|e| e.as_array())
        .expect("egress rules")
        .iter()
        .flat_map(|r| r.pointer("/ports").and_then(|p| p.as_array()).cloned().unwrap_or_default())
        .filter_map(|p| p.get("port").and_then(|n| n.as_u64()).map(|n| n.to_string()))
        .collect();
    assert!(ports.contains("53"), "DNS missing: {ports:?}");
    assert!(ports.contains("5432"), "postgres missing: {ports:?}");
    assert!(ports.contains("3128"), "proxy missing: {ports:?}");
    assert!(!ports.contains("443"), "direct 443 egress must go via the proxy, not the controller: {ports:?}");
}

#[test]
fn controller_routes_refresh_through_the_proxy_by_default() {
    // Deployment audit: the egress policy blocks direct internet, so the
    // shipped controller must point its token refresh at the proxy.
    let docs = load_docs("controller/controller.yaml");
    let deploy = docs
        .iter()
        .find(|d| d.get("kind").and_then(|k| k.as_str()) == Some("Deployment"))
        .expect("controller Deployment");
    let env = deploy
        .pointer("/spec/template/spec/containers/0/env")
        .and_then(|e| e.as_array())
        .expect("container env");
    let proxy = env
        .iter()
        .find(|e| e.get("name").and_then(|n| n.as_str()) == Some("ACP_RUNNER_CODEX_REFRESH_PROXY"))
        .unwrap_or_else(|| panic!("ACP_RUNNER_CODEX_REFRESH_PROXY not set in controller.yaml"));
    let value = proxy.get("value").and_then(|v| v.as_str()).unwrap_or("");
    assert!(value.starts_with("http://acp-egress-proxy."), "unexpected refresh proxy default: {value}");
}

#[test]
fn proxy_admits_the_controller() {
    let docs = load_docs("egress-proxy/proxy.yaml");
    let proxy = policy(&docs, "acp-egress-proxy");
    let ingress = proxy.pointer("/spec/ingress").and_then(|v| v.as_array()).expect("ingress rules");
    let controller_rule = ingress.iter().any(|r| {
        let mut strings = vec![];
        walk_strings(r, &mut strings);
        strings.iter().any(|s| s == "acp-runner-controller") && strings.iter().any(|s| s == "3128")
    });
    assert!(controller_rule, "proxy must admit the controller on 3128");
}

#[test]
fn direct_egress_excludes_non_public_ranges() {
    // V7: the direct-mode except list mirrors the proxy's `is_public`
    // classification, including IPv4-embedded-into-IPv6 tunnel ranges.
    let docs = load_docs("agents/networkpolicy.yaml");
    let direct = policy(&docs, "acp-agent-egress-direct");
    let mut strings = vec![];
    walk_strings(direct, &mut strings);
    for cidr in [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "0.0.0.0/8",
        "192.0.0.0/24",
        "192.88.99.0/24",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "::1/128",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2002::/16",
    ] {
        assert!(strings.iter().any(|s| s == cidr), "direct except list missing {cidr}");
    }
}
