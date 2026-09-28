//! Deterministic fake coding agent for CI and the driver compatibility suite.
//!
//! Personalities:
//!
//! * default: an **ACP v1 agent** over stdio (initialize, session/new, session/prompt,
//!   session/cancel, session/update notifications, session/request_permission).
//! * `fake-acp-agent claude-mode ...`: emulates the **Claude Code `-p` stream-json**
//!   interface closely enough to exercise the `claude` driver without a subscription.
//! * invoked as **`codex`** (symlink): emulates the Codex CLI commands the `codex` driver
//!   uses (`--version`, `login status`, reading `$CODEX_HOME/auth.json`).
//! * invoked as **`codex-acp`** (symlink): the ACP agent with codex-acp's auth behaviour —
//!   `session/new` fails with `-32000 Authentication required` without
//!   `$CODEX_HOME/auth.json`, and an API-key `auth.json` is announced via
//!   `_auth/status_update` (`kind: api_key`). Together they exercise the real `codex` driver
//!   (env, config.toml, probe classification, credential refresh + write-back) through
//!   agentd without an OpenAI account.
//!
//! The scenario comes from `FAKE_ACP_SCENARIO` or a `[[fake:<scenario>]]` directive inside
//! the prompt (the directive wins). Scenarios:
//!
//! | scenario            | behaviour                                                         |
//! |---------------------|-------------------------------------------------------------------|
//! | `fix` (default)     | asks permission, fixes `add.sh`, ends turn                         |
//! | `fix-binary`        | `fix` + adds a binary file                                          |
//! | `commit`            | `fix` + `git commit`                                                |
//! | `noop`              | talks, changes nothing                                              |
//! | `crash`             | exits with code 3 mid-turn                                          |
//! | `fix-then-crash`    | fixes `add.sh`, then exits with code 3 (partial patch)             |
//! | `crash-until:N`     | crashes while `FAKE_ACP_ATTEMPT_ORDINAL < N`, then `fix`             |
//! | `hang-until:N`      | hangs (`hang`) while `FAKE_ACP_ATTEMPT_ORDINAL < N`, then `fix`      |
//! | `hang`              | stops producing output; honours `session/cancel`                    |
//! | `hang-hard`         | stops producing output; ignores `session/cancel` (needs SIGTERM)    |
//! | `slow:N`            | N progress messages 200ms apart, then `fix`                          |
//! | `silent-then-fix:S` | S seconds without output, then `fix`                                |
//! | `refuse`            | ends turn with `stopReason: refusal`                                |
//! | `auth-required`     | `session/new` fails with -32000 (ACP AuthRequired)                  |
//! | `bad-protocol`      | answers `initialize` with protocolVersion 99                        |
//! | `garbage`           | prints a non-JSON line, then `fix`                                  |
//! | `leak-secret`       | echoes credential material it can see, then `fix`                   |
//! | `escape-symlink`    | creates `evil -> /etc/passwd`                                        |
//! | `huge`              | writes a ~2 MiB file                                                 |
//! | `write-outside`     | writes outside the repository, then `fix`                           |
//! | `refresh-credential`| rewrites `$HOME/.codex/auth.json` (token refresh), then `fix`        |
//! | `api-key-mode`      | reports API-key auth (codex-acp `_auth/status_update`)              |
//! | `read:PATH`         | replies with the content of PATH (relative to the session cwd)      |
//! | `touch:NAME`        | writes NAME (relative to the session cwd), ends the turn            |
//! | `trust-probe`       | reports whether the agent can see the secret, ACP_RUNNER_* env, runnerd, or reach blocked hosts (egress) |
//! | `auth-fail`         | (claude-mode) authentication failure result                         |
//! | `api-key`           | (claude-mode) `apiKeySource: ANTHROPIC_API_KEY` in init              |

use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUGGY: &str = "$(( $1 - $2 ))";
const FIXED: &str = "$(( $1 + $2 ))";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let argv0 = std::env::args().next().unwrap_or_default();
    let personality = Path::new(&argv0).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    if personality == "codex" {
        codex_cli(&args);
        return;
    }
    if personality == "codex-acp" {
        if args.iter().any(|a| a == "--version") {
            println!("@agentclientprotocol/codex-acp 1.13.1-fake");
            return;
        }
        CODEX_EMULATION.store(true, Ordering::SeqCst);
        acp_mode();
        return;
    }
    if args.first().map(String::as_str) == Some("claude-mode") {
        claude_mode(&args[1..]);
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("fake-acp-agent {VERSION}");
        return;
    }
    acp_mode();
}

static CODEX_EMULATION: AtomicBool = AtomicBool::new(false);

fn codex_auth() -> Option<Value> {
    let home = std::env::var("CODEX_HOME").ok()?;
    serde_json::from_str(&std::fs::read_to_string(Path::new(&home).join("auth.json")).ok()?).ok()
}

fn codex_uses_api_key(auth: &Value) -> bool {
    auth.get("auth_mode").and_then(|m| m.as_str()) == Some("apikey")
        || auth.get("OPENAI_API_KEY").map(|k| !k.is_null()).unwrap_or(false)
}

/// `codex --version` / `codex login status` emulation (strings as printed by codex-rs).
fn codex_cli(args: &[String]) {
    if args.iter().any(|a| a == "--version") {
        println!("codex-cli 0.156.1-fake");
        return;
    }
    if args.first().map(String::as_str) == Some("login") && args.get(1).map(String::as_str) == Some("status") {
        match codex_auth() {
            None => {
                eprintln!("Not logged in");
                std::process::exit(1);
            }
            Some(a) if codex_uses_api_key(&a) => {
                eprintln!("Logged in using an API key - sk-***fake");
                return;
            }
            Some(_) => {
                eprintln!("Logged in using ChatGPT");
                return;
            }
        }
    }
    eprintln!("fake codex: unsupported arguments {args:?}");
    std::process::exit(2);
}

fn scenario_from(prompt: &str) -> String {
    if let Some(start) = prompt.find("[[fake:") {
        let rest = &prompt[start + 7..];
        if let Some(end) = rest.find("]]") {
            return rest[..end].trim().to_string();
        }
    }
    std::env::var("FAKE_ACP_SCENARIO").unwrap_or_else(|_| "fix".into())
}

fn ordinal() -> u32 {
    std::env::var("FAKE_ACP_ATTEMPT_ORDINAL").ok().and_then(|s| s.parse().ok()).unwrap_or(1)
}

/// Resolve dynamic scenarios to a concrete one.
fn resolve(s: &str) -> String {
    if let Some(n) = s.strip_prefix("crash-until:") {
        let n: u32 = n.parse().unwrap_or(2);
        return if ordinal() < n { "crash".into() } else { "fix".into() };
    }
    if let Some(n) = s.strip_prefix("hang-until:") {
        let n: u32 = n.parse().unwrap_or(2);
        return if ordinal() < n { "hang".into() } else { "fix".into() };
    }
    s.to_string()
}

fn fix_add_sh(cwd: &Path) -> Result<(), String> {
    let p = cwd.join("add.sh");
    let s = std::fs::read_to_string(&p).map_err(|e| format!("read add.sh: {e}"))?;
    std::fs::write(&p, s.replace(BUGGY, FIXED)).map_err(|e| format!("write add.sh: {e}"))
}

// ------------------------------------------------------------------------------------
// ACP mode
// ------------------------------------------------------------------------------------

#[derive(Clone)]
struct Out(Arc<Mutex<std::io::Stdout>>);

impl Out {
    fn send(&self, v: &Value) {
        let mut o = self.0.lock().unwrap();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    }
    fn raw_line(&self, s: &str) {
        let mut o = self.0.lock().unwrap();
        let _ = writeln!(o, "{s}");
        let _ = o.flush();
    }
}

struct Shared {
    out: Out,
    cancelled: AtomicBool,
    next_id: AtomicU64,
    waiters: Mutex<HashMap<u64, Sender<Value>>>,
    cwd: Mutex<PathBuf>,
    scenario: Mutex<String>,
}

fn acp_mode() {
    let shared = Arc::new(Shared {
        out: Out(Arc::new(Mutex::new(std::io::stdout()))),
        cancelled: AtomicBool::new(false),
        next_id: AtomicU64::new(1000),
        waiters: Mutex::new(HashMap::new()),
        cwd: Mutex::new(std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
        scenario: Mutex::new(std::env::var("FAKE_ACP_SCENARIO").unwrap_or_else(|_| "fix".into())),
    });
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            eprintln!("fake-acp-agent: ignoring invalid json");
            continue;
        };
        let method = msg.get("method").and_then(|m| m.as_str()).map(str::to_string);
        let id = msg.get("id").cloned();
        match (method.as_deref(), id) {
            (Some("initialize"), Some(id)) => {
                let scen = resolve(&shared.scenario.lock().unwrap());
                let requested = msg.pointer("/params/protocolVersion").and_then(|v| v.as_u64()).unwrap_or(1);
                let version = if scen == "bad-protocol" { 99 } else { requested.min(1) };
                shared.out.send(&json!({"jsonrpc":"2.0","id":id,"result":{
                    "protocolVersion": version,
                    "agentInfo": {"name":"fake-acp-agent","title":"Fake agent","version":VERSION},
                    "agentCapabilities": {"loadSession": false, "promptCapabilities": {"image": false, "embeddedContext": true}},
                    "authMethods": []
                }}));
            }
            (Some("session/new"), Some(id)) => {
                let scen = resolve(&shared.scenario.lock().unwrap());
                if let Some(cwd) = msg.pointer("/params/cwd").and_then(|c| c.as_str()) {
                    *shared.cwd.lock().unwrap() = PathBuf::from(cwd);
                }
                let codex = CODEX_EMULATION.load(Ordering::SeqCst);
                let auth = if codex { codex_auth() } else { None };
                if codex && auth.as_ref().is_some_and(codex_uses_api_key) {
                    shared.out.send(&json!({"jsonrpc":"2.0","method":"_auth/status_update","params":{"authStatus":{"kind":"api_key","label":"OpenAI API key"}}}));
                }
                if scen == "auth-required" || (codex && auth.is_none()) {
                    shared.out.send(
                        &json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Authentication required"}}),
                    );
                } else {
                    if scen == "api-key-mode" {
                        shared.out.send(&json!({"jsonrpc":"2.0","method":"_auth/status_update","params":{"authStatus":{"kind":"api_key","label":"OpenAI API key"}}}));
                    }
                    // V9 (A21/conformance): report the requested model when the
                    // harness is told one via the environment; unset = no
                    // `models` key at all (as before).
                    let mut result =
                        json!({"sessionId": format!("fake-session-{}", std::process::id())});
                    if let Ok(model) = std::env::var("FAKE_ACP_MODEL")
                        && !model.is_empty()
                    {
                        result["models"] = json!({"currentModelId": model});
                    }
                    shared.out.send(&json!({"jsonrpc":"2.0","id":id,"result": result}));
                }
            }
            (Some("session/prompt"), Some(id)) => {
                let prompt = msg
                    .pointer("/params/prompt")
                    .and_then(|p| p.as_array())
                    .map(|a| {
                        a.iter().filter_map(|b| b.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n")
                    })
                    .unwrap_or_default();
                let sid = msg.pointer("/params/sessionId").and_then(|s| s.as_str()).unwrap_or("").to_string();
                let scen = resolve(&scenario_from_prompt_or(&prompt, &shared.scenario.lock().unwrap()));
                let sh = shared.clone();
                std::thread::spawn(move || run_turn(sh, id, sid, scen));
            }
            (Some("session/cancel"), None) => {
                shared.cancelled.store(true, Ordering::SeqCst);
            }
            (Some(other), Some(id)) => {
                shared.out.send(&json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("method not found: {other}")}}));
            }
            (Some(_), None) => {}
            (None, Some(id)) => {
                // response to one of our requests
                if let Some(n) = id.as_u64()
                    && let Some(w) = shared.waiters.lock().unwrap().remove(&n)
                {
                    let _ = w.send(msg.clone());
                }
            }
            (None, None) => {}
        }
    }
}

fn scenario_from_prompt_or(prompt: &str, default: &str) -> String {
    if prompt.contains("[[fake:") { scenario_from(prompt) } else { default.to_string() }
}

fn update(sh: &Shared, sid: &str, update: Value) {
    sh.out.send(&json!({"jsonrpc":"2.0","method":"session/update","params":{"sessionId":sid,"update":update}}));
}

fn say(sh: &Shared, sid: &str, text: &str) {
    update(sh, sid, json!({"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":text}}));
}

fn request(sh: &Shared, method: &str, params: Value) -> Option<Value> {
    let id = sh.next_id.fetch_add(1, Ordering::SeqCst);
    let (tx, rx) = channel();
    sh.waiters.lock().unwrap().insert(id, tx);
    sh.out.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
    rx.recv_timeout(Duration::from_secs(60)).ok()
}

fn end_turn(sh: &Shared, id: Value, reason: &str) {
    sh.out.send(&json!({"jsonrpc":"2.0","id":id,"result":{"stopReason":reason}}));
}

fn wait_cancelled(sh: &Shared, honour: bool) -> bool {
    loop {
        if honour && sh.cancelled.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn run_turn(sh: Arc<Shared>, id: Value, sid: String, scen: String) {
    let cwd = sh.cwd.lock().unwrap().clone();
    let (base, arg) = match scen.split_once(':') {
        Some((b, a)) => (b.to_string(), a.to_string()),
        None => (scen.clone(), String::new()),
    };
    say(&sh, &sid, &format!("Fake agent running scenario `{scen}`. "));
    match base.as_str() {
        "crash" => {
            eprintln!("fake-acp-agent: simulated crash");
            std::process::exit(3);
        }
        "fix-then-crash" => {
            let _ = fix_add_sh(&cwd);
            say(&sh, &sid, "Edited add.sh, now crashing.");
            eprintln!("fake-acp-agent: simulated crash after editing");
            std::process::exit(3);
        }
        "hang" => {
            wait_cancelled(&sh, true);
            end_turn(&sh, id, "cancelled");
            return;
        }
        "hang-hard" => {
            wait_cancelled(&sh, false);
        }
        "trust-probe" => {
            let report = trust_probe();
            say(&sh, &sid, &format!("TRUST-PROBE {report}\n"));
        }
        "refuse" => {
            say(&sh, &sid, "I cannot help with that.");
            end_turn(&sh, id, "refusal");
            return;
        }
        "noop" => {
            say(&sh, &sid, "Nothing to change.");
            end_turn(&sh, id, "end_turn");
            return;
        }
        // Review-style turn: report the content of file `arg` (relative to the session cwd).
        "read" => {
            let text = std::fs::read_to_string(cwd.join(&arg)).unwrap_or_else(|_| "MISSING".into());
            say(&sh, &sid, &format!("CONTENT[{arg}]:{text}"));
            end_turn(&sh, id, "end_turn");
            return;
        }
        // Environment multi-turn: write/overwrite a file `arg` (default note.txt), end the turn.
        "touch" => {
            let name = if arg.is_empty() { "note.txt".to_string() } else { arg.clone() };
            let _ = std::fs::write(cwd.join(&name), format!("touched {name}\n"));
            say(&sh, &sid, &format!("Wrote {name}."));
            end_turn(&sh, id, "end_turn");
            return;
        }
        "slow" => {
            let n: u32 = arg.parse().unwrap_or(5);
            for i in 0..n {
                if sh.cancelled.load(Ordering::SeqCst) {
                    end_turn(&sh, id, "cancelled");
                    return;
                }
                update(
                    &sh,
                    &sid,
                    json!({"sessionUpdate":"plan","entries":[{"content":format!("step {i}"),"priority":"medium","status":"in_progress"}]}),
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        "silent-then-fix" => {
            let secs: u64 = arg.parse().unwrap_or(5);
            let until = std::time::Instant::now() + Duration::from_secs(secs);
            while std::time::Instant::now() < until {
                if sh.cancelled.load(Ordering::SeqCst) {
                    end_turn(&sh, id, "cancelled");
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        "garbage" => sh.out.raw_line("this line is not JSON-RPC"),
        "leak-secret" => {
            let mut leaked = std::env::var("CLAUDE_CODE_OAUTH_TOKEN").unwrap_or_default();
            if let Ok(home) = std::env::var("HOME")
                && let Ok(s) = std::fs::read_to_string(Path::new(&home).join(".codex/auth.json"))
            {
                leaked.push_str(&s);
            }
            if let Ok(dir) = std::env::var("FAKE_LEAK_FILE")
                && let Ok(s) = std::fs::read_to_string(dir)
            {
                leaked.push_str(&s);
            }
            say(&sh, &sid, &format!("I found these credentials: {leaked}"));
            eprintln!("fake-acp-agent stderr leak: {leaked}");
        }
        "refresh-credential" => {
            // Simulates Codex refreshing its ChatGPT tokens in $CODEX_HOME/auth.json.
            if let Ok(home) = std::env::var("HOME") {
                let p = Path::new(&home).join(".codex/auth.json");
                if let Ok(s) = std::fs::read_to_string(&p)
                    && let Ok(mut v) = serde_json::from_str::<Value>(&s)
                {
                    v["refreshed"] = json!(true);
                    v["last_refresh"] = json!("2026-09-26T00:00:00Z");
                    let _ = std::fs::write(&p, v.to_string());
                }
            }
        }
        "escape-symlink" => {
            let _ = std::os::unix::fs::symlink("/etc/passwd", cwd.join("evil"));
            end_turn(&sh, id, "end_turn");
            return;
        }
        "huge" => {
            let line = "0123456789abcdef".repeat(8) + "\n";
            let _ = std::fs::write(cwd.join("huge.txt"), line.repeat(2 * 1024 * 1024 / 129));
            end_turn(&sh, id, "end_turn");
            return;
        }
        "write-outside" => {
            let _ = std::fs::write(cwd.join("../outside.txt"), "outside");
            if let Ok(home) = std::env::var("HOME") {
                let _ = std::fs::write(Path::new(&home).join("outside-home.txt"), "home");
            }
        }
        _ => {}
    }
    // --- the "fix" path ---------------------------------------------------------------
    update(
        &sh,
        &sid,
        json!({"sessionUpdate":"tool_call","toolCallId":"call-1","title":"Edit add.sh","kind":"edit","status":"pending",
        "locations":[{"path": cwd.join("add.sh").to_string_lossy()}],"rawInput":{"path":"add.sh"}}),
    );
    let resp = request(
        &sh,
        "session/request_permission",
        json!({
            "sessionId": sid,
            "toolCall": {"toolCallId":"call-1","title":"Edit add.sh","kind":"edit","status":"pending"},
            "options": [
                {"optionId":"allow","name":"Allow","kind":"allow_once"},
                {"optionId":"reject","name":"Reject","kind":"reject_once"}
            ]
        }),
    );
    let allowed =
        resp.as_ref().and_then(|r| r.pointer("/result/outcome/optionId")).and_then(|o| o.as_str()) == Some("allow");
    if !allowed {
        update(
            &sh,
            &sid,
            json!({"sessionUpdate":"tool_call_update","toolCallId":"call-1","status":"failed",
            "content":[{"type":"content","content":{"type":"text","text":"permission denied"}}]}),
        );
        say(&sh, &sid, "Permission denied; no changes made.");
        end_turn(&sh, id, "end_turn");
        return;
    }
    update(&sh, &sid, json!({"sessionUpdate":"tool_call_update","toolCallId":"call-1","status":"in_progress"}));
    let result = fix_add_sh(&cwd);
    if base == "fix-binary" {
        let _ = std::fs::create_dir_all(cwd.join("assets"));
        let _ = std::fs::write(cwd.join("assets/logo.bin"), [0u8, 1, 2, 3, 255, 254, 0, 10, 13, 0]);
    }
    if base == "commit" {
        let _ =
            std::process::Command::new("git").args(["commit", "-qam", "fake agent commit"]).current_dir(&cwd).status();
    }
    match result {
        Ok(()) => {
            update(
                &sh,
                &sid,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"call-1","status":"completed",
                "content":[{"type":"diff","path":cwd.join("add.sh").to_string_lossy(),"oldText":BUGGY,"newText":FIXED}]}),
            );
            say(&sh, &sid, "Fixed add.sh: it now adds its arguments.");
        }
        Err(e) => {
            update(
                &sh,
                &sid,
                json!({"sessionUpdate":"tool_call_update","toolCallId":"call-1","status":"failed",
                "content":[{"type":"content","content":{"type":"text","text":e}}]}),
            );
            say(&sh, &sid, "Could not edit add.sh.");
        }
    }
    let reason = if sh.cancelled.load(Ordering::SeqCst) { "cancelled" } else { "end_turn" };
    end_turn(&sh, id, reason);
}

// ------------------------------------------------------------------------------------
// Claude Code stream-json emulation
// ------------------------------------------------------------------------------------

fn claude_mode(args: &[String]) {
    if args.iter().any(|a| a == "--version" || a == "-v") {
        println!("2.1.274 (Fake Claude Code)");
        return;
    }
    if args.first().map(String::as_str) == Some("auth") {
        let token = std::env::var("CLAUDE_CODE_OAUTH_TOKEN").unwrap_or_default();
        let api_key = std::env::var("ANTHROPIC_API_KEY").is_ok();
        let v = if api_key {
            json!({"loggedIn": true, "authMethod": "api_key", "apiProvider": "firstParty"})
        } else if !token.is_empty() {
            json!({"loggedIn": true, "authMethod": "oauth_token", "apiProvider": "firstParty"})
        } else {
            json!({"loggedIn": false, "apiProvider": "firstParty"})
        };
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
        return;
    }
    let flag = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let resumed = flag("--resume");
    let session_id = flag("--session-id")
        .or_else(|| resumed.clone())
        .unwrap_or_else(|| "00000000-0000-0000-0000-000000000000".into());
    // Read the first user message.
    let stdin = std::io::stdin();
    let mut prompt = String::new();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if let Ok(v) = serde_json::from_str::<Value>(&line)
            && v.get("type").and_then(|t| t.as_str()) == Some("user")
        {
            prompt = v
                .pointer("/message/content")
                .and_then(|c| c.as_array())
                .map(|a| a.iter().filter_map(|b| b.get("text").and_then(|t| t.as_str())).collect::<Vec<_>>().join("\n"))
                .unwrap_or_default();
            break;
        }
    }
    let scen = resolve(&scenario_from(&prompt));
    let out = |v: Value| {
        let mut o = std::io::stdout().lock();
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    };
    let key_source = if scen == "api-key" { "ANTHROPIC_API_KEY" } else { "none" };
    out(
        json!({"type":"system","subtype":"init","cwd":std::env::current_dir().unwrap_or_default(),"session_id":session_id,
        "tools":["Bash","Edit","Read"],"mcp_servers":[],"model":"fake-model","permissionMode":"acceptEdits",
        "apiKeySource":key_source,"claude_code_version":"2.1.274-fake","uuid":"u0"}),
    );
    let assistant = |content: Value| json!({"type":"assistant","message":{"role":"assistant","content":content},"parent_tool_use_id":null,"session_id":session_id});
    let how = if resumed.is_some() { "resumed" } else { "new" };
    out(assistant(
        json!([{"type":"text","text":format!("Fake Claude running scenario `{scen}` ({how} session {session_id}).")}]),
    ));
    let (base, arg) =
        scen.split_once(':').map(|(b, a)| (b.to_string(), a.to_string())).unwrap_or((scen.clone(), String::new()));
    match base.as_str() {
        "crash" => std::process::exit(1),
        "hang" | "hang-hard" => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        "auth-fail" => {
            out(
                json!({"type":"system","subtype":"api_retry","attempt":1,"max_retries":1,"retry_delay_ms":10,"error_status":401,"error":"authentication_failed","session_id":session_id}),
            );
            out(
                json!({"type":"result","subtype":"error_during_execution","is_error":true,"result":"Failed to authenticate. API Error: 401","session_id":session_id}),
            );
            std::process::exit(1);
        }
        "noop" => {}
        "touch" => {
            let name = if arg.is_empty() { "note.txt".to_string() } else { arg };
            let cwd = std::env::current_dir().unwrap_or_default();
            out(assistant(json!([{"type":"tool_use","id":"toolu_t","name":"Write","input":{"file_path":name}}])));
            let _ = std::fs::write(cwd.join(&name), format!("touched {name}\n"));
            out(
                json!({"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_t","content":"written","is_error":false}]},"parent_tool_use_id":null,"session_id":session_id}),
            );
            out(assistant(json!([{"type":"text","text":format!("Wrote {name}.")}])));
        }
        _ => {
            out(assistant(json!([{"type":"tool_use","id":"toolu_1","name":"Edit","input":{"file_path":"add.sh"}}])));
            let cwd = std::env::current_dir().unwrap_or_default();
            let r = fix_add_sh(&cwd);
            out(
                json!({"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1",
                "content": if r.is_ok() {"updated"} else {"failed"}, "is_error": r.is_err()}]},"parent_tool_use_id":null,"session_id":session_id}),
            );
            out(
                json!({"type":"rate_limit_event","rate_limit_info":{"status":"allowed","rateLimitType":"five_hour","utilization":0.01}}),
            );
            out(assistant(json!([{"type":"text","text":"Fixed add.sh."}])));
        }
    }
    out(
        json!({"type":"result","subtype":"success","is_error":false,"num_turns":2,"duration_ms":5,"result":"Fixed add.sh.","session_id":session_id}),
    );
}

// ------------------------------------------------------------------------------------
// trust-probe: verify the isolation boundary from inside the agent.
//
// This reports only whether each boundary held (booleans and connection outcome codes). It
// deliberately does NOT read, assemble or transmit any credential material — it checks
// reachability and visibility, which is what the security regression tests assert on.
// Configured through non-secret env:
//   FAKE_PROBE_INGEST   host:port of the controller ingest API (expect: auth rejected)
//   FAKE_PROBE_BLOCKED  host:port that egress policy must NOT allow (expect: not reachable)
//   FAKE_PROBE_ALLOWED  host:port that the egress proxy allows       (expect: reachable)
// ------------------------------------------------------------------------------------

/// Open a TCP connection and return a short outcome code. Nothing is sent.
fn can_connect(addr: &str) -> String {
    use std::net::ToSocketAddrs;
    let Ok(mut it) = addr.to_socket_addrs() else { return "resolve-failed".into() };
    let Some(sa) = it.next() else { return "no-address".into() };
    match std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(2)) {
        Ok(_) => "connected".into(),
        Err(e) => format!("refused:{:?}", e.kind()),
    }
}

/// Ask the ingest API for the attempt spec without a token and report the HTTP status only.
fn ingest_status_without_token(addr: &str) -> String {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let Ok(mut it) = addr.to_socket_addrs() else { return "resolve-failed".into() };
    let Some(sa) = it.next() else { return "no-address".into() };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(2)) else {
        return "unreachable".into();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET /v1/attempt HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return "write-failed".into();
    }
    let mut buf = [0u8; 128];
    let n = s.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1).unwrap_or("none").to_string()
}

/// Reachability of a host through the configured egress proxy (HTTPS_PROXY): reports the
/// CONNECT response status only, never sends a payload.
fn proxy_connect_status(target: &str) -> String {
    use std::io::{Read, Write};
    use std::net::ToSocketAddrs;
    let Some(proxy) = std::env::var("HTTPS_PROXY").ok().or_else(|| std::env::var("https_proxy").ok()) else {
        return "no-proxy".into();
    };
    let addr = proxy.trim_start_matches("http://").trim_end_matches('/').to_string();
    let Ok(mut it) = addr.to_socket_addrs() else { return "resolve-failed".into() };
    let Some(sa) = it.next() else { return "no-address".into() };
    let Ok(mut s) = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(2)) else {
        return "proxy-unreachable".into();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return "write-failed".into();
    }
    let mut buf = [0u8; 128];
    let n = s.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).split_whitespace().nth(1).unwrap_or("none").to_string()
}

fn trust_probe() -> Value {
    // 1. runnerd's per-attempt secret must not exist in the agent's view.
    let secret_dir_visible = Path::new("/var/run/acp-runner/attempt").exists();
    let secret_readable = std::fs::read("/var/run/acp-runner/attempt/token").is_ok();
    // 2. no controller configuration in the agent environment.
    let acp_runner_env: Vec<String> =
        std::env::vars().map(|(k, _)| k).filter(|k| k.starts_with("ACP_RUNNER_")).collect();
    // 3. runnerd's process (and its /proc) must not be visible.
    let mut runnerd_visible = false;
    let mut runnerd_environ_readable = false;
    if let Ok(d) = std::fs::read_dir("/proc") {
        for e in d.flatten() {
            if std::fs::read_to_string(e.path().join("comm")).map(|c| c.trim() == "runnerd").unwrap_or(false) {
                runnerd_visible = true;
                runnerd_environ_readable |= std::fs::read(e.path().join("environ")).is_ok();
            }
        }
    }
    // 4. network reachability of the ingest API, a blocked host and an allowed host.
    let ingest = std::env::var("FAKE_PROBE_INGEST")
        .ok()
        .map(|a| json!({"authStatus": ingest_status_without_token(&a), "reachable": can_connect(&a)}));
    let blocked = std::env::var("FAKE_PROBE_BLOCKED")
        .ok()
        .map(|a| json!({"directConnect": can_connect(&a), "viaProxy": proxy_connect_status(&a)}));
    let allowed = std::env::var("FAKE_PROBE_ALLOWED").ok().map(|a| proxy_connect_status(&a));
    json!({
        "secretDirVisible": secret_dir_visible,
        "secretReadable": secret_readable,
        "acpRunnerEnv": acp_runner_env,
        "runnerdVisible": runnerd_visible,
        "runnerdEnvironReadable": runnerd_environ_readable,
        "ingest": ingest,
        "blockedHost": blocked,
        "allowedHost": allowed,
    })
}
