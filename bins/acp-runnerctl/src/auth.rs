//! Credential enrollment and inspection.
//!
//! Enrollment always goes through the provider's own login flow, completed by a human:
//!
//! * **codex**: `codex login --device-auth` (default), `codex login` (browser; callback on
//!   localhost:1455) or `codex login --with-access-token` (workspace access token), with an
//!   isolated `CODEX_HOME` and `cli_auth_credentials_store="file"`. Afterwards only
//!   `$CODEX_HOME/auth.json` is captured (whitelist) — never the whole HOME. `--from-file`
//!   imports an `auth.json` produced by `codex login` on a trusted machine (documented by
//!   OpenAI for headless machines).
//! * **claude**: `claude setup-token` (Anthropic's documented long-lived token for CI and
//!   scripts). The token is printed by Claude Code; the administrator pastes it into a hidden
//!   prompt. It is verified with `claude auth status --json` (no model request).
//!
//! API keys are rejected for both providers.

use crate::{AuthCmd, Method, Runtime, StoreArgs, StoreKind};
use acp_runner_core::credentials::{
    CredentialBundle, CredentialMetadata, Provider, validate_bundle, validate_claude_token,
};
use acp_runner_drivers::AuthState;
use acp_runner_engine::creds::{CredentialStore, FileCredentialStore, StoredProfile, check_profile_name};
use acp_runner_journal::Journal;
use acp_runner_k8s::secret_store::K8sSecretStore;
use anyhow::{Context, bail};
use clap::Args;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

#[derive(Args, Debug, Clone)]
pub struct EnrollArgs {
    /// `codex`, `claude` or `files` (generic named files, V9).
    pub provider: String,
    /// Profile name (DNS label), referenced from ACPRunnerClass.spec.credentials.profiles.
    pub profile: String,
    #[command(flatten)]
    pub store: StoreArgs,
    /// Where the provider CLI runs during enrollment.
    #[arg(long, value_enum, default_value = "local")]
    pub runtime: Runtime,
    /// Login method (codex: device|browser|access-token; claude: setup-token).
    #[arg(long, value_enum)]
    pub method: Option<Method>,
    /// Runner image (docker / kubectl runtimes); use the same pinned image the runner uses.
    #[arg(long, env = "ACP_RUNNER_IMAGE", default_value = "acp-runner/runner:dev")]
    pub image: String,
    /// Namespace for the temporary enrollment pod (kubectl runtime).
    #[arg(long, default_value = "acp-runner-system")]
    pub pod_namespace: String,
    #[arg(long, default_value = "codex")]
    pub codex_command: String,
    #[arg(long, default_value = "claude")]
    pub claude_command: String,
    /// codex: import an auth.json created by `codex login` on a trusted machine.
    /// files: the file to enroll (required; its name becomes the bundle key).
    #[arg(long)]
    pub from_file: Option<PathBuf>,
    /// files: keep only these top-level JSON keys (repeatable, e.g.
    /// `--select openai`). The stored file contains just the selection.
    #[arg(long = "select")]
    pub select: Vec<String>,
    /// claude: read the setup-token from stdin instead of running `claude setup-token`.
    #[arg(long)]
    pub token_stdin: bool,
    /// Concurrent leases allowed (claude and files; codex profiles are always exclusive).
    #[arg(long, default_value_t = 1)]
    pub max_concurrent_leases: i32,
    /// Replace an existing profile.
    #[arg(long)]
    pub force: bool,
    /// Skip the post-login status check.
    #[arg(long)]
    pub no_verify: bool,
    /// V2 usage grant: namespaces allowed to lease this profile (repeatable).
    /// Empty means deny; grant explicitly after enrollment (or here).
    #[arg(long = "allow-namespace")]
    pub allow_namespaces: Vec<String>,
    /// V2 usage grant: runner classes allowed to lease this profile (repeatable).
    #[arg(long = "allow-class")]
    pub allow_classes: Vec<String>,
}

pub async fn open_store(s: &StoreArgs) -> anyhow::Result<Box<dyn CredentialStore>> {
    Ok(match s.store {
        StoreKind::K8s => {
            let client =
                kube::Client::try_default().await.context("kubernetes client (set KUBECONFIG or use --store file)")?;
            Box::new(K8sSecretStore { client, namespace: s.namespace.clone() })
        }
        StoreKind::File => Box::new(FileCredentialStore {
            root: s.credential_dir.clone().context("--credential-dir is required with --store file")?,
        }),
    })
}

pub async fn run(cmd: AuthCmd) -> anyhow::Result<()> {
    match cmd {
        AuthCmd::Enroll(a) => enroll(a).await,
        AuthCmd::List { store, output } => list(store, &output).await,
        AuthCmd::Inspect { profile, store, output } => inspect(&profile, store, &output).await,
        AuthCmd::Disable { profile, database_url } => set_status(&profile, &database_url, "disabled").await,
        AuthCmd::Enable { profile, database_url } => set_status(&profile, &database_url, "active").await,
        AuthCmd::Allow { profile, store, allow_namespaces, allow_classes } => {
            open_store(&store).await?.set_policy(&profile, allow_namespaces, allow_classes).await?;
            println!("updated usage policy for credential profile {profile:?}");
            Ok(())
        }
        AuthCmd::Delete { profile, store } => {
            open_store(&store).await?.delete(&profile).await?;
            if let Some(url) = &store.database_url {
                Journal::connect(url, 2).await?.delete_profile(&profile).await?;
            }
            println!("deleted credential profile {profile}");
            Ok(())
        }
    }
}

async fn set_status(profile: &str, url: &str, status: &str) -> anyhow::Result<()> {
    let j = Journal::connect(url, 2).await?;
    j.get_profile(profile).await?.with_context(|| format!("profile {profile} not in journal"))?;
    j.set_profile_status(profile, status, None).await?;
    println!("profile {profile}: {status}");
    Ok(())
}

// ---------------------------------------------------------------------------------------
// runtimes

/// Executes provider CLIs with an isolated HOME in one of the enrollment runtimes.
struct CliEnv {
    runtime: Runtime,
    /// Host directory used as HOME (local, docker) — removed afterwards.
    host_home: tempfile::TempDir,
    image: String,
    pod: Option<(String, String)>, // (namespace, name)
    publish_callback_port: bool,
}

const CONTAINER_HOME: &str = "/enroll";

impl CliEnv {
    fn new(a: &EnrollArgs, publish_callback_port: bool) -> anyhow::Result<CliEnv> {
        let host_home = tempfile::Builder::new().prefix("acp-enroll-").tempdir()?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(host_home.path(), std::fs::Permissions::from_mode(0o700))?;
        let mut env =
            CliEnv { runtime: a.runtime, host_home, image: a.image.clone(), pod: None, publish_callback_port };
        if a.runtime == Runtime::Kubectl {
            env.start_pod(&a.pod_namespace)?;
        }
        Ok(env)
    }

    fn home(&self) -> String {
        match self.runtime {
            Runtime::Local => self.host_home.path().to_string_lossy().to_string(),
            _ => CONTAINER_HOME.to_string(),
        }
    }

    fn start_pod(&mut self, ns: &str) -> anyhow::Result<()> {
        let name = format!("acp-enroll-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        let manifest = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": {"app.kubernetes.io/name": "acp-runner-enroll"}},
            "spec": {
                "restartPolicy": "Never",
                "automountServiceAccountToken": false,
                "enableServiceLinks": false,
                "activeDeadlineSeconds": 3600,
                "securityContext": {"runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": 10001, "fsGroup": 10001,
                                     "seccompProfile": {"type": "RuntimeDefault"}},
                "containers": [{
                    "name": "enroll", "image": self.image, "command": ["sleep", "3600"],
                    "env": [{"name": "HOME", "value": CONTAINER_HOME}],
                    "securityContext": {"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
                                         "capabilities": {"drop": ["ALL"]}},
                    "volumeMounts": [{"name": "home", "mountPath": CONTAINER_HOME}, {"name": "tmp", "mountPath": "/tmp"}]
                }],
                "volumes": [{"name": "home", "emptyDir": {"medium": "Memory"}}, {"name": "tmp", "emptyDir": {"medium": "Memory"}}]
            }
        });
        let mut child = Command::new("kubectl").args(["apply", "-f", "-"]).stdin(Stdio::piped()).spawn()?;
        child.stdin.take().expect("stdin").write_all(manifest.to_string().as_bytes())?;
        if !child.wait()?.success() {
            bail!("creating enrollment pod failed");
        }
        self.pod = Some((ns.to_string(), name.clone()));
        let st = Command::new("kubectl")
            .args(["-n", ns, "wait", "--for=condition=Ready", &format!("pod/{name}"), "--timeout=180s"])
            .status()?;
        if !st.success() {
            bail!("enrollment pod did not become ready");
        }
        Ok(())
    }

    /// Build the command. `secret_env` (name) is passed from our environment (docker) or via
    /// stdin (kubectl) so the value never appears in process arguments.
    fn command(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, String)],
        tty: bool,
        secret_env: Option<&str>,
    ) -> Command {
        match self.runtime {
            Runtime::Local => {
                let mut c = Command::new(program);
                c.args(args).env_clear();
                for k in [
                    "PATH",
                    "TERM",
                    "LANG",
                    "HTTPS_PROXY",
                    "HTTP_PROXY",
                    "NO_PROXY",
                    "https_proxy",
                    "http_proxy",
                    "no_proxy",
                    "SSL_CERT_FILE",
                ] {
                    if let Ok(v) = std::env::var(k) {
                        c.env(k, v);
                    }
                }
                c.env("HOME", self.home());
                for (k, v) in env {
                    c.env(k, v);
                }
                c
            }
            Runtime::Docker => {
                let mut c = Command::new("docker");
                c.args(["run", "--rm", "-i"]);
                if tty {
                    c.arg("-t");
                }
                let uid = nix_ids();
                c.args([
                    "--read-only",
                    "--tmpfs",
                    "/tmp",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--user",
                    &uid,
                ]);
                c.args(["-v", &format!("{}:{CONTAINER_HOME}", self.host_home.path().display())]);
                c.args(["-e", &format!("HOME={CONTAINER_HOME}")]);
                if self.publish_callback_port {
                    c.args(["-p", "127.0.0.1:1455:1455"]);
                }
                for (k, v) in env {
                    c.args(["-e", &format!("{k}={v}")]);
                }
                if let Some(name) = secret_env {
                    c.args(["-e", name]); // value taken from the docker CLI's environment
                }
                c.arg(&self.image).arg(program).args(args);
                c
            }
            Runtime::Kubectl => {
                let (ns, pod) = self.pod.clone().expect("pod started");
                let mut c = Command::new("kubectl");
                c.args(["-n", &ns, "exec", "-i"]);
                if tty {
                    c.arg("-t");
                }
                c.args([pod.as_str(), "--"]);
                let mut script = String::new();
                if let Some(name) = secret_env {
                    script.push_str(&format!(
                        "IFS= read -r ACP_SECRET; export {name}=\"$ACP_SECRET\"; unset ACP_SECRET; "
                    ));
                }
                let mut exports = String::new();
                for (k, v) in env {
                    exports.push_str(&format!("export {k}='{}'; ", v.replace('\'', "'\\''")));
                }
                let quoted: Vec<String> = std::iter::once(program)
                    .chain(args.iter().copied())
                    .map(|s| format!("'{}'", s.replace('\'', "'\\''")))
                    .collect();
                c.args(["sh", "-c", &format!("{script}{exports}exec {}", quoted.join(" "))]);
                c
            }
        }
    }

    fn interactive(&self, program: &str, args: &[&str], env: &[(&str, String)]) -> anyhow::Result<bool> {
        let st = self
            .command(program, args, env, true, None)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .with_context(|| format!("running {program}"))?;
        Ok(st.success())
    }

    /// Run and capture output. `secret_env` is exposed to the program as an environment
    /// variable without ever appearing in process arguments; `stdin_data` is written to the
    /// program's stdin (e.g. `codex login --with-access-token`).
    fn capture(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, String)],
        secret_env: Option<(&str, &str)>,
        stdin_data: Option<&str>,
    ) -> anyhow::Result<(String, String, Option<i32>)> {
        let mut cmd = self.command(program, args, env, false, secret_env.map(|(n, _)| n));
        if let Some((name, value)) = secret_env
            && self.runtime != Runtime::Kubectl
        {
            // local: env of the CLI process only; docker: env of the docker client,
            // forwarded by name (`-e NAME`)
            cmd.env(name, value);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        {
            let mut stdin = child.stdin.take().expect("stdin");
            if let Some((_, value)) = secret_env
                && self.runtime == Runtime::Kubectl
            {
                writeln!(stdin, "{value}")?; // consumed by the `read` in the exec script
            }
            if let Some(d) = stdin_data {
                writeln!(stdin, "{d}")?;
            }
        }
        let out = child.wait_with_output()?;
        Ok((
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
            out.status.code(),
        ))
    }

    /// Read a file relative to HOME from the runtime (never printed).
    fn read_file(&self, rel: &str) -> anyhow::Result<Vec<u8>> {
        match self.runtime {
            Runtime::Local | Runtime::Docker => std::fs::read(self.host_home.path().join(rel))
                .with_context(|| format!("reading {rel} from the enrollment HOME")),
            Runtime::Kubectl => {
                let (ns, pod) = self.pod.clone().expect("pod");
                let out = Command::new("kubectl")
                    .args(["-n", &ns, "exec", &pod, "--", "cat", &format!("{CONTAINER_HOME}/{rel}")])
                    .output()?;
                if !out.status.success() {
                    bail!("reading {rel} from the enrollment pod failed");
                }
                Ok(out.stdout)
            }
        }
    }
}

impl Drop for CliEnv {
    fn drop(&mut self) {
        if let Some((ns, pod)) = &self.pod {
            let _ = Command::new("kubectl").args(["-n", ns, "delete", "pod", pod, "--wait=false"]).status();
        }
        // host_home (TempDir) is removed on drop; overwrite auth material first
        let auth = self.host_home.path().join(".codex/auth.json");
        if let Ok(m) = std::fs::metadata(&auth) {
            let _ = std::fs::write(&auth, vec![0u8; m.len() as usize]);
        }
    }
}

fn nix_ids() -> String {
    // SAFETY-free: read our uid/gid from /proc
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |n: &str| {
        status
            .lines()
            .find(|l| l.starts_with(n))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("10001")
            .to_string()
    };
    format!("{}:{}", field("Uid:"), field("Gid:"))
}

// ---------------------------------------------------------------------------------------

async fn enroll(a: EnrollArgs) -> anyhow::Result<()> {
    let provider: Provider = a.provider.parse()?;
    check_profile_name(&a.profile)?;
    let store = open_store(&a.store).await?;
    if !a.force && store.load(&a.profile).await.is_ok() {
        bail!("profile {} already exists (use --force to replace it after re-login)", a.profile);
    }
    let bundle = match provider {
        Provider::Codex => enroll_codex(&a)?,
        Provider::Claude => enroll_claude(&a)?,
        Provider::Files => enroll_files(&a)?,
    };
    let metadata = validate_bundle(provider, &bundle).context("validating the captured login state")?;
    let max = if provider.spec().exclusive_lease { 1 } else { a.max_concurrent_leases.max(1) };
    let sp = StoredProfile {
        name: a.profile.clone(),
        provider,
        max_concurrent_leases: max,
        metadata: metadata.clone(),
        allowed_namespaces: a.allow_namespaces.clone(),
        allowed_classes: a.allow_classes.clone(),
        store_ref: String::new(),
    };
    store.save(&sp, &bundle).await?;
    println!("enrolled credential profile {:?}", a.profile);
    if a.allow_namespaces.is_empty() || a.allow_classes.is_empty() {
        println!("NOTE: no usage grant given (--allow-namespace/--allow-class): the profile denies all leases until `auth allow` grants it.");
    }
    print_metadata(&a.profile, provider, max, &metadata, "yaml")?;
    println!(
        "\nReference it from an ACPRunnerClass:\n  credentials:\n    provider: {}\n    profiles: [{}]",
        provider.as_str(),
        a.profile
    );
    Ok(())
}

fn enroll_codex(a: &EnrollArgs) -> anyhow::Result<CredentialBundle> {
    let mut bundle = CredentialBundle::new();
    if let Some(f) = &a.from_file {
        bundle.insert("auth.json".into(), std::fs::read(f).with_context(|| format!("reading {}", f.display()))?);
        return Ok(bundle);
    }
    let method = a.method.unwrap_or(Method::Device);
    let env = CliEnv::new(a, method == Method::Browser)?;
    let codex_home = format!("{}/.codex", env.home());
    if matches!(a.runtime, Runtime::Local | Runtime::Docker) {
        std::fs::create_dir_all(env.host_home.path().join(".codex"))?;
    } else {
        env.capture("mkdir", &["-p", &codex_home], &[], None, None)?;
    }
    let vars = [("CODEX_HOME", codex_home.clone())];
    let store_opt = "cli_auth_credentials_store=\"file\"";
    match method {
        Method::Device => {
            eprintln!(
                "Starting `codex login --device-auth`. Open the printed URL, sign in with the ChatGPT account for \
                 profile {:?} and enter the code. (Device code login must be enabled in ChatGPT security settings.)",
                a.profile
            );
            if !env.interactive(&a.codex_command, &["login", "-c", store_opt, "--device-auth"], &vars)? {
                bail!("codex login --device-auth failed");
            }
        }
        Method::Browser => {
            eprintln!(
                "Starting `codex login` (browser flow, callback on localhost:1455; forward the port when remote)."
            );
            if !env.interactive(&a.codex_command, &["login", "-c", store_opt], &vars)? {
                bail!("codex login failed");
            }
        }
        Method::AccessToken => {
            let token = rpassword::prompt_password("Workspace access token (input hidden): ")?;
            let (_, err, code) = env.capture(
                &a.codex_command,
                &["login", "-c", store_opt, "--with-access-token"],
                &vars,
                None,
                Some(token.trim()),
            )?;
            if code != Some(0) {
                bail!("codex login --with-access-token failed: {}", err.lines().last().unwrap_or(""));
            }
        }
        Method::SetupToken => bail!("--method setup-token is for claude"),
    }
    if !a.no_verify {
        let (out, err, code) = env.capture(&a.codex_command, &["login", "status"], &vars, None, None)?;
        match acp_runner_drivers::codex::classify_login_status(&format!("{out}\n{err}"), code) {
            AuthState::Ready { method } => eprintln!("codex reports: logged in ({method})"),
            AuthState::PolicyViolation { detail } => bail!("refusing to enroll: {detail}"),
            other => bail!("codex is not logged in: {other:?}"),
        }
    }
    // Whitelist: only auth.json leaves the enrollment environment.
    bundle.insert("auth.json".into(), env.read_file(".codex/auth.json")?);
    Ok(bundle)
}

/// Enroll a generic named file (V9 `files` provider): no provider CLI is
/// involved, so there is nothing to verify against — the bytes are stored as
/// given (optionally reduced to `--select` top-level JSON keys). There is no
/// refresh and no write-back for these profiles.
fn enroll_files(a: &EnrollArgs) -> anyhow::Result<CredentialBundle> {
    use anyhow::Context as _;
    let f = a.from_file.as_ref().with_context(|| "files enrollment needs --from-file <path> (key = file name)")?;
    let key = f
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .with_context(|| format!("cannot use {} as a bundle key", f.display()))?
        .to_string();
    let bytes = std::fs::read(f).with_context(|| format!("reading {}", f.display()))?;
    let stored = if a.select.is_empty() {
        bytes
    } else {
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).with_context(|| format!("{} is not JSON, cannot --select", f.display()))?;
        let obj = v.as_object().with_context(|| format!("{} is not a JSON object, cannot --select", f.display()))?;
        let mut kept = serde_json::Map::new();
        for want in &a.select {
            let val = obj
                .get(want)
                .with_context(|| format!("key {want:?} not present in {}", f.display()))?
                .clone();
            kept.insert(want.clone(), val);
        }
        serde_json::to_vec(&serde_json::Value::Object(kept)).expect("selected JSON serializes")
    };
    let mut bundle = CredentialBundle::new();
    bundle.insert(key, stored);
    Ok(bundle)
}

fn enroll_claude(a: &EnrollArgs) -> anyhow::Result<CredentialBundle> {
    let env = CliEnv::new(a, false)?;
    let home = env.home();
    let vars = [
        ("CLAUDE_CONFIG_DIR", format!("{home}/.claude")),
        ("DISABLE_AUTOUPDATER", "1".to_string()),
        ("DISABLE_UPDATES", "1".to_string()),
    ];
    let token = if a.token_stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s.trim().to_string()
    } else {
        eprintln!(
            "Starting `claude setup-token`. Complete the browser authorization with the Claude account for profile {:?}.\n\
             Claude Code prints a one-year OAuth token and does not store it; you will paste it next.",
            a.profile
        );
        if !env.interactive(&a.claude_command, &["setup-token"], &vars)? {
            bail!("claude setup-token failed");
        }
        rpassword::prompt_password("Paste the token printed by `claude setup-token` (input hidden): ")?
            .trim()
            .to_string()
    };
    validate_claude_token(token.as_bytes()).context("token rejected")?;
    if !a.no_verify {
        let (out, _err, _code) = env.capture(
            &a.claude_command,
            &["auth", "status", "--json"],
            &vars,
            Some(("CLAUDE_CODE_OAUTH_TOKEN", &token)),
            None,
        )?;
        match acp_runner_drivers::claude::classify_auth_status(&out) {
            AuthState::Ready { method } => eprintln!("claude reports: logged in ({method})"),
            AuthState::PolicyViolation { detail } => bail!("refusing to enroll: {detail}"),
            other => bail!("claude does not accept the token: {other:?}"),
        }
    }
    let mut bundle = CredentialBundle::new();
    bundle.insert("oauth-token".into(), token.into_bytes());
    Ok(bundle)
}

// ---------------------------------------------------------------------------------------

fn print_metadata(
    name: &str,
    provider: Provider,
    max: i32,
    md: &CredentialMetadata,
    output: &str,
) -> anyhow::Result<()> {
    let v = serde_json::json!({
        "profile": name,
        "provider": provider.as_str(),
        "maxConcurrentLeases": max,
        "exclusive": provider.spec().exclusive_lease,
        "metadata": md,
    });
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!("{}", serde_yaml::to_string(&v)?);
    }
    Ok(())
}

async fn list(s: StoreArgs, output: &str) -> anyhow::Result<()> {
    let store = open_store(&s).await?;
    let profiles = store.list().await?;
    let journal = match &s.database_url {
        Some(u) => Some(Journal::connect(u, 2).await?),
        None => None,
    };
    let leases = match &journal {
        Some(j) => j.active_leases().await?,
        None => vec![],
    };
    let mut rows = vec![];
    for p in &profiles {
        let status = match &journal {
            Some(j) => j.get_profile(&p.name).await?.map(|r| r.status).unwrap_or_else(|| "unsynced".into()),
            None => "-".into(),
        };
        let active = leases.iter().filter(|l| l.profile_name == p.name).count();
        rows.push(serde_json::json!({
            "name": p.name, "provider": p.provider.as_str(), "authKind": p.metadata.auth_kind,
            "plan": p.metadata.plan, "fingerprint": p.metadata.material_fingerprint,
            "maxLeases": p.max_concurrent_leases, "activeLeases": active, "status": status,
        }));
    }
    if output == "json" {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    println!(
        "{:<20} {:<8} {:<22} {:<10} {:<18} {:<8} {:<10}",
        "NAME", "PROVIDER", "AUTH", "PLAN", "FINGERPRINT", "LEASES", "STATUS"
    );
    for r in rows {
        println!(
            "{:<20} {:<8} {:<22} {:<10} {:<18} {:<8} {:<10}",
            r["name"].as_str().unwrap_or(""),
            r["provider"].as_str().unwrap_or(""),
            r["authKind"].as_str().unwrap_or(""),
            r["plan"].as_str().unwrap_or("-"),
            r["fingerprint"].as_str().unwrap_or(""),
            format!("{}/{}", r["activeLeases"], r["maxLeases"]),
            r["status"].as_str().unwrap_or(""),
        );
    }
    Ok(())
}

async fn inspect(profile: &str, s: StoreArgs, output: &str) -> anyhow::Result<()> {
    let store = open_store(&s).await?;
    let (p, bundle) = store.load(profile).await?;
    // Recompute from the material (catches drift) — only derived, non-secret facts are printed.
    let md = validate_bundle(p.provider, &bundle).unwrap_or_else(|e| CredentialMetadata {
        provider: p.provider.as_str().into(),
        auth_kind: "INVALID".into(),
        notes: vec![e.to_string()],
        ..Default::default()
    });
    print_metadata(profile, p.provider, p.max_concurrent_leases, &md, output)?;
    let keys: Vec<&String> = bundle.keys().collect();
    println!("storedKeys: {keys:?}");
    if let Some(url) = &s.database_url {
        let j = Journal::connect(url, 2).await?;
        if let Some(r) = j.get_profile(profile).await? {
            println!(
                "journal:\n  status: {}\n  generation: {}\n  lastUsedAt: {:?}\n  lastError: {:?}",
                r.status, r.generation, r.last_used_at, r.last_error
            );
        }
        for l in j.active_leases().await?.into_iter().filter(|l| l.profile_name == profile) {
            println!("  lease: attempt={} holder={} expires={}", l.attempt_id, l.holder, l.expires_at);
        }
    }
    Ok(())
}
