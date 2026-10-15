//! Official existing ChatGPT CLI access. Public diagnostics only; never copy tokens.
use serde_json::{Value, json};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const LIMIT: usize = 1_048_576;
const PROMPT: &str = "Reply exactly SYNCP-CONNECTION-OK. Do not use tools or inspect files.";
fn fail(code: &str) -> io::Error { io::Error::other(code.to_owned()) }

pub fn executable() -> io::Result<PathBuf> {
    if let Some(path) = crate::discovery::on_path("codex") { return Ok(path); }
    // The desktop bundles a native CLI. This is an optional Linux discovery location,
    // not a runtime dependency or a default assumed on other machines.
    #[cfg(target_os = "linux")]
    {
        let path = PathBuf::from("/usr/lib/chatgpt/resources/codex");
        if path.is_file() { return path.canonicalize(); }
    }
    Err(fail("OFFICIAL_CODEX_CLI_NOT_DISCOVERED"))
}

fn command() -> io::Result<Command> {
    let mut command = Command::new(executable()?);
    command.env_clear();
    for key in ["HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "LANG", "CODEX_HOME"] {
        if let Some(value) = std::env::var_os(key) { command.env(key, value); }
    }
    Ok(command)
}

struct OwnedCli(Child);
impl Drop for OwnedCli {
    fn drop(&mut self) {
        // Only this freshly spawned metadata/diagnostic process is owned. The outer
        // onboarding worker provides process-group cancellation and crash cleanup.
        if self.0.try_wait().ok().flatten().is_none() { let _ = self.0.kill(); }
        let _ = self.0.wait();
    }
}

fn rpc(child: &mut Child, reader: &mut BufReader<std::process::ChildStdout>, id: u64, method: &str, params: Value, remaining: &mut usize) -> io::Result<Value> {
    let stdin = child.stdin.as_mut().ok_or_else(|| fail("CODEX_STDIN_MISSING"))?;
    serde_json::to_writer(&mut *stdin, &json!({"id":id,"method":method,"params":params}))?;
    stdin.write_all(b"\n")?; stdin.flush()?;
    loop {
        let mut line = Vec::new();
        reader.by_ref().take((*remaining + 1) as u64).read_until(b'\n', &mut line)?;
        if line.is_empty() { return Err(fail("CODEX_METADATA_PROCESS_ENDED")); }
        if line.len() > *remaining { return Err(fail("CODEX_OUTPUT_TOO_LARGE")); }
        *remaining -= line.len();
        let value: Value = serde_json::from_slice(&line).map_err(|_| fail("INVALID_CODEX_PROTOCOL"))?;
        if value.get("id").is_some() {
            if value["id"] != id || value.get("error").is_some() { return Err(fail("CODEX_METADATA_REQUEST_FAILED")); }
            return value.get("result").cloned().ok_or_else(|| fail("CODEX_RPC_RESULT_MISSING"));
        }
    }
}

pub fn catalog(workspace: &Path) -> io::Result<Value> {
    let mut command = command()?;
    // No thread or turn is started. Config overrides prevent alternate endpoints;
    // inference below uses exec's official --ignore-user-config isolation instead.
    command.args(["app-server", "--listen", "stdio://", "-c", "model_provider=\"openai\"", "-c", "model_providers={}", "-c", "chatgpt_base_url=\"https://chatgpt.com/backend-api/\"", "-c", "mcp_servers={}", "-c", "hooks={}"]);
    let mut child = OwnedCli(command.current_dir(workspace).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| fail("OFFICIAL_CODEX_CLI_LAUNCH_FAILED"))?);
    let mut reader = BufReader::new(child.0.stdout.take().ok_or_else(|| fail("CODEX_STDOUT_MISSING"))?);
    let mut remaining = LIMIT;
    rpc(&mut child.0, &mut reader, 1, "initialize", json!({"clientInfo":{"name":"synforge_syncp","title":"SynCP","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":false}}), &mut remaining)?;
    let stdin = child.0.stdin.as_mut().unwrap();
    stdin.write_all(b"{\"method\":\"initialized\",\"params\":{}}\n")?; stdin.flush()?;
    let account = rpc(&mut child.0, &mut reader, 2, "account/read", json!({"refreshToken":false}), &mut remaining)?;
    // Discard email/account/plan fields; neither credentials nor identity are returned.
    if account["account"]["type"] != "chatgpt" { return Err(fail("EXISTING_CHATGPT_CLI_LOGIN_REQUIRED_NO_API_FALLBACK")); }
    let mut ids = Vec::new(); let mut cursor: Option<String> = None;
    for page in 0..8 {
        let result = rpc(&mut child.0, &mut reader, 3 + page, "model/list", json!({"limit":100,"includeHidden":false,"cursor":cursor}), &mut remaining)?;
        for item in result["data"].as_array().ok_or_else(|| fail("CODEX_MODEL_CATALOG_MISSING"))? {
            if let Some(id) = item["model"].as_str().filter(|id| crate::onboarding::model_id(id)) { ids.push(id.to_owned()); }
        }
        cursor = result["nextCursor"].as_str().map(str::to_owned);
        if cursor.is_none() { break; }
    }
    if cursor.is_some() { return Err(fail("CODEX_MODEL_CATALOG_PAGE_LIMIT")); }
    ids.sort(); ids.dedup();
    if ids.is_empty() { return Err(fail("NO_CHATGPT_CATALOG_MODELS")); }
    Ok(json!({"model_ids":ids,"inference_performed":false,"availability":"official CLI catalog; each model still needs an inference test","cloud_guard":guard()}))
}

pub fn guard() -> Value {
    json!({"authentication":"existing official Codex ChatGPT login; tokens are not read or copied by SynCP","billing":"ChatGPT plan quota","paid_overage_authorized":false,"api_access_assumed":false,"credential_changes":false,"api_key_environment_forwarded":false})
}

pub fn smoke(workspace: &Path, model: &str) -> io::Result<Value> {
    // Require ChatGPT mode immediately before exec; exec also enforces it, so an
    // account change cannot silently turn this approved subscription test into API use.
    let catalog = catalog(workspace)?;
    if !catalog["model_ids"].as_array().unwrap().iter().any(|id| id == model) { return Err(fail("EXPLICIT_CHATGPT_MODEL_NOT_IN_CATALOG")); }
    let mut command = command()?;
    command.args(["exec", "--ignore-user-config", "--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only", "--json", "--color", "never", "--model", model,
        "-c", "forced_login_method=\"chatgpt\"", "-c", "web_search=\"disabled\""]);
    for feature in ["shell_tool", "unified_exec", "apps", "plugins", "hooks", "multi_agent", "computer_use", "browser_use", "image_generation", "view_image", "goals", "skill_search", "code_mode_host", "workspace_dependencies", "sleep_tool"] {
        command.args(["--disable", feature]);
    }
    command.args(["--cd"]).arg(workspace).arg(PROMPT);
    let mut child = OwnedCli(command.current_dir(workspace).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| fail("OFFICIAL_CODEX_CLI_LAUNCH_FAILED"))?);
    let mut bytes = Vec::new();
    child.0.stdout.take().ok_or_else(|| fail("CODEX_STDOUT_MISSING"))?.take((LIMIT + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT { return Err(fail("CODEX_OUTPUT_TOO_LARGE")); }
    let exit = child.0.wait()?;
    interpret(&bytes, model, exit.success())
}

fn interpret(bytes: &[u8], model: &str, successful_exit: bool) -> io::Result<Value> {
    let mut completed = false; let mut response = String::new(); let mut usage = Value::Null; let mut tools = 0; let mut turn_started = false; let mut pre_turn_diagnostics = 0;
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let value: Value = serde_json::from_slice(line).map_err(|_| fail("INVALID_CODEX_PROTOCOL"))?;
        if matches!(value["type"].as_str(), Some("error" | "turn.failed")) { return Err(fail("CHATGPT_AUTH_QUOTA_OR_EXECUTION_FAILED_NO_FALLBACK")); }
        if value["type"] == "turn.started" { turn_started = true; }
        if value["type"] == "item.completed" {
            match value["item"]["type"].as_str() {
                Some("agent_message") => response = value["item"]["text"].as_str().unwrap_or("").to_owned(),
                Some("reasoning") => {},
                Some("error") if !turn_started => pre_turn_diagnostics += 1,
                Some("error") => return Err(fail("CHATGPT_TURN_DIAGNOSTIC_ERROR")),
                _ => tools += 1,
            }
        }
        if value["type"] == "turn.completed" { completed = true; usage = value["usage"].clone(); }
    }
    let ok = successful_exit && completed && response.trim() == "SYNCP-CONNECTION-OK" && tools == 0;
    Ok(json!({"ok":ok,"selected_model":model,"actual_model":null,"model_verification":"explicit --model request; no configured fallback; CLI JSONL does not independently echo server model identity",
        "terminal_status":if completed{"completed"}else{"missing"},"response":if response.trim()=="SYNCP-CONNECTION-OK"{Some("SYNCP-CONNECTION-OK")}else{None},"tool_events":tools,"pre_turn_diagnostic_count":pre_turn_diagnostics,"diagnostic_content":"not retained; public smoke success does not qualify unrelated CLI capabilities","usage":usage,"cloud_guard":guard(),
        "task_timeout_seconds":0,"fallback":false,"private_project_context":false,"instructions":"literal public connection test; no CM scaffolding"}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn protocol(extra: Value, before: bool) -> Vec<u8> {
        let mut rows=vec![json!({"type":"thread.started"})];
        if before {rows.push(extra.clone());}
        rows.push(json!({"type":"turn.started"}));
        if !before {rows.push(extra);}
        rows.push(json!({"type":"item.completed","item":{"type":"agent_message","text":"SYNCP-CONNECTION-OK"}}));
        rows.push(json!({"type":"turn.completed","usage":{}}));
        rows.iter().map(|v|serde_json::to_string(v).unwrap()).collect::<Vec<_>>().join("\n").into_bytes()
    }
    #[test]
    fn pre_turn_cli_diagnostic_is_observable_and_is_not_a_tool() {
        let result=interpret(&protocol(json!({"type":"item.completed","item":{"type":"error","message":"explicit synthetic pre-turn diagnostic"}}),true),"fixture-model",true).unwrap();
        assert_eq!(result["ok"],true);assert_eq!(result["pre_turn_diagnostic_count"],1);assert_eq!(result["tool_events"],0);assert_eq!(result["actual_model"],Value::Null);
    }
    #[test]
    fn turn_error_and_nonzero_exit_never_pass() {
        let bytes=protocol(json!({"type":"item.completed","item":{"type":"error"}}),false);
        assert!(interpret(&bytes,"fixture-model",true).is_err());
        let bytes=protocol(json!({"type":"item.completed","item":{"type":"reasoning"}}),false);
        assert_eq!(interpret(&bytes,"fixture-model",false).unwrap()["ok"],false);
    }
    #[test]
    fn completed_tool_event_never_passes_even_with_marker() {
        let result=interpret(&protocol(json!({"type":"item.completed","item":{"type":"command_execution"}}),false),"fixture-model",true).unwrap();
        assert_eq!(result["ok"],false);assert_eq!(result["tool_events"],1);
    }
}
