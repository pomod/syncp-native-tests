//! Independent onboarding. Only literal public connection tests are executable in P3.
//! No CM imports, arbitrary prompts, login forms, paid fallback or foreign-process control.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const PUBLIC_PROMPT: &str = "Reply exactly SYNCP-CONNECTION-OK. Do not use tools or inspect files.";
const RESULT_LIMIT: usize = 1_048_576;
const PROFILES: &str = include_str!("../catalog/runtime-profiles-v1.json");
fn fail(code: &str) -> io::Error { io::Error::other(code.to_owned()) }

#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub api_version: u32,
    pub network_mode: String,
    pub local_endpoint: String,
    pub local_model: String,
    pub cloud_connection: String,
    pub cloud_model: String,
}
impl Default for Configuration {
    fn default() -> Self { Self {api_version:1,network_mode:"OFFLINE".into(),local_endpoint:"http://127.0.0.1:8092".into(),local_model:String::new(),cloud_connection:"none".into(),cloud_model:String::new()} }
}
fn local_url(endpoint: &str) -> io::Result<()> {
    let uri: ureq::http::Uri=endpoint.parse().map_err(|_|fail("INVALID_LOCAL_ENDPOINT"))?;
    if uri.scheme_str()!=Some("http") || uri.host()!=Some("127.0.0.1") || uri.port_u16().is_none()
        || !matches!(uri.path(),"/"|"") || endpoint.contains(['@','?','#']) || endpoint.ends_with('/') {
        return Err(fail("LITERAL_LOOPBACK_HTTP_ENDPOINT_WITH_PORT_REQUIRED"));
    }
    Ok(())
}
pub(crate) fn model_id(value:&str)->bool { !value.is_empty() && value.len()<=128 && value.bytes().all(|b|b.is_ascii_alphanumeric() || matches!(b,b'-'|b'_'|b'.')) }
fn configuration_valid(c:&Configuration)->io::Result<()> {
    if c.api_version!=1 || !matches!(c.network_mode.as_str(),"OFFLINE"|"ONLINE") || !matches!(c.cloud_connection.as_str(),"none"|"official-antigravity-subscription"|"official-chatgpt-subscription") {return Err(fail("UNSUPPORTED_PROVIDER_CONFIGURATION"));}
    local_url(&c.local_endpoint)?;
    if (!c.local_model.is_empty()&&!model_id(&c.local_model)) || (!c.cloud_model.is_empty()&&!model_id(&c.cloud_model)) {return Err(fail("INVALID_EXPLICIT_MODEL_ID"));}
    if c.cloud_connection=="none"&&!c.cloud_model.is_empty(){return Err(fail("CLOUD_MODEL_REQUIRES_CONNECTION"));}
    Ok(())
}
fn bounded_read(path:&Path)->io::Result<Vec<u8>> {
    if fs::symlink_metadata(path)?.file_type().is_symlink(){return Err(fail("SYMLINK_NOT_ALLOWED"));}
    let mut data=Vec::new();fs::File::open(path)?.take((RESULT_LIMIT+1) as u64).read_to_end(&mut data)?;
    if data.len()>RESULT_LIMIT{return Err(fail("FILE_TOO_LARGE"));}Ok(data)
}
fn agent(probe:bool)->ureq::Agent {
    ureq::Agent::config_builder().timeout_global(if probe{Some(Duration::from_secs(5))}else{None})
        .timeout_per_call(None).timeout_recv_body(None).timeout_send_body(None)
        .timeout_connect(Some(Duration::from_secs(5))).timeout_resolve(Some(Duration::from_secs(5)))
        .timeout_recv_response(if probe{Some(Duration::from_secs(5))}else{None})
        .max_redirects(0).proxy(None).build().new_agent()
}
fn get_json(endpoint:&str,path:&str)->io::Result<Value>{
    local_url(endpoint)?;
    let mut response=agent(true).get(format!("{endpoint}{path}")).call().map_err(|_|fail("LOCAL_ENDPOINT_UNAVAILABLE"))?;
    let mut bytes=Vec::new();response.body_mut().as_reader().take((RESULT_LIMIT+1) as u64).read_to_end(&mut bytes)?;
    if bytes.len()>RESULT_LIMIT{return Err(fail("LOCAL_OBSERVATION_TOO_LARGE"));}
    serde_json::from_slice(&bytes).map_err(|_|fail("INVALID_LOCAL_PROTOCOL"))
}
fn cloud_executable()->io::Result<PathBuf>{
    let name=if cfg!(windows){"agy.exe"}else{"agy"};
    let mut paths=Vec::new();
    if let Some(home)=dirs::home_dir(){paths.push(home.join(".local/bin").join(name));}
    if cfg!(windows){if let Some(path)=std::env::var_os("LOCALAPPDATA"){paths.push(PathBuf::from(path).join("agy/bin").join(name));}}
    if let Some(path)=std::env::var_os("PATH"){for directory in std::env::split_paths(&path){if directory.is_absolute(){paths.push(directory.join(name));}}}
    for path in paths {if path.is_file(){return path.canonicalize();}}
    Err(fail("OFFICIAL_CLOUD_CLI_NOT_DISCOVERED"))
}
fn cloud_guard()->io::Result<Value>{
    // No credential file is read. The provider's settings must still be baseline subscription.
    // An absent setting uses the documented false default; it is never silently changed.
    let home=dirs::home_dir().ok_or_else(||fail("HOME_UNAVAILABLE"))?;
    let settings=home.join(".gemini/antigravity-cli/settings.json");
    let value:Value=if settings.exists(){serde_json::from_slice(&bounded_read(&settings)?).map_err(|_|fail("OFFICIAL_CLI_SETTINGS_INVALID"))?}else{json!({})};
    if !value.is_object(){return Err(fail("OFFICIAL_CLI_SETTINGS_INVALID"));}
    if value.get("useG1Credits").is_some_and(|v|v!=&json!(false)) || value.get("modelProvider").is_some_and(|v|v!=&json!("antigravity")) {
        return Err(fail("PAID_OR_ALTERNATE_PROVIDER_CONFIGURATION_REQUIRES_SEPARATE_APPROVAL"));
    }
    if value.get("allowNonWorkspaceAccess").is_some_and(|v|v!=&json!(false)) {return Err(fail("NON_WORKSPACE_ACCESS_CONFIGURATION_REQUIRES_REVIEW"));}
    Ok(json!({"authentication":"existing official CLI account; not read or migrated","billing":"subscription quota","paid_overage_authorized":false,
        "useG1Credits":false,"setting_source":if value.get("useG1Credits").is_some(){"observed false"}else{"official documented false default"},
        "api_access_assumed":false,"credential_changes":false}))
}
fn cloud_command()->io::Result<Command>{
    cloud_guard()?;
    let mut command=Command::new(cloud_executable()?);
    // Cached official login is resolved by the provider. Never forward API-mode secrets or
    // project-specific environment/instructions from a running application.
    command.env_clear();
    for key in ["HOME","USERPROFILE","LOCALAPPDATA","APPDATA","PATH","SYSTEMROOT","WINDIR","TMP","TEMP","TMPDIR","XDG_CONFIG_HOME","XDG_CACHE_HOME","LANG"] {
        if let Some(value)=std::env::var_os(key){command.env(key,value);}
    }
    Ok(command)
}

fn connection_guard(connection:&str)->io::Result<Value>{
    match connection {
        "none"|"official-antigravity-subscription"=>cloud_guard(),
        "official-chatgpt-subscription"=>Ok(crate::codex_cloud::guard()),
        _=>Err(fail("UNSUPPORTED_CLOUD_CONNECTION"))
    }
}
fn connection_executable(connection:&str)->io::Result<PathBuf>{
    if connection=="official-chatgpt-subscription" {crate::codex_cloud::executable()} else {cloud_executable()}
}
fn catalog_connection(connection:&str)->&str {
    if connection=="none" {"official-antigravity-subscription"} else {connection}
}

pub struct Onboarding {
    root:PathBuf, config:Configuration, generation:u64, model_directory:Option<PathBuf>,
    child:Option<Child>, output:Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    job:Value, cloud_models:Vec<String>, cloud_catalog_connection:String, cloud_cli_sha256:Option<String>, cancelling:bool,
}
impl Onboarding {
    pub fn new(root:&Path,model_directory:Option<PathBuf>)->io::Result<Self>{
        let mut generation=0;let mut config=Configuration::default();
        for entry in fs::read_dir(root)? {let path=entry?.path();let name=path.file_name().and_then(|p|p.to_str()).unwrap_or("");
            if let Some(number)=name.strip_prefix("onboarding-").and_then(|s|s.strip_suffix(".json")) {
                if number.len()!=20 || !number.bytes().all(|b|b.is_ascii_digit()){return Err(fail("INVALID_ONBOARDING_GENERATION"));}
                let next=number.parse::<u64>().map_err(|_|fail("INVALID_ONBOARDING_GENERATION"))?;
                if next>generation {config=serde_json::from_slice(&bounded_read(&path)?).map_err(|_|fail("CORRUPT_ONBOARDING_CONFIGURATION"))?;configuration_valid(&config)?;generation=next;}
            }
        }
        if let Some(path)=&model_directory {if !path.is_absolute() || !path.is_dir(){return Err(fail("MODEL_DIRECTORY_MUST_EXIST_AND_BE_ABSOLUTE"));}}
        Ok(Self {root:root.to_owned(),config,generation,model_directory,child:None,output:None,job:json!({"status":"IDLE"}),cloud_models:Vec::new(),cloud_catalog_connection:String::new(),cloud_cli_sha256:None,cancelling:false})
    }
    pub fn configuration_plan(&self,c:Configuration)->io::Result<Value>{
        configuration_valid(&c)?;
        if c.cloud_connection!="none" && c.network_mode=="ONLINE" {connection_guard(&c.cloud_connection)?;if !c.cloud_model.is_empty() && (self.cloud_catalog_connection!=c.cloud_connection || !self.cloud_models.contains(&c.cloud_model)){return Err(fail("DISCOVER_AVAILABLE_CLOUD_MODELS_BEFORE_SELECTING"));}}
        let mut plan=json!({"api_version":1,"ok":true,"operation":"save-independent-provider-configuration","configuration":c,"previous_generation":self.generation,
            "destination":self.root,"credentials":"existing official CLI login referenced; no secret copied","production_changes":false,
            "local_runtime_ownership":"external endpoint; no model switching or process takeover","auto_candidates":[],"silent_fallback":false,
            "task_timeout_seconds":0,"cloud_billing":if c.cloud_connection=="none"{json!(null)}else if c.network_mode=="OFFLINE"{json!({"connection_blocked":true,"paid_overage_authorized":false,"settings_not_probed":true})}else{connection_guard(&c.cloud_connection)?}});
        if c.cloud_connection!="none" && c.network_mode=="ONLINE" {let executable=connection_executable(&c.cloud_connection)?;plan["cli_identity"]=json!({"executable":executable,"sha256":crate::discovery::sha256(&executable)?});}
        let bytes=serde_json::to_vec(&plan)?;use sha2::{Digest,Sha256};plan["plan_id"]=json!(format!("{:x}",Sha256::digest(bytes)));Ok(plan)
    }
    pub fn approve(&mut self,c:Configuration,plan_id:&str,approved:bool)->io::Result<()> {
        if !approved {return Err(fail("EXPLICIT_APPROVAL_REQUIRED"));}
        if self.child.is_some(){return Err(fail("CONNECTION_TEST_ALREADY_RUNNING"));}
        let plan=self.configuration_plan(c.clone())?;
        if plan["plan_id"]!=plan_id{return Err(fail("CONFIGURATION_PLAN_CHANGED"));}
        let next=self.generation.checked_add(1).ok_or_else(||fail("GENERATION_OVERFLOW"))?;
        crate::state::write_new_private(&self.root.join(format!("onboarding-{next:020}.json")),&serde_json::to_vec(&c)?)?;
        if self.cloud_catalog_connection!=c.cloud_connection {self.cloud_models.clear();self.cloud_cli_sha256=None;self.cloud_catalog_connection.clear();}
        self.config=c;self.generation=next;Ok(())
    }
    pub fn status(&mut self)->io::Result<Value>{
        if let Some(child)=self.child.as_mut(){if let Some(exit)=child.try_wait()? {
            let observed=self.output.take().ok_or_else(||fail("OUTPUT_HANDLE_MISSING"))?.join();
            let output=match observed {Ok(Ok(bytes))=>Some(bytes),_=>None};
            self.child=None;
            self.job=if self.cancelling {json!({"status":"CANCELLED","termination_observed":true,"termination_scope":"owned request worker and inherited CLI group; external model server remains unmanaged","external_inference_termination":"not established"})}
                else if output.is_none(){json!({"status":"FAILED","error":"INVALID_OR_OVERSIZED_WORKER_OUTPUT"})}
                else if exit.success(){match serde_json::from_slice::<Value>(output.as_ref().unwrap()){Ok(value)=>json!({"status":if value["ok"]==true{"SUCCEEDED"}else{"FAILED"},"result":value}),Err(_)=>json!({"status":"FAILED","error":"INVALID_NATIVE_WORKER_RESULT"})}}
                else {json!({"status":"FAILED","error":"NATIVE_CONNECTION_WORKER_FAILED","exit_code":exit.code()})};
            if self.job["result"]["kind"]=="cloud-models" && self.job["result"]["ok"]==true {
                self.cloud_catalog_connection=self.job["result"]["connection"].as_str().unwrap_or("").to_owned();
                self.cloud_cli_sha256=self.job["result"]["cli_sha256"].as_str().map(str::to_owned);
                self.cloud_models=self.job["result"]["model_ids"].as_array().unwrap_or(&Vec::new()).iter().filter_map(|v|v.as_str().map(str::to_owned)).collect();
            }
        }}
        Ok(json!({"api_version":1,"ok":true,"configuration":self.config,"generation":self.generation,"job":self.job,
            "cloud_models":self.cloud_models,"cloud_catalog_connection":self.cloud_catalog_connection,"supported_connections":["none","local-openai-compatible","official-antigravity-subscription","official-chatgpt-subscription"],
            "unqualified_connections":["new-api-key-storage","other-official-cli-adapters"],"auto":"UNAVAILABLE; no approved candidate set",
            "model_switching":"UNAVAILABLE; existing runtime is externally owned","arbitrary_prompt_execution":"NOT_QUALIFIED",
            "task_timeout_seconds":0,"cloud_cli_launch_qualification":if cfg!(target_os="linux"){"Linux owned worker process group"}else{"UNQUALIFIED; execution disabled"}}))
    }
    pub fn start(&mut self,kind:&str,cloud_quota_approved:bool)->io::Result<()> {
        self.status()?;
        if !cfg!(target_os="linux"){return Err(fail("NATIVE_EXECUTION_PLATFORM_NOT_QUALIFIED"));}
        if self.child.is_some(){return Err(fail("CONNECTION_TEST_ALREADY_RUNNING"));}
        if !matches!(kind,"local-probe"|"local-smoke"|"cloud-models"|"cloud-smoke"){return Err(fail("UNSUPPORTED_CONNECTION_RECIPE"));}
        if kind.starts_with("cloud-") {
            if self.config.network_mode!="ONLINE" {return Err(fail("CLOUD_BLOCKED_IN_OFFLINE_MODE"));}
            connection_guard(&self.config.cloud_connection)?;
            if kind=="cloud-smoke" && (!cloud_quota_approved || self.config.cloud_connection=="none" || self.cloud_catalog_connection!=self.config.cloud_connection || !self.cloud_models.contains(&self.config.cloud_model)) {return Err(fail("SELECT_AVAILABLE_CLOUD_ROUTE_AND_APPROVE_SUBSCRIPTION_QUOTA"));}
        }
        if kind=="local-smoke"&&self.config.local_model.is_empty(){return Err(fail("SELECT_EXPLICIT_LOCAL_MODEL"));}
        let cli_sha256=if kind.starts_with("cloud-"){Some(crate::discovery::sha256(&connection_executable(&self.config.cloud_connection)?)?)}else{None};
        if kind=="cloud-smoke" && cli_sha256!=self.cloud_cli_sha256 {return Err(fail("CLOUD_CLI_CHANGED_REDISCOVER_MODELS"));}
        if kind=="cloud-models" {self.cloud_models.clear();self.cloud_catalog_connection.clear();self.cloud_cli_sha256=None;}
        let mut command=Command::new(std::env::current_exe()?);command.arg("--onboarding-worker");
        #[cfg(unix)] {use std::os::unix::process::CommandExt;command.process_group(0);}
        let mut child=command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
        let spec=WorkerSpec{kind:kind.to_owned(),configuration:self.config.clone(),workspace:self.root.clone(),cli_sha256};
        let input=child.stdin.as_mut().ok_or_else(||fail("WORKER_STDIN_MISSING"))?;
        let bytes=serde_json::to_vec(&spec)?;
        input.write_all(&bytes)?;input.write_all(b"\n")?;input.flush()?;
        let mut stdout=child.stdout.take().ok_or_else(||fail("WORKER_STDOUT_MISSING"))?;
        self.output=Some(std::thread::spawn(move||{let mut data=Vec::new();stdout.by_ref().take((RESULT_LIMIT+1) as u64).read_to_end(&mut data)?;
            if data.len()>RESULT_LIMIT {return Err(fail("WORKER_OUTPUT_TOO_LARGE"));}Ok(data)}));
        self.job=json!({"status":"RUNNING","kind":kind,"worker_pid":child.id(),"task_timeout_seconds":0,"prompt":if kind.ends_with("smoke"){Some(PUBLIC_PROMPT)}else{None},"private_project_context":false});
        self.cancelling=false;self.child=Some(child);Ok(())
    }
    pub fn cancel(&mut self)->io::Result<()> {
        if let Some(child)=self.child.as_mut(){self.cancelling=true;child.stdin.take();self.job["status"]=json!("CANCEL_REQUESTED");}Ok(())
    }
    pub fn shutdown(&mut self)->io::Result<()> {self.cancel()?;if let Some(child)=self.child.as_mut(){child.wait()?;}self.status()?;Ok(())}
    pub fn models(&self)->io::Result<Value>{
        let mut models=Vec::new();let mut scanned=0usize;
        if let Some(directory)=&self.model_directory {
            let mut directories=vec![(directory.clone(),0)];
            while let Some((directory,depth))=directories.pop(){for entry in fs::read_dir(directory)? {
                scanned+=1;if scanned>2048{return Err(fail("MODEL_DIRECTORY_SCAN_LIMIT"));}
                let entry=entry?;let path=entry.path();let metadata=fs::symlink_metadata(&path)?;
                if metadata.file_type().is_symlink(){continue;}
                if metadata.is_dir()&&depth<2{directories.push((path,depth+1));continue;}
                if !metadata.is_file()||path.extension().and_then(|p|p.to_str())!=Some("gguf"){continue;}
                let mut header=[0u8;8];let valid=fs::File::open(&path)?.read_exact(&mut header).is_ok()&&&header[..4]==b"GGUF";
                let name=path.file_name().and_then(|p|p.to_str()).unwrap_or("");
                let profile=if name.contains("Qwen3-Coder-Next")&&name.contains("Q4_K_XL"){Some("q3-coder-next")}else if name.contains("Qwen3.8-27B-Q4_K_M"){Some("qwen38-q4-k-m")}else{None};
                models.push(json!({"path":path,"bytes":metadata.len(),"gguf_header_observed":valid,"gguf_version":if valid{Some(u32::from_le_bytes(header[4..8].try_into().unwrap()))}else{None},
                    "profile_catalog_id":profile,"quantization":if name.contains("IQ3_KT"){Some("IQ3_KT")}else{None},"runtime_compatibility":if name.contains("IQ3_KT"){"deferred; requires independently qualified ik_llama"}else{"must be verified with selected runtime"},
                    "download_required":false,"license":"not independently audited; no redistribution authorized"}));
            }}
        }
        Ok(json!({"api_version":1,"ok":true,"directory":self.model_directory,"models":models,"writes_performed":false,"downloads":[],"ownership":"discovery only"}))
    }
}
impl Drop for Onboarding {fn drop(&mut self){let _=self.shutdown();}}

#[derive(Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
struct WorkerSpec{kind:String,configuration:Configuration,workspace:PathBuf,#[serde(default)]cli_sha256:Option<String>}
pub fn worker()->io::Result<()> {
    if !cfg!(target_os="linux"){return Err(fail("NATIVE_EXECUTION_PLATFORM_NOT_QUALIFIED"));}
    #[cfg(unix)] {
        use nix::unistd::{getpid,getpgrp};
        // Internal workers must be a fresh process-group leader before they can execute a CLI.
        if getpid()!=getpgrp(){return Err(fail("OWNED_WORKER_PROCESS_GROUP_REQUIRED"));}
    }
    let mut input=io::BufReader::new(io::stdin());let mut request=Vec::new();input.by_ref().take(8193).read_until(b'\n',&mut request)?;
    if request.len()>8192||request.last()!=Some(&b'\n'){return Err(fail("INVALID_BOUNDED_WORKER_PROTOCOL"));}
    let spec:WorkerSpec=serde_json::from_slice(&request)?;configuration_valid(&spec.configuration)?;
    std::thread::spawn(move||{let mut byte=[0u8;1];loop{match input.read(&mut byte){Ok(0)|Err(_)=>{
        #[cfg(unix)] {let _=nix::sys::signal::killpg(nix::unistd::getpgrp(),nix::sys::signal::Signal::SIGKILL);}
        std::process::exit(23);
    },Ok(_)=>{}}}});
    let result=match execute_worker(&spec){Ok(result)=>result,Err(error)=>json!({"api_version":1,"ok":false,"kind":spec.kind,"error":error.to_string()})};
    println!("{}",result);Ok(())
}
fn execute_worker(spec:&WorkerSpec)->io::Result<Value>{
    let c=&spec.configuration;
    if spec.kind.starts_with("cloud-")&&c.network_mode!="ONLINE"{return Err(fail("CLOUD_BLOCKED_IN_OFFLINE_MODE"));}
    match spec.kind.as_str(){
        "local-probe"|"local-smoke"=>{
            let models=get_json(&c.local_endpoint,"/v1/models")?;
            let ids:Vec<String>=models["data"].as_array().ok_or_else(||fail("NO_LOCAL_MODEL_LIST"))?.iter().filter_map(|v|v["id"].as_str().map(str::to_owned)).collect();
            let props=get_json(&c.local_endpoint,"/props").ok();
            let context=props.as_ref().and_then(|p|p["default_generation_settings"]["n_ctx"].as_u64()).or_else(||models["data"][0]["meta"]["n_ctx"].as_u64());
            if spec.kind=="local-probe"{return Ok(json!({"api_version":1,"ok":true,"kind":spec.kind,"model_ids":ids,"context_size":context,
                "healthy":true,"managed":false,"effective_generation_parameters":props.as_ref().map(|p|&p["default_generation_settings"]["params"]),"task_timeout_seconds":0}));}
            if !ids.contains(&c.local_model){return Err(fail("EXPLICIT_LOCAL_MODEL_NOT_AVAILABLE"));}
            let payload=json!({"model":c.local_model,"messages":[{"role":"user","content":PUBLIC_PROMPT}],"temperature":0.0,"max_tokens":32,"stream":false});
            let mut response=agent(false).post(format!("{}/v1/chat/completions",c.local_endpoint)).header("Content-Type","application/json").send(serde_json::to_vec(&payload)?).map_err(|_|fail("LOCAL_INFERENCE_REQUEST_FAILED"))?;
            let mut data=Vec::new();response.body_mut().as_reader().take((RESULT_LIMIT+1) as u64).read_to_end(&mut data)?;
            if data.len()>RESULT_LIMIT{return Err(fail("LOCAL_RESPONSE_TOO_LARGE"));}
            let result:Value=serde_json::from_slice(&data).map_err(|_|fail("INVALID_LOCAL_INFERENCE_RESULT"))?;
            let output=result["choices"][0]["message"]["content"].as_str().unwrap_or("");
            Ok(json!({"api_version":1,"ok":output.trim()=="SYNCP-CONNECTION-OK"&&result["model"]==c.local_model,"kind":spec.kind,"selected_model":c.local_model,"actual_model":result["model"],"response":output,
                "usage":result["usage"],"context_size":context,"effective_request_parameters":{"temperature":0.0,"max_tokens":32},"task_timeout_seconds":0,"fallback":false,"private_project_context":false,"managed":false}))
        },
        "cloud-models"|"cloud-smoke"=>{
            let executable=connection_executable(&c.cloud_connection)?;
            let cli_sha256=crate::discovery::sha256(&executable)?;
            if spec.cli_sha256.as_deref()!=Some(cli_sha256.as_str()){return Err(fail("CLOUD_CLI_IDENTITY_CHANGED"));}
            // This directory is newly owned by the independent host, never a company workspace.
            let workspace=spec.workspace.join(format!("public-connection-test-{}",crate::auth::token().map_err(|_|fail("RANDOM_SOURCE_FAILED"))?));
            fs::create_dir(&workspace)?;
            #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&workspace,fs::Permissions::from_mode(0o700))?;}
            if c.cloud_connection=="official-chatgpt-subscription" {
                let mut result=if spec.kind=="cloud-models" {crate::codex_cloud::catalog(&workspace)?} else {crate::codex_cloud::smoke(&workspace,&c.cloud_model)?};
                result["api_version"]=json!(1);result["kind"]=json!(spec.kind);result["connection"]=json!(c.cloud_connection);result["cli_sha256"]=json!(cli_sha256);
                if spec.kind=="cloud-models" {result["ok"]=json!(true);}
                return Ok(result);
            }
            let mut command=cloud_command()?;
            command.current_dir(&workspace).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
            if spec.kind=="cloud-models" {command.arg("models");}
            else {if c.cloud_connection!="official-antigravity-subscription"||!model_id(&c.cloud_model){return Err(fail("SELECT_EXPLICIT_CLOUD_ROUTE"));}
                command.args(["--output-format","stream-json","--model",&c.cloud_model,"--new-project","--mode","plan","--sandbox","--disable-slash-commands","--print-timeout","0","-p",PUBLIC_PROMPT]);}
            let mut child=command.spawn().map_err(|_|fail("OFFICIAL_CLI_LAUNCH_FAILED"))?;let mut stdout=child.stdout.take().ok_or_else(||fail("CLI_STDOUT_MISSING"))?;
            let mut data=Vec::new();stdout.by_ref().take((RESULT_LIMIT+1) as u64).read_to_end(&mut data)?;
            if data.len()>RESULT_LIMIT {let _=child.kill();let _=child.wait();return Err(fail("CLI_OUTPUT_TOO_LARGE"));}
            let exit=child.wait()?;
            if !exit.success(){return Err(fail("OFFICIAL_CLI_AUTH_QUOTA_OR_EXECUTION_FAILED"));}
            if spec.kind=="cloud-models" {
                let text=String::from_utf8(data).map_err(|_|fail("INVALID_MODEL_LIST"))?;
                let mut ids:Vec<String>=text.lines().filter_map(|line|line.split_whitespace().next()).filter(|id|model_id(id)&&(id.starts_with("gemini-")||id.starts_with("claude-")||id.starts_with("gpt-"))).map(str::to_owned).collect();ids.sort();ids.dedup();
                if ids.is_empty(){return Err(fail("NO_AVAILABLE_SUBSCRIPTION_MODELS"));}
                return Ok(json!({"api_version":1,"ok":true,"kind":spec.kind,"model_ids":ids,"inference_performed":false,"connection":catalog_connection(&c.cloud_connection),"cli_sha256":cli_sha256,"cloud_guard":cloud_guard()?}));
            }
            let mut actual=None;let mut terminal=None;let mut tools=0;
            for line in data.split(|b|*b==b'\n').filter(|line|!line.is_empty()) {
                let value:Value=serde_json::from_slice(line).map_err(|_|fail("INVALID_OFFICIAL_CLI_PROTOCOL"))?;
                if value["event"]=="init" {actual=value["init"]["model"].as_str().map(str::to_owned);}
                if value["event"]=="step_update"&&value["step_update"]["step_type"]=="tool"{tools+=1;}
                if value["event"]=="result"{terminal=Some(value["result"].clone());}
            }
            let result=terminal.ok_or_else(||fail("CLOUD_TERMINAL_RESULT_MISSING"))?;
            let response=result["response"].as_str().unwrap_or("");
            Ok(json!({"api_version":1,"ok":actual.as_deref()==Some(c.cloud_model.as_str())&&result["status"]=="SUCCESS"&&response.trim()=="SYNCP-CONNECTION-OK"&&tools==0,
                "kind":spec.kind,"connection":c.cloud_connection,"cli_sha256":cli_sha256,"selected_model":c.cloud_model,"actual_model":actual,"terminal_status":result["status"],"response":response,"tool_events":tools,"usage":result["usage"],
                "cloud_guard":cloud_guard()?,"private_project_context":false,"task_timeout_seconds":0,"fallback":false,"instructions":"literal public connection test; no CM scaffolding"}))
        },_=>Err(fail("UNSUPPORTED_CONNECTION_RECIPE"))
    }
}

pub fn nvidia_observation()->Value {
    let mut command=Command::new("nvidia-smi");command.args(["--query-gpu=name,memory.total,memory.free,driver_version","--format=csv,noheader,nounits"]);
    let child=command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn();
    let Ok(mut child)=child else{return json!({"devices":[],"confidence":"unknown","source":"nvidia-smi not available; AMD/Intel/Apple adapters unqualified"});};
    let start=Instant::now();
    loop{match child.try_wait(){Ok(Some(exit))=>{if !exit.success(){break;}let mut text=String::new();if child.stdout.take().unwrap().take(8192).read_to_string(&mut text).is_err(){break;}
        let devices:Vec<Value>=text.lines().filter_map(|line|{let cols:Vec<_>=line.split(',').map(str::trim).collect();if cols.len()!=4{return None;}
            let total=cols[1].parse::<u64>().ok()?;let free=cols[2].parse::<u64>().ok()?;Some(json!({"name":cols[0],"total_bytes":total*1048576,"available_bytes":free*1048576,"driver":cols[3]}))}).collect();
        return json!({"devices":devices,"confidence":"observed","source":"nvidia-smi native management utility","diagnostic_timeout_seconds":5});},Ok(None)=>{},Err(_)=>break}
        if start.elapsed()>Duration::from_secs(5){let _=child.kill();let _=child.wait();break;}
        std::thread::sleep(Duration::from_millis(20));
    }
    json!({"devices":[],"confidence":"unknown","source":"NVIDIA diagnostic unavailable, failed or exceeded explicit 5-second observation limit"})
}

pub fn recommendation(input:&Value,gpu:&Value,memory:&Value)->Value {
    let catalog:Value=serde_json::from_str(PROFILES).expect("embedded calibration catalog");
    let model=input["model_id"].as_str().unwrap_or("");let backend=input["backend"].as_str().unwrap_or("");let build=input["build"].as_str().unwrap_or("");
    let Some(entry)=catalog["models"].get(model) else{return json!({"api_version":1,"ok":false,"error":"NO_QUALIFIED_PROFILE"});};
    let devices=gpu["devices"].as_array();let device=devices.filter(|v|v.len()==1).and_then(|v|v.first());
    let profile=entry["profiles"].as_array().and_then(|profiles|profiles.iter().find(|p| {
        let m=&p["match"];m["platform"]==std::env::consts::OS && m["backend"]==backend && m["build"]==build && device.is_some_and(|d| {
            let total=d["total_bytes"].as_u64().unwrap_or(0);m["gpu_name"]==d["name"] && m["driver"]==d["driver"] && m["vram_class_gb"].as_u64()==Some((total+536870912)/1073741824)
        })
    }));
    let logical_cpu=std::thread::available_parallelism().ok().map(|n|n.get());
    let mut settings=profile.map(|p|p["settings"].clone()).unwrap_or_else(||entry["safe_baseline"].clone());
    if profile.is_none() {
        // Preserve calibration data; adapt only the unmatched safe recommendation to this CPU.
        settings["threads"]=json!(logical_cpu.unwrap_or(1).min(12));
        settings["threads-batch"]=json!(logical_cpu.unwrap_or(1).min(16));
    }
    let required_ram=if model=="q3-coder-next"{50_000_000_000u64}else{20_000_000_000};
    let available=memory["available_bytes"].as_u64();
    let free=device.and_then(|d|d["available_bytes"].as_u64());
    json!({"api_version":1,"ok":true,"model_id":model,"profile":profile,"settings":settings,"logical_cpu_observation":logical_cpu,"unmatched_cpu_policy":"conservative thread caps bounded by this process available parallelism; unknown uses one safe thread",
        "selection":if profile.is_some(){"exact historical hardware/backend/build/driver match"}else{"CPU safe baseline; no calibrated match"},
        "historical_windows_settings":entry["windows_legacy"],"windows_qualification":"UNTESTED; historic profile preserved, not applied",
        "available_ram_bytes":available,"available_vram_bytes":free,"conservative_ram_reserve_bytes":required_ram,
        "launch_approved":false,"resource_readiness":if available.is_none()||free.is_none(){"UNKNOWN"}else if available.unwrap()<required_ram||free.unwrap()<2_000_000_000{"BLOCKED_OR_REQUIRES_MEMORY_REVIEW"}else{"REQUIRES_RUNTIME_AND_CONTEXT_VALIDATION"},
        "limitations":["Existing server resources cannot be reclaimed without its owner's approval","GGUF metadata/tool calling/model license require independent qualification","No download, model switch or task deadline is introduced"],
        "catalog_source":"standalone data extracted from preserved runtime_profiles.json; no AICP runtime import"})
}

pub fn doctor_local(config:&Value)->Value {
    let endpoint=config["local_endpoint"].as_str().unwrap_or("");
    match get_json(endpoint,"/v1/models") {
        Ok(models)=>{let ids:Vec<String>=models["data"].as_array().unwrap_or(&Vec::new()).iter().filter_map(|v|v["id"].as_str().map(str::to_owned)).collect();
            json!({"available":!ids.is_empty(),"selected_model":config["local_model"],"selected_available":config["local_model"]=="" || ids.iter().any(|id|config["local_model"]==id.as_str()),"model_ids":ids,"managed":false})},
        Err(_)=>json!({"available":false,"selected_model":config["local_model"],"cause":"not established","managed":false})
    }
}
