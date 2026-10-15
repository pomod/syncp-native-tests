mod auth;
mod owned_process;
mod state;
mod discovery;
mod platform;
mod installer;
mod download;
mod onboarding;
mod codex_cloud;
mod doctor;
mod applications;

use serde_json::{Value, json};
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::time::Duration;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const MAX_BODY: usize = 8192;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const HTML: &str = include_str!("../../web/index.html");
const JS: &str = include_str!("../../web/host.js");
const CSS: &str = include_str!("../../web/assets/syncp.css");
const LOGO: &[u8] = include_bytes!("../../web/assets/synforge-logo.png");

fn reply(request: Request, status: u16, content_type: &str, bytes: Vec<u8>) {
    let mut response = Response::from_data(bytes).with_status_code(StatusCode(status));
    for (name, value) in [
        ("Content-Type", content_type), ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
    ] {
        response.add_header(Header::from_bytes(name, value).expect("source-defined header"));
    }
    let _ = request.respond(response);
}

fn api(request: Request, status: u16, result: Value) {
    reply(request, status, "application/json", serde_json::to_vec(&result).expect("JSON values are serializable"));
}

fn error(request: Request, status: u16, code: &str) {
    api(request, status, json!({"api_version":1,"ok":false,"error":code}));
}

fn body(request: &mut Request) -> io::Result<Vec<u8>> {
    if auth::header(request, "Content-Type") != Some("application/json") {
        return Err(io::Error::other("Content type must be application/json"));
    }
    // Known bounded Content-Length only; no unbounded/chunked request reads.
    let length = request.body_length().ok_or_else(|| io::Error::other("Content length is required"))?;
    if length > MAX_BODY { return Err(io::Error::other("Request too large")); }
    let mut bytes = Vec::new();
    request.as_reader().take((MAX_BODY + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BODY { return Err(io::Error::other("Request too large")); }
    Ok(bytes)
}

fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if std::env::current_exe()?.file_stem().and_then(|n|n.to_str())==Some("syncp-opencode-paperclip") { applications::opencode_compat()?; return Ok(()); }
    let mut args = std::env::args().skip(1);
    let mut root = None;
    let mut port = 0u16;
    let mut open_browser = std::env::args().len()==1;
    let mut installer_mode = std::env::current_exe()?.file_stem().and_then(|n|n.to_str()).is_some_and(|n|n.to_ascii_lowercase().contains("setup"));
    open_browser = open_browser || installer_mode;
    let mut install_root = None;
    let mut test_download_url = None;
    let mut model_directory = None;
    let mut optional_root = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--data-dir" => root = Some(PathBuf::from(args.next().ok_or("Missing data directory")?)),
            "--port" => port = args.next().ok_or("Missing port")?.parse()?,
            "--installer" => installer_mode = true,
            "--install-root" => install_root = Some(PathBuf::from(args.next().ok_or("Missing install root")?)),
            "--test-download-url" => test_download_url = Some(args.next().ok_or("Missing test URL")?),
            "--optional-root" => optional_root = Some(PathBuf::from(args.next().ok_or("Missing optional application root")?)),
            "--model-directory" => model_directory = Some(PathBuf::from(args.next().ok_or("Missing model directory")?)),
            "--onboarding-worker" => { onboarding::worker()?; return Ok(()); }
            "--download-worker" => {
                if let Err(error)=download::worker() {
                    // This worker accepts only credential-free pinned download URLs.
                    // Report its bounded transport/integrity error; never capabilities.
                    eprintln!("Native download failed: {error}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            "--paths" => { println!("{}", discovery::user_paths()?); return Ok(()); }
            "--open" => open_browser = true,
            "--no-open" => open_browser = false,
            "--version" => { println!("syncp-native-host {VERSION} api=1 architecture-proof"); return Ok(()); }
            "--fixture-child" => std::process::exit(owned_process::fixture_child()),
            _ => return Err("Unsupported argument; use --data-dir ABSOLUTE_ISOLATED_PATH [--port 0]".into()),
        }
    }
    let installer = if installer_mode {
        let destination = match install_root { Some(path)=>path, None=>PathBuf::from(discovery::user_paths()?["data"].as_str().ok_or("User data path unavailable")?) };
        Some(installer::Installer::new(destination,VERSION,test_download_url)?)
    } else { if install_root.is_some() || test_download_url.is_some(){return Err("Installer options require --installer".into());}None };
    let root = match root { Some(root) => root, None if installer_mode => std::env::temp_dir().join(format!("syncp-installer-session-{}",auth::token().map_err(|_|"OS random source unavailable")?)), None => match installer::installed_data_root()? {Some(path)=>path,None=>PathBuf::from(discovery::user_paths()?["data"].as_str().ok_or("User data path unavailable")?)} };
    let optional = optional_root.map(applications::Applications::new).transpose()?;
    let mut store = state::Store::open(&root)?;
    let mut onboarding = onboarding::Onboarding::new(&root, model_directory)?;
    let server = Server::http((std::net::Ipv4Addr::LOCALHOST, port))?;
    let address = server.server_addr().to_ip().ok_or("TCP listener is required")?;
    let host = address.to_string();
    let origin = format!("http://{host}");
    let read_token = auth::token().map_err(|_| "OS random source is unavailable")?;
    let manage_token = auth::token().map_err(|_| "OS random source is unavailable")?;
    let session_name = format!("session-{}.json", auth::token().map_err(|_| "OS random source is unavailable")?);
    let session_path = root.join(&session_name);
    let session = json!({"api_version":1,"origin":origin,"read_token":read_token,"manage_token":manage_token,
                        "host_pid":std::process::id(),"qualification":"ARCHITECTURE_PROOF"});
    state::write_new_private(&session_path, &serde_json::to_vec(&session)?)?;
    store.journal("host.started")?;
    // The descriptor contains capabilities; stdout and diagnostic events do not.
    println!("{}", json!({"api_version":1,"origin":origin,"session_file":session_path,"version":VERSION}));
    let identity = discovery::self_identity()?;
    if open_browser { platform::browser(&origin, &manage_token)?; }
    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_shutdown = shutdown.clone();
    ctrlc::set_handler(move || { signal_shutdown.store(true, Ordering::SeqCst); })?;
    let mut fixture = owned_process::OwnedFixture::new();
    let mut previous_failure = false;
    while !shutdown.load(Ordering::SeqCst) {
        store.observe_staging()?;
        onboarding.status()?;
        let process = fixture.observe()?;
        let failure = process["failed"] == true;
        if failure && !previous_failure { store.journal("owned_process.unexpected_exit")?; }
        previous_failure = failure;
        let Some(mut request) = server.recv_timeout(Duration::from_millis(250))? else { continue; };
        if !auth::local_origin(&request, &origin, &host) {
            error(request, 403, "LOCAL_ORIGIN_REQUIRED"); continue;
        }
        let path = request.url().to_owned();
        if request.method() == &Method::Get {
            let asset: Option<(&str, Vec<u8>)> = match path.as_str() {
                "/" => Some(("text/html; charset=utf-8", HTML.as_bytes().to_vec())),
                "/host.js" => Some(("text/javascript; charset=utf-8", JS.as_bytes().to_vec())),
                "/assets/syncp.css" => Some(("text/css; charset=utf-8", CSS.as_bytes().to_vec())),
                "/assets/synforge-logo.png" => Some(("image/png", LOGO.to_vec())),
                _ => None,
            };
            if let Some((content_type, bytes)) = asset { reply(request, 200, content_type, bytes); continue; }
            if path == "/api/v1/health" {
                api(request, 200, json!({"api_version":1,"ok":true,"host":"syncp-native-host","version":VERSION,
                                       "qualification":"ARCHITECTURE_PROOF"})); continue;
            }
        }
        let can_manage = auth::authorized(&request, &manage_token);
        if !can_manage && !auth::authorized(&request, &read_token) {
            error(request, 401, "LOCAL_AUTHORIZATION_REQUIRED"); continue;
        }
        if request.method() == &Method::Get && path == "/api/v1/status" {
            match fixture.observe() {
                Ok(process) => api(request, 200, json!({"api_version":1,"ok":true,"host":{"version":VERSION,"healthy":true,
                        "os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"scope":"native foundation development","identity":identity},
                        "preferences":store.preferences,"generation":store.generation,
                        "interrupted_staging_files":store.interrupted_staging_files,"owned_process":process,
                        "capabilities":{"view":true,"manage_proof":can_manage,"install":can_manage && installer.is_some(),"installer_enabled":installer.is_some(),"inference":false,"connection_tests":cfg!(target_os="linux")},
                        "optional_applications":if optional.is_some(){"PREPARED_LINUX_TEST_INSTALLATION"}else{"NOT_ENABLED"}})),
                Err(_) => error(request, 500, "PROCESS_OBSERVATION_FAILED"),
            }
            continue;
        }
        if request.method() == &Method::Get && path == "/api/v1/doctor/report" {
            let installation=installer.as_ref().and_then(|manager|manager.status().ok());
            let current=onboarding.status()?;
            match doctor::inspect(&mut store,&mut fixture,&current,installation) {Ok(value)=>api(request,200,value),Err(_)=>error(request,500,"DOCTOR_OBSERVATION_FAILED")}
            continue;
        }
        if request.method() == &Method::Get && path.starts_with("/api/v1/onboarding/") {
            let result = match path.as_str() {
                "/api/v1/onboarding/status" => onboarding.status(),
                "/api/v1/onboarding/models" => onboarding.models(),
                _ => {error(request,404,"UNSUPPORTED_ONBOARDING_ROUTE");continue;}
            };
            match result {Ok(value)=>api(request,200,value),Err(_)=>error(request,409,"ONBOARDING_OBSERVATION_FAILED")}
            continue;
        }
        if request.method() == &Method::Get && path.starts_with("/api/v1/applications/") {
            let Some(manager)=&optional else {error(request,404,"OPTIONAL_APPLICATIONS_NOT_ENABLED");continue;};
            let result=if path=="/api/v1/applications/status" {manager.status()}
                else if let Some(operation)=path.strip_prefix("/api/v1/applications/plan/"){manager.plan(operation)}
                else {error(request,404,"UNSUPPORTED_APPLICATION_ROUTE");continue;};
            match result {Ok(value)=>api(request,200,value),Err(error_value)=>api(request,409,json!({"api_version":1,"ok":false,"error":"APPLICATION_REQUIRES_REVIEW","detail":error_value.to_string()}))}
            continue;
        }
        if request.method() == &Method::Get && path.starts_with("/api/v1/installer/") {
            let Some(manager)=&installer else { error(request,404,"INSTALLER_NOT_ENABLED");continue; };
            let result=if path=="/api/v1/installer/status" {manager.status()}
                else if let Some(operation)=path.strip_prefix("/api/v1/installer/plan/"){manager.plan(operation)}
                else {error(request,404,"UNSUPPORTED_INSTALLER_ROUTE");continue;};
            match result {Ok(value)=>api(request,200,value),Err(_)=>error(request,409,"INSTALLER_PLAN_OR_STATE_REQUIRES_REVIEW")}
            continue;
        }
        if request.method() == &Method::Get {
            let result = match path.as_str() {
                "/api/v1/components" => {
                    let mut components=discovery::components(VERSION,&identity);
                    if let Some(manager)=&optional {
                        if let Ok(observed)=manager.status() {
                            if let Some(rows)=components["applications"].as_array_mut() {
                                for row in rows {
                                    if row["id"]=="paperclip" {
                                        row["installed"]=observed["installed"].clone();row["version"]=observed["version"].clone();row["configured"]=observed["configured"].clone();row["managed"]=json!(true);
                                        for field in ["running","healthy","failed"] {row[field]=observed["process"][field].clone();}
                                        row["installation_qualification"]=observed["installation_qualification"].clone();row["limitation"]=json!("Prepared isolated Linux package only; fresh-machine bootstrap and agent routes require separate qualification");
                                    } else if row["id"]=="opencode" && observed["additional_harness"]["installed"]==true {
                                        row["installed"]=json!(true);row["managed"]=json!(true);row["version"]=json!("2.0.27");row["executable"]=observed["additional_harness"]["executable"].clone();row["installation_qualification"]=json!("pinned native binary reuse; public local task verified separately");
                                    }
                                }
                            }
                        }
                    }
                    Ok(components)
                },
                "/api/v1/hardware" => Ok(json!({"api_version":1,"ok":true,"observation":discovery::hardware(store.root())})),
                "/api/v1/paths" => discovery::user_paths().map(|paths|json!({"api_version":1,"ok":true,"paths":paths})),
                "/api/v1/recovery/plan" => store.recovery_plan(),
                "/api/v1/events" => store.events(),
                _ => { error(request, 404, "UNSUPPORTED_ROUTE"); continue; }
            };
            match result { Ok(value) => api(request,200,value), Err(_) => error(request,500,"OBSERVATION_FAILED") }
            continue;
        }
        if request.method() != &Method::Post { error(request, 404, "UNSUPPORTED_ROUTE"); continue; }
        if !can_manage { error(request, 403, "MANAGE_CAPABILITY_REQUIRED"); continue; }
        let bytes = match body(&mut request) {
            Ok(bytes) => bytes,
            Err(_) => { error(request, 400, "INVALID_BOUNDED_JSON_REQUEST"); continue; }
        };
        if path=="/api/v1/applications/approve" {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct AppApproval {operation:String,plan_id:String,approved:bool}
            let Some(manager)=&optional else {error(request,404,"OPTIONAL_APPLICATIONS_NOT_ENABLED");continue;};
            let approval:AppApproval=match serde_json::from_slice(&bytes){Ok(value)=>value,Err(_)=>{error(request,400,"INVALID_APP_APPROVAL");continue;}};
            match manager.approve(&approval.operation,&approval.plan_id,approval.approved){Ok(value)=>api(request,200,value),Err(error_value)=>api(request,409,json!({"api_version":1,"ok":false,"error":"APPLICATION_REQUIRES_REVIEW","detail":error_value.to_string()}))}
            continue;
        }
        if path.starts_with("/api/v1/doctor/") {
            let result=match path.as_str() {
                "/api/v1/doctor/plan"=>{
                    #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Plan {recipe:String}
                    serde_json::from_slice::<Plan>(&bytes).map_err(std::io::Error::other).and_then(|p|doctor::plan(&store,&mut fixture,&p.recipe))
                },
                "/api/v1/doctor/repair"=>{
                    #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)] struct Repair {recipe:String,plan_id:String,approved:bool}
                    serde_json::from_slice::<Repair>(&bytes).map_err(std::io::Error::other).and_then(|p|doctor::repair(&mut store,&mut fixture,&p.recipe,&p.plan_id,p.approved))
                },_=>{error(request,404,"UNSUPPORTED_DOCTOR_ROUTE");continue;}
            };
            match result {Ok(value)=>api(request,200,value),Err(e)=>{
                let message=e.to_string();let safe=if message.bytes().all(|b|b.is_ascii_uppercase()||b==b'_'){message.as_str()}else{"INVALID_DOCTOR_REQUEST"};error(request,409,safe);
            }}
            continue;
        }
        if path.starts_with("/api/v1/onboarding/") {
            let result: std::io::Result<Value> = match path.as_str() {
                "/api/v1/onboarding/plan" => serde_json::from_slice::<onboarding::Configuration>(&bytes).map_err(std::io::Error::other).and_then(|c|onboarding.configuration_plan(c)),
                "/api/v1/onboarding/approve" => {
                    #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)]
                    struct Approval {configuration:onboarding::Configuration,plan_id:String,approved:bool}
                    serde_json::from_slice::<Approval>(&bytes).map_err(std::io::Error::other).and_then(|a|onboarding.approve(a.configuration,&a.plan_id,a.approved)).map(|_|json!({"api_version":1,"ok":true}))
                },
                "/api/v1/onboarding/test" => {
                    #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)]
                    struct Test {kind:String,cloud_quota_approved:bool}
                    serde_json::from_slice::<Test>(&bytes).map_err(std::io::Error::other).and_then(|t|onboarding.start(&t.kind,t.cloud_quota_approved)).map(|_|json!({"api_version":1,"ok":true,"status":"RUNNING"}))
                },
                "/api/v1/onboarding/cancel" => {
                    if serde_json::from_slice::<Value>(&bytes).ok()!=Some(json!({})){Err(std::io::Error::other("CANCEL_ACCEPTS_NO_ARGUMENTS"))}
                    else{onboarding.cancel().map(|_|json!({"api_version":1,"ok":true}))}
                },
                "/api/v1/onboarding/recommend" => {
                    #[derive(serde::Deserialize)] #[serde(deny_unknown_fields)]
                    struct Profile {model_id:String,backend:String,build:String}
                    serde_json::from_slice::<Profile>(&bytes).map_err(std::io::Error::other).map(|p|{
                        let hardware=discovery::hardware(store.root());
                        onboarding::recommendation(&json!({"model_id":p.model_id,"backend":p.backend,"build":p.build}),&hardware["gpu"],&hardware["memory"])
                    })
                },_=>{error(request,404,"UNSUPPORTED_ONBOARDING_ROUTE");continue;}
            };
            // Source-defined runtime rejection codes are public. Parser errors are redacted.
            match result {Ok(value)=>api(request,200,value),Err(e)=>{
                let message=e.to_string();let safe=if message.bytes().all(|b|b.is_ascii_uppercase()||b==b'_'){message.as_str()}else{"INVALID_ONBOARDING_REQUEST"};
                error(request,409,safe);
            }}
            continue;
        }
        if path=="/api/v1/installer/approve" {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct InstallApproval {operation:String,plan_id:String,approved:bool}
            let Some(manager)=&installer else {error(request,404,"INSTALLER_NOT_ENABLED");continue;};
            let approval:InstallApproval=match serde_json::from_slice(&bytes){Ok(value)=>value,Err(_)=>{error(request,400,"INVALID_INSTALL_APPROVAL");continue;}};
            match manager.approve(&approval.operation,&approval.plan_id,approval.approved){Ok(())=>api(request,202,json!({"api_version":1,"ok":true,"status":"RUNNING"})),Err(_)=>error(request,409,"INSTALL_APPROVAL_REJECTED")}
            continue;
        }
        if path=="/api/v1/installer/cancel" {
            let Some(manager)=&installer else {error(request,404,"INSTALLER_NOT_ENABLED");continue;};
            if serde_json::from_slice::<Value>(&bytes).ok()!=Some(json!({})){error(request,400,"CANCEL_ACCEPTS_NO_EXTRA_ARGUMENTS");continue;}
            match manager.cancel(){Ok(())=>api(request,202,json!({"api_version":1,"ok":true,"status":"CANCEL_REQUESTED"})),Err(_)=>error(request,500,"CANCEL_REQUEST_FAILED")}
            continue;
        }
        if path == "/api/v1/recovery/approve" {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Approval { plan_id: String, approved: bool }
            let approval: Approval = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => { error(request,400,"INVALID_RECOVERY_APPROVAL"); continue; }
            };
            if !approval.approved { error(request,403,"EXPLICIT_APPROVAL_REQUIRED"); continue; }
            match store.approve_recovery(&approval.plan_id) {
                Ok(()) => api(request,200,json!({"api_version":1,"ok":true,"verification":"pending files quarantined; committed settings preserved"})),
                Err(_) => error(request,409,"RECOVERY_REJECTED_OR_REQUIRES_REVIEW"),
            }
            continue;
        }
        if path == "/api/v1/preferences" {
            let preferences: state::Preferences = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => { error(request, 400, "INVALID_PREFERENCES"); continue; }
            };
            match store.save(preferences).and_then(|_| store.journal("preferences.saved")) {
                Ok(()) => api(request, 200, json!({"api_version":1,"ok":true,"generation":store.generation})),
                Err(_) => error(request, 500, "CONFIGURATION_COMMIT_FAILED"),
            }
            continue;
        }
        if serde_json::from_slice::<Value>(&bytes).ok() != Some(json!({})) {
            error(request, 400, "THIS_RECIPE_ACCEPTS_NO_ARGUMENTS"); continue;
        }
        let outcome = match path.as_str() {
            "/api/v1/proof/start" => fixture.start().and_then(|_| store.journal("proof.started")),
            "/api/v1/proof/stop" => fixture.stop().and_then(|_| store.journal("proof.stopped")),
            "/api/v1/host/stop" => fixture.stop().and_then(|_| store.journal("host.stopped")),
            _ => { error(request, 404, "UNSUPPORTED_ROUTE"); continue; }
        };
        if outcome.is_err() { error(request, 500, "OWNED_OPERATION_FAILED"); continue; }
        let stop_host = path == "/api/v1/host/stop";
        api(request, 200, json!({"api_version":1,"ok":true}));
        if stop_host { break; }
    }
    onboarding.shutdown()?;
    if let Some(manager)=&installer { manager.shutdown()?; }
    fixture.stop()?;
    if shutdown.load(Ordering::SeqCst) { store.journal("host.signal_shutdown")?; }
    // Session capabilities expire when the host exits. No old PID is adopted on restart.
    Ok(())
}

fn main() {
    if run().is_err() {
        // No request bodies, session capabilities or provider configuration in error logs.
        eprintln!("SynCP native proof failed to initialize or complete; inspect the isolated state and documented prerequisites.");
        std::process::exit(1);
    }
}
