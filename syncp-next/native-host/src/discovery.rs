use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub fn sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 { break; }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn user_paths() -> io::Result<Value> {
    let data = dirs::data_local_dir().ok_or_else(|| io::Error::other("USER_DATA_DIRECTORY_UNAVAILABLE"))?.join("synforge").join("syncp");
    let config = dirs::config_dir().ok_or_else(|| io::Error::other("USER_CONFIG_DIRECTORY_UNAVAILABLE"))?.join("synforge").join("syncp");
    let cache = dirs::cache_dir().ok_or_else(|| io::Error::other("USER_CACHE_DIRECTORY_UNAVAILABLE"))?.join("synforge").join("syncp");
    if !data.is_absolute() || !config.is_absolute() || !cache.is_absolute() {
        return Err(io::Error::other("USER_DIRECTORIES_MUST_BE_ABSOLUTE"));
    }
    Ok(json!({"api_version":1,"data":data,"config":config,"cache":cache,"writes_performed":false}))
}

fn read_limited(path: &str, limit: u64) -> Option<String> {
    let mut text = String::new();
    File::open(path).ok()?.take(limit).read_to_string(&mut text).ok()?;
    Some(text)
}

pub fn hardware(destination: &Path) -> Value {
    let mut memory = json!({"total_bytes":null,"available_bytes":null,"source":"unavailable","confidence":"unknown"});
    let mut cpu = json!({"logical_processors":std::thread::available_parallelism().ok().map(|n|n.get()),"model":null,"features":null,"source":"native standard library; additional probes unavailable"});
    let mut os_version = json!(null);
    #[cfg(target_os = "linux")]
    {
        if let Some(text) = read_limited("/proc/meminfo", 16384) {
            let mut total = None; let mut available = None;
            for line in text.lines() {
                let parts: Vec<_> = line.split_whitespace().collect();
                if parts.len() == 3 && parts[2] == "kB" {
                    let value = parts[1].parse::<u64>().ok().and_then(|n|n.checked_mul(1024));
                    if parts[0] == "MemTotal:" { total = value; }
                    if parts[0] == "MemAvailable:" { available = value; }
                }
            }
            memory = json!({"total_bytes":total,"available_bytes":available,"source":"/proc/meminfo","confidence":"observed"});
        }
        if let Some(text) = read_limited("/proc/cpuinfo", 65536) {
            for line in text.lines() {
                if let Some((key,value)) = line.split_once(':') {
                    if key.trim() == "model name" && cpu["model"].is_null() { cpu["model"] = json!(value.trim()); }
                    if (key.trim() == "flags" || key.trim() == "Features") && cpu["features"].is_null() {
                        cpu["features"] = json!(value.split_whitespace().collect::<Vec<_>>());
                    }
                }
            }
            cpu["source"] = json!("native standard library and /proc/cpuinfo");
        }
        if let Some(text) = read_limited("/etc/os-release", 16384) {
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("PRETTY_NAME=") { os_version = json!(value.trim_matches('"')); }
            }
        }
    }
    json!({"api_version":1,"os":{"system":std::env::consts::OS,"architecture":std::env::consts::ARCH,"version":os_version},
        "cpu":cpu,"memory":memory,"disk":{"available_bytes":fs2::available_space(destination).ok(),"source":"native filesystem","destination":destination},
        "gpu":crate::onboarding::nvidia_observation(),
        "network":{"available":null,"source":"not probed"},"inference_backends":"NOT_QUALIFIED"})
}

pub(crate) fn on_path(name: &str) -> Option<PathBuf> {
    let names = if cfg!(windows) { vec![format!("{name}.exe"), format!("{name}.cmd"), name.to_owned()] } else { vec![name.to_owned()] };
    for directory in std::env::split_paths(&std::env::var_os("PATH")?) {
        if !directory.is_absolute() { continue; }
        for name in &names {
            let path = directory.join(name);
            if path.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if path.metadata().ok()?.permissions().mode() & 0o111 == 0 { continue; }
                }
                return path.canonicalize().ok();
            }
        }
    }
    None
}

pub fn components(version: &str, self_identity: &Value) -> Value {
    let mut applications = Vec::new();
    for (id,name,url,license) in [
        ("opencode","OpenCode","https://github.com/anomalyco/opencode","MIT"),
        ("pi","Pi","https://github.com/earendil-works/pi","See pinned upstream license before distribution"),
        ("paperclip","Paperclip","https://github.com/paperclipai/paperclip","MIT"),
        ("llama-server","llama.cpp","https://github.com/ggml-org/llama.cpp","MIT"),
        ("dsh","DSH","https://github.com/deepseek-ai/deepseek-harness","MIT"),
    ] {
        let executable = on_path(id);
        applications.push(json!({"id":id,"name":name,"publisher":"upstream","source":url,"license":license,
            "installed":if executable.is_some() {Some(true)} else {None},
            "installation_observation":if executable.is_some(){"executable discovered on PATH"}else{"not discovered on PATH; other installations may exist"},
            "executable":executable,"version":null,"configured":null,"running":null,"healthy":null,"failed":null,
            "managed":false,"installation_qualification":"UNAVAILABLE","launch_authorized":false,
            "limitation":"Discovery does not grant authority, qualify installation, or take over an existing application"}));
    }
    json!({"api_version":1,"ok":true,"host":{"id":"syncp-native-host","version":version,"identity":self_identity,
        "installed":true,"configured":true,"running":true,"healthy":true,"managed":true},"applications":applications})
}

pub fn self_identity() -> io::Result<Value> {
    let path = std::env::current_exe()?.canonicalize()?;
    Ok(json!({"executable":path,"bytes":path.metadata()?.len(),"sha256":sha256(&path)?,"verification":"running native executable identity; unsigned development build"}))
}

pub fn sha512(path:&Path)->io::Result<String> {
    let mut file=File::open(path)?;let mut hash=sha2::Sha512::new();let mut buffer=[0u8;65536];
    loop{let count=file.read(&mut buffer)?;if count==0{break;}hash.update(&buffer[..count]);}
    Ok(format!("{:x}",hash.finalize()))
}
