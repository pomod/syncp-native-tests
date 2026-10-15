use crate::discovery;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DownloadSpec {
    pub root: PathBuf,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub sha512: Option<String>,
    pub bytes: u64,
    pub loopback_test: bool,
}

fn identity(spec:&DownloadSpec)->&str {spec.sha512.as_deref().unwrap_or(&spec.sha256)}
fn checksum(spec:&DownloadSpec,path:&std::path::Path)->io::Result<String>{if spec.sha512.is_some(){discovery::sha512(path)}else{discovery::sha256(path)}}

pub fn validate_url(url: &str, loopback_test: bool) -> io::Result<()> {
    let uri: ureq::http::Uri = url.parse().map_err(|_|io::Error::other("INVALID_DOWNLOAD_URL"))?;
    if uri.authority().is_none() || uri.authority().is_some_and(|authority|authority.as_str().contains('@')) || url.contains(['?','#']) { return Err(io::Error::other("DOWNLOAD_URL_MUST_NOT_CONTAIN_CREDENTIALS")); }
    if uri.scheme_str() == Some("https") { return Ok(()); }
    if loopback_test && uri.scheme_str() == Some("http") && uri.host() == Some("127.0.0.1") { return Ok(()); }
    Err(io::Error::other("HTTPS_REQUIRED_OUTSIDE_EXPLICIT_LOOPBACK_TEST"))
}

pub fn worker() -> io::Result<()> {
    let mut input=std::io::BufReader::new(io::stdin());
    let mut request=Vec::new();
    input.by_ref().take(8193).read_until(b'\n',&mut request)?;
    if request.len()>8192 || request.last()!=Some(&b'\n'){return Err(io::Error::other("INVALID_BOUNDED_DOWNLOAD_PROTOCOL"));}
    let spec:DownloadSpec=serde_json::from_slice(&request)?;
    // The parent keeps this pipe open. EOF means its exact owner died; no PID scan,
    // platform-specific kill-by-name or arbitrary elapsed deadline is needed.
    std::thread::spawn(move||{let mut byte=[0u8;1];loop{match input.read(&mut byte){Ok(0)|Err(_)=>std::process::exit(23),Ok(_)=>{}}}});
    validate_url(&spec.url, spec.loopback_test)?;
    let expected=identity(&spec);
    let required_length=if spec.sha512.is_some(){128}else{64};
    if expected.len()!=required_length || !expected.bytes().all(|b|b.is_ascii_digit() || matches!(b,b'a'..=b'f')) || (spec.sha512.is_some()&&!spec.sha256.is_empty()) || spec.bytes == 0 {
        return Err(io::Error::other("INVALID_PINNED_DOWNLOAD_IDENTITY"));
    }
    crate::installer::check_owned_root(&spec.root)?;
    let cache = crate::installer::safe_dir(&spec.root, "cache")?;
    let partial = cache.join(format!("{}.partial",identity(&spec)));
    if partial.exists() && (fs::symlink_metadata(&partial)?.file_type().is_symlink() || !partial.is_file()) {
        return Err(io::Error::other("UNSAFE_PARTIAL_DOWNLOAD"));
    }
    let mut offset = partial.metadata().map(|m|m.len()).unwrap_or(0);
    if offset > spec.bytes { return Err(io::Error::other("PARTIAL_DOWNLOAD_EXCEEDS_PINNED_SIZE")); }
    if offset == spec.bytes {
        if checksum(&spec,&partial)? == identity(&spec) { return finish(&spec,&partial); }
        return Err(io::Error::other("PARTIAL_DOWNLOAD_HASH_MISMATCH"));
    }
    // No overall/per-call/body deadline. Cancellation kills only this exact helper handle.
    // Finite DNS/connect/header observations do not impose a deadline on a download/task.
    let agent = ureq::Agent::config_builder().timeout_global(None).timeout_per_call(None)
        .timeout_recv_body(None).timeout_connect(Some(Duration::from_secs(10)))
        .timeout_resolve(Some(Duration::from_secs(10))).timeout_recv_response(Some(Duration::from_secs(10)))
        .max_redirects(0).proxy(None).build().new_agent();
    let mut request = agent.get(&spec.url).header("Accept-Encoding","identity");
    if offset>0 { request=request.header("Range",format!("bytes={offset}-")); }
    let mut response = request.call().map_err(|error|io::Error::other(format!("DOWNLOAD_CONNECTION_FAILED: {error}")))?;
    let status = response.status().as_u16();
    if offset>0 && status==206 {
        let expected = format!("bytes {offset}-{} /{}",spec.bytes-1,spec.bytes).replace(" /","/");
        let observed = response.headers().get("Content-Range").and_then(|h|h.to_str().ok());
        if observed != Some(expected.as_str()) { return Err(io::Error::other("INVALID_DOWNLOAD_RANGE")); }
    } else if status==200 {
        if offset>0 {
            // Preserve the old prefix rather than append a full response to it.
            let archived=cache.join(format!("discarded-prefix-{}-{}",identity(&spec),crate::auth::token().map_err(|_|io::Error::other("RANDOM_SOURCE_FAILED"))?));
            fs::rename(&partial,archived)?;
        }
        offset=0;
    } else { return Err(io::Error::other("UNEXPECTED_DOWNLOAD_STATUS")); }
    let mut options=OpenOptions::new();options.write(true).append(offset>0).create_new(offset==0);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt;options.mode(0o600); }
    let mut output=options.open(&partial)?;
    let mut reader=response.body_mut().as_reader();
    let mut buffer=[0u8;65536];let mut total=offset;
    loop {
        let count=reader.read(&mut buffer)?;
        if count==0 { break; }
        total=total.checked_add(count as u64).ok_or_else(||io::Error::other("DOWNLOAD_SIZE_OVERFLOW"))?;
        if total>spec.bytes { return Err(io::Error::other("DOWNLOAD_EXCEEDS_PINNED_SIZE")); }
        output.write_all(&buffer[..count])?;
    }
    output.sync_all()?;drop(output);
    if total!=spec.bytes || checksum(&spec,&partial)?!=identity(&spec) {
        return Err(io::Error::other("DOWNLOAD_INTEGRITY_FAILED"));
    }
    finish(&spec,&partial)
}

fn finish(spec:&DownloadSpec,partial:&std::path::Path)->io::Result<()> {
    let verified=spec.root.join("cache").join(format!("{}.verified",identity(&spec)));
    if verified.exists() {
        if fs::symlink_metadata(&verified)?.file_type().is_symlink() || checksum(spec,&verified)?!=identity(spec) {
            return Err(io::Error::other("CACHE_INTEGRITY_FAILED"));
        }
    } else { fs::rename(partial,&verified)?; }
    println!("{}",serde_json::json!({"ok":true,"sha256":if spec.sha512.is_none(){Some(spec.sha256.as_str())}else{None},"sha512":spec.sha512,"bytes":spec.bytes}));
    Ok(())
}
