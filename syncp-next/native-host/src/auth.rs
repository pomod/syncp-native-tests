use subtle::ConstantTimeEq;
use tiny_http::Request;

pub fn token() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn header<'a>(request: &'a Request, key: &'static str) -> Option<&'a str> {
    request.headers().iter().find(|h| h.field.equiv(key)).map(|h| h.value.as_str())
}

pub fn authorized(request: &Request, expected: &str) -> bool {
    let Some(supplied) = header(request, "Authorization").and_then(|s| s.strip_prefix("Bearer ")) else { return false; };
    supplied.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub fn local_origin(request: &Request, origin: &str, host: &str) -> bool {
    if header(request, "Host") != Some(host) { return false; }
    if let Some(value) = header(request, "Origin") {
        if value != origin { return false; }
    }
    if let Some(value) = header(request, "Sec-Fetch-Site") {
        if value != "same-origin" && value != "none" { return false; }
    }
    true
}
