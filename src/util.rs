use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
