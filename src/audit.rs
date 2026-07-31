use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS: &str = "GENESIS";

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub seq: u64,
    pub ts: u64,
    pub action: String,
    pub target: String,
    pub prev: String,
    pub hash: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

pub fn digest(seq: u64, ts: u64, action: &str, target: &str, prev: &str) -> String {
    let mut h = Sha256::new();
    h.update(seq.to_le_bytes());
    h.update(ts.to_le_bytes());
    h.update([0]);
    h.update(action.as_bytes());
    h.update([0]);
    h.update(target.as_bytes());
    h.update([0]);
    h.update(prev.as_bytes());
    hex(&h.finalize())
}

pub fn read(path: &Path) -> std::io::Result<Vec<Entry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = std::fs::File::open(path)?;
    let mut entries = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Entry>(&line) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub fn append(path: &Path, action: &str, target: &str, ts: u64) -> std::io::Result<Entry> {
    let log = read(path)?;
    let (seq, prev) = match log.last() {
        Some(last) => (last.seq + 1, last.hash.clone()),
        None => (1, GENESIS.to_string()),
    };
    let entry = Entry {
        seq,
        ts,
        action: action.to_string(),
        target: target.to_string(),
        hash: digest(seq, ts, action, target, &prev),
        prev,
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{}", serde_json::to_string(&entry).unwrap())?;
    Ok(entry)
}

pub fn verify(path: &Path) -> Result<usize, String> {
    let log = read(path).map_err(|e| e.to_string())?;
    if log.is_empty() {
        return Err("audit log is empty or missing (expected at least the init entry)".to_string());
    }
    let mut prev = GENESIS.to_string();
    for (i, entry) in log.iter().enumerate() {
        let expected = i as u64 + 1;
        if entry.seq != expected {
            return Err(format!("entry {expected}: bad sequence {}", entry.seq));
        }
        if entry.prev != prev {
            return Err(format!("entry {}: broken chain link", entry.seq));
        }
        let recomputed = digest(
            entry.seq,
            entry.ts,
            &entry.action,
            &entry.target,
            &entry.prev,
        );
        if recomputed != entry.hash {
            return Err(format!("entry {}: hash mismatch (tampered)", entry.seq));
        }
        prev = entry.hash.clone();
    }
    Ok(log.len())
}
