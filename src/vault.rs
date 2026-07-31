use std::fmt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::model::{Kdf, Sealed, Secret, Vault, Version};
use crate::util::{b64, now, unb64};
use crate::{audit, crypto};

const FORMAT: u32 = 2;
const DEK_AAD: &[u8] = b"keyrot/dek";

fn context(name: &str, version: u32) -> Vec<u8> {
    let mut aad = (name.len() as u64).to_le_bytes().to_vec();
    aad.extend_from_slice(name.as_bytes());
    aad.extend_from_slice(&version.to_le_bytes());
    aad
}

#[derive(Debug)]
pub enum Error {
    Io(String),
    NotInitialized,
    AlreadyInitialized,
    WrongPassphrase,
    Corrupt(String),
    NotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io error: {e}"),
            Error::NotInitialized => write!(f, "vault not initialized (run `keyrot init`)"),
            Error::AlreadyInitialized => write!(f, "vault already exists"),
            Error::WrongPassphrase => write!(f, "wrong passphrase"),
            Error::Corrupt(what) => write!(f, "corrupt vault: {what}"),
            Error::NotFound(name) => write!(f, "secret not found: {name}"),
        }
    }
}

pub struct Store {
    path: PathBuf,
    audit_path: PathBuf,
}

impl Store {
    pub fn new(path: PathBuf) -> Self {
        let mut audit = path.clone().into_os_string();
        audit.push(".audit");
        Store {
            path,
            audit_path: PathBuf::from(audit),
        }
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    pub fn audit_path(&self) -> &Path {
        &self.audit_path
    }

    fn load(&self) -> Result<Vault, Error> {
        let raw = std::fs::read(&self.path).map_err(|_| Error::NotInitialized)?;
        serde_json::from_slice(&raw).map_err(|e| Error::Corrupt(e.to_string()))
    }

    fn save(&self, vault: &Vault) -> Result<(), Error> {
        let raw = serde_json::to_vec_pretty(vault).map_err(|e| Error::Corrupt(e.to_string()))?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, &raw).map_err(|e| Error::Io(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| Error::Io(e.to_string()))
    }

    fn record(&self, action: &str, target: &str) {
        if let Err(e) = audit::append(&self.audit_path, action, target, now()) {
            eprintln!("warning: audit append failed: {e}");
        }
    }

    pub fn init(&self, passphrase: &str) -> Result<(), Error> {
        if self.exists() {
            return Err(Error::AlreadyInitialized);
        }
        let salt = crypto::random(crypto::SALT_LEN);
        let kek = crypto::derive_key(passphrase, &salt);
        let dek = Zeroizing::new(crypto::random(crypto::KEY_LEN));
        let (nonce, ct) = crypto::seal(&kek[..], &dek, DEK_AAD);
        let vault = Vault {
            format: FORMAT,
            kdf: Kdf {
                algo: "argon2id".into(),
                salt: b64(&salt),
            },
            dek: Sealed {
                nonce: b64(&nonce),
                ct: b64(&ct),
            },
            secrets: Default::default(),
        };
        self.save(&vault)?;
        self.record("init", "");
        Ok(())
    }

    fn unlock(&self, passphrase: &str) -> Result<(Vault, Zeroizing<Vec<u8>>), Error> {
        let vault = self.load()?;
        if vault.format != FORMAT {
            return Err(Error::Corrupt(format!(
                "unsupported vault format {} (re-init required)",
                vault.format
            )));
        }
        let salt = unb64(&vault.kdf.salt).ok_or_else(|| Error::Corrupt("salt".into()))?;
        let kek = crypto::derive_key(passphrase, &salt);
        let nonce = unb64(&vault.dek.nonce).ok_or_else(|| Error::Corrupt("dek nonce".into()))?;
        let ct = unb64(&vault.dek.ct).ok_or_else(|| Error::Corrupt("dek".into()))?;
        let dek =
            Zeroizing::new(crypto::open(&kek[..], &nonce, &ct, DEK_AAD).ok_or(Error::WrongPassphrase)?);
        Ok((vault, dek))
    }

    fn write_version(
        &self,
        passphrase: &str,
        name: &str,
        value: &[u8],
        action: &str,
        require_existing: bool,
    ) -> Result<u32, Error> {
        let (mut vault, dek) = self.unlock(passphrase)?;
        if require_existing && !vault.secrets.contains_key(name) {
            return Err(Error::NotFound(name.into()));
        }
        let secret = vault
            .secrets
            .entry(name.to_string())
            .or_insert_with(|| Secret {
                current: 0,
                versions: Vec::new(),
            });
        let version = secret.current + 1;
        let (nonce, ct) = crypto::seal(&dek, value, &context(name, version));
        secret.versions.push(Version {
            version,
            created_at: now(),
            nonce: b64(&nonce),
            ct: b64(&ct),
        });
        secret.current = version;
        self.save(&vault)?;
        self.record(action, name);
        Ok(version)
    }

    pub fn put(&self, passphrase: &str, name: &str, value: &[u8]) -> Result<u32, Error> {
        self.write_version(passphrase, name, value, "put", false)
    }

    pub fn rotate(&self, passphrase: &str, name: &str, value: &[u8]) -> Result<u32, Error> {
        self.write_version(passphrase, name, value, "rotate", true)
    }

    pub fn get(
        &self,
        passphrase: &str,
        name: &str,
        version: Option<u32>,
    ) -> Result<Vec<u8>, Error> {
        let (vault, dek) = self.unlock(passphrase)?;
        let secret = vault
            .secrets
            .get(name)
            .ok_or_else(|| Error::NotFound(name.into()))?;
        let want = version.unwrap_or(secret.current);
        let chosen = secret
            .versions
            .iter()
            .find(|v| v.version == want)
            .ok_or_else(|| Error::NotFound(format!("{name}@{want}")))?;
        let nonce = unb64(&chosen.nonce).ok_or_else(|| Error::Corrupt("nonce".into()))?;
        let ct = unb64(&chosen.ct).ok_or_else(|| Error::Corrupt("ciphertext".into()))?;
        let plaintext = crypto::open(&dek, &nonce, &ct, &context(name, want))
            .ok_or_else(|| Error::Corrupt("secret".into()))?;
        self.record("get", name);
        Ok(plaintext)
    }

    pub fn remove(&self, passphrase: &str, name: &str) -> Result<(), Error> {
        let (mut vault, _dek) = self.unlock(passphrase)?;
        if vault.secrets.remove(name).is_none() {
            return Err(Error::NotFound(name.into()));
        }
        self.save(&vault)?;
        self.record("rm", name);
        Ok(())
    }

    pub fn list(&self, passphrase: &str) -> Result<Vec<(String, u32, usize)>, Error> {
        let (vault, _dek) = self.unlock(passphrase)?;
        Ok(vault
            .secrets
            .iter()
            .map(|(name, s)| (name.clone(), s.current, s.versions.len()))
            .collect())
    }

    pub fn history(&self, passphrase: &str, name: &str) -> Result<Vec<(u32, u64)>, Error> {
        let (vault, _dek) = self.unlock(passphrase)?;
        let secret = vault
            .secrets
            .get(name)
            .ok_or_else(|| Error::NotFound(name.into()))?;
        Ok(secret
            .versions
            .iter()
            .map(|v| (v.version, v.created_at))
            .collect())
    }
}
