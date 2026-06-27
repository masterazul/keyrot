use std::path::PathBuf;

use keyrot::util::b64;
use keyrot::{audit, crypto, vault};

fn unique(tag: &str, ext: &str) -> PathBuf {
    let suffix = b64(&crypto::random(9)).replace(['/', '+', '='], "_");
    std::env::temp_dir().join(format!("keyrot-{tag}-{suffix}.{ext}"))
}

#[test]
fn crypto_roundtrip_and_wrong_key() {
    let salt = crypto::random(crypto::SALT_LEN);
    let key = crypto::derive_key("correct horse", &salt);
    let (nonce, ct) = crypto::seal(&key[..], b"top secret");
    assert_eq!(
        crypto::open(&key[..], &nonce, &ct).as_deref(),
        Some(&b"top secret"[..])
    );

    let wrong = crypto::derive_key("battery staple", &salt);
    assert!(crypto::open(&wrong[..], &nonce, &ct).is_none());
}

#[test]
fn vault_put_get_rotate_versions() {
    let path = unique("rt", "vault");
    let store = vault::Store::new(path.clone());
    let pass = "hunter2";

    store.init(pass).unwrap();
    assert!(matches!(
        store.init(pass),
        Err(vault::Error::AlreadyInitialized)
    ));

    assert_eq!(store.put(pass, "api", b"v1").unwrap(), 1);
    assert_eq!(store.get(pass, "api", None).unwrap(), b"v1");
    assert_eq!(store.rotate(pass, "api", b"v2").unwrap(), 2);
    assert_eq!(store.get(pass, "api", None).unwrap(), b"v2");
    assert_eq!(store.get(pass, "api", Some(1)).unwrap(), b"v1");

    assert!(matches!(
        store.get("nope", "api", None),
        Err(vault::Error::WrongPassphrase)
    ));
    assert!(matches!(
        store.rotate(pass, "ghost", b"x"),
        Err(vault::Error::NotFound(_))
    ));

    let audit_path = store.audit_path().to_path_buf();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn audit_chain_detects_tampering() {
    let path = unique("audit", "audit");
    audit::append(&path, "init", "", 100).unwrap();
    audit::append(&path, "put", "api", 200).unwrap();
    assert_eq!(audit::verify(&path).unwrap(), 2);

    let tampered = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\"target\":\"api\"", "\"target\":\"evil\"");
    std::fs::write(&path, tampered).unwrap();
    assert!(audit::verify(&path).is_err());

    let _ = std::fs::remove_file(&path);
}
