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
    let (nonce, ct) = crypto::seal(&key[..], b"top secret", b"ctx");
    assert_eq!(
        crypto::open(&key[..], &nonce, &ct, b"ctx").as_deref(),
        Some(&b"top secret"[..])
    );
    assert!(crypto::open(&key[..], &nonce, &ct, b"other").is_none());

    let wrong = crypto::derive_key("battery staple", &salt);
    assert!(crypto::open(&wrong[..], &nonce, &ct, b"ctx").is_none());
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
fn list_history_remove_and_missing_version() {
    let path = unique("ops", "vault");
    let store = vault::Store::new(path.clone());
    let pass = "hunter2";

    store.init(pass).unwrap();
    store.put(pass, "alpha", b"a1").unwrap();
    store.put(pass, "beta", b"b1").unwrap();
    store.rotate(pass, "alpha", b"a2").unwrap();

    let mut listed = store.list(pass).unwrap();
    listed.sort();
    assert_eq!(
        listed,
        vec![("alpha".to_string(), 2, 2), ("beta".to_string(), 1, 1)]
    );

    let versions: Vec<u32> = store
        .history(pass, "alpha")
        .unwrap()
        .into_iter()
        .map(|(v, _ts)| v)
        .collect();
    assert_eq!(versions, vec![1, 2]);

    assert!(matches!(
        store.get(pass, "alpha", Some(9)),
        Err(vault::Error::NotFound(_))
    ));

    store.remove(pass, "alpha").unwrap();
    assert!(store
        .list(pass)
        .unwrap()
        .iter()
        .all(|(n, _, _)| n != "alpha"));
    assert!(matches!(
        store.get(pass, "alpha", None),
        Err(vault::Error::NotFound(_))
    ));

    let audit_path = store.audit_path().to_path_buf();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn get_rejects_cross_slot_ciphertext_swap() {
    let path = unique("swap", "vault");
    let store = vault::Store::new(path.clone());
    let pass = "hunter2";

    store.init(pass).unwrap();
    store.put(pass, "alpha", b"AAAA").unwrap();
    store.put(pass, "beta", b"BBBB").unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let a_nonce = json["secrets"]["alpha"]["versions"][0]["nonce"].clone();
    let a_ct = json["secrets"]["alpha"]["versions"][0]["ct"].clone();
    let b_nonce = json["secrets"]["beta"]["versions"][0]["nonce"].clone();
    let b_ct = json["secrets"]["beta"]["versions"][0]["ct"].clone();
    json["secrets"]["alpha"]["versions"][0]["nonce"] = b_nonce;
    json["secrets"]["alpha"]["versions"][0]["ct"] = b_ct;
    json["secrets"]["beta"]["versions"][0]["nonce"] = a_nonce;
    json["secrets"]["beta"]["versions"][0]["ct"] = a_ct;
    std::fs::write(&path, serde_json::to_string(&json).unwrap()).unwrap();

    assert!(matches!(
        store.get(pass, "alpha", None),
        Err(vault::Error::Corrupt(_))
    ));

    let audit_path = store.audit_path().to_path_buf();
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&audit_path);
}

#[test]
fn verify_rejects_empty_or_missing_log() {
    let path = unique("missing", "audit");
    assert!(audit::verify(&path).is_err());
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
