#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use keyrot::util::b64;
use keyrot::{audit, crypto, vault};

const USAGE: &str = "keyrot - encrypted secrets vault with rotation and an audit trail

usage:
  keyrot <command> [args] [--vault <path>]

commands:
  init                  create a new vault
  put <name> [value]    store/replace a secret (value from arg or stdin)
  get <name>            print a secret  [--version N]
  rotate <name> [value] new version of an existing secret  [--generate]
  rm <name>             delete a secret and all its versions
  ls                    list secret names, current version and count
  history <name>        list version numbers and timestamps
  gen [bytes]           print a fresh random secret (default 24 bytes)
  audit                 print the audit log
  verify                check the audit log hash-chain
  help / version

env:
  KEYROT_PASSPHRASE     master passphrase (prompted if unset)
  KEYROT_VAULT          default vault path (else ./keyrot.vault)
";

struct Args {
    command: String,
    positionals: Vec<String>,
    vault: Option<String>,
    version: Option<u32>,
    generate: bool,
}

fn parse() -> Option<Args> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut iter = raw.into_iter();
    let command = iter.next()?;
    let mut a = Args {
        command,
        positionals: Vec::new(),
        vault: None,
        version: None,
        generate: false,
    };
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--vault" => a.vault = Some(iter.next()?),
            "--version" => a.version = Some(iter.next().and_then(|s| s.parse::<u32>().ok())?),
            "--generate" | "-g" => a.generate = true,
            other => a.positionals.push(other.to_string()),
        }
    }
    Some(a)
}

fn main() -> ExitCode {
    let args = match parse() {
        Some(a) => a,
        None => {
            print!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match args.command.as_str() {
        "help" | "-h" | "--help" => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        "version" | "-V" => {
            println!("keyrot {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        "gen" => {
            let len = match args.positionals.first() {
                None => 24usize,
                Some(s) => match s.parse::<usize>() {
                    Ok(n) if n > 0 => n,
                    _ => return usage_error("gen needs a positive byte count"),
                },
            };
            println!("{}", b64(&crypto::random(len)));
            ExitCode::SUCCESS
        }
        _ => run(args),
    }
}

fn run(args: Args) -> ExitCode {
    let store = vault::Store::new(vault_path(args.vault.clone()));

    let outcome: Result<(), vault::Error> = match args.command.as_str() {
        "init" => store.init(&passphrase()),
        "put" => match name(&args) {
            Some(name) => collect_value(&args)
                .and_then(|v| store.put(&passphrase(), &name, &v).map(report_version)),
            None => return usage_error("put needs a name"),
        },
        "rotate" => match name(&args) {
            Some(name) => collect_value(&args)
                .and_then(|v| store.rotate(&passphrase(), &name, &v).map(report_version)),
            None => return usage_error("rotate needs a name"),
        },
        "get" => match name(&args) {
            Some(name) => store
                .get(&passphrase(), &name, args.version)
                .and_then(print_secret),
            None => return usage_error("get needs a name"),
        },
        "rm" => match name(&args) {
            Some(name) => store.remove(&passphrase(), &name),
            None => return usage_error("rm needs a name"),
        },
        "ls" => store.list(&passphrase()).map(|items| {
            for (name, current, count) in items {
                println!("{name}\tv{current}\t{count} version(s)");
            }
        }),
        "history" => match name(&args) {
            Some(name) => store.history(&passphrase(), &name).map(|rows| {
                for (version, ts) in rows {
                    println!("v{version}\t{ts}");
                }
            }),
            None => return usage_error("history needs a name"),
        },
        "audit" => return show_audit(&store),
        "verify" => return verify_audit(&store),
        other => {
            eprintln!("unknown command: {other}\n");
            print!("{USAGE}");
            return ExitCode::FAILURE;
        }
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn name(args: &Args) -> Option<String> {
    args.positionals.first().cloned()
}

fn report_version(version: u32) {
    println!("stored version {version}");
}

fn print_secret(value: Vec<u8>) -> Result<(), vault::Error> {
    let mut out = std::io::stdout();
    out.write_all(&value)
        .and_then(|_| out.write_all(b"\n"))
        .and_then(|_| out.flush())
        .map_err(|e| vault::Error::Io(e.to_string()))
}

fn collect_value(args: &Args) -> Result<Vec<u8>, vault::Error> {
    if args.generate {
        return Ok(b64(&crypto::random(24)).into_bytes());
    }
    if let Some(value) = args.positionals.get(1) {
        return Ok(value.clone().into_bytes());
    }
    if std::env::var("KEYROT_PASSPHRASE")
        .map(|p| p.is_empty())
        .unwrap_or(true)
    {
        return Err(vault::Error::Io(
            "set KEYROT_PASSPHRASE to read the secret value from stdin".into(),
        ));
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| vault::Error::Io(e.to_string()))?;
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    Ok(buf)
}

fn show_audit(store: &vault::Store) -> ExitCode {
    match audit::read(store.audit_path()) {
        Ok(entries) => {
            for e in entries {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    e.seq,
                    e.ts,
                    e.action,
                    e.target,
                    e.hash.get(..12).unwrap_or(e.hash.as_str())
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn verify_audit(store: &vault::Store) -> ExitCode {
    match audit::verify(store.audit_path()) {
        Ok(n) => {
            println!("audit chain ok ({n} entries)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("audit chain INVALID: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage_error(message: &str) -> ExitCode {
    eprintln!("{message}");
    ExitCode::FAILURE
}

fn vault_path(flag: Option<String>) -> PathBuf {
    if let Some(path) = flag {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("KEYROT_VAULT") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    PathBuf::from("keyrot.vault")
}

fn passphrase() -> String {
    if let Ok(p) = std::env::var("KEYROT_PASSPHRASE") {
        if !p.is_empty() {
            return p;
        }
    }
    eprint!("passphrase: ");
    let _ = std::io::stderr().flush();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).unwrap_or(0) == 0 {
        eprintln!("error: empty passphrase");
        std::process::exit(1);
    }
    let input = input.trim_end_matches(['\n', '\r']).to_string();
    if input.is_empty() {
        eprintln!("error: empty passphrase");
        std::process::exit(1);
    }
    input
}
