//! Actual CLI processes and HTTPS, with explicitly synthetic native keys in a
//! disposable Linux container or macOS runner. Never physical-device evidence.
mod support;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::Generate;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use vault_rs::{
    crypto::*,
    native::NativeConfig,
    protocol::*,
    resident::{Purpose, ResidentConfig, ResidentKey, RuntimeKeyConfig},
    runner::{Bundle, BundleFile},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn write(path: &Path, value: &impl Serialize) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn jwt(value: &AccessClaims, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        encode(br#"{"typ":"at+jwt","alg":"ES256"}"#),
        encode(&serde_json::to_vec(value).unwrap())
    );
    let sig: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", encode(&sig.to_bytes()))
}
fn service_key(
    root: &Path,
    name: &str,
    protector: NativeConfig,
    purpose: Purpose,
) -> (RuntimeKeyConfig, String) {
    let (envelope, public_key) = ResidentKey::generate(&protector.public_key, purpose).unwrap();
    let path = root.join(format!("{name}.envelope.json"));
    write(&path, &envelope);
    (
        RuntimeKeyConfig::Resident(ResidentConfig {
            protector,
            envelope: path,
            purpose,
            public_key: public_key.clone(),
        }),
        public_key,
    )
}
fn start(
    binary: &Path,
    kind: &str,
    config: &Path,
    client: &reqwest::blocking::Client,
    origin: &str,
) -> Process {
    let mut p = Process(
        Command::new(binary)
            .args([kind, "--config"])
            .arg(config)
            .arg("--verification-run")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..150 {
        assert!(
            p.0.try_wait().unwrap().is_none(),
            "service exited during startup"
        );
        if client.get(origin).send().is_ok() {
            return p;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("service startup timeout");
}

#[test]
#[ignore = "requires disposable root container; scripts/test-deployment.sh"]
fn real_cli_services_broker_two_users_restart_and_revocation() {
    assert!(nix::unistd::geteuid().is_root());
    let root = PathBuf::from("/opt/vault-deployment-test");
    fs::create_dir(&root).unwrap();
    let staging = root.join("staging");
    fs::create_dir(&staging).unwrap();
    let binary = PathBuf::from(std::env::var("VAULT_TEST_RUNNER_BIN").unwrap());
    let helper = PathBuf::from("/opt/deployment-test-helper");
    #[cfg(target_os = "macos")]
    let key_uid = Some(
        std::env::var("VAULT_TEST_MACOS_KEY_UID")
            .unwrap()
            .parse::<u32>()
            .unwrap(),
    );
    #[cfg(not(target_os = "macos"))]
    let key_uid: Option<u32> = None;
    let output = Command::new(&helper)
        .args(["--fixture-init", &key_uid.unwrap_or(0).to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let keys: Value = serde_json::from_slice(&output.stdout).unwrap();
    use sha2::{Digest, Sha256};
    let helper_hash = hex::encode(Sha256::digest(fs::read(&helper).unwrap()));
    let native = |id: &str, usage: &str| NativeConfig {
        macos_uid: key_uid,
        helper: helper.clone(),
        helper_sha256: helper_hash.clone(),
        key_id: id.into(),
        public_key: keys[id][usage].as_str().unwrap().into(),
    };
    let (gate_signing, gate_signing_public) = service_key(
        &root,
        "gate-signing",
        native("gate", "agreement"),
        Purpose::Signing,
    );
    let (gate_decryption, gate_decryption_public) = service_key(
        &root,
        "gate-decryption",
        native("gate", "agreement"),
        Purpose::Agreement,
    );
    let (witness_signing, witness_public) = service_key(
        &root,
        "witness-signing",
        native("witness", "agreement"),
        Purpose::Signing,
    );
    let (witness_decryption, _) = service_key(
        &root,
        "witness-decryption",
        native("witness", "agreement"),
        Purpose::Agreement,
    );
    let cert = root.join("tls.crt");
    let tls_key = root.join("tls.key");
    support::localhost_certificate(&cert, &tls_key);
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .add_root_certificate(reqwest::Certificate::from_pem(&fs::read(&cert).unwrap()).unwrap())
        .build()
        .unwrap();
    let wp = port();
    let vp = port();
    let wo = format!("https://localhost:{wp}");
    let vo = format!("https://localhost:{vp}");
    let owner = SigningKey::generate();
    let issuer = SigningKey::generate();
    let guardian = SigningKey::generate();
    let trust = Trust {
        vault: Uuid::new_v4(),
        audience: vo.clone(),
        issuer: "https://synthetic-issuer.invalid".into(),
        issuer_public_key: public(&issuer),
        owner_public_key: public(&owner),
    };
    let wc = root.join("witness.json");
    let vc = root.join("vault.json");
    write(
        &wc,
        &json!({"listen":format!("127.0.0.1:{wp}"),"certificate":cert,"tls_key":tls_key,"database":root.join("witness.db"),"backend":{"kind":"native","signing":witness_signing,"decryption":witness_decryption},"operator_public_key":gate_signing_public}),
    );
    write(
        &vc,
        &json!({"listen":format!("127.0.0.1:{vp}"),"certificate":cert,"tls_key":tls_key,"database":root.join("vault.db"),"backend":{"kind":"native","signing":gate_signing,"decryption":gate_decryption},"trust":trust,"witness_url":format!("{wo}/v1/witness"),"witness_public_key":witness_public,"witness_ca":cert}),
    );
    // The normal launch must not mistake synthetic software evidence for acceptance.
    assert!(!Command::new(&binary)
        .args(["serve", "--config"])
        .arg(&vc)
        .output()
        .unwrap()
        .status
        .success());
    let mut witness = start(&binary, "witness", &wc, &client, &wo);
    let mut vault = start(&binary, "serve", &vc, &client, &vo);
    let native_calls_after_startup = fs::read_to_string(root.join("calls.log"))
        .unwrap()
        .lines()
        .count();
    let record = seal_record(
        RecordContext {
            vault: trust.vault,
            resource: Uuid::new_v4(),
            version: 1,
        },
        b"SYNTHETIC AUTHORIZED SECRET",
        keys["device"]["agreement"].as_str().unwrap(),
        &gate_decryption_public,
    )
    .unwrap();
    let rp = root.join("record.json");
    write(&rp, &record);
    let workload = b"#!/usr/bin/python3\nimport os,sys\nassert os.getuid()>=10000\nassert os.getgid()==os.getuid() and all(g==os.getuid() for g in os.getgroups())\nassert sys.stdin.buffer.read()==b'SYNTHETIC AUTHORIZED SECRET'\nassert 'VAULT_PARENT_ONLY' not in os.environ\nprint('WORKLOAD_OK')\n";
    let bundle = Bundle {
        entrypoint: "main.py".into(),
        arguments: vec![],
        files: vec![BundleFile {
            path: "main.py".into(),
            contents: encode(workload),
            executable: true,
        }],
    };
    let bp = root.join("bundle.json");
    write(&bp, &bundle);
    let namespace = Uuid::new_v4();
    let mut grants = Vec::new();
    for subject in ["alice", "bob"] {
        let bc = root.join(format!("broker-{subject}.json"));
        write(
            &bc,
            &json!({"trust":trust,"subject":subject,"record":rp,"bundle":bp,"staging_directory":staging,"ai_uid":1000,"uid_base":10000,"uid_limit":20000,"timeout_seconds":5,"device_signing":native("device","signing"),"device_decryption":native("device","agreement"),"allocator_signing":gate_signing,"allocator_namespace":namespace,"allocator_url":format!("{wo}/v1/witness"),"allocator_public_key":witness_public,"ca":cert,"allocator_ca":cert}),
        );
        let mut broker = Process(
            Command::new(&binary)
                .args(["broker", "--config"])
                .arg(&bc)
                .arg("--verification-run")
                .env("VAULT_PARENT_ONLY", "SYNTHETIC PARENT SECRET")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut input = broker.0.stdin.take().unwrap();
        let output = broker.0.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let intent: Value =
            serde_json::from_str(&rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        let dpop: Jwk = serde_json::from_value(intent["dpop"].clone()).unwrap();
        let grant = sign(
            "owner-grant",
            &Grant {
                vault: trust.vault,
                id: Uuid::new_v4(),
                subject: subject.into(),
                resource: record.context.resource,
                version: 1,
                record_hash: object_hash(&record).unwrap(),
                action: Action::Read,
                issue: None,
                epoch: 1,
                not_before: now() - 1,
                expires: now() + 120,
                uses: 1,
                dpop_thumbprint: dpop.thumbprint().unwrap(),
                device_public_key: keys["device"]["signing"].as_str().unwrap().into(),
                guardian_public_key: public(&guardian),
                recipient: intent["recipient"].as_str().unwrap().into(),
                instance: serde_json::from_value(intent["instance"].clone()).unwrap(),
                artifact_hash: bundle.hash().unwrap(),
            },
            &owner,
        )
        .unwrap();
        let token = jwt(
            &AccessClaims {
                iss: trust.issuer.clone(),
                aud: vo.clone(),
                sub: subject.into(),
                exp: now() + 120,
                nbf: now() - 1,
                scope: "secret:read".into(),
                grant_id: grant.payload.id,
                cnf: Confirmation {
                    jkt: dpop.thumbprint().unwrap(),
                },
            },
            &issuer,
        );
        writeln!(input, "{}", json!({"grant":grant,"access_token":token})).unwrap();
        input.flush().unwrap();
        let operation: Operation =
            serde_json::from_str(&rx.recv_timeout(Duration::from_secs(5)).unwrap()).unwrap();
        assert_eq!(operation.grant, grant.payload.id);
        let approval = sign("guardian-operation", &operation, &guardian).unwrap();
        writeln!(
            input,
            "{}",
            json!({"guardian_signature":approval.signature})
        )
        .unwrap();
        input.flush().unwrap();
        drop(input);
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            "WORKLOAD_OK"
        );
        assert!(broker.0.wait().unwrap().success());
        assert!(!client
            .post(format!("{vo}/v1/challenge"))
            .json(&grant)
            .send()
            .unwrap()
            .status()
            .is_success());
        grants.push(grant);
    }
    let calls = fs::read_to_string(root.join("calls.log")).unwrap();
    // Service keys remain resident: after startup only each broker's device sign
    // and ECDH plus allocator startup-unlock reach the native fixture.
    let later = calls
        .lines()
        .skip(native_calls_after_startup)
        .collect::<Vec<_>>();
    assert_eq!(later.iter().filter(|v| **v == "device:sign").count(), 2);
    assert_eq!(later.iter().filter(|v| **v == "device:ecdh").count(), 2);
    assert_eq!(later.iter().filter(|v| **v == "gate:ecdh").count(), 2);
    assert!(!later.iter().any(|v| v.starts_with("witness:")));
    drop(vault);
    drop(witness);
    witness = start(&binary, "witness", &wc, &client, &wo);
    vault = start(&binary, "serve", &vc, &client, &vo);
    for grant in &grants {
        assert!(!client
            .post(format!("{vo}/v1/challenge"))
            .json(grant)
            .send()
            .unwrap()
            .status()
            .is_success());
        let revoked = sign(
            "owner-revoke",
            &Revocation {
                vault: trust.vault,
                grant: grant.payload.id,
            },
            &owner,
        )
        .unwrap();
        assert!(client
            .post(format!("{vo}/v1/revoke"))
            .json(&revoked)
            .send()
            .unwrap()
            .status()
            .is_success());
    }
    drop(vault);
    drop(witness);
    println!("PASS: real CLI HTTPS witness/Vault/broker; two subjects; isolated private-pipe workload; resident service keys; independent process restart; no restored uses; owner revocation. SOFTWARE KEY FIXTURE ONLY.");
}
