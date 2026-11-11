//! Untrusted pure-Wasm proposal plugins: no host imports, WASI, credentials,
//! filesystem, sockets, clocks or entropy. Only a fixed-size IssueSpec crosses
//! this boundary. The trusted issuer remains the sole credential authority.
use crate::{crypto::digest, extension::*};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;
use wasmi::{Config, Engine, Linker, Module, Store, StoreLimitsBuilder};

const MAX_MODULE: usize = 131072;
const MAX_JSON: usize = 4096;
const MEMORY: usize = 65536;
const FUEL: u64 = 100000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionConfig {
    pub module: PathBuf,
    pub sha256: String,
}

pub struct ProposalModule {
    engine: Engine,
    module: Module,
}
impl ProposalModule {
    pub fn load(config: &ExtensionConfig) -> Result<Self> {
        let bytes = crate::runner::read_bounded(&config.module, MAX_MODULE as u64)?;
        Self::from_bytes(&bytes, &config.sha256)
    }
    pub fn from_bytes(bytes: &[u8], expected_hash: &str) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_MODULE && bytes.starts_with(b"\0asm"),
            "invalid Wasm binary"
        );
        ensure!(digest(bytes) == expected_hash, "extension digest mismatch");
        let mut config = Config::default();
        config.consume_fuel(true);
        let engine = Engine::new(&config);
        let module = Module::new(&engine, bytes)?;
        ensure!(
            module.imports().len() == 0,
            "extensions may not import host capabilities"
        );
        Ok(Self { engine, module })
    }
    pub fn evaluate(&self, requested: &IssueSpec) -> Result<IssueSpec> {
        let input = serde_json::to_vec(requested)?;
        ensure!(input.len() <= MAX_JSON, "proposal too large");
        let limits = StoreLimitsBuilder::new()
            .memory_size(MEMORY)
            .memories(1)
            .tables(0)
            .instances(1)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|limits| limits);
        store.set_fuel(FUEL)?;
        let instance = Linker::<wasmi::StoreLimits>::new(&self.engine)
            .instantiate_and_start(&mut store, &self.module)?;
        let memory = instance
            .get_memory(&store, "memory")
            .context("missing extension memory")?;
        memory.write(&mut store, 0, &input)?;
        let propose = instance.get_typed_func::<(i32, i32), i64>(&store, "propose")?;
        let output = propose.call(&mut store, (0, input.len() as i32))? as u64;
        let pointer = (output >> 32) as usize;
        let length = (output & 0xffff_ffff) as usize;
        ensure!(
            length <= MAX_JSON && pointer.checked_add(length).is_some_and(|end| end <= MEMORY),
            "extension output exceeds bounds"
        );
        let mut bytes = vec![0; length];
        memory.read(&store, pointer, &mut bytes)?;
        let proposal: IssueSpec = serde_json::from_slice(&bytes)?;
        ensure!(
            proposal == *requested,
            "extension altered signed authorization"
        );
        Ok(proposal)
    }
}

pub struct SandboxedIssuer {
    inner: Arc<dyn Issuer>,
    extension: ProposalModule,
}
impl SandboxedIssuer {
    pub fn new(inner: Arc<dyn Issuer>, extension: ProposalModule) -> Self {
        Self { inner, extension }
    }
}
impl Issuer for SandboxedIssuer {
    fn issue(&self, permit: &CommittedIssue, now: u64) -> Result<IssuedLease> {
        self.extension.evaluate(&permit.inner.spec)?;
        self.inner.issue(permit, now)
    }
    fn revoke(&self, id: &str) -> Result<()> {
        self.inner.revoke(id)
    }
    fn revoke_grant(&self, grant: Uuid) -> Result<()> {
        self.inner.revoke_grant(grant)
    }
    fn expire(&self, now: u64) -> Result<usize> {
        self.inner.expire(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn module(wat: &str) -> Result<ProposalModule> {
        let bytes = wat::parse_str(wat)?;
        ProposalModule::from_bytes(&bytes, &digest(&bytes))
    }
    fn spec() -> IssueSpec {
        IssueSpec {
            provider: "postgres".into(),
            role: "reader".into(),
            ttl_seconds: 10,
        }
    }
    #[test]
    fn valid_plugin_roundtrip() {
        let m=module(r#"(module (memory (export "memory") 1 1) (func (export "propose") (param i32 i32) (result i64) local.get 1 i64.extend_i32_u))"#).unwrap();
        assert_eq!(m.evaluate(&spec()).unwrap(), spec());
    }
    #[test]
    fn imports_digest_changes_and_wasi_are_denied() {
        for name in ["fd_read", "path_open", "sock_open", "get_secret"] {
            assert!(module(&format!(
                r#"(module (import "wasi_snapshot_preview1" "{name}" (func)))"#
            ))
            .is_err());
        }
        assert!(ProposalModule::from_bytes(
            &wat::parse_str("(module)").unwrap(),
            &digest(b"different")
        )
        .is_err());
    }
    #[test]
    fn infinite_loop_memory_and_output_abuse_are_bounded() {
        for code in [
            r#"(module (memory (export "memory") 1) (func (export "propose") (param i32 i32) (result i64) (loop br 0) i64.const 0))"#,
            r#"(module (memory (export "memory") 2) (func (export "propose") (param i32 i32) (result i64) i64.const 0))"#,
            r#"(module (memory (export "memory") 1) (func (export "propose") (param i32 i32) (result i64) i64.const -1))"#,
            r#"(module (memory (export "memory") 1) (func (export "propose") (param i32 i32) (result i64) i32.const 0 i32.const 65 i32.store8 local.get 1 i64.extend_i32_u))"#,
            r#"(module (func $s (loop br 0)) (start $s))"#,
        ] {
            assert!(module(code).unwrap().evaluate(&spec()).is_err());
        }
    }
}
