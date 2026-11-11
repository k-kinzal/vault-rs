//! Role separation for enrolled non-exportable key handles.
//! Hardware non-exportability is a primitive contract, not proved by this matrix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
#[cfg_attr(feature = "wire", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wire", serde(rename_all = "snake_case"))]
pub enum KeyUsage {
    #[default]
    Interactive,
    Service,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum KeyRole {
    ApprovalSigning,
    DeviceSigning,
    DeviceUnwrap,
    ServiceSigning,
    ServiceUnwrap,
    TlsSigning,
}

pub fn key_allowed(role: KeyRole, usage: KeyUsage, agreement: bool) -> bool {
    match role {
        KeyRole::ApprovalSigning | KeyRole::DeviceSigning => {
            usage == KeyUsage::Interactive && !agreement
        }
        KeyRole::DeviceUnwrap => usage == KeyUsage::Interactive && agreement,
        KeyRole::ServiceSigning | KeyRole::TlsSigning => usage == KeyUsage::Service && !agreement,
        KeyRole::ServiceUnwrap => usage == KeyUsage::Service && agreement,
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn key_role_separation_is_exact() {
        let role: KeyRole = kani::any();
        let usage: KeyUsage = kani::any();
        let agreement: bool = kani::any();
        let interactive = matches!(
            role,
            KeyRole::ApprovalSigning | KeyRole::DeviceSigning | KeyRole::DeviceUnwrap
        );
        let unwrap = matches!(role, KeyRole::DeviceUnwrap | KeyRole::ServiceUnwrap);
        assert_eq!(
            key_allowed(role, usage, agreement),
            (interactive == (usage == KeyUsage::Interactive)) && (unwrap == agreement)
        );
    }
    #[kani::proof]
    fn service_keys_cannot_authorize_user_approval() {
        let agreement: bool = kani::any();
        assert!(!key_allowed(
            KeyRole::ApprovalSigning,
            KeyUsage::Service,
            agreement
        ));
        assert!(!key_allowed(
            KeyRole::DeviceSigning,
            KeyUsage::Service,
            agreement
        ));
        assert!(!key_allowed(
            KeyRole::DeviceUnwrap,
            KeyUsage::Service,
            agreement
        ));
    }
}
