use mtp::codec::{CommunicationType, CommunicationValue};

pub use tau::MessageSecurityClass;

/// Classification does not authorize a sender. Handlers still enforce their
/// principal-specific application and Omikron control permissions.
pub fn message_security_class(frame: &CommunicationValue) -> MessageSecurityClass {
    const PEER_CONTROL_TYPES: &[CommunicationType] = &[
        CommunicationType::Relay,
        CommunicationType::GetChatSecret,
        CommunicationType::MessageGet,
        CommunicationType::MessagesGet,
    ];
    const LOCAL_REQUEST_TYPES: &[CommunicationType] = &[
        CommunicationType::Challenge,
        CommunicationType::UserResolve,
        CommunicationType::TAuthAuthorize,
        CommunicationType::PasswordEnrollmentStart,
        CommunicationType::PasswordEnrollmentFinish,
        CommunicationType::PasswordEnrollmentStatus,
        CommunicationType::PasswordEnrollmentDisable,
        CommunicationType::PasswordProvisioningStart,
        CommunicationType::PasswordProvisioningFinish,
        CommunicationType::TAuthExchangeCode,
        CommunicationType::TAuthUser,
        CommunicationType::TAuthContacts,
        CommunicationType::TAuthPublicLookup,
        CommunicationType::TAuthMetadataGet,
        CommunicationType::TAuthMetadataSet,
        CommunicationType::TAuthMetadataDelete,
        CommunicationType::TAuthDisconnectDelete,
        CommunicationType::TAuthGrantList,
        CommunicationType::TAuthGrantRevoke,
        CommunicationType::TAuthGrantMetadataSet,
        CommunicationType::AccountStateRequest,
        CommunicationType::RelayReceiptPage,
        CommunicationType::AccountStateApplied,
        CommunicationType::ReadNotification,
        CommunicationType::GetChats,
        CommunicationType::GetCommunities,
        CommunicationType::GlobalSettingsLoad,
        CommunicationType::SettingsLoad,
        CommunicationType::SettingsList,
        CommunicationType::SyncedSettingSet,
        CommunicationType::SyncedSettingGet,
        CommunicationType::SyncedSettingDelete,
        CommunicationType::SyncedSettingsList,
        CommunicationType::UserBlobPut,
        CommunicationType::UserBlobGet,
        CommunicationType::UserBlobDelete,
        CommunicationType::UserBlobList,
        CommunicationType::UserAssetUploadStart,
        CommunicationType::UserAssetUploadChunk,
        CommunicationType::UserAssetUploadStatus,
        CommunicationType::UserAssetUploadCommit,
        CommunicationType::UserAssetUploadAbort,
        CommunicationType::UserAssetGetChunk,
        CommunicationType::UserAssetList,
        CommunicationType::UserAssetDelete,
        CommunicationType::UserBlock,
        CommunicationType::UserUnblock,
        CommunicationType::BlockedUsersGet,
        CommunicationType::ReceiptPolicyGet,
        CommunicationType::ReceiptPolicySet,
        CommunicationType::MessageStoragePolicyGet,
        CommunicationType::MessageStoragePolicySet,
        CommunicationType::UserBlockCheck,
        CommunicationType::CallContactCheck,
        CommunicationType::CallEnvelopeStore,
        CommunicationType::CallEnvelopeGet,
        CommunicationType::CallContactAccept,
        CommunicationType::EraseHostedUserData,
        CommunicationType::ProvisionIotaUser,
    ];
    tau::message_security_class_with(frame, PEER_CONTROL_TYPES, LOCAL_REQUEST_TYPES)
}

#[cfg(test)]
mod security_tests {
    use super::{MessageSecurityClass, message_security_class};
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn relay_envelopes_require_authenticated_peer_control() {
        assert_eq!(
            message_security_class(&CommunicationValue::new(CommunicationType::Relay)),
            MessageSecurityClass::AuthenticatedPeerControl
        );
    }

    #[test]
    fn synchronized_setting_requests_are_authenticated_local_requests() {
        for setting_type in [
            CommunicationType::SyncedSettingSet,
            CommunicationType::SyncedSettingGet,
            CommunicationType::SyncedSettingDelete,
            CommunicationType::SyncedSettingsList,
        ] {
            assert_eq!(
                message_security_class(&CommunicationValue::new(setting_type)),
                MessageSecurityClass::AuthenticatedLocalRequest
            );
        }
    }
}
