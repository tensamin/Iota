use super::*;

impl OmikronConnection {
    pub async fn handle_message(self: Arc<Self>, cv: CommunicationValue) {
        if cv.type_map().is_none() {
            return;
        }
        if !matches!(
            cv.get_comm_type_enum(),
            Some(
                CommunicationType::PasswordEnrollmentStart
                    | CommunicationType::PasswordEnrollmentFinish
                    | CommunicationType::PasswordEnrollmentStatus
                    | CommunicationType::PasswordEnrollmentDisable
                    | CommunicationType::PasswordProvisioningStart
                    | CommunicationType::PasswordProvisioningFinish
            )
        ) {
            log_cv_in!(&cv);
        }

        let Some(msg_id) = cv.id() else {
            self.handle_message_impl(cv).await;
            return;
        };

        if !cv.is_type(CommunicationType::Relay)
            && self
                .request_attempt()
                .await
                .is_ok_and(|attempt| attempt.responses.complete(msg_id, cv.clone()))
        {
            return;
        }

        self.clone().handle_message_impl(cv).await;
    }

    pub(super) async fn handle_message_impl(self: Arc<Self>, cv: CommunicationValue) {
        if cv.type_map().is_none() {
            log!("Rejecting Omikron frame without a negotiated type map");
            return;
        }
        if cv.is_type(CommunicationType::Relay) {
            self.dispatch_relay(cv).await;
            return;
        }
        if cv.require_id().is_err() {
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        if matches!(
            iota_connection::relay::message_security_class(&cv),
            iota_connection::relay::MessageSecurityClass::RelayOnly
                | iota_connection::relay::MessageSecurityClass::Unsupported
        ) {
            log!("Rejecting sender-based application mutation outside Relay");
            let _ = self
                .send_message(&error_response(&cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        }

        macro_rules! dispatch {
            ($ty:ident, $method:ident) => {
                if cv.is_type(CommunicationType::$ty) {
                    self.clone().$method(&cv).await;
                    return;
                }
            };
        }

        dispatch!(GetChatSecret, handle_get_chat_secret);
        dispatch!(TAuthAuthorize, handle_tauth_authorize);
        dispatch!(PasswordEnrollmentStart, handle_password_enrollment_start);
        dispatch!(PasswordEnrollmentFinish, handle_password_enrollment_finish);
        dispatch!(PasswordEnrollmentStatus, handle_password_enrollment_status);
        dispatch!(
            PasswordEnrollmentDisable,
            handle_password_enrollment_disable
        );
        dispatch!(
            PasswordProvisioningStart,
            handle_password_provisioning_start
        );
        dispatch!(
            PasswordProvisioningFinish,
            handle_password_provisioning_finish
        );
        dispatch!(TAuthExchangeCode, handle_tauth_exchange_code);
        dispatch!(TAuthUser, handle_tauth_user);
        dispatch!(TAuthContacts, handle_tauth_contacts);
        dispatch!(TAuthPublicLookup, handle_tauth_public_lookup);
        dispatch!(TAuthMetadataGet, handle_tauth_metadata_get);
        dispatch!(TAuthMetadataSet, handle_tauth_metadata_set);
        dispatch!(TAuthMetadataDelete, handle_tauth_metadata_delete);
        dispatch!(TAuthDisconnectDelete, handle_tauth_disconnect_delete);
        dispatch!(TAuthGrantList, handle_tauth_grant_list);
        dispatch!(TAuthGrantRevoke, handle_tauth_grant_revoke);
        dispatch!(TAuthGrantMetadataSet, handle_tauth_grant_metadata_set);
        dispatch!(AccountStateRequest, handle_account_state_request);
        dispatch!(RelayReceiptPage, handle_relay_receipt_page);
        dispatch!(AccountStateApplied, handle_account_state_applied);
        dispatch!(ReadNotification, handle_read_notification);
        dispatch!(MessageEdit, handle_message_edit);
        dispatch!(MessageEditLive, handle_message_edit_live);
        dispatch!(MessageReactionAdd, handle_message_reaction_add);
        dispatch!(MessageReactionRemove, handle_message_reaction_remove);
        dispatch!(MessageReactionLive, handle_message_reaction_live);
        dispatch!(MessageDeleteLive, handle_message_delete_live);
        dispatch!(MessageGet, handle_message_get);
        dispatch!(MessagesGet, handle_messages_get);
        dispatch!(GetChats, handle_get_chats);
        dispatch!(AddCommunity, handle_add_community);
        dispatch!(GetCommunities, handle_get_communities);
        dispatch!(RemoveCommunity, handle_remove_community);
        dispatch!(GlobalSettingsSave, handle_global_settings_save);
        dispatch!(GlobalSettingsLoad, handle_global_settings_load);
        dispatch!(SettingsSave, handle_settings_save);
        dispatch!(SettingsLoad, handle_settings_load);
        dispatch!(SettingsList, handle_settings_list);
        dispatch!(SyncedSettingSet, handle_synced_setting_set);
        dispatch!(SyncedSettingGet, handle_synced_setting_get);
        dispatch!(SyncedSettingDelete, handle_synced_setting_delete);
        dispatch!(SyncedSettingsList, handle_synced_settings_list);
        dispatch!(UserBlobPut, handle_user_blob_put);
        dispatch!(UserBlobGet, handle_user_blob_get);
        dispatch!(UserBlobDelete, handle_user_blob_delete);
        dispatch!(UserBlobList, handle_user_blob_list);
        dispatch!(UserAssetUploadStart, handle_user_asset_upload_start);
        dispatch!(UserAssetUploadChunk, handle_user_asset_upload_chunk);
        dispatch!(UserAssetUploadStatus, handle_user_asset_upload_status);
        dispatch!(UserAssetUploadCommit, handle_user_asset_upload_commit);
        dispatch!(UserAssetUploadAbort, handle_user_asset_upload_abort);
        dispatch!(UserAssetGetChunk, handle_user_asset_get_chunk);
        dispatch!(UserAssetList, handle_user_asset_list);
        dispatch!(UserAssetDelete, handle_user_asset_delete);
        dispatch!(UserBlock, handle_user_block);
        dispatch!(UserUnblock, handle_user_unblock);
        dispatch!(BlockedUsersGet, handle_blocked_users_get);
        dispatch!(ReceiptPolicyGet, handle_receipt_policy_get);
        dispatch!(ReceiptPolicySet, handle_receipt_policy_set);
        dispatch!(MessageStoragePolicyGet, handle_message_storage_policy_get);
        dispatch!(MessageStoragePolicySet, handle_message_storage_policy_set);
        dispatch!(UserBlockCheck, handle_user_block_check);
        dispatch!(CallContactCheck, handle_call_contact_check);
        dispatch!(CallEnvelopeStore, handle_call_envelope_store);
        dispatch!(CallEnvelopeGet, handle_call_envelope_get);
        dispatch!(CallContactAccept, handle_call_contact_accept);
        dispatch!(EraseHostedUserData, handle_erase_hosted_user_data);
        dispatch!(ProvisionIotaUser, handle_iota_user_provisioning);
    }
}
