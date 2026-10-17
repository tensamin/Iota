use super::*;

impl OmikronConnection {
    pub(super) async fn handle_get_chat_secret(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chat_secret(cv))
            .await;
    }

    pub(super) async fn handle_read_notification(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_read_notification(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) fn mutation_live_message(
        ty: CommunicationType,
        request: &CommunicationValue,
        mutation: &message_handlers::MessageMutation,
        extra: Vec<(DataType, DataValue)>,
    ) -> CommunicationValue {
        let mut message = CommunicationValue::new(ty)
            .with_request_id(request)
            .with_sender(wire_user_id(mutation.sender_id))
            .with_receiver(wire_user_id(mutation.partner_id))
            .add_typed_default(
                DataType::ChatPartnerId,
                DataValue::SignedNumber(mutation.sender_id as i128),
            )
            .add_typed_default(
                DataType::SendTime,
                DataValue::SignedNumber(mutation.send_time as i128),
            );
        for (data_type, value) in extra {
            message = message.add_typed_default(data_type, value);
        }
        message
    }

    pub(super) async fn persist_and_deliver_remote_edit(&self, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        let Some(content) = cv.get_data(DataType::Content).as_str() else {
            return;
        };
        if chat_files::apply_remote_edit(receiver_id, sender_id, send_time, sender_id, content)
            .is_ok()
        {
            let _ = self.send_message(cv).await;
        }
    }

    pub(super) async fn persist_and_deliver_remote_reaction(
        &self,
        cv: &CommunicationValue,
        add: bool,
    ) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
            return;
        };
        if reaction.is_empty() || reaction.len() > 64 {
            return;
        }
        let result = if add {
            chat_files::add_reaction(receiver_id, sender_id, send_time, sender_id, reaction)
        } else {
            chat_files::remove_reaction(receiver_id, sender_id, send_time, sender_id, reaction)
        };
        if result.is_ok() {
            let _ = self.send_message(cv).await;
        }
    }

    pub(super) async fn persist_and_deliver_remote_delete(&self, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let receiver_id = match cv
            .require_receiver()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(receiver_id) if receiver_id > 0 => receiver_id,
            _ => return,
        };
        let Some(send_time) = data_i64(cv, DataType::SendTime).filter(|time| *time > 0) else {
            return;
        };
        if chat_files::apply_remote_delete(receiver_id, sender_id, send_time, sender_id).is_ok() {
            let _ = self.send_message(cv).await;
        }
    }

    pub(super) async fn handle_message_edit(self: Arc<Self>, cv: &CommunicationValue) {
        let response = message_handlers::handle_message_edit(cv);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let Some(content) = cv.get_data(DataType::Content).as_str() else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageEditLive,
            cv,
            &mutation,
            vec![(DataType::Content, DataValue::Str(content.to_string()))],
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local
            && chat_files::apply_remote_edit(
                mutation.partner_id,
                mutation.sender_id,
                mutation.send_time,
                mutation.sender_id,
                content,
            )
            .is_err()
        {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                .await;
            return;
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    pub(super) async fn handle_message_edit_live(self: Arc<Self>, cv: &CommunicationValue) {
        self.persist_and_deliver_remote_edit(cv).await;
    }

    pub(super) async fn handle_message_reaction_add(self: Arc<Self>, cv: &CommunicationValue) {
        self.handle_message_reaction(cv, true).await;
    }

    pub(super) async fn handle_message_reaction_remove(self: Arc<Self>, cv: &CommunicationValue) {
        self.handle_message_reaction(cv, false).await;
    }

    pub(super) async fn handle_message_reaction(
        self: Arc<Self>,
        cv: &CommunicationValue,
        add: bool,
    ) {
        let response = message_handlers::handle_message_reaction(cv, add);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let Some(reaction) = cv.get_data(DataType::Reaction).as_str() else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageReactionLive,
            cv,
            &mutation,
            vec![
                (DataType::Reaction, DataValue::Str(reaction.to_string())),
                (
                    DataType::SenderId,
                    DataValue::SignedNumber(mutation.sender_id as i128),
                ),
                (DataType::Accepted, DataValue::Bool(add)),
            ],
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local {
            let result = if add {
                chat_files::add_reaction(
                    mutation.partner_id,
                    mutation.sender_id,
                    mutation.send_time,
                    mutation.sender_id,
                    reaction,
                )
            } else {
                chat_files::remove_reaction(
                    mutation.partner_id,
                    mutation.sender_id,
                    mutation.send_time,
                    mutation.sender_id,
                    reaction,
                )
            };
            if result.is_err() {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                    .await;
                return;
            }
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    pub(super) async fn handle_message_reaction_live(self: Arc<Self>, cv: &CommunicationValue) {
        let add = cv.get_data(DataType::Accepted).as_bool().unwrap_or(true);
        self.persist_and_deliver_remote_reaction(cv, add).await;
    }

    pub(super) async fn handle_message_delete_live(self: Arc<Self>, cv: &CommunicationValue) {
        let sender_id = match cv
            .require_sender()
            .ok()
            .and_then(|id| i64::try_from(id).ok())
        {
            Some(sender_id) => sender_id,
            None => return,
        };
        let sender_is_local = match iota_storage::users::user_manager::get_user(sender_id) {
            Ok(user) => user.is_some(),
            Err(_) => {
                let _ = self
                    .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                    .await;
                return;
            }
        };
        if !sender_is_local {
            self.persist_and_deliver_remote_delete(cv).await;
            return;
        }

        let response = message_handlers::handle_message_delete(cv);
        if !response.is_type(CommunicationType::Success) {
            let _ = self.send_message(&response).await;
            return;
        }
        let Ok(mutation) = message_handlers::message_mutation(cv) else {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorInvalidData))
                .await;
            return;
        };
        let live = Self::mutation_live_message(
            CommunicationType::MessageDeleteLive,
            cv,
            &mutation,
            Vec::new(),
        );
        let partner_is_local =
            match iota_storage::users::user_manager::get_user(mutation.partner_id) {
                Ok(user) => user.is_some(),
                Err(_) => {
                    let _ = self
                        .send_message(&error_response(cv, CommunicationType::ErrorInternal))
                        .await;
                    return;
                }
            };
        if partner_is_local
            && chat_files::apply_remote_delete(
                mutation.partner_id,
                mutation.sender_id,
                mutation.send_time,
                mutation.sender_id,
            )
            .is_err()
        {
            let _ = self
                .send_message(&error_response(cv, CommunicationType::ErrorNotFound))
                .await;
            return;
        }
        let _ = self.send_message(&response).await;
        let _ = self.send_message(&live).await;
    }

    pub(super) async fn handle_messages_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_messages_get(cv))
            .await;
    }

    pub(super) async fn handle_message_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_message_get(cv))
            .await;
    }

    pub(super) async fn handle_get_chats(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_chats(cv))
            .await;
    }

    pub(super) async fn handle_add_community(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_add_community(cv))
            .await;
    }

    pub(super) async fn handle_get_communities(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_get_communities(cv))
            .await;
    }

    pub(super) async fn handle_remove_community(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_remove_community(cv))
            .await;
    }

    pub(super) async fn handle_global_settings_save(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_global_settings_save(cv))
            .await;
    }

    pub(super) async fn handle_global_settings_load(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_global_settings_load(cv))
            .await;
    }

    pub(super) async fn handle_settings_save(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_save(cv, 0))
            .await;
    }

    pub(super) async fn handle_settings_load(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_load(cv, 0))
            .await;
    }

    pub(super) async fn handle_settings_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_settings_list(cv, 0))
            .await;
    }

    pub(super) async fn handle_synced_setting_set(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_synced_setting_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_synced_setting_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_synced_setting_get(cv))
            .await;
    }

    pub(super) async fn handle_synced_setting_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_synced_setting_delete(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_synced_settings_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_synced_settings_list(cv))
            .await;
    }

    pub(super) async fn handle_user_blob_put(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_blob_put(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_blob_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_blob_get(cv))
            .await;
    }

    pub(super) async fn handle_user_blob_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_blob_delete(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_blob_list(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_blob_list(cv))
            .await;
    }

    pub(super) async fn handle_user_asset_upload_start(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_start).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_upload_chunk(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_chunk).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_upload_status(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_status).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_upload_commit(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_commit).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let mutation = result;
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_asset_upload_abort(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_upload_abort).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_get_chunk(self: Arc<Self>, cv: &CommunicationValue) {
        let result =
            match run_asset_handler(cv, message_handlers::handle_user_asset_get_chunk).await {
                Ok(result) => result,
                Err(response) => {
                    let _ = self.send_message(&response).await;
                    return;
                }
            };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_list(self: Arc<Self>, cv: &CommunicationValue) {
        let result = match run_asset_handler(cv, message_handlers::handle_user_asset_list).await {
            Ok(result) => result,
            Err(response) => {
                let _ = self.send_message(&response).await;
                return;
            }
        };
        let _ = self.send_message(&result).await;
    }

    pub(super) async fn handle_user_asset_delete(self: Arc<Self>, cv: &CommunicationValue) {
        let result = match run_asset_handler(cv, message_handlers::handle_user_asset_delete).await {
            Ok(result) => result,
            Err(response) => {
                let _ = self.send_message(&response).await;
                return;
            }
        };
        let mutation = result;
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_block(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_block(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_unblock(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_user_unblock(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_blocked_users_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_blocked_users_get(cv))
            .await;
    }

    pub(super) async fn handle_receipt_policy_get(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_receipt_policy_get(cv))
            .await;
    }

    pub(super) async fn handle_receipt_policy_set(self: Arc<Self>, cv: &CommunicationValue) {
        let mutation = message_handlers::handle_receipt_policy_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_message_storage_policy_get(
        self: Arc<Self>,
        cv: &CommunicationValue,
    ) {
        let _ = self
            .send_message(&message_handlers::handle_message_storage_policy_get(cv))
            .await;
    }

    pub(super) async fn handle_message_storage_policy_set(
        self: Arc<Self>,
        cv: &CommunicationValue,
    ) {
        let mutation = message_handlers::handle_message_storage_policy_set(cv);
        let _ = self.send_message(&mutation.response).await;
        if let Some(changed) = mutation.changed {
            let _ = self.send_message(&changed).await;
        }
    }

    pub(super) async fn handle_user_block_check(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_user_block_check(cv))
            .await;
    }

    pub(super) async fn handle_call_contact_check(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_call_contact_check(cv))
            .await;
    }

    pub(super) async fn handle_call_envelope_store(self: Arc<Self>, cv: &CommunicationValue) {
        let response = match CONFIG.load().omikron_id {
            Some(owner) => message_handlers::handle_call_envelope_store(cv, owner),
            None => error_response(cv, CommunicationType::ErrorInternal),
        };
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn handle_call_envelope_get(self: Arc<Self>, cv: &CommunicationValue) {
        let response = match CONFIG.load().omikron_id {
            Some(owner) => message_handlers::handle_call_envelope_get(cv, owner),
            None => error_response(cv, CommunicationType::ErrorInternal),
        };
        let _ = self.send_message(&response).await;
    }

    pub(super) async fn handle_call_contact_accept(self: Arc<Self>, cv: &CommunicationValue) {
        let _ = self
            .send_message(&message_handlers::handle_call_contact_accept(cv))
            .await;
    }
}
