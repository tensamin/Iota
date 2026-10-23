use super::*;

pub fn handle_add_community(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let Some(address) = cv.get_data(DataType::CommunityAddress).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(title) = cv.get_data(DataType::CommunityTitle).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    let Some(position) = cv.get_data(DataType::Position).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if CommunitiesUtil::add_community(
        sender_id,
        address.to_string(),
        title.to_string(),
        position.to_string(),
    )
    .is_err()
    {
        return error_response(cv, CommunicationType::ErrorInternal);
    }
    CommunicationValue::new(CommunicationType::AddCommunity)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}

pub fn handle_get_communities(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let communities = match community_values(
        sender_id,
        cv.type_map().unwrap_or(&mtp::codec::TypeMap::latest()),
    ) {
        Ok(communities) => communities,
        Err(_) => return error_response(cv, CommunicationType::ErrorInternal),
    };
    CommunicationValue::new(CommunicationType::GetCommunities)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
        .add_typed_default(DataType::Communities, DataValue::Array(communities))
}

pub(super) fn community_values(
    storage_owner: i64,
    map: &mtp::codec::TypeMap,
) -> Result<Vec<DataValue>, StorageError> {
    CommunitiesUtil::get_communities(storage_owner)?
        .into_iter()
        .map(|community| {
            tau::typed_container(
                map,
                vec![
                    (
                        DataType::CommunityAddress,
                        DataValue::Str(community.address),
                    ),
                    (DataType::CommunityTitle, DataValue::Str(community.title)),
                    (DataType::Position, DataValue::Str(community.position)),
                ],
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| StorageError::Other(error.to_string()))
}

pub fn handle_remove_community(cv: &CommunicationValue) -> CommunicationValue {
    let sender_id = match required_sender_id(cv) {
        Ok(sender_id) => sender_id,
        Err(response) => return response,
    };
    let Some(address) = cv.get_data(DataType::CommunityAddress).as_str() else {
        return error_response(cv, CommunicationType::ErrorInvalidData);
    };
    if CommunitiesUtil::remove_community(sender_id, address.to_string()).is_err() {
        return error_response(cv, CommunicationType::ErrorInternal);
    }
    CommunicationValue::new(CommunicationType::RemoveCommunity)
        .with_request_id(cv)
        .with_receiver(sender_wire_id(sender_id))
}
