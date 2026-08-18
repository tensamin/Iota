use mtp::codec::{CommunicationValue, DataValue};
use mtp::type_map::DataTypeId;

/*
 * Keep legacy control-plane handlers source-compatible while they migrate to
 * MTP's explicit optional routing fields. Relay handlers must use sender() and
 * receiver() directly so an absent outer sender cannot become an identity.
 */
pub trait CommunicationValueCompat {
    fn get_id(&self) -> u32;
    fn get_sender(&self) -> u64;
    fn get_receiver(&self) -> u64;
}

impl CommunicationValueCompat for CommunicationValue {
    fn get_id(&self) -> u32 {
        self.id().unwrap_or_default()
    }

    fn get_sender(&self) -> u64 {
        self.sender().unwrap_or_default()
    }

    fn get_receiver(&self) -> u64 {
        self.receiver().unwrap_or_default()
    }
}

pub trait OptionalDataValueExt<'a> {
    fn as_bool(self) -> Option<bool>;
    fn as_str(self) -> Option<&'a str>;
    fn as_string(self) -> Option<String>;
    fn as_number(self) -> Option<i128>;
    fn as_signed_number(self) -> Option<i128>;
    fn as_array(self) -> Option<Vec<DataValue>>;
    fn as_container(self) -> Option<Vec<(DataTypeId, DataValue)>>;
}

impl<'a> OptionalDataValueExt<'a> for Option<&'a DataValue> {
    fn as_bool(self) -> Option<bool> {
        self.and_then(DataValue::as_bool)
    }

    fn as_str(self) -> Option<&'a str> {
        self.and_then(DataValue::as_str)
    }

    fn as_string(self) -> Option<String> {
        self.and_then(DataValue::as_string)
    }

    fn as_number(self) -> Option<i128> {
        self.and_then(DataValue::as_number)
    }

    fn as_signed_number(self) -> Option<i128> {
        self.and_then(DataValue::as_signed_number)
    }

    fn as_array(self) -> Option<Vec<DataValue>> {
        self.and_then(DataValue::as_array)
    }

    fn as_container(self) -> Option<Vec<(DataTypeId, DataValue)>> {
        self.and_then(DataValue::as_container)
    }
}
