use mtp::codec::{CommunicationValue, DataValue};
use mtp::type_map::DataTypeId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MtpFieldError {
    MissingId,
    MissingSender,
    MissingReceiver,
}

impl std::fmt::Display for MtpFieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingId => "missing message id",
            Self::MissingSender => "missing sender",
            Self::MissingReceiver => "missing receiver",
        })
    }
}

impl std::error::Error for MtpFieldError {}

pub trait RequiredCommunicationFields {
    fn require_id(&self) -> Result<u32, MtpFieldError>;
    fn require_sender(&self) -> Result<u64, MtpFieldError>;
    fn require_receiver(&self) -> Result<u64, MtpFieldError>;
}

impl RequiredCommunicationFields for CommunicationValue {
    fn require_id(&self) -> Result<u32, MtpFieldError> {
        self.id().ok_or(MtpFieldError::MissingId)
    }

    fn require_sender(&self) -> Result<u64, MtpFieldError> {
        self.sender().ok_or(MtpFieldError::MissingSender)
    }

    fn require_receiver(&self) -> Result<u64, MtpFieldError> {
        self.receiver().ok_or(MtpFieldError::MissingReceiver)
    }
}

#[allow(
    clippy::wrong_self_convention,
    reason = "mirror DataValue accessors on optional borrowed values"
)]
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

#[cfg(test)]
mod tests {
    use super::{MtpFieldError, RequiredCommunicationFields};
    use mtp::codec::{CommunicationType, CommunicationValue};

    #[test]
    fn missing_routing_fields_are_reported_instead_of_defaulted() {
        let message = CommunicationValue::new(CommunicationType::Success).without_id();

        assert_eq!(message.require_id(), Err(MtpFieldError::MissingId));
        assert_eq!(message.require_sender(), Err(MtpFieldError::MissingSender));
        assert_eq!(
            message.require_receiver(),
            Err(MtpFieldError::MissingReceiver)
        );
    }

    #[test]
    fn present_routing_fields_are_returned_unchanged() {
        let message = CommunicationValue::new(CommunicationType::Success)
            .with_id(7)
            .with_sender(8)
            .with_receiver(9);

        assert_eq!(message.require_id(), Ok(7));
        assert_eq!(message.require_sender(), Ok(8));
        assert_eq!(message.require_receiver(), Ok(9));
    }
}
