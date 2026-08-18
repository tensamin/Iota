const TARGET_KIND_MASK: u64 = 0xC000_0000_0000_0000;
const TARGET_ID_MASK: u64 = (1_u64 << 48) - 1;
const USER_TARGET_KIND: u64 = 0x4000_0000_0000_0000;
const IOTA_TARGET_KIND: u64 = 0x8000_0000_0000_0000;

/*
 * Relay receivers carry their namespace in the wire identity. This prevents
 * a user ID and an Iota ID with the same numeric value from selecting the
 * wrong connection at an Omikron.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteTarget {
    User(u64),
    Iota(u64),
}

impl RouteTarget {
    pub fn wire_id(self) -> Option<u64> {
        let (kind, id) = match self {
            Self::User(id) => (USER_TARGET_KIND, id),
            Self::Iota(id) => (IOTA_TARGET_KIND, id),
        };
        (id > 0 && id <= TARGET_ID_MASK).then_some(kind | id)
    }

    pub fn from_wire_id(value: u64) -> Option<Self> {
        let id = value & TARGET_ID_MASK;
        if id == 0 || value & !(TARGET_KIND_MASK | TARGET_ID_MASK) != 0 {
            return None;
        }

        match value & TARGET_KIND_MASK {
            USER_TARGET_KIND => Some(Self::User(id)),
            IOTA_TARGET_KIND => Some(Self::Iota(id)),
            _ => None,
        }
    }

    pub const fn id(self) -> u64 {
        match self {
            Self::User(id) | Self::Iota(id) => id,
        }
    }
}
