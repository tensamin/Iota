#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AuthUser {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub public_key: String,
}

impl AuthUser {
    pub fn new(id: i64, username: String, password_hash: String, public_key: String) -> Self {
        AuthUser {
            id,
            username,
            password_hash,
            public_key,
        }
    }
}
