use json::JsonValue;

use crate::util::file_util::load_file;
// NOT USED AT MOMENT
pub fn is_private_key_valid(user_id: &i64, key_hash: &str) -> bool {
    let file_contents = load_file("", "users.json");

    let users = json::parse(&file_contents).unwrap();
    if let JsonValue::Array(users_array) = users {
        for user in users_array {
            if user["uuid"] == user_id.to_string() && user["private_key_hash"] == key_hash {
                return true;
            }
        }
    }

    false
}
