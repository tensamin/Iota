use super::UserEntry;
pub fn matches_filter(user: &UserEntry, filter: &str) -> bool {
    let needle = filter.to_ascii_lowercase();
    needle.is_empty()
        || user.username.to_ascii_lowercase().contains(&needle)
        || user.user_id.to_string().contains(&needle)
}
