#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DisabledFocusPolicy {
    Include,
    #[default]
    Skip,
}
