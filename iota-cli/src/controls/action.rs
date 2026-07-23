#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    FocusNext,
    FocusPrevious,
    Select,
    Activate,
}
