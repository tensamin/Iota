#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Eula,
    Tos,
    Pp,
    Cancel,
    Continue,
    ContinueAll,
}

impl Focus {
    pub fn next(&mut self, order: &[Focus]) {
        if let Some(pos) = order.iter().position(|&f| f == *self) {
            let next_pos = (pos + 1) % order.len();
            *self = order[next_pos];
        }
    }

    pub fn prev(&mut self, order: &[Focus]) {
        if let Some(pos) = order.iter().position(|&f| f == *self) {
            let prev_pos = if pos == 0 { order.len() - 1 } else { pos - 1 };
            *self = order[prev_pos];
        }
    }
}
