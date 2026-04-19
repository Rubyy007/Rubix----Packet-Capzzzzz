//! Message priority levels

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    High,
    Normal,
    Low,
}

impl Default for Priority {
    fn default() -> Self {
        Priority::Normal
    }
}