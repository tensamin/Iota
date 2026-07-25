use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;

use crate::screens::screens::{Screen, UiEvent};

#[allow(unused)]
pub enum InteractionResult {
    CloseScreen,
    OpenScreen {
        screen: Box<dyn Screen>,
    },
    OpenFutureScreen {
        screen: Pin<Box<dyn Future<Output = Box<dyn Screen>> + Send>>,
    },
    AppTask {
        task: Pin<Box<dyn Future<Output = UiEvent> + Send>>,
    },
    Handled,
    Unhandled,
}

impl Debug for InteractionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InteractionResult::OpenScreen { screen: _ } => write!(f, "OpenScreen"),
            InteractionResult::OpenFutureScreen { screen: _ } => write!(f, "OpenFutureScreen"),
            InteractionResult::AppTask { task: _ } => write!(f, "AppTask"),
            InteractionResult::CloseScreen => write!(f, "CloseScreen"),
            InteractionResult::Handled => write!(f, "Handled"),
            InteractionResult::Unhandled => write!(f, "Unhandled"),
        }
    }
}

impl PartialEq for InteractionResult {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                InteractionResult::OpenScreen { screen: _ },
                InteractionResult::OpenScreen { screen: _ },
            ) => true,
            (InteractionResult::AppTask { task: _ }, InteractionResult::AppTask { task: _ }) => {
                true
            }
            (
                InteractionResult::OpenFutureScreen { screen: _ },
                InteractionResult::OpenFutureScreen { screen: _ },
            ) => true,
            (InteractionResult::CloseScreen, InteractionResult::CloseScreen) => true,
            (InteractionResult::Handled, InteractionResult::Handled) => true,
            (InteractionResult::Unhandled, InteractionResult::Unhandled) => true,
            _ => false,
        }
    }
}
