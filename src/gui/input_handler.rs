use crate::gui::ui::{UI, UNIQUE};
use crate::{RELOAD, SHUTDOWN};
use crossterm::event::{Event, KeyEvent, KeyEventKind, KeyModifiers, poll, read};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub fn setup_input_handler(ui: Arc<UI>) {
    tokio::spawn(async move {
        loop {
            if *SHUTDOWN.read().await {
                break;
            }

            let event_result = tokio::task::spawn_blocking(|| {
                if let Ok(true) = poll(Duration::from_millis(100)) {
                    read().ok().and_then(|ev| match ev {
                        Event::Key(key) if key.kind == KeyEventKind::Press => Some(key),
                        _ => None,
                    })
                } else {
                    None
                }
            })
            .await;

            match event_result {
                Ok(Some(key_event)) => {
                    handle_input(key_event, ui.clone()).await;
                    UNIQUE.store(true, Ordering::Relaxed);
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Input task error: {}", e);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });
}

pub async fn handle_input(key: KeyEvent, ui: Arc<UI>) {
    match (key.code, key.modifiers) {
        (crossterm::event::KeyCode::Char('q'), KeyModifiers::CONTROL)
        | (crossterm::event::KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            *SHUTDOWN.write().await = true;
        }
        (crossterm::event::KeyCode::Char('r'), KeyModifiers::CONTROL) => {
            *RELOAD.write().await = true;
            *SHUTDOWN.write().await = true;
        }
        _ => {
            ui.handle_input(key).await;
        }
    }
}
