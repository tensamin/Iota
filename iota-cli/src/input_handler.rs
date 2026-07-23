use crate::ui::UI;
use crossterm::event::{Event, KeyEvent, KeyEventKind, KeyModifiers, poll, read};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub fn setup_input_handler(ui: Arc<UI>) -> JoinHandle<Result<(), String>> {
    tokio::spawn(async move {
        let cancellation = ui.cancellation_token();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::task::spawn_blocking(move || -> Result<(), String> {
            while !worker_cancellation.is_cancelled() {
                if poll(Duration::from_millis(100)).map_err(|e| e.to_string())? {
                    tx.send(read().map_err(|e| e.to_string())?)
                        .map_err(|_| "input session closed".to_string())?;
                }
            }
            Ok(())
        });
        loop {
            if ui.is_shutdown() {
                break;
            }

            tokio::select! {
                event = rx.recv() => match event {
                    Some(Event::Key(key)) if key.kind == KeyEventKind::Press => handle_input(key, ui.clone()).await,
                    Some(Event::Resize(_, _)) => ui.invalidate(),
                    Some(Event::Paste(text)) => ui.handle_paste(text).await,
                    Some(_) => {},
                    None => break,
                },
                _ = cancellation.cancelled() => break,
            }
        }
        let result = match worker.await {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(format!("input worker failed: {error}")),
        };
        if result.is_err() {
            ui.request_shutdown();
        }
        result
    })
}

pub async fn handle_input(key: KeyEvent, ui: Arc<UI>) {
    if matches!(
        key.code,
        crossterm::event::KeyCode::Char('q') | crossterm::event::KeyCode::Char('c')
    ) && key.modifiers.contains(KeyModifiers::CONTROL)
    {
        ui.request_shutdown();
    } else {
        ui.handle_input(key).await;
    }
}
