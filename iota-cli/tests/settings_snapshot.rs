use iota_cli::{
    interaction_result::InteractionResult,
    render_context::RenderContext,
    screens::{
        screens::{AppEvent, HitMap, Screen, UiEvent},
        settings::SettingsScreen,
    },
    theme::{ThemeName, resolve},
};
use ratatui::{Terminal, backend::TestBackend};
use crossterm::event::{KeyCode, KeyEvent};

fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[tokio::test]
async fn settings_preview_and_save_emit_typed_application_events() {
    let mut screen = SettingsScreen::new(ThemeName::Ansi);
    let preview = screen.handle_event(UiEvent::Key(KeyEvent::from(KeyCode::Right)));
    let InteractionResult::AppTask { task } = preview else {
        panic!("theme preview should emit an application task");
    };
    assert!(matches!(
        task.await,
        UiEvent::App(AppEvent::ApplyTheme {
            theme: ThemeName::Surface,
            persist: false
        })
    ));

    let save = screen.handle_event(UiEvent::Key(KeyEvent::from(KeyCode::Enter)));
    let InteractionResult::AppTask { task } = save else {
        panic!("theme save should emit an application task");
    };
    assert!(matches!(
        task.await,
        UiEvent::App(AppEvent::SaveSettings {
            theme: ThemeName::Surface,
            color: _,
            unicode: _
        })
    ));
}

#[test]
fn settings_is_readable_in_every_theme_and_layout() {
    for theme_name in ThemeName::ALL {
        for (width, height) in [(42, 12), (72, 20), (100, 28)] {
            let theme = resolve(theme_name);
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            let screen = SettingsScreen::new(theme_name);
            terminal
                .draw(|frame| {
                    screen.render(
                        frame,
                        frame.area(),
                        &RenderContext { theme: &theme },
                        &mut HitMap::default(),
                    );
                })
                .unwrap();
            let rendered = buffer_text(&terminal);
            assert!(rendered.contains("Settings"));
            assert!(rendered.contains("Theme:"));
            assert!(rendered.contains("[OK] Healthy"));
            assert!(rendered.contains("[FAIL] Failed"));
        }
    }
}
