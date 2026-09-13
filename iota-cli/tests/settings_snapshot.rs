use crossterm::event::{KeyCode, KeyEvent};
use iota_cli::{
    screens::{
        screens::{HitMap, IotaEffect, IotaInteraction, IotaScreen, UiEvent},
        settings::SettingsScreen,
    },
    theme::{ThemeName, resolve},
};
use ratatui::{Terminal, backend::TestBackend};

fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect()
}

#[test]
fn settings_preview_and_save_emit_typed_effects() {
    let mut screen = SettingsScreen::new(ThemeName::Ansi);
    let preview = screen.handle_event(&UiEvent::Key(KeyEvent::from(KeyCode::Right)));
    let IotaInteraction::Effect(IotaEffect::ApplyTheme { theme, persist }) = preview else {
        panic!("theme preview should emit an effect");
    };
    assert_eq!(theme, ThemeName::Surface);
    assert!(!persist);

    let save = screen.handle_event(&UiEvent::Key(KeyEvent::from(KeyCode::Enter)));
    let IotaInteraction::Effect(IotaEffect::SaveSettings { theme, .. }) = save else {
        panic!("theme save should emit an effect");
    };
    assert_eq!(theme, ThemeName::Surface);
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
                    screen.render_legacy(frame, frame.area(), &theme, &mut HitMap::new());
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
