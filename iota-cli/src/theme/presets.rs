use super::{
    BorderStyles, ButtonStyles, ChoiceItemStyle, ChoiceStyles, ConsoleStyles, CursorPresentation,
    GraphStyles, LogStyles, MarkdownStyles, MarkerSet, ResolvedTheme, StatusStyles, TextStyles,
    ThemeName,
};
use ratatui::style::{Color, Modifier, Style};

fn marker() -> MarkerSet {
    MarkerSet {
        checkbox_unselected: "[ ]",
        checkbox_selected: "[x]",
        radio_unselected: "( )",
        radio_selected: "(x)",
    }
}
fn choice(
    marker: Style,
    label: Style,
    prefix: &'static str,
    suffix: &'static str,
) -> ChoiceItemStyle {
    ChoiceItemStyle {
        marker,
        label,
        description: label,
        prefix,
        suffix,
    }
}
fn base(
    name: ThemeName,
    normal: Style,
    muted: Style,
    focused: Style,
    selected: Style,
    disabled: Style,
    status: StatusStyles,
    buttons: ButtonStyles,
) -> ResolvedTheme {
    let error = status.error;
    let (prefix, suffix) = if matches!(name, ThemeName::Monospace | ThemeName::Binary) {
        ("> ", " <")
    } else {
        ("", "")
    };
    ResolvedTheme {
        name,
        text: TextStyles {
            normal,
            muted,
            heading: normal,
            link: focused,
            code: normal,
        },
        status,
        choices: ChoiceStyles {
            normal: choice(normal, normal, "", ""),
            focused: choice(focused, focused, prefix, suffix),
            selected: choice(selected, selected, "", ""),
            focused_selected: choice(
                selected.patch(focused),
                selected.patch(focused),
                prefix,
                suffix,
            ),
            disabled: choice(disabled, disabled, "", ""),
            focused_disabled: choice(disabled, error, prefix, suffix),
            selected_disabled: choice(disabled, disabled, "", ""),
        },
        buttons,
        borders: BorderStyles {
            normal,
            focused,
            disabled,
            title: normal,
        },
        console: ConsoleStyles {
            text: normal,
            prefix: muted,
            hint: muted,
            error,
            confirmation: focused,
            cursor: CursorPresentation::StyledCell(focused),
            border: normal,
            focused_border: focused,
            title: normal,
        },
        graphs: GraphStyles {
            ram: Color::Reset,
            cpu: Color::Reset,
            ping: Color::Reset,
            text: normal,
            border: normal,
            focused_border: focused,
        },
        logs: LogStyles {
            call: normal,
            client: normal,
            iota: normal,
            omikron: normal,
            omega: normal,
            command: normal,
            other: normal,
            text: normal,
            error,
            timestamp: muted,
            border: normal,
            focused_border: focused,
        },
        markdown: MarkdownStyles {
            normal,
            muted,
            heading: focused,
            link: focused,
            code: focused,
            table_header: focused,
            table_text: normal,
            divider: muted,
        },
        markers: marker(),
    }
}
pub fn resolve(name: ThemeName) -> ResolvedTheme {
    let plain = Style::default();
    match name {
        ThemeName::Monospace => {
            let mut theme = base(
                name,
                plain,
                plain,
                plain,
                plain,
                plain,
                StatusStyles {
                    info: plain,
                    success: plain,
                    warning: plain,
                    error: plain,
                },
                ButtonStyles {
                    primary: plain,
                    primary_focused: plain,
                    neutral: plain,
                    neutral_focused: plain,
                    cancel: plain,
                    cancel_focused: plain,
                    destructive: plain,
                    disabled: plain,
                },
            );
            theme.console.cursor = CursorPresentation::Character {
                glyph: "▌",
                style: plain,
            };
            theme.graphs = GraphStyles {
                ram: Color::Reset,
                cpu: Color::Reset,
                ping: Color::Reset,
                text: plain,
                border: plain,
                focused_border: plain,
            };
            theme
        }
        ThemeName::Binary => {
            let reversed = plain.add_modifier(Modifier::REVERSED);
            base(
                name,
                plain,
                plain,
                plain,
                reversed,
                plain,
                StatusStyles {
                    info: plain,
                    success: plain,
                    warning: plain,
                    error: plain,
                },
                ButtonStyles {
                    primary: plain,
                    primary_focused: reversed,
                    neutral: plain,
                    neutral_focused: reversed,
                    cancel: plain,
                    cancel_focused: reversed,
                    destructive: plain,
                    disabled: plain,
                },
            )
        }
        ThemeName::Ansi => {
            let yellow = plain.fg(Color::Yellow).add_modifier(Modifier::BOLD);
            let mut theme = base(
                name,
                plain,
                plain.fg(Color::DarkGray),
                yellow,
                plain,
                plain.fg(Color::DarkGray),
                StatusStyles {
                    info: plain,
                    success: plain.fg(Color::Green),
                    warning: plain.fg(Color::Yellow),
                    error: plain.fg(Color::Red),
                },
                ButtonStyles {
                    primary: plain.fg(Color::Green),
                    primary_focused: plain
                        .fg(Color::Black)
                        .bg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                    neutral: plain,
                    neutral_focused: yellow,
                    cancel: plain.fg(Color::Red),
                    cancel_focused: plain
                        .fg(Color::Black)
                        .bg(Color::Red)
                        .add_modifier(Modifier::BOLD),
                    destructive: plain.fg(Color::Red),
                    disabled: plain.fg(Color::DarkGray),
                },
            );
            theme.console = ConsoleStyles {
                text: plain.fg(Color::White),
                prefix: plain.fg(Color::DarkGray),
                hint: plain.fg(Color::DarkGray),
                error: plain.fg(Color::Red),
                confirmation: plain.fg(Color::Yellow),
                cursor: CursorPresentation::StyledCell(plain.fg(Color::White).bg(Color::DarkGray)),
                border: plain,
                focused_border: plain.fg(Color::Yellow),
                title: plain.fg(Color::White),
            };
            theme.graphs = GraphStyles {
                ram: Color::Blue,
                cpu: Color::Red,
                ping: Color::Green,
                text: plain,
                border: plain,
                focused_border: plain.fg(Color::Yellow),
            };
            theme.logs = LogStyles {
                call: plain.fg(Color::Magenta),
                client: plain.fg(Color::Green),
                iota: plain.fg(Color::Yellow),
                omikron: plain.fg(Color::Blue),
                omega: plain.fg(Color::Cyan),
                command: plain.fg(Color::LightGreen),
                other: plain.fg(Color::LightCyan),
                text: plain.fg(Color::White),
                error: plain.fg(Color::Red),
                timestamp: plain.fg(Color::DarkGray),
                border: plain,
                focused_border: plain.fg(Color::Yellow),
            };
            theme.markdown = MarkdownStyles {
                normal: plain,
                muted: plain.fg(Color::DarkGray),
                heading: plain.fg(Color::Cyan),
                link: plain.fg(Color::Cyan),
                code: plain.fg(Color::Yellow),
                table_header: plain.fg(Color::Cyan),
                table_text: plain.fg(Color::Green),
                divider: plain.fg(Color::DarkGray),
            };
            theme
        }
        ThemeName::Surface => {
            let focus = plain.fg(Color::Black).bg(Color::Yellow);
            let selected = plain.fg(Color::Black).bg(Color::Cyan);
            let mut theme = base(
                name,
                plain,
                plain.fg(Color::DarkGray),
                focus,
                selected,
                plain.fg(Color::DarkGray),
                StatusStyles {
                    info: plain,
                    success: plain.fg(Color::Green),
                    warning: plain.fg(Color::Yellow),
                    error: plain.fg(Color::Red),
                },
                ButtonStyles {
                    primary: plain.fg(Color::Black).bg(Color::Green),
                    primary_focused: focus,
                    neutral: plain,
                    neutral_focused: focus,
                    cancel: plain.fg(Color::Black).bg(Color::Red),
                    cancel_focused: focus,
                    destructive: plain.fg(Color::Black).bg(Color::Red),
                    disabled: plain.fg(Color::DarkGray),
                },
            );
            theme.console.cursor =
                CursorPresentation::StyledCell(plain.fg(Color::Black).bg(Color::Yellow));
            theme
        }
    }
}
