use crate::{
    gui::{
        interaction_result::InteractionResult,
        screens::{md_viewer::FileViewer, screens::Screen},
        ui::UI,
    },
    terms::{
        buttons::{checkbox, draw_buttons},
        consent_state::UserChoice,
        focus::Focus,
        terms_getter::{Type, get_link, get_terms},
    },
};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
};
use std::{any::Any, pin::Pin, sync::Arc};
use tokio::sync::oneshot;

pub struct TermsCheckerScreen {
    ui: Arc<UI>,
    sender: Option<oneshot::Sender<UserChoice>>,

    eula: bool,
    tos: bool,
    pp: bool,

    focus: Focus,
}

impl TermsCheckerScreen {
    pub fn new(ui: Arc<UI>, sender: Option<oneshot::Sender<UserChoice>>) -> Self {
        Self {
            ui,
            sender,
            eula: false,
            tos: false,
            pp: false,
            focus: Focus::Eula,
        }
    }
}

impl Screen for TermsCheckerScreen {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn render(&self, f: &mut Frame, size: Rect) {
        let mut needed_height = 5;

        if size.height < 6 || size.width < 27 {
            f.render_widget(
                Line::from(format!("too small {}/63 by {}/13", size.width, size.height)),
                size,
            );
            return;
        }

        let max_width = 150;
        let max_height = 26;

        let content_width = if max_width < size.width {
            max_width
        } else {
            size.width
        };
        let content_height = if max_height < size.height {
            max_height
        } else {
            size.height
        };

        let horizontal_margin = (size.width.saturating_sub(content_width)) / 2;
        let vertical_margin = (size.height.saturating_sub(content_height)) / 2;

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(7), Constraint::Length(3)])
            .split(Rect {
                x: horizontal_margin,
                y: vertical_margin,
                width: content_width,
                height: content_height,
            });
        let eula_text = if size.width < 70 {
            "EULA ¹ (https://legal.tensamin.net/eula/)"
        } else {
            "End User Licence Agreement ¹ (https://legal.tensamin.net/eula/)"
        };
        let tos_text = if size.width < 72 {
            "ToS ² (https://legal.tensamin.net/terms-of-service/)"
        } else {
            "Terms of Service ² (https://legal.tensamin.net/terms-of-service/)"
        };
        let pp_text = if size.width < 68 {
            "PP ² (https://legal.tensamin.net/privacy-policy/)"
        } else {
            "Privacy Policy ² (https://legal.tensamin.net/privacy-policy/)"
        };

        let (mut optional_lines, agree_lines): (Vec<i16>, Vec<&str>) = if size.width > 143 {
            (
                vec![8, 3, 8, 5],
                vec![
                    "",
                    "By selecting Continue, you confirm that you agree to the End User License Agreement and applicable Terms of Service.",
                    "",
                    "Tensamin services require acceptance of the Terms of Service and Privacy Policy.",
                    "",
                    "While having a document selected press O to view in this UI or press L to open as a link.",
                ],
            )
        } else if size.width > 92 {
            (
                vec![9, 3, 9, 5],
                vec![
                    "",
                    "By selecting Continue, you confirm that you agree to the End User License",
                    "Agreement and applicable Terms of Service.",
                    "",
                    "Tensamin services require acceptance of the Terms of Service and Privacy Policy.",
                    "",
                    "While having a document selected press O to view in this UI or press L to open as a link.",
                ],
            )
        } else if size.width > 73 {
            (
                vec![9, 3, 9, 5],
                vec![
                    "",
                    "By selecting Continue, you confirm that you agree to the",
                    "End User License Agreement and applicable Terms of Service.",
                    "",
                    "Tensamin services require acceptance of the ToS and Privacy Policy.",
                    "",
                    "While having a document selected press O to view in this UI or press L",
                    "to open as a link.",
                ],
            )
        } else {
            (
                vec![10, 3, 11, 5],
                vec![
                    "",
                    "By selecting Continue, you confirm that you agree",
                    "to the End User License Agreement and",
                    "applicable Terms of Service.",
                    "",
                    "Tensamin services require acceptance of the",
                    "Terms of Service and Privacy Policy.",
                    "",
                    "While having a document selected press O to view",
                    "in this UI or press L to open as a link.",
                ],
            )
        };
        let mut text_lines = vec![
            checkbox(eula_text, self.eula, self.focus == Focus::Eula, true),
            checkbox(tos_text, self.tos, self.focus == Focus::Tos, self.eula),
            checkbox(pp_text, self.pp, self.focus == Focus::Pp, self.eula),
            Line::from(""),
            Line::from("¹ Necessary– required to run the program"),
            Line::from("² Optional – required only for Tensamin services"),
        ];
        for line in agree_lines {
            text_lines.insert(text_lines.len(), Line::from(line));
        }

        while size.height - 5 < text_lines.len() as u16 {
            if optional_lines.len() == 0 {
                break;
            }
            text_lines.remove(optional_lines[0] as usize);
            optional_lines.remove(0);
        }
        needed_height += text_lines.len();

        if size.width < 60 || size.height < needed_height as u16 {
            let width_style = if size.width > 76 {
                Style::default().fg(Color::Green)
            } else if size.width >= 60 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };

            let height_style = if size.height > 19 {
                Style::default().fg(Color::Green)
            } else if size.height >= 13 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };

            let warning_text = Text::from(vec![
                Line::from(vec![
                    Span::raw("Width: "),
                    Span::styled(format!("{}", size.width), width_style),
                    Span::raw(" / 60"),
                ]),
                Line::from(vec![
                    Span::raw("Height: "),
                    Span::styled(format!("{}", size.height), height_style),
                    Span::raw(format!(" / 13")),
                ]),
            ]);

            let warning = Paragraph::new(warning_text)
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("UI Too Small [Q to Quit]")),
                );
            f.render_widget(warning, size);
            return;
        }

        let consent_block = Paragraph::new(Text::from(text_lines)).block(
            Block::default()
                .title(format!(" Tensamin User Consent [Q to Quit] ",))
                .borders(Borders::ALL),
        );
        f.render_widget(consent_block, chunks[0]);

        draw_buttons(
            f,
            chunks[1],
            self.focus,
            (self.eula, self.tos && self.pp),
            true,
            false,
            true,
        );
    }

    fn handle_input(&mut self, event: KeyEvent) -> InteractionResult {
        let mut possible_states = vec![Focus::Eula, Focus::Tos, Focus::Pp, Focus::Cancel];

        if self.eula {
            possible_states.push(Focus::Continue);
            if self.tos && self.pp {
                possible_states.push(Focus::ContinueAll);
            }
        }

        match event.code {
            KeyCode::Esc => {
                if let Some(sender) = self.sender.take() {
                    let _ = sender.send(UserChoice::Deny);
                }
                InteractionResult::CloseScreen
            }
            KeyCode::Up | KeyCode::Left => {
                self.focus.prev(&possible_states);
                InteractionResult::Handled
            }
            KeyCode::Down | KeyCode::Right | KeyCode::Tab => {
                self.focus.next(&possible_states);
                InteractionResult::Handled
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if let Some(sender) = self.sender.take() {
                    let _ = sender.send(UserChoice::Deny);
                }
                InteractionResult::CloseScreen
            }
            KeyCode::Char('o') | KeyCode::Char('O') => {
                let terms_type = match self.focus {
                    Focus::Eula => Some(Type::EULA),
                    Focus::Tos => Some(Type::TOS),
                    Focus::Pp => Some(Type::PP),
                    _ => None,
                };
                if let Some(terms_type) = terms_type {
                    let fut: Pin<Box<dyn Future<Output = Box<dyn Screen>> + Send>> =
                        Box::pin(async move {
                            let content = get_terms(terms_type.clone()).await.unwrap();
                            let screen: FileViewer =
                                FileViewer::new(terms_type.to_string(), &content);
                            Box::new(screen) as Box<dyn Screen>
                        });
                    InteractionResult::OpenFutureScreen { screen: fut }
                } else {
                    InteractionResult::Unhandled
                }
            }
            KeyCode::Char('l') | KeyCode::Char('L') => match self.focus {
                Focus::Eula => {
                    let _ = open::that(get_link(Type::EULA));
                    InteractionResult::Handled
                }
                Focus::Tos => {
                    let _ = open::that(get_link(Type::TOS));
                    InteractionResult::Handled
                }
                Focus::Pp => {
                    let _ = open::that(get_link(Type::PP));
                    InteractionResult::Handled
                }
                _ => InteractionResult::Unhandled,
            },
            KeyCode::Enter | KeyCode::Char(' ') => match self.focus {
                Focus::Eula => {
                    self.eula = !self.eula;
                    self.tos = false;
                    self.pp = false;
                    InteractionResult::Handled
                }
                Focus::Tos if self.eula => {
                    self.tos = !self.tos;
                    InteractionResult::Handled
                }
                Focus::Pp if self.eula => {
                    self.pp = !self.pp;
                    InteractionResult::Handled
                }
                Focus::Cancel => {
                    if let Some(sender) = self.sender.take() {
                        let _ = sender.send(UserChoice::Deny);
                    }
                    InteractionResult::CloseScreen
                }
                Focus::Continue if self.eula => {
                    if let Some(sender) = self.sender.take() {
                        let _ = sender.send(UserChoice::AcceptEULA);
                    }
                    InteractionResult::CloseScreen
                }
                Focus::ContinueAll if self.eula && self.tos && self.pp => {
                    if let Some(sender) = self.sender.take() {
                        let _ = sender.send(UserChoice::AcceptAll);
                    }
                    InteractionResult::CloseScreen
                }
                _ => InteractionResult::Unhandled,
            },

            _ => InteractionResult::Unhandled,
        }
    }
}
