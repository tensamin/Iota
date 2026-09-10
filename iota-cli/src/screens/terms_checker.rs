use crate::{
    controls::choice::{ChoiceKind, ChoiceVisualState, render_choice_line},
    interaction_result::InteractionResult,
    render_context::RenderContext,
    screens::{
        md_viewer::FileViewer,
        screens::{HitMap, Screen, UiEvent},
    },
    util::{buttons::draw_buttons, terms_focus::Focus},
};
use crossterm::event::KeyCode;
use iota_terms::{LegalDocument, TermsType, get_link};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
};
use std::{any::Any, pin::Pin};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserChoice {
    Deny,
    AcceptEULA,
    AcceptAll,
}

pub struct TermsCheckerScreen {
    sender: Option<oneshot::Sender<UserChoice>>,
    documents: [LegalDocument; 3],

    eula: bool,
    tos: bool,
    pp: bool,

    focus: Focus,
}

impl TermsCheckerScreen {
    pub fn new(sender: Option<oneshot::Sender<UserChoice>>, documents: [LegalDocument; 3]) -> Self {
        Self {
            sender,
            documents,
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

    fn render(&self, f: &mut Frame, size: Rect, context: &RenderContext<'_>, _hits: &mut HitMap) {
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
            "EULA ¹ (https://legal.methanium.net/tensamin/eula)"
        } else {
            "End User Licence Agreement ¹ (https://legal.methanium.net/tensamin/eula)"
        };
        let tos_text = if size.width < 72 {
            "ToS ² (https://legal.methanium.net/tensamin/terms-of-service)"
        } else {
            "Terms of Service ² (https://legal.methanium.net/tensamin/terms-of-service)"
        };
        let pp_text = if size.width < 68 {
            "PP ² (https://legal.methanium.net/tensamin/privacy-policy)"
        } else {
            "Privacy Policy ² (https://legal.methanium.net/tensamin/privacy-policy)"
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
            render_choice_line(
                eula_text,
                ChoiceKind::Checkbox,
                ChoiceVisualState {
                    selected: self.eula,
                    focused: self.focus == Focus::Eula,
                    enabled: true,
                },
                context.theme,
            ),
            render_choice_line(
                tos_text,
                ChoiceKind::Checkbox,
                ChoiceVisualState {
                    selected: self.tos,
                    focused: self.focus == Focus::Tos,
                    enabled: self.eula,
                },
                context.theme,
            ),
            render_choice_line(
                pp_text,
                ChoiceKind::Checkbox,
                ChoiceVisualState {
                    selected: self.pp,
                    focused: self.focus == Focus::Pp,
                    enabled: self.eula,
                },
                context.theme,
            ),
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
                context.theme.status.success
            } else if size.width >= 60 {
                context.theme.status.warning
            } else {
                context.theme.status.error
            };

            let height_style = if size.height > 19 {
                context.theme.status.success
            } else if size.height >= 13 {
                context.theme.status.warning
            } else {
                context.theme.status.error
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
            context.theme,
        );
    }

    fn handle_event(&mut self, event: UiEvent) -> InteractionResult {
        let UiEvent::Key(event) = event else {
            return InteractionResult::Unhandled;
        };
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
                    Focus::Eula => Some(TermsType::EULA),
                    Focus::Tos => Some(TermsType::TOS),
                    Focus::Pp => Some(TermsType::PP),
                    _ => None,
                };
                if let Some(terms_type) = terms_type {
                    let document = self
                        .documents
                        .iter()
                        .find(|document| document.kind() == terms_type)
                        .cloned();
                    let fut: Pin<Box<dyn Future<Output = Box<dyn Screen>> + Send>> =
                        Box::pin(async move {
                            if let Some(document) = document {
                                let screen: FileViewer =
                                    FileViewer::new(terms_type.to_string(), document.content());
                                Box::new(screen) as Box<dyn Screen>
                            } else {
                                let screen: FileViewer = FileViewer::new(
                                    "Error".to_string(),
                                    "The fetched legal document is unavailable.",
                                );
                                Box::new(screen) as Box<dyn Screen>
                            }
                        });
                    InteractionResult::OpenFutureScreen { screen: fut }
                } else {
                    InteractionResult::Unhandled
                }
            }
            KeyCode::Char('l') | KeyCode::Char('L') => match self.focus {
                Focus::Eula => {
                    let _ = open::that(get_link(TermsType::EULA));
                    InteractionResult::Handled
                }
                Focus::Tos => {
                    let _ = open::that(get_link(TermsType::TOS));
                    InteractionResult::Handled
                }
                Focus::Pp => {
                    let _ = open::that(get_link(TermsType::PP));
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
