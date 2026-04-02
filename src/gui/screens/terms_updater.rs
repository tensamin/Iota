use crate::{
    gui::{
        interaction_result::InteractionResult,
        screens::{md_viewer::FileViewer, screens::Screen},
    },
    terms::{
        buttons::{checkbox, draw_buttons},
        consent_state::{UpdateDecision, UserChoice},
        doc::Doc,
        focus::Focus,
        terms_getter::{Type, get_newest_link, get_terms},
    },
};
use chrono::{Local, TimeZone, Utc};
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Paragraph},
};
use std::any::Any;
use tokio::sync::oneshot;

pub struct TermsUpdaterScreen {
    sender: Option<oneshot::Sender<UserChoice>>,

    eula_needed: bool,
    tos_needed: bool,
    pp_needed: bool,

    eula_future: bool,
    tos_future: bool,
    pp_future: bool,

    eula_for_future: Option<Doc>,
    tos_for_future: Option<Doc>,
    pp_for_future: Option<Doc>,

    update_needed: bool,

    eula: bool,
    tos: bool,
    pp: bool,

    focus: Focus,
}
impl TermsUpdaterScreen {
    pub fn new(
        consent_eula: UpdateDecision,
        consent_tos: UpdateDecision,
        consent_pp: UpdateDecision,
        sender: Option<oneshot::Sender<UserChoice>>,
    ) -> Self {
        let (eula_needed, eula_future, eula_for_future): (bool, bool, Option<Doc>) =
            match consent_eula {
                UpdateDecision::NoChange => (false, false, None),
                UpdateDecision::Future { newest } => (true, true, Some(newest)),
                UpdateDecision::Forced(doc) => (true, false, Some(doc)),
            };
        let (tos_needed, tos_future, tos_for_future): (bool, bool, Option<Doc>) = match consent_tos
        {
            UpdateDecision::NoChange => (false, false, None),
            UpdateDecision::Future { newest } => (true, true, Some(newest)),
            UpdateDecision::Forced(doc) => (true, false, Some(doc)),
        };
        let (pp_needed, pp_future, pp_for_future): (bool, bool, Option<Doc>) = match consent_pp {
            UpdateDecision::NoChange => (false, false, None),
            UpdateDecision::Future { newest } => (true, true, Some(newest)),
            UpdateDecision::Forced(doc) => (true, false, Some(doc)),
        };

        let focus = if eula_needed {
            Focus::Eula
        } else if tos_needed {
            Focus::Tos
        } else if pp_needed {
            Focus::Pp
        } else {
            Focus::Cancel
        };

        let update_needed = (eula_needed && !eula_future)
            || (tos_needed && !tos_future)
            || (pp_needed && !pp_future);

        Self {
            sender,

            eula_needed,
            tos_needed,
            pp_needed,

            eula_for_future,
            tos_for_future,
            pp_for_future,

            eula_future,
            tos_future,
            pp_future,

            update_needed,

            eula: !eula_needed,
            tos: !tos_needed,
            pp: !pp_needed,

            focus,
        }
    }
}
impl Screen for TermsUpdaterScreen {
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
                Line::from(format!("too small {}/63 by {}/15", size.width, size.height)),
                size,
            );
            return;
        }

        let max_width = 150;
        let max_height = 30;

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

        let mut text_lines: Vec<Line> = Vec::new();
        let mut header_lines = 0;
        let separator = if size.width > 72 {
            header_lines += 3;
            text_lines.push(Line::from(
                "You previously accepted earlier versions of Tensamin’s legal documents.",
            ));
            text_lines.push(Line::from(
                "Some of them have been updated and are listed below for your review.",
            ));
            text_lines.push(Line::from(""));
            2
        } else {
            header_lines += 5;
            text_lines.push(Line::from("You previously accepted earlier "));
            text_lines.push(Line::from("versions of Tensamin’s legal documents."));
            text_lines.push(Line::from("Some of them have been updated and"));
            text_lines.push(Line::from("are listed below for your review."));
            text_lines.push(Line::from(""));
            4
        };

        if self.eula_needed {
            header_lines += 1;
            if self.eula_future {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "EULA ¹³ (https://legal.tensamin.net/eula/newest/)",
                        self.eula,
                        self.focus == Focus::Eula,
                        true,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.eula_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                } else {
                    text_lines.push(checkbox(
                        "End User Licence Agreement ¹³ (https://legal.tensamin.net/eula/newest/)",
                        self.eula,
                        self.focus == Focus::Eula,
                        true,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.eula_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                }
            } else {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "EULA ¹ (https://legal.tensamin.net/eula/newest/)",
                        self.eula,
                        self.focus == Focus::Eula,
                        true,
                    ));
                } else {
                    text_lines.push(checkbox(
                        "End User Licence Agreement ¹ (https://legal.tensamin.net/eula/newest/)",
                        self.eula,
                        self.focus == Focus::Eula,
                        true,
                    ));
                }
            }
        }

        if self.tos_needed {
            header_lines += 1;
            if self.tos_future {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "ToS ²³ (https://legal.tensamin.net/tos/newest/)",
                        self.tos,
                        self.focus == Focus::Tos,
                        self.eula,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.tos_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                } else {
                    text_lines.push(checkbox(
                        "Terms of Service ²³ (https://legal.tensamin.net/terms-of-service/newest/)",
                        self.tos,
                        self.focus == Focus::Tos,
                        self.eula,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.tos_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                }
            } else {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "ToS ² (https://legal.tensamin.net/tos/newest/)",
                        self.tos,
                        self.focus == Focus::Tos,
                        self.eula,
                    ));
                } else {
                    text_lines.push(checkbox(
                        "Terms of Service ² (https://legal.tensamin.net/terms-of-service/newest/)",
                        self.tos,
                        self.focus == Focus::Tos,
                        self.eula,
                    ));
                }
            }
        }

        if self.pp_needed {
            header_lines += 1;
            if self.pp_future {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "PP ²³ (https://legal.tensamin.net/privacy-policy/newest/)",
                        self.pp,
                        self.focus == Focus::Pp,
                        self.eula,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.pp_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                } else {
                    text_lines.push(checkbox(
                        "Privacy Policy ²³ (https://legal.tensamin.net/privacy-policy/newest/)",
                        self.pp,
                        self.focus == Focus::Pp,
                        self.eula,
                    ));

                    header_lines += 1;
                    let unix_timestamp = self.pp_for_future.clone().unwrap().get_time() as i64;
                    let datetime = Utc.timestamp_opt(unix_timestamp, 0).single().unwrap();
                    let date = datetime.with_timezone(&Local).format("%Y-%m-%d at %H:%M");
                    text_lines.push(Line::from(format!("    Goes into effect on {}", date)));
                }
            } else {
                if size.width < 80 {
                    text_lines.push(checkbox(
                        "PP ² (https://legal.tensamin.net/privacy-policy/newest/)",
                        self.pp,
                        self.focus == Focus::Pp,
                        self.eula,
                    ));
                } else {
                    text_lines.push(checkbox(
                        "Privacy Policy ² (https://legal.tensamin.net/privacy-policy/newest/)",
                        self.pp,
                        self.focus == Focus::Pp,
                        self.eula,
                    ));
                }
            }
        }

        text_lines.push(Line::from(""));
        text_lines.push(Line::from("¹ Necessary to run the program"));
        text_lines.push(Line::from("² Optional - only for Tensamin services"));
        if size.width < 100 {
            text_lines.push(Line::from(
                "³ Future version - consent stored now, takes effect later",
            ));
        } else {
            text_lines.push(Line::from("³ Future version - You’ll continue using this version, automatically updated when changes apply."));
        }

        text_lines.push(Line::from(""));

        let mut optional_lines: Vec<i16> = if size.width > 143 {
            if self.tos_needed || self.pp_needed {
                text_lines.push(Line::from("By selecting Downgrade, you confirm that you agree to the End User License Agreement and applicable Terms of Service."));
                text_lines.push(Line::from(
                    "On Downgrade: Tensamin Services will deactivate once these changes apply.",
                ));
            } else {
                text_lines.push(Line::from("By selecting Continue, you confirm that you agree to the End User License Agreement and applicable Terms of Service."));
            }
            text_lines.push(Line::from(""));
            text_lines.push(Line::from(
                "Tensamin services require acceptance of the Terms of Service and Privacy Policy.",
            ));
            text_lines.push(Line::from(""));
            text_lines.push(Line::from("While having a document selected press O to view in this UI or press L to open as a link."));

            if self.tos_needed || self.pp_needed {
                vec![
                    header_lines + 7,
                    header_lines,
                    header_lines + 7,
                    separator,
                    header_lines + 2,
                ]
            } else {
                vec![
                    header_lines + 6,
                    header_lines,
                    header_lines + 6,
                    separator,
                    header_lines + 2,
                ]
            }
        } else if size.width > 92 {
            if self.tos_needed || self.pp_needed {
                text_lines.push(Line::from(
                    "By selecting Continue, you confirm that you agree to the End User",
                ));
                text_lines.push(Line::from(
                    "License Agreement and applicable Terms of Service.",
                ));
                text_lines.push(Line::from(
                    "On Downgrade: Tensamin Services will deactivate once these changes apply.",
                ));
            } else {
                text_lines.push(Line::from(
                    "By selecting Continue, you confirm that you agree to the End User",
                ));
                text_lines.push(Line::from(
                    "License Agreement and applicable Terms of Service.",
                ));
            }

            text_lines.push(Line::from(""));
            text_lines.push(Line::from(
                "Tensamin services require acceptance of the Terms of Service and Privacy Policy.",
            ));
            text_lines.push(Line::from(""));
            text_lines.push(Line::from("While having a document selected press O to view in this UI or press L to open as a link."));

            if self.tos_needed || self.pp_needed {
                vec![
                    header_lines + 8,
                    header_lines,
                    header_lines + 8,
                    separator,
                    header_lines + 2,
                ]
            } else {
                vec![
                    header_lines + 7,
                    header_lines,
                    header_lines + 7,
                    separator,
                    header_lines + 2,
                ]
            }
        } else if size.width > 73 {
            if self.tos_needed || self.pp_needed {
                text_lines.push(Line::from(
                    "By selecting Continue, you confirm that you read, understood and",
                ));
                text_lines.push(Line::from(
                    "agree to the End User License Agreement and applicable Terms of Service.",
                ));
                text_lines.push(Line::from(
                    "On Downgrade: Tensamin Services will deactivate once these changes apply.",
                ));
            } else {
                text_lines.push(Line::from(
                    "By selecting Continue, you confirm that you read, understood and",
                ));
                text_lines.push(Line::from(
                    "agree to the End User License Agreement and applicable Terms of Service.",
                ));
            }
            text_lines.push(Line::from(""));
            text_lines.push(Line::from(
                "Tensamin services require acceptance of the ToS and Privacy Policy.",
            ));
            text_lines.push(Line::from(""));
            text_lines.push(Line::from(
                "While having a document selected press O to view in this UI or press L",
            ));
            text_lines.push(Line::from("to open as a link."));

            if self.tos_needed || self.pp_needed {
                vec![
                    header_lines + 8,
                    header_lines,
                    header_lines + 8,
                    separator,
                    header_lines + 2,
                ]
            } else {
                vec![
                    header_lines + 7,
                    header_lines,
                    header_lines + 7,
                    separator,
                    header_lines + 2,
                ]
            }
        } else {
            if self.tos_needed || self.pp_needed {
                text_lines.push(Line::from("By selecting Continue, you confirm that you"));
                text_lines.push(Line::from("agree to the End User License"));
                text_lines.push(Line::from("Agreement and applicable Terms of Service."));
                text_lines.push(Line::from(
                    "On Downgrade: Tensamin Services will deactivate",
                ));
                text_lines.push(Line::from("once these changes apply."));
            } else {
                text_lines.push(Line::from("By selecting Continue, you confirm that you"));
                text_lines.push(Line::from("agree to the End User License"));
                text_lines.push(Line::from("Agreement and applicable Terms of Service."));
            }
            text_lines.push(Line::from(""));
            text_lines.push(Line::from("Tensamin services require acceptance of the"));
            text_lines.push(Line::from("Terms of Service and Privacy Policy."));
            text_lines.push(Line::from(""));
            text_lines.push(Line::from(
                "While having a document selected press O to view",
            ));
            text_lines.push(Line::from("in this UI or press L to open as a link."));
            if self.tos_needed || self.pp_needed {
                vec![
                    header_lines + 10,
                    header_lines,
                    header_lines + 11,
                    separator,
                    header_lines + 2,
                ]
            } else {
                vec![
                    header_lines + 8,
                    header_lines,
                    header_lines + 9,
                    separator,
                    header_lines + 2,
                ]
            }
        };

        while size.height - 5 < text_lines.len() as u16 {
            if optional_lines.len() == 0 {
                break;
            }
            text_lines.remove(optional_lines[0] as usize);
            optional_lines.remove(0);
        }
        needed_height += text_lines.len();

        let q_informer = if self.update_needed {
            "Q to Exit"
        } else {
            "Q to Cancel"
        };
        if size.width < 60 || size.height < needed_height as u16 {
            let width_style = if size.width > 76 {
                Style::default().fg(Color::Green)
            } else if size.width >= 60 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Red)
            };

            let height_style = if size.height > 20 {
                Style::default().fg(Color::Green)
            } else if size.height >= (header_lines as u16 + 10) {
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
                    Span::raw(format!(" / {}", header_lines + 10)),
                ]),
            ]);

            let warning = Paragraph::new(warning_text)
                .alignment(Alignment::Center)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("UI Too Small [{}]", q_informer)),
                );

            f.render_widget(warning, size);
            return;
        }

        let consent_block = Paragraph::new(Text::from(text_lines)).block(
            Block::default()
                .title(format!(" Update Tensamin User Consent [{}] ", q_informer))
                .borders(Borders::ALL),
        );
        f.render_widget(consent_block, chunks[0]);

        let downgrade_scenario = self.tos_needed || self.pp_needed;
        draw_buttons(
            f,
            chunks[1],
            self.focus,
            (self.eula, self.tos && self.pp),
            self.update_needed,
            downgrade_scenario,
            self.pp_needed || self.tos_needed,
        );
    }

    fn handle_input(&mut self, event: KeyEvent) -> InteractionResult {
        let mut possible_states = Vec::new();

        if self.eula_needed {
            possible_states.push(Focus::Eula);
        }
        if self.tos_needed {
            possible_states.push(Focus::Tos);
        }
        if self.pp_needed {
            possible_states.push(Focus::Pp);
        }

        possible_states.push(Focus::Cancel);

        if self.eula {
            possible_states.push(Focus::Continue);
            if self.tos && self.pp {
                possible_states.push(Focus::ContinueAll);
            }
        }

        match event.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                if let Some(sender) = self.sender.take() {
                    let _ = sender.send(UserChoice::Deny);
                }
                return InteractionResult::CloseScreen;
            }
            KeyCode::Enter | KeyCode::Char(' ') => match self.focus {
                Focus::Eula => {
                    self.eula = !self.eula;
                    self.tos = !self.tos_needed;
                    self.pp = !self.pp_needed;
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
            KeyCode::Char('o') | KeyCode::Char('O') => {
                let terms_type = match self.focus {
                    Focus::Eula => Some(Type::EULA),
                    Focus::Tos => Some(Type::TOS),
                    Focus::Pp => Some(Type::PP),
                    _ => None,
                };

                if let Some(terms_type) = terms_type {
                    let fut = Box::pin(async move {
                        let content = get_terms(terms_type.clone()).await.unwrap();
                        Box::new(FileViewer::new(terms_type.to_string(), &content))
                            as Box<dyn Screen>
                    });

                    return InteractionResult::OpenFutureScreen { screen: fut };
                } else {
                    InteractionResult::Unhandled
                }
            }
            KeyCode::Char('l') | KeyCode::Char('L') => match self.focus {
                Focus::Eula => {
                    let _ = open::that(get_newest_link(Type::EULA));
                    InteractionResult::Handled
                }
                Focus::Tos => {
                    let _ = open::that(get_newest_link(Type::TOS));
                    InteractionResult::Handled
                }
                Focus::Pp => {
                    let _ = open::that(get_newest_link(Type::PP));
                    InteractionResult::Handled
                }
                _ => InteractionResult::Unhandled,
            },
            KeyCode::Up | KeyCode::Left => {
                self.focus.prev(&possible_states);
                InteractionResult::Handled
            }
            KeyCode::Down | KeyCode::Right | KeyCode::Tab => {
                self.focus.next(&possible_states);
                InteractionResult::Handled
            }
            _ => InteractionResult::Unhandled,
        }
    }
}
