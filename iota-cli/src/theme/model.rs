use super::ThemeName;
use ratatui::style::Style;

#[derive(Clone, Debug)]
pub struct TextStyles {
    pub normal: Style,
    pub muted: Style,
    pub heading: Style,
    pub link: Style,
    pub code: Style,
}
#[derive(Clone, Debug)]
pub struct StatusStyles {
    pub info: Style,
    pub success: Style,
    pub warning: Style,
    pub error: Style,
}
#[derive(Clone, Debug)]
pub struct BorderStyles {
    pub normal: Style,
    pub focused: Style,
    pub disabled: Style,
    pub title: Style,
}
#[derive(Clone, Debug)]
pub struct SurfaceStyles {
    pub canvas: Style,
    pub toolbar: Style,
    pub panel: Style,
    pub panel_alternate: Style,
    pub panel_focused: Style,
    pub panel_selected: Style,
    pub footer: Style,
    pub overlay: Style,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeMode {
    Bordered,
    Surfaces,
}
#[derive(Clone, Debug)]
pub struct ChoiceItemStyle {
    pub marker: Style,
    pub label: Style,
    pub description: Style,
    pub prefix: &'static str,
    pub suffix: &'static str,
}
#[derive(Clone, Debug)]
pub struct ChoiceStyles {
    pub normal: ChoiceItemStyle,
    pub focused: ChoiceItemStyle,
    pub selected: ChoiceItemStyle,
    pub focused_selected: ChoiceItemStyle,
    pub disabled: ChoiceItemStyle,
    pub focused_disabled: ChoiceItemStyle,
    pub selected_disabled: ChoiceItemStyle,
}
#[derive(Clone, Debug)]
pub struct ButtonStyles {
    pub primary: Style,
    pub primary_focused: Style,
    pub neutral: Style,
    pub neutral_focused: Style,
    pub cancel: Style,
    pub cancel_focused: Style,
    pub destructive: Style,
    pub disabled: Style,
}
#[derive(Clone, Debug)]
pub struct MarkerSet {
    pub checkbox_unselected: &'static str,
    pub checkbox_selected: &'static str,
    pub radio_unselected: &'static str,
    pub radio_selected: &'static str,
}
#[derive(Clone, Debug)]
pub enum CursorPresentation {
    StyledCell(Style),
    Character { glyph: &'static str, style: Style },
}
#[derive(Clone, Debug)]
pub struct ConsoleStyles {
    pub text: Style,
    pub prefix: Style,
    pub hint: Style,
    pub error: Style,
    pub confirmation: Style,
    pub cursor: CursorPresentation,
    pub border: Style,
    pub focused_border: Style,
    pub title: Style,
}
#[derive(Clone, Debug)]
pub struct GraphStyles {
    pub ram: ratatui::style::Color,
    pub cpu: ratatui::style::Color,
    pub ping: ratatui::style::Color,
    pub text: Style,
    pub border: Style,
    pub focused_border: Style,
}
#[derive(Clone, Debug)]
pub struct LogStyles {
    pub call: Style,
    pub client: Style,
    pub iota: Style,
    pub omikron: Style,
    pub omega: Style,
    pub command: Style,
    pub other: Style,
    pub text: Style,
    pub error: Style,
    pub timestamp: Style,
    pub border: Style,
    pub focused_border: Style,
}
#[derive(Clone, Debug)]
pub struct MarkdownStyles {
    pub normal: Style,
    pub muted: Style,
    pub heading: Style,
    pub link: Style,
    pub code: Style,
    pub table_header: Style,
    pub table_text: Style,
    pub divider: Style,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct TextSemantics {
    pub bold: bool,
    pub underline: bool,
}
#[derive(Clone, Debug)]
pub struct ResolvedTheme {
    pub name: ThemeName,
    pub unicode: bool,
    pub surfaces: SurfaceStyles,
    pub chrome: ChromeMode,
    pub text: TextStyles,
    pub status: StatusStyles,
    pub choices: ChoiceStyles,
    pub buttons: ButtonStyles,
    pub borders: BorderStyles,
    pub console: ConsoleStyles,
    pub graphs: GraphStyles,
    pub logs: LogStyles,
    pub markdown: MarkdownStyles,
    pub markers: MarkerSet,
}

impl ResolvedTheme {
    pub fn apply_text_semantics(&self, base: Style, semantics: TextSemantics) -> Style {
        use ratatui::style::Modifier;
        if matches!(self.name, ThemeName::Monospace) {
            return base;
        }
        let mut style = base;
        if semantics.bold {
            style = style.add_modifier(Modifier::BOLD);
        }
        if semantics.underline {
            style = style.add_modifier(Modifier::UNDERLINED);
        }
        style
    }
}
