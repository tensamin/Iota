use unicode_width::UnicodeWidthStr;
pub fn wrapped_line_count(text: &str, width: u16) -> u16 {
    if width == 0 {
        return 0;
    }
    text.split('\n')
        .map(|line| (UnicodeWidthStr::width(line).max(1) + width as usize - 1) / width as usize)
        .sum::<usize>()
        .min(u16::MAX as usize) as u16
}
