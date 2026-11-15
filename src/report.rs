//! Copy report (SPEC section 10): plain text, every line cleaned (outside text never carries a
//! control or direction character into another program), the window's caps not applied.

/// One section: its title and its lines.
pub struct Section {
    pub title: String,
    pub lines: Vec<String>,
}

pub fn text(sections: &[Section], version: &str) -> String {
    let mut out = String::new();
    for s in sections {
        out.push_str(&clean_line(&s.title));
        out.push('\n');
        for l in &s.lines {
            out.push_str("  ");
            out.push_str(&clean_line(l));
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(&format!("VibePath {version}\n"));
    out
}

fn clean_line(l: &str) -> String {
    // Long lines stay whole (a report reads everything): only invisible characters go.
    l.chars().filter(|c| !crate::text::invisible(*c) || *c == '\t').collect::<String>().replace('\t', " ")
}
