//! Turns PIA region ids ("us-new-york", "de-germany-streaming-optimized") into
//! readable names and groups them for the tray menu.

const COUNTRIES: &[(&str, &str)] = &[
    ("us", "US"),
    ("ca", "Canada"),
    ("uk", "UK"),
    ("de", "Germany"),
    ("it", "Italy"),
    ("es", "Spain"),
    ("fi", "Finland"),
    ("se", "Sweden"),
    ("jp", "Japan"),
    ("au", "Australia"),
    ("nl", "Netherlands"),
    ("be", "Belgium"),
    ("dk", "Denmark"),
    ("at", "Austria"),
    ("fr", "France"),
    ("ch", "Switzerland"),
    ("lu", "Luxembourg"),
    ("hu", "Hungary"),
    ("rs", "Serbia"),
    ("sk", "Slovakia"),
    ("lt", "Lithuania"),
    ("cl", "Chile"),
    ("il", "Israel"),
    ("pl", "Poland"),
    ("br", "Brazil"),
    ("ar", "Argentina"),
    ("kr", "South Korea"),
    ("nz", "New Zealand"),
    ("tw", "Taiwan"),
    ("sg", "Singapore"),
    ("za", "South Africa"),
    ("mx", "Mexico"),
    ("ro", "Romania"),
    ("pt", "Portugal"),
];

const STREAMING: &str = "-streaming-optimized";

fn country(code: &str) -> Option<&'static str> {
    COUNTRIES.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

fn capitalize(word: &str) -> String {
    let mut c = word.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn title_words(s: &str) -> String {
    s.split('-')
        .enumerate()
        .map(|(i, w)| match w {
            "of" | "and" if i > 0 => w.to_string(),
            "dc" => "DC".to_string(),
            _ => capitalize(w),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Readable name for a PIA region id.
pub fn pretty(id: &str) -> String {
    if id == "auto" {
        return "Auto (fastest)".to_string();
    }
    let (base, streaming) = match id.strip_suffix(STREAMING) {
        Some(b) => (b, true),
        None => (id, false),
    };
    let mut label = match base.split_once('-') {
        Some((cc, rest)) if cc.len() == 2 && country(cc).is_some() => {
            let name = country(cc).unwrap_or(cc);
            let city = title_words(rest);
            if city.eq_ignore_ascii_case(name) {
                name.to_string()
            } else {
                format!("{name} - {city}")
            }
        }
        _ => match country(base) {
            Some(name) => name.to_string(),
            None => title_words(base),
        },
    };
    if streaming {
        label.push_str(" (Streaming)");
    }
    label
}

/// Parse `piactl get regions` output (one id per line). "auto" is left out.
pub fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| {
            *l != "auto"
                && l.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                && l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Default, PartialEq)]
pub struct Groups {
    pub us: Vec<String>,
    pub ca: Vec<String>,
    pub streaming: Vec<String>,
    pub other_a: Vec<String>,
    pub other_b: Vec<String>,
}

fn sort_by_label(v: &mut [String]) {
    v.sort_by_key(|id| pretty(id).to_lowercase());
}

/// Groups for the tray menu: US, Canada, Streaming, Other A-M, Other N-Z.
pub fn group(ids: &[String]) -> Groups {
    let mut g = Groups::default();
    for id in ids {
        if id.ends_with(STREAMING) {
            g.streaming.push(id.clone());
        } else if id.starts_with("us-") {
            g.us.push(id.clone());
        } else if id.starts_with("ca-") {
            g.ca.push(id.clone());
        } else {
            let first = pretty(id).chars().next().unwrap_or('A').to_ascii_uppercase();
            if first <= 'M' {
                g.other_a.push(id.clone())
            } else {
                g.other_b.push(id.clone())
            }
        }
    }
    for v in [&mut g.us, &mut g.ca, &mut g.streaming, &mut g.other_a, &mut g.other_b] {
        sort_by_label(v);
    }
    g
}

/// All regions sorted by name, filtered by a search text (matches name or id).
pub fn filtered(ids: &[String], filter: &str) -> Vec<String> {
    let f = filter.trim().to_lowercase();
    let mut v: Vec<String> =
        ids.iter().filter(|id| f.is_empty() || id.contains(&f) || pretty(id).to_lowercase().contains(&f)).cloned().collect();
    sort_by_label(&mut v);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pretty_names() {
        assert_eq!(pretty("auto"), "Auto (fastest)");
        assert_eq!(pretty("us-east"), "US - East");
        assert_eq!(pretty("us-new-york"), "US - New York");
        assert_eq!(pretty("us-washington-dc"), "US - Washington DC");
        assert_eq!(pretty("us-east-streaming-optimized"), "US - East (Streaming)");
        assert_eq!(pretty("de-germany-streaming-optimized"), "Germany (Streaming)");
        assert_eq!(pretty("nl-netherlands-streaming-optimized"), "Netherlands (Streaming)");
        assert_eq!(pretty("be-streaming-optimized"), "Belgium (Streaming)");
        assert_eq!(pretty("australia-streaming-optimized"), "Australia (Streaming)");
        assert_eq!(pretty("ca-ontario-streaming-optimized"), "Canada - Ontario (Streaming)");
        assert_eq!(pretty("isle-of-man"), "Isle of Man");
        assert_eq!(pretty("trinidad-and-tobago"), "Trinidad and Tobago");
        assert_eq!(pretty("hong-kong"), "Hong Kong");
        assert_eq!(pretty("uk-london"), "UK - London");
        assert_eq!(pretty("au-woolloomooloo"), "Australia - Woolloomooloo");
    }

    #[test]
    fn parse_and_group() {
        let text = "auto\r\nus-east\nca-toronto\nus-east-streaming-optimized\nnetherlands\nbahamas\n\n=====\nSome Error\n";
        let ids = parse_list(text);
        assert_eq!(ids.len(), 5);
        let g = group(&ids);
        assert_eq!(g.us, vec!["us-east"]);
        assert_eq!(g.ca, vec!["ca-toronto"]);
        assert_eq!(g.streaming, vec!["us-east-streaming-optimized"]);
        assert_eq!(g.other_a, vec!["bahamas"]);
        assert_eq!(g.other_b, vec!["netherlands"]);
    }

    #[test]
    fn filter_matches_name_and_id() {
        let ids: Vec<String> = ["us-new-york", "us-east", "ca-toronto"].iter().map(|s| s.to_string()).collect();
        assert_eq!(filtered(&ids, "york"), vec!["us-new-york"]);
        assert_eq!(filtered(&ids, "ca-"), vec!["ca-toronto"]);
        assert_eq!(filtered(&ids, "").len(), 3);
    }
}

#[cfg(test)]
mod dump {
    // Dev helper: PIALITE_REGIONS=<file> cargo test dump_regions -- --nocapture
    #[test]
    fn dump_regions() {
        let Ok(path) = std::env::var("PIALITE_REGIONS") else { return };
        let ids = super::parse_list(&std::fs::read_to_string(path).unwrap());
        let g = super::group(&ids);
        for (name, v) in [("US", &g.us), ("CA", &g.ca), ("STREAM", &g.streaming), ("A-M", &g.other_a), ("N-Z", &g.other_b)] {
            println!("== {name} ({})", v.len());
            println!("{}", v.iter().map(|i| super::pretty(i)).collect::<Vec<_>>().join(" | "));
        }
    }
}
