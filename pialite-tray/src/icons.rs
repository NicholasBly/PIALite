//! Draws the tray icon in code (no image files): a power symbol with a status dot.
//! 4x4 supersampling gives smooth edges.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum Kind {
    Unknown = 0,
    Good = 1,
    Busy = 2,
    Bad = 3,
}

impl Kind {
    /// Status colour group for a piactl connection state (None = PIA not reachable).
    pub fn from_state(state: Option<&str>) -> Kind {
        match state {
            None => Kind::Unknown,
            Some("Connected") => Kind::Good,
            Some("Disconnected") => Kind::Bad,
            Some(_) => Kind::Busy,
        }
    }

    pub fn rgb(self) -> [u8; 3] {
        match self {
            Kind::Good => [0x4c, 0xb6, 0x49],
            Kind::Busy => [0xe8, 0xa6, 0x28],
            Kind::Bad => [0xd9, 0x53, 0x4f],
            Kind::Unknown => [0x8a, 0x8f, 0x9c],
        }
    }
}

pub const SIZE: u32 = 32;

fn dist(x: f32, y: f32, cx: f32, cy: f32) -> f32 {
    ((x - cx).powi(2) + (y - cy).powi(2)).sqrt()
}

fn sample(x: f32, y: f32, glyph: [u8; 3], outline: [u8; 3], dot: [u8; 3]) -> Option<[u8; 3]> {
    // status dot (bottom-right, drawn on top) with a thin outline
    let d = dist(x, y, 23.5, 23.5);
    if d <= 6.0 {
        return Some(dot);
    }
    if d <= 7.8 {
        return Some(outline);
    }
    // power symbol: open ring + vertical bar
    let (cx, cy) = (14.0, 15.5);
    let r = dist(x, y, cx, cy);
    let angle_from_top = (x - cx).atan2(cy - y).abs();
    if (r - 9.0).abs() <= 1.7 && angle_from_top > 0.70 {
        return Some(glyph);
    }
    if (x - cx).abs() <= 1.6 && (3.5..=15.0).contains(&y) {
        return Some(glyph);
    }
    None
}

/// RGBA pixels (SIZE x SIZE). `light_taskbar` picks a dark glyph for light taskbars.
pub fn render(kind: Kind, light_taskbar: bool) -> Vec<u8> {
    let n = SIZE as usize;
    let ss = 4usize;
    let glyph = if light_taskbar { [0x30, 0x30, 0x30] } else { [0xf2, 0xf2, 0xf2] };
    let outline = if light_taskbar { [0xff, 0xff, 0xff] } else { [0x20, 0x20, 0x20] };
    let dot = kind.rgb();
    let mut out = vec![0u8; n * n * 4];
    for py in 0..n {
        for px in 0..n {
            let (mut r, mut g, mut b, mut hits) = (0u32, 0u32, 0u32, 0u32);
            for sy in 0..ss {
                for sx in 0..ss {
                    let x = px as f32 + (sx as f32 + 0.5) / ss as f32;
                    let y = py as f32 + (sy as f32 + 0.5) / ss as f32;
                    if let Some(c) = sample(x, y, glyph, outline, dot) {
                        r += c[0] as u32;
                        g += c[1] as u32;
                        b += c[2] as u32;
                        hits += 1;
                    }
                }
            }
            if let (Some(r), Some(g), Some(b)) = (r.checked_div(hits), g.checked_div(hits), b.checked_div(hits)) {
                let i = (py * n + px) * 4;
                out[i] = r as u8;
                out[i + 1] = g as u8;
                out[i + 2] = b as u8;
                out[i + 3] = (hits * 255 / (ss * ss) as u32) as u8;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn px(img: &[u8], x: usize, y: usize) -> [u8; 4] {
        let i = (y * SIZE as usize + x) * 4;
        [img[i], img[i + 1], img[i + 2], img[i + 3]]
    }

    #[test]
    fn icon_shape_and_colours() {
        let img = render(Kind::Good, false);
        assert_eq!(img.len(), (SIZE * SIZE * 4) as usize);
        assert_eq!(px(&img, 0, 0)[3], 0, "corner is transparent");
        assert_eq!(px(&img, 23, 23), [0x4c, 0xb6, 0x49, 255], "dot is green");
        assert_eq!(px(&img, 13, 8)[3], 255, "power bar is drawn");
        let red = render(Kind::Bad, true);
        assert_eq!(px(&red, 23, 23), [0xd9, 0x53, 0x4f, 255]);
        assert_eq!(&px(&red, 13, 8)[..3], &[0x30, 0x30, 0x30], "dark glyph on light taskbar");
    }

    #[test]
    fn state_mapping() {
        assert_eq!(Kind::from_state(Some("Connected")), Kind::Good);
        assert_eq!(Kind::from_state(Some("Disconnected")), Kind::Bad);
        assert_eq!(Kind::from_state(Some("Reconnecting")), Kind::Busy);
        assert_eq!(Kind::from_state(None), Kind::Unknown);
    }
}

#[cfg(test)]
mod dump {
    // Dev helper: PIALITE_ICONS=<dir> cargo test dump_icons
    #[test]
    fn dump_icons() {
        let Ok(dir) = std::env::var("PIALITE_ICONS") else { return };
        for (name, k) in
            [("good", super::Kind::Good), ("busy", super::Kind::Busy), ("bad", super::Kind::Bad), ("unknown", super::Kind::Unknown)]
        {
            for (theme, light) in [("dark", false), ("light", true)] {
                std::fs::write(format!("{dir}/{name}_{theme}.rgba"), super::render(k, light)).unwrap();
            }
        }
    }
}
