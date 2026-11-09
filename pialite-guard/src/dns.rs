//! Minimal DNS wire-format helpers: forward queries untouched, check that an
//! answer really belongs to the question asked (audit P2-14), build error /
//! truncated replies, and read A records for the self-test.

pub const HEADER: usize = 12;
/// Largest DNS message (DNS over TCP uses a 16-bit length).
pub const MAX_MESSAGE: usize = 65_535;

pub fn id(msg: &[u8]) -> Option<u16> {
    (msg.len() >= HEADER).then(|| u16::from_be_bytes([msg[0], msg[1]]))
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

/// Skip a (possibly compressed) domain name; returns the offset just after it.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *msg.get(at)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(at + 1),
            0x00 => at += 1 + len,
            0xC0 => {
                msg.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None, // reserved label types
        }
    }
    None
}

/// End offset of the question section (header + questions).
fn questions_end(msg: &[u8]) -> Option<usize> {
    let qd = u16_at(msg, 4)? as usize;
    let mut at = HEADER;
    for _ in 0..qd {
        at = skip_name(msg, at)? + 4; // qtype + qclass
        if at > msg.len() {
            return None;
        }
    }
    Some(at)
}

/// The raw question section.
pub fn question(msg: &[u8]) -> Option<&[u8]> {
    questions_end(msg).map(|end| &msg[HEADER..end])
}

/// The first question's name: lowercase, dotted, no trailing dot.
pub fn qname(msg: &[u8]) -> Option<String> {
    let q = question(msg)?;
    let (mut i, mut parts) = (0usize, Vec::new());
    loop {
        let len = *q.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer: not expected in a question
        }
        parts.push(String::from_utf8_lossy(q.get(i + 1..i + 1 + len)?).to_ascii_lowercase());
        i += 1 + len;
    }
    Some(parts.join("."))
}

/// Is this plausibly a DNS query we should forward? (QR=0, standard opcode, 1+ question)
pub fn is_query(msg: &[u8]) -> bool {
    msg.len() >= HEADER
        && msg.len() <= MAX_MESSAGE
        && msg[2] & 0x80 == 0
        && (msg[2] >> 3) & 0x0F == 0
        && u16_at(msg, 4).unwrap_or(0) >= 1
        && questions_end(msg).is_some()
}

/// Does `reply` answer `query`? Checks the response bit, opcode and that the
/// question matches (names compared case-insensitively). IDs are checked by
/// the caller because DoH uses ID 0 on the wire.
pub fn check_response(reply: &[u8], query: &[u8]) -> Result<(), String> {
    if reply.len() < HEADER || reply.len() > MAX_MESSAGE {
        return Err("answer has a bad size".into());
    }
    if reply[2] & 0x80 == 0 {
        return Err("answer is not marked as a response".into());
    }
    if (reply[2] >> 3) & 0x0F != (query[2] >> 3) & 0x0F {
        return Err("answer has a different opcode".into());
    }
    let (Some(rq), Some(qq)) = (question(reply), question(query)) else {
        return Err("answer has an unreadable question section".into());
    };
    if !rq.eq_ignore_ascii_case(qq) {
        return Err("answer is for a different question".into());
    }
    Ok(())
}

/// Largest UDP reply the client accepts: EDNS0 payload size if present, else 512.
pub fn udp_limit(query: &[u8]) -> usize {
    let mut limit = 512usize;
    (|| -> Option<()> {
        let an = u16_at(query, 6)? as usize;
        let ns = u16_at(query, 8)? as usize;
        let ar = u16_at(query, 10)? as usize;
        let mut at = questions_end(query)?;
        for i in 0..(an + ns + ar) {
            at = skip_name(query, at)?;
            let rtype = u16_at(query, at)?;
            let class = u16_at(query, at + 2)?;
            let rdlen = u16_at(query, at + 8)? as usize;
            if i >= an + ns && rtype == 41 {
                limit = (class as usize).clamp(512, 4096);
            }
            at += 10 + rdlen;
        }
        Some(())
    })();
    limit
}

/// Reply with the TC (truncated) bit so the client retries over TCP.
pub fn truncated(reply: &[u8]) -> Vec<u8> {
    let end = questions_end(reply).unwrap_or(HEADER.min(reply.len()));
    let mut out = reply[..end].to_vec();
    if out.len() >= HEADER {
        out[2] |= 0x02; // TC
        out[6..12].fill(0); // no answer / authority / additional records
    }
    out
}

/// SERVFAIL reply for a query we couldn't answer (no fallback to unencrypted DNS).
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let end = questions_end(query).unwrap_or(HEADER.min(query.len()));
    let mut out = query[..end].to_vec();
    if out.len() >= HEADER {
        out[2] = 0x80 | (query[2] & 0x79); // QR=1, keep opcode + RD
        out[3] = 0x80 | 0x02; // RA=1, RCODE=2 (SERVFAIL)
        out[6..12].fill(0);
    }
    out
}

/// Build a query (with EDNS0), refusing names DNS can't carry.
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err("name must be 1-253 characters".into());
    }
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("bad label '{label}' (1-63 characters each)"));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    q.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // OPT, 1232-byte UDP payload
    Ok(q)
}

/// (RCODE, number of answers) of a reply.
pub fn summary(reply: &[u8]) -> Option<(u8, u16)> {
    Some((reply.get(3)? & 0x0F, u16_at(reply, 6)?))
}

/// IPv4 addresses from the answer section.
pub fn a_records(reply: &[u8]) -> Vec<std::net::Ipv4Addr> {
    let mut out = vec![];
    (|| -> Option<()> {
        let an = u16_at(reply, 6)? as usize;
        let mut at = questions_end(reply)?;
        for _ in 0..an {
            at = skip_name(reply, at)?;
            let rtype = u16_at(reply, at)?;
            let rdlen = u16_at(reply, at + 8)? as usize;
            let data = reply.get(at + 10..at + 10 + rdlen)?;
            if rtype == 1 && rdlen == 4 {
                out.push(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            at += 10 + rdlen;
        }
        Some(())
    })();
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// A query for example.com A, optionally with an EDNS0 OPT record.
    pub fn query(id: u16, edns: Option<u16>) -> Vec<u8> {
        let mut q = vec![];
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if edns.is_some() { 1 } else { 0 }]);
        for label in ["example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        if let Some(size) = edns {
            q.extend_from_slice(&[0, 0, 41]);
            q.extend_from_slice(&size.to_be_bytes());
            q.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        }
        q
    }

    /// The query turned into an answer with one A record (compressed name).
    pub fn answer(q: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let end = questions_end(q).unwrap();
        let mut a = q[..end].to_vec();
        a[2] |= 0x80;
        a[7] = 1;
        a[10] = 0;
        a[11] = 0;
        a.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        a.extend_from_slice(&ip);
        a
    }

    #[test]
    fn parse_and_build() {
        let q = query(0xBEEF, None);
        assert!(is_query(&q));
        assert_eq!(id(&q), Some(0xBEEF));
        assert_eq!(udp_limit(&q), 512);
        assert_eq!(udp_limit(&query(1, Some(1232))), 1232);
        assert_eq!(udp_limit(&query(1, Some(100))), 512);

        let sf = servfail(&q);
        assert_eq!(sf.len(), q.len());
        assert_eq!(sf[3] & 0x0F, 2, "RCODE SERVFAIL");
        assert!(!is_query(&sf));

        let mut big = q.clone();
        big[2] |= 0x80;
        big[7] = 3;
        big.extend(vec![0u8; 900]);
        let tc = truncated(&big);
        assert_eq!(tc.len(), q.len());
        assert_eq!(tc[2] & 0x02, 0x02, "TC set");

        let b = build_query(0x5151, "www.example.com.", 1).unwrap();
        assert!(is_query(&b));
        assert_eq!(udp_limit(&b), 1232);
        assert!(build_query(1, &format!("{}.com", "a".repeat(64)), 1).is_err(), "64-char label");
        assert!(build_query(1, "a..b", 1).is_err());
        assert!(build_query(1, &"a.".repeat(130), 1).is_err(), "over 253");
        assert!(!is_query(&[0u8; 5]));
    }

    #[test]
    fn answer_must_match_question() {
        let q = query(7, None);
        let a = answer(&q, [1, 2, 3, 4]);
        assert!(check_response(&a, &q).is_ok());
        assert_eq!(a_records(&a), vec![std::net::Ipv4Addr::new(1, 2, 3, 4)]);
        // name case differs (DNS 0x20) -> still the same question
        let mut a2 = a.clone();
        a2[13] = b'E';
        assert!(check_response(&a2, &q).is_ok());
        // different name
        let mut a3 = a.clone();
        a3[14] = b'z';
        assert!(check_response(&a3, &q).unwrap_err().contains("different question"));
        // not a response
        assert!(check_response(&q, &q).is_err());
        // junk
        assert!(check_response(b"<html>hello</html>", &q).is_err());
        // reserved label type (0x40) is rejected, not misparsed
        let mut bad = q.clone();
        bad[12] = 0x41;
        assert!(!is_query(&bad));
    }
}
