//! Minimal HTTP/1.1 client for DoH (RFC 8484 POST) over any Read+Write stream.
//! Strict and bounded (audit P2-15): header size checked before it's accepted,
//! chunk sizes/trailers capped with checked arithmetic, chunk CRLFs verified,
//! body capped at the largest possible DNS message.

use std::io::{Read, Write};

const MAX_HEADER: usize = 8 * 1024;
pub const MAX_BODY: usize = 65_535;
const MAX_CHUNK_LINE: usize = 64;

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    /// Redirect target (3xx replies only), original spelling.
    pub location: String,
    pub body: Vec<u8>,
    pub content_type: String,
    pub keep_alive: bool,
}

pub fn post_dns<S: Read + Write>(s: &mut S, host: &str, path: &str, query: &[u8]) -> Result<Reply, String> {
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: pialite-guard\r\nAccept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        query.len()
    );
    let mut req = head.into_bytes();
    req.extend_from_slice(query);
    s.write_all(&req).map_err(|e| format!("send: {e}"))?;
    s.flush().map_err(|e| format!("send: {e}"))?;
    let r = read_reply(s)?;
    if r.status != 200 {
        return Err(format!("server answered HTTP {}", r.status)); // DoH never follows redirects
    }
    Ok(r)
}

pub fn get<S: Read + Write>(s: &mut S, host: &str, path: &str) -> Result<Reply, String> {
    // NextDNS's test page answers JSON to command-line clients; its own
    // `nextdns diag` tool identifies as curl for the same reason.
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
    s.flush().map_err(|e| format!("send: {e}"))?;
    read_reply(s)
}

/// Buffered reader with a cursor, so parsing never re-copies the buffer.
struct Buf<'a, S: Read> {
    s: &'a mut S,
    data: Vec<u8>,
    pos: usize,
}

impl<'a, S: Read> Buf<'a, S> {
    fn avail(&self) -> &[u8] {
        &self.data[self.pos..]
    }
    fn more(&mut self) -> Result<usize, String> {
        if self.pos > 0 && self.pos == self.data.len() {
            self.data.clear();
            self.pos = 0;
        }
        let mut tmp = [0u8; 4096];
        let n = match self.s.read(&mut tmp) {
            Ok(n) => n,
            // server hung up without a TLS goodbye: same as a close (length
            // checks still catch a cut-off body)
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(format!("receive: {e}")),
        };
        self.data.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
    /// Bytes up to (not including) the next CRLF, at most `cap` long.
    fn line(&mut self, cap: usize, what: &str) -> Result<Vec<u8>, String> {
        loop {
            if let Some(p) = self.avail().windows(2).position(|w| w == b"\r\n") {
                if p > cap {
                    return Err(format!("{what} too long"));
                }
                let l = self.avail()[..p].to_vec();
                self.pos += p + 2;
                return Ok(l);
            }
            if self.avail().len() > cap + 1 {
                return Err(format!("{what} too long"));
            }
            if self.more()? == 0 {
                return Err(format!("connection closed in {what}"));
            }
        }
    }
    fn take(&mut self, n: usize) -> Result<Vec<u8>, String> {
        while self.avail().len() < n {
            if self.more()? == 0 {
                return Err("connection closed mid-response".into());
            }
        }
        let v = self.avail()[..n].to_vec();
        self.pos += n;
        Ok(v)
    }
}

pub fn read_reply<S: Read>(s: &mut S) -> Result<Reply, String> {
    read_reply_max(s, MAX_BODY)
}

/// GET for downloads (updates): any body size up to `max_body`.
pub fn get_max<S: Read + Write>(s: &mut S, host: &str, path: &str, max_body: usize) -> Result<Reply, String> {
    let ua = concat!("pialite/", env!("CARGO_PKG_VERSION"));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("send: {e}"))?;
    s.flush().map_err(|e| format!("send: {e}"))?;
    read_reply_max(s, max_body)
}

pub fn read_reply_max<S: Read>(s: &mut S, max_body: usize) -> Result<Reply, String> {
    let mut b = Buf { s, data: Vec::with_capacity(2048), pos: 0 };

    // ---- status line + headers, limited to MAX_HEADER in total
    let mut used = 0usize;
    let status = b.line(MAX_HEADER, "response header")?;
    used += status.len() + 2;
    let status = String::from_utf8_lossy(&status).to_string();
    if !status.starts_with("HTTP/1.") {
        return Err("not an HTTP/1.x response".into());
    }
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or("bad status line")?;
    let mut close = status.starts_with("HTTP/1.0");
    let mut location = String::new();
    let (mut content_length, mut chunked, mut content_type) = (None::<usize>, false, String::new());
    loop {
        let line = b.line(MAX_HEADER.saturating_sub(used), "response header")?;
        used += line.len() + 2;
        if used > MAX_HEADER {
            return Err("response header too large".into());
        }
        if line.is_empty() {
            break;
        }
        let line = String::from_utf8_lossy(&line).to_string();
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.trim().eq_ignore_ascii_case("location") {
            location = v.trim().to_string();
        }
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        match k.as_str() {
            "content-length" => content_length = Some(v.parse().map_err(|_| "bad Content-Length")?),
            "transfer-encoding" => chunked = v.contains("chunked"),
            "content-type" => content_type = v,
            "connection" if v.contains("close") => close = true,
            "connection" if v.contains("keep-alive") => close = false,
            _ => {}
        }
    }

    // ---- body
    let body = if chunked {
        read_chunked(&mut b, max_body)?
    } else if let Some(len) = content_length {
        if len > max_body {
            return Err("response too large".into());
        }
        b.take(len)?
    } else {
        // no length: runs until the server closes the connection
        close = true;
        loop {
            if b.avail().len() > max_body {
                return Err("response too large".into());
            }
            if b.more()? == 0 {
                break;
            }
        }
        b.avail().to_vec()
    };

    // 200, or a redirect with a target (the caller decides whether to follow)
    if code != 200 && !((300..400).contains(&code) && !location.is_empty()) {
        return Err(format!("server answered HTTP {code}"));
    }
    Ok(Reply { status: code, location, body, content_type, keep_alive: !close })
}

fn read_chunked<S: Read>(b: &mut Buf<S>, max_body: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line = b.line(MAX_CHUNK_LINE, "chunk size")?;
        let txt = String::from_utf8_lossy(&line).to_string();
        let size = usize::from_str_radix(txt.split(';').next().unwrap_or("").trim(), 16).map_err(|_| "bad chunk size")?;
        if size == 0 {
            // trailers (bounded), then a blank line
            let mut used = 0usize;
            loop {
                let t = b.line(MAX_HEADER, "trailer")?;
                used += t.len() + 2;
                if used > MAX_HEADER {
                    return Err("trailers too large".into());
                }
                if t.is_empty() {
                    return Ok(body);
                }
            }
        }
        let total = body.len().checked_add(size).filter(|&t| t <= max_body).ok_or("response too large")?;
        let data = b.take(size)?;
        if b.take(2)? != b"\r\n" {
            return Err("chunk not followed by CRLF".into());
        }
        body.extend_from_slice(&data);
        debug_assert_eq!(body.len(), total);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Fake connection: reads canned bytes (in small pieces), records writes.
    struct Fake {
        input: Cursor<Vec<u8>>,
        written: Vec<u8>,
        piece: usize,
    }
    impl Read for Fake {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.piece);
            self.input.read(&mut buf[..n])
        }
    }
    impl Write for Fake {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn fake(resp: &[u8]) -> Fake {
        Fake { input: Cursor::new(resp.to_vec()), written: vec![], piece: 7 }
    }
    fn big(resp: &[u8]) -> Fake {
        Fake { input: Cursor::new(resp.to_vec()), written: vec![], piece: 4096 }
    }

    #[test]
    fn content_length_keepalive() {
        let mut f = fake(b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 5\r\n\r\nhelloEXTRA");
        let r = post_dns(&mut f, "dns.nextdns.io", "/abc123/pc", b"Q").unwrap();
        assert_eq!(r.body, b"hello");
        assert_eq!(r.content_type, "application/dns-message");
        assert!(r.keep_alive);
        let req = String::from_utf8_lossy(&f.written);
        assert!(req.starts_with("POST /abc123/pc HTTP/1.1\r\nHost: dns.nextdns.io\r\n"));
        assert!(req.contains("Content-Length: 1\r\n"));
        assert!(req.ends_with("\r\n\r\nQ"));
    }

    #[test]
    fn redirects_only_for_get() {
        let resp = b"HTTP/1.1 302 Found\r\nLocation: https://Ab12.test.nextdns.io/\r\nContent-Length: 0\r\n\r\n";
        let r = get(&mut fake(resp), "test.nextdns.io", "/").unwrap();
        assert_eq!((r.status, r.location.as_str()), (302, "https://Ab12.test.nextdns.io/"));
        assert!(post_dns(&mut fake(resp), "h", "/", b"").unwrap_err().contains("302"), "DoH never follows redirects");
        assert!(read_reply(&mut fake(b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n")).is_err(), "redirect without target");
    }

    #[test]
    fn chunked_body() {
        let mut f = fake(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nX-T: 1\r\n\r\n");
        let r = post_dns(&mut f, "h", "/", b"").unwrap();
        assert_eq!(r.body, b"abcde");
        assert!(r.keep_alive);
    }

    #[test]
    fn close_and_errors() {
        let mut f = fake(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok");
        assert!(!post_dns(&mut f, "h", "/", b"").unwrap().keep_alive);
        let mut f = fake(b"HTTP/1.1 200 OK\r\n\r\nuntil-eof");
        let r = post_dns(&mut f, "h", "/", b"").unwrap();
        assert_eq!(r.body, b"until-eof");
        assert!(!r.keep_alive);
        let mut f = fake(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        assert!(post_dns(&mut f, "h", "/", b"").unwrap_err().contains("400"));
        let mut f = fake(b"HTTP/1.1 200 OK\r\nContent-Len");
        assert!(post_dns(&mut f, "h", "/", b"").is_err());
        let mut f = fake(b"SSH-2.0-OpenSSH\r\n\r\n");
        assert!(post_dns(&mut f, "h", "/", b"").unwrap_err().contains("HTTP/1.x"));
    }

    #[test]
    fn oversized_header_rejected_even_when_terminator_arrives() {
        let mut resp = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        resp.extend(vec![b'a'; MAX_HEADER]);
        resp.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        // one big read delivers the whole thing including the terminator
        assert!(read_reply(&mut big(&resp)).unwrap_err().contains("too l"));
        // many small headers adding up
        let mut resp = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..1000 {
            resp.extend_from_slice(b"X-A: bbbbbbbbbbbbbbbbbbbb\r\n");
        }
        resp.extend_from_slice(b"\r\n");
        assert!(read_reply(&mut big(&resp)).is_err());
    }

    #[test]
    fn chunk_framing_is_validated() {
        // CRLF after chunk data must really be CRLF
        assert!(read_reply(&mut fake(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXY0\r\n\r\n"))
            .unwrap_err()
            .contains("CRLF"));
        // absurd chunk size
        assert!(read_reply(&mut fake(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n")).is_err());
        // endless chunk-size line
        let mut resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        resp.extend(vec![b'0'; 500]);
        assert!(read_reply(&mut big(&resp)).unwrap_err().contains("chunk size too long"));
        // endless trailers
        let mut resp = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        for _ in 0..1000 {
            resp.extend_from_slice(b"X-T: cccccccccccccccc\r\n");
        }
        resp.extend_from_slice(b"\r\n");
        assert!(read_reply(&mut big(&resp)).unwrap_err().contains("trailers"));
        // body over the DNS maximum
        let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert!(read_reply(&mut fake(resp.as_bytes())).unwrap_err().contains("too large"));
    }
}
