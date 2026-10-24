//! TCP, HTTP `/json/version` discovery, RFC 6455 WebSocket client transport, JSON-RPC session
//! multiplexing, base64 chunk decoding, and RFC 1952 `GzipStoredWriter`.

use serde_json::json;

use super::{
    RuntimeScanProbeSnapshot,
    analysis::parse_runtime_scan_snapshot_payload,
    capture::{DroppedEvidence, store_navigation_snapshot},
};

pub(super) fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' {
            break;
        }
        let val = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("Invalid base64 byte in trace chunk.".to_string()),
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Ok(out)
}

pub(super) struct GzipStoredWriter<W: std::io::Write> {
    inner: W,
    buffer: Vec<u8>,
    crc: u32,
    total_bytes: u32,
}

impl<W: std::io::Write> GzipStoredWriter<W> {
    pub(super) fn new(mut inner: W) -> std::io::Result<Self> {
        // RFC 1952 10-byte header: ID1=0x1f, ID2=0x8b, CM=8 (deflate), FLG=0, MTIME=0, XFL=0, OS=0xff
        inner.write_all(&[0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff])?;
        Ok(Self {
            inner,
            buffer: Vec::with_capacity(65_535),
            crc: 0xffff_ffff,
            total_bytes: 0,
        })
    }

    fn update_crc(&mut self, data: &[u8]) {
        for &b in data {
            let mut c = (self.crc ^ u32::from(b)) & 0xff;
            for _ in 0..8 {
                c = if (c & 1) != 0 {
                    0xedb8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            self.crc = (self.crc >> 8) ^ c;
        }
        self.total_bytes = self
            .total_bytes
            .wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
    }

    fn write_stored_block(&mut self, block: &[u8], final_block: bool) -> std::io::Result<()> {
        let header_byte = u8::from(final_block);
        let len = u16::try_from(block.len()).unwrap_or(u16::MAX);
        let nlen = !len;
        self.inner.write_all(&[header_byte])?;
        self.inner.write_all(&len.to_le_bytes())?;
        self.inner.write_all(&nlen.to_le_bytes())?;
        self.inner.write_all(block)
    }

    pub(super) fn write_chunk(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.update_crc(data);
        let mut slice = data;
        while !slice.is_empty() {
            if self.buffer.len() == 65_535 {
                let block = std::mem::replace(&mut self.buffer, Vec::with_capacity(65_535));
                self.write_stored_block(&block, false)?;
            }
            let space = 65_535 - self.buffer.len();
            let take = space.min(slice.len());
            self.buffer.extend_from_slice(&slice[..take]);
            slice = &slice[take..];
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> std::io::Result<W> {
        let remaining = std::mem::take(&mut self.buffer);
        self.write_stored_block(&remaining, true)?;
        let crc_final = !self.crc;
        self.inner.write_all(&crc_final.to_le_bytes())?;
        self.inner.write_all(&self.total_bytes.to_le_bytes())?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

fn parse_host_port_path(
    raw_url: &str,
    default_scheme: &str,
) -> Result<(String, u16, String), String> {
    let (scheme, after_scheme) = raw_url
        .split_once("://")
        .unwrap_or((default_scheme, raw_url));
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    let default_port = if scheme.eq_ignore_ascii_case("wss") || scheme.eq_ignore_ascii_case("https")
    {
        443
    } else {
        80
    };
    let (host, port) = if let Some(bracket_end) = authority.find(']') {
        let h = &authority[1..bracket_end];
        let p = authority[bracket_end + 1..]
            .strip_prefix(':')
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(default_port);
        (h.to_string(), p)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| format!("Invalid port in URL: {raw_url}"))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host, port, path.to_string()))
}

pub(super) fn resolve_cdp_ws_url(cdp_url: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let trimmed = cdp_url.trim();
    if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        return Ok(trimmed.to_string());
    }
    let (host, port, _) = parse_host_port_path(trimmed, "http")?;
    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| "Could not resolve CDP host".to_string())?;
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let req =
        format!("GET /json/version HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let (_, body) = resp
        .split_once("\r\n\r\n")
        .ok_or_else(|| "Invalid HTTP response from CDP endpoint".to_string())?;
    let json_val: serde_json::Value =
        serde_json::from_str(body.trim()).map_err(|e| e.to_string())?;
    json_val
        .get("webSocketDebuggerUrl")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "Missing webSocketDebuggerUrl in /json/version".to_string())
}

pub(super) struct CdpWebSocketClient {
    stream: std::net::TcpStream,
    read_buf: Vec<u8>,
    read_pos: usize,
    next_id: u64,
    pending_events: Vec<serde_json::Value>,
}

impl CdpWebSocketClient {
    pub(super) fn connect(ws_url: &str) -> Result<Self, String> {
        use std::io::{Read, Write};
        use std::net::{TcpStream, ToSocketAddrs};
        use std::time::Duration;

        let (host, port, path) = parse_host_port_path(ws_url, "ws")?;
        let addr = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?
            .next()
            .ok_or_else(|| "Could not resolve CDP WebSocket host".to_string())?;
        let timeout = Duration::from_secs(10);
        let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| e.to_string())?;
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));
        let handshake = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}:{port}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        );
        stream
            .write_all(handshake.as_bytes())
            .map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;

        let mut buf = Vec::with_capacity(1024);
        let mut temp = [0u8; 512];
        let header_end = loop {
            let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("CDP WebSocket closed during handshake".to_string());
            }
            buf.extend_from_slice(&temp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let header_str = String::from_utf8_lossy(&buf[..header_end]);
        if !header_str.starts_with("HTTP/1.1 101") {
            return Err(format!("CDP WebSocket upgrade failed: {header_str}"));
        }
        let leftover = buf[header_end..].to_vec();
        Ok(Self {
            stream,
            read_buf: leftover,
            read_pos: 0,
            next_id: 1,
            pending_events: Vec::new(),
        })
    }

    fn read_exact_bytes(&mut self, count: usize) -> Result<Vec<u8>, String> {
        use std::io::Read;

        let mut out = Vec::with_capacity(count);
        while out.len() < count {
            if self.read_pos < self.read_buf.len() {
                let avail = self.read_buf.len() - self.read_pos;
                let need = count - out.len();
                let take = avail.min(need);
                out.extend_from_slice(&self.read_buf[self.read_pos..self.read_pos + take]);
                self.read_pos += take;
                if self.read_pos == self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_pos = 0;
                }
            } else {
                let mut chunk = [0u8; 4096];
                let n = self.stream.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("CDP WebSocket connection closed unexpectedly".to_string());
                }
                self.read_buf.extend_from_slice(&chunk[..n]);
            }
        }
        Ok(out)
    }

    fn send_masked_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        use std::io::Write;

        let mask = [0x37u8, 0xfau8, 0x21u8, 0x3du8];
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (opcode & 0x0f));
        if payload.len() <= 125 {
            frame.push(0x80 | u8::try_from(payload.len()).unwrap_or(0));
        } else if payload.len() <= 65_535 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(
                &u16::try_from(payload.len())
                    .unwrap_or(u16::MAX)
                    .to_be_bytes(),
            );
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (idx, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[idx % 4]);
        }
        self.stream.write_all(&frame).map_err(|e| e.to_string())?;
        self.stream.flush().map_err(|e| e.to_string())
    }

    fn read_json_message(&mut self) -> Result<serde_json::Value, String> {
        let mut message_bytes = Vec::new();
        loop {
            let hdr = self.read_exact_bytes(2)?;
            let fin = (hdr[0] & 0x80) != 0;
            let opcode = hdr[0] & 0x0f;
            let masked = (hdr[1] & 0x80) != 0;
            let mut len = (hdr[1] & 0x7f) as usize;
            if len == 126 {
                let ext = self.read_exact_bytes(2)?;
                len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
            } else if len == 127 {
                let ext = self.read_exact_bytes(8)?;
                let len_u64 = u64::from_be_bytes([
                    ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
                ]);
                len = usize::try_from(len_u64).map_err(|_| "Frame too large".to_string())?;
            }
            let mask = if masked {
                let m = self.read_exact_bytes(4)?;
                [m[0], m[1], m[2], m[3]]
            } else {
                [0; 4]
            };
            let mut payload = self.read_exact_bytes(len)?;
            if masked {
                for (idx, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[idx % 4];
                }
            }
            match opcode {
                0x8 => return Err("CDP WebSocket closed by browser".to_string()),
                0x9 => {
                    let _ = self.send_masked_frame(0xA, &payload);
                    continue;
                }
                0xA => continue,
                0x0..=0x2 => {
                    message_bytes.extend_from_slice(&payload);
                    if fin {
                        break;
                    }
                }
                _ => continue,
            }
        }
        serde_json::from_slice(&message_bytes).map_err(|e| e.to_string())
    }

    pub(super) fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
        session_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let mut req = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(sid) = session_id {
            req["sessionId"] = serde_json::Value::String(sid.to_string());
        }
        let payload = req.to_string();
        self.send_masked_frame(0x1, payload.as_bytes())?;
        loop {
            let msg = self.read_json_message()?;
            if msg.get("id").and_then(serde_json::Value::as_u64) == Some(id) {
                if let Some(err_obj) = msg.get("error") {
                    let err_msg = err_obj
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("Unknown CDP error");
                    return Err(err_msg.to_string());
                }
                return Ok(msg
                    .get("result")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null));
            }
            self.pending_events.push(msg);
        }
    }

    pub(super) fn wait_for_event(
        &mut self,
        event_method: &str,
        timeout_ms: u64,
    ) -> Result<serde_json::Value, String> {
        use std::time::{Duration, Instant};

        if let Some(pos) = self
            .pending_events
            .iter()
            .position(|e| e.get("method").and_then(serde_json::Value::as_str) == Some(event_method))
        {
            return Ok(self.pending_events.remove(pos));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(format!("Timed out waiting for CDP event {event_method}"));
            }
            let _ = self.stream.set_read_timeout(Some(deadline - now));
            let msg = self.read_json_message()?;
            if msg.get("method").and_then(serde_json::Value::as_str) == Some(event_method) {
                let _ = self.stream.set_read_timeout(Some(Duration::from_secs(10)));
                return Ok(msg);
            }
            self.pending_events.push(msg);
        }
    }

    pub(super) fn drain_binding_events(
        &mut self,
        binding_name: &str,
        expected_token: &str,
        snapshots: &mut Vec<RuntimeScanProbeSnapshot>,
        discarded: &mut DroppedEvidence,
    ) {
        let events = std::mem::take(&mut self.pending_events);
        for event in events {
            if event.get("method").and_then(serde_json::Value::as_str)
                == Some("Runtime.bindingCalled")
            {
                let params = &event["params"];
                if params.get("name").and_then(serde_json::Value::as_str) == Some(binding_name)
                    && let Some(payload) = params.get("payload").and_then(serde_json::Value::as_str)
                    && let Some(snap) = parse_runtime_scan_snapshot_payload(payload, expected_token)
                {
                    store_navigation_snapshot(snapshots, discarded, snap);
                }
            } else {
                self.pending_events.push(event);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{GzipStoredWriter, decode_base64, parse_host_port_path};

    #[test]
    fn parses_ws_and_http_endpoints_and_writes_rfc1952_stored_gzip() {
        assert_eq!(
            parse_host_port_path("ws://127.0.0.1:9222/devtools/browser/abc", "ws"),
            Ok((
                "127.0.0.1".to_string(),
                9222,
                "/devtools/browser/abc".to_string()
            ))
        );
        assert_eq!(
            parse_host_port_path("http://[::1]:9333", "http"),
            Ok(("::1".to_string(), 9333, "/".to_string()))
        );
        assert_eq!(
            decode_base64("eyJ0cmFjZSI6dHJ1ZX0="),
            Ok(b"{\"trace\":true}".to_vec())
        );

        let mut gz = GzipStoredWriter::new(Vec::new()).unwrap_or_else(|e| panic!("{e}"));
        gz.write_chunk(b"{\"traceEvents\":[]}")
            .unwrap_or_else(|e| panic!("{e}"));
        let bytes = gz.finish().unwrap_or_else(|e| panic!("{e}"));
        assert!(bytes.starts_with(&[0x1f, 0x8b, 0x08]));
    }
}
