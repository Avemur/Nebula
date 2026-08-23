//! The client half: one POST to the HTTP gateway of §11.1.
//!
//! ponytail: hand-rolled HTTP/1.1 over `TcpStream`, one connection per call.
//! Every request sends `Connection: close`, so "read to EOF" is the whole
//! response framing and there is no chunked decoding to get wrong. The ceiling
//! is the connection setup per tool call — negligible against a sandboxed
//! script, and the upgrade path is a pooled `hyper-util` client if a tool call
//! ever gets cheap enough for a TCP handshake to show up next to it.

use std::collections::HashMap;
use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Set by the gateway on every non-200 (§11.1).
pub const FAULT_HEADER: &str = "x-nebula-fault";
/// Read by the gateway; echoed back with the budget that was actually applied.
pub const DEADLINE_HEADER: &str = "x-nebula-deadline-ms";

/// Where to reach the cluster, and as whom.
#[derive(Clone)]
pub struct Gateway {
    /// `host:port` of the §11.1 HTTP gateway.
    pub address: String,
    /// v1 auth: the bearer token *is* the tenant id (§13).
    pub token: String,
}

pub struct Reply {
    pub status: u16,
    /// `X-Nebula-Fault`, absent on success.
    pub fault: Option<String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).trim_end().to_string()
    }

    /// The fault name, or `unknown` when a non-200 arrived without one — which
    /// would mean something other than the gateway answered.
    pub fn fault_or_unknown(&self) -> &str {
        self.fault.as_deref().unwrap_or("unknown")
    }
}

impl Gateway {
    /// `POST /execute/{function_id}` with the script as the body.
    pub async fn execute(
        &self,
        function_id: &str,
        deadline_ms: u32,
        body: &[u8],
    ) -> io::Result<Reply> {
        let head = format!(
            "POST /execute/{function_id} HTTP/1.1\r\n\
             Host: nebula\r\n\
             Connection: close\r\n\
             Authorization: Bearer {}\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Length: {}\r\n\
             {DEADLINE_HEADER}: {deadline_ms}\r\n\r\n",
            self.token,
            body.len()
        );

        let mut stream = TcpStream::connect(&self.address).await?;
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body).await?;

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await?;
        parse(&raw)
    }
}

fn parse(raw: &[u8]) -> io::Result<Reply> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no header terminator"))?;

    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.lines();

    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no status line"))?;

    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_lowercase(), value.trim().to_string()))
        .collect();

    Ok(Reply {
        status,
        fault: headers.get(FAULT_HEADER).cloned(),
        body: raw[split + 4..].to_vec(),
    })
}
