use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use futures_util::StreamExt;
use serde::{Deserialize, Deserializer, Serialize};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

use crate::runtime::RuntimeEvent;

/// Maximum number of recent connections retained in the live traffic ring buffer.
pub const MAX_LIVE_CONNECTIONS: usize = 200;

const INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(150);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Single live or recent connection reported by the Clash API `/connections` stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveConnection {
    pub id: String,
    pub process_name: String,
    pub destination: String,
    pub network: String,
    pub outbound_tag: String,
    pub node_id: Option<String>,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// Bounded ring buffer retaining up to [`MAX_LIVE_CONNECTIONS`] recent connections.
#[derive(Debug, Clone)]
pub struct ConnectionRingBuffer {
    capacity: usize,
    entries: VecDeque<LiveConnection>,
}

impl ConnectionRingBuffer {
    /// Creates a new ring buffer with capacity `capacity` (clamped to at least 1).
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            entries: VecDeque::with_capacity(cap),
        }
    }

    /// Merges a parsed Clash `/connections` snapshot into the buffer and returns the current items.
    pub fn push_snapshot(&mut self, connections: Vec<LiveConnection>) -> Vec<LiveConnection> {
        for conn in connections {
            if !conn.id.is_empty() {
                if let Some(pos) = self.entries.iter().position(|c| c.id == conn.id) {
                    self.entries.remove(pos);
                }
            }
            while self.entries.len() >= self.capacity {
                self.entries.pop_front();
            }
            self.entries.push_back(conn);
        }
        self.snapshot()
    }

    /// Returns a snapshot of buffered connections (most recent last).
    pub fn snapshot(&self) -> Vec<LiveConnection> {
        self.entries.iter().cloned().collect()
    }
}

impl Default for ConnectionRingBuffer {
    fn default() -> Self {
        Self::new(MAX_LIVE_CONNECTIONS)
    }
}

#[derive(Debug, Deserialize)]
struct ClashConnectionsPayload {
    #[serde(default)]
    connections: Option<Vec<ClashConnectionEntry>>,
}

#[derive(Debug, Deserialize)]
struct ClashConnectionEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    metadata: ClashMetadata,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    upload: u64,
    #[serde(default)]
    download: u64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClashMetadata {
    #[serde(default)]
    network: String,
    #[serde(default)]
    host: String,
    #[serde(default, rename = "destinationIP")]
    destination_ip: String,
    #[serde(default, deserialize_with = "deserialize_port_opt")]
    destination_port: Option<String>,
    #[serde(default)]
    process: String,
    #[serde(default)]
    process_path: String,
}

fn deserialize_port_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let val = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match val {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(other) => Some(other.to_string()),
    })
}

fn resolve_process_name(process: &str, process_path: &str) -> String {
    let direct = process.trim();
    if !direct.is_empty() {
        return direct.to_string();
    }
    process_path
        .trim()
        .rsplit(['\\', '/'])
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("")
        .to_string()
}

fn format_destination(host: &str, dest_ip: &str, port: Option<&str>) -> String {
    let target = {
        let h = host.trim();
        if !h.is_empty() {
            h
        } else {
            dest_ip.trim()
        }
    };
    if target.is_empty() {
        return String::new();
    }
    match port.map(str::trim).filter(|p| !p.is_empty() && *p != "0") {
        Some(p) => {
            if target.contains(':') && !target.starts_with('[') {
                format!("[{target}]:{p}")
            } else {
                format!("{target}:{p}")
            }
        }
        None => target.to_string(),
    }
}

/// Parses a Clash API `/connections` JSON payload and resolves outbound tags to NetFlow node IDs.
pub fn parse_clash_connections_json(
    raw: &str,
    outbound_to_node_id: &HashMap<String, String>,
) -> Result<Vec<LiveConnection>, serde_json::Error> {
    let payload: ClashConnectionsPayload = serde_json::from_str(raw)?;
    let entries = payload.connections.unwrap_or_default();

    let connections = entries
        .into_iter()
        .map(|entry| {
            let (outbound_tag, node_id) = entry
                .chains
                .iter()
                .find_map(|tag| {
                    outbound_to_node_id
                        .get(tag)
                        .map(|id| (tag.clone(), Some(id.clone())))
                })
                .unwrap_or_else(|| {
                    let fallback = entry.chains.first().cloned().unwrap_or_default();
                    (fallback, None)
                });

            LiveConnection {
                id: entry.id,
                process_name: resolve_process_name(
                    &entry.metadata.process,
                    &entry.metadata.process_path,
                ),
                destination: format_destination(
                    &entry.metadata.host,
                    &entry.metadata.destination_ip,
                    entry.metadata.destination_port.as_deref(),
                ),
                network: entry.metadata.network.trim().to_string(),
                outbound_tag,
                node_id,
                upload_bytes: entry.upload,
                download_bytes: entry.download,
            }
        })
        .collect();

    Ok(connections)
}

/// Background WebSocket client streaming Clash API `/connections` updates as [`RuntimeEvent::TrafficUpdated`].
pub struct TrafficMonitor {
    stop_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<JoinHandle<()>>,
}

impl TrafficMonitor {
    /// Spawns a Tokio task connecting to `ws://127.0.0.1:<clash_api_port>/connections?interval=1000`.
    pub fn spawn(
        clash_api_port: u16,
        outbound_to_node_id: HashMap<String, String>,
        tx: broadcast::Sender<RuntimeEvent>,
    ) -> Self {
        let (stop_tx, mut stop_rx) = oneshot::channel();
        let url = format!("ws://127.0.0.1:{clash_api_port}/connections?interval=1000");

        let join_handle = tokio::spawn(async move {
            let mut ring = ConnectionRingBuffer::new(MAX_LIVE_CONNECTIONS);
            let mut backoff = INITIAL_RECONNECT_DELAY;

            loop {
                let connect_fut = connect_async(&url);
                let ws_result = tokio::select! {
                    biased;
                    _ = &mut stop_rx => break,
                    res = connect_fut => res,
                };

                if let Ok((mut ws_stream, _)) = ws_result {
                    backoff = INITIAL_RECONNECT_DELAY;
                    loop {
                        let next_msg = tokio::select! {
                            biased;
                            _ = &mut stop_rx => return,
                            msg = ws_stream.next() => msg,
                        };

                        match next_msg {
                            Some(Ok(Message::Text(text))) => {
                                if let Ok(parsed) =
                                    parse_clash_connections_json(&text, &outbound_to_node_id)
                                {
                                    let snapshot = ring.push_snapshot(parsed);
                                    let _ = tx.send(RuntimeEvent::TrafficUpdated(snapshot));
                                }
                            }
                            Some(Ok(Message::Binary(bytes))) => {
                                if let Ok(text) = std::str::from_utf8(&bytes) {
                                    if let Ok(parsed) =
                                        parse_clash_connections_json(text, &outbound_to_node_id)
                                    {
                                        let snapshot = ring.push_snapshot(parsed);
                                        let _ = tx.send(RuntimeEvent::TrafficUpdated(snapshot));
                                    }
                                }
                            }
                            Some(Ok(Message::Ping(_)))
                            | Some(Ok(Message::Pong(_)))
                            | Some(Ok(Message::Frame(_))) => {}
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                        }
                    }
                }

                tokio::select! {
                    biased;
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = (backoff * 2).min(MAX_RECONNECT_DELAY);
            }
        });

        Self {
            stop_tx: Some(stop_tx),
            join_handle: Some(join_handle),
        }
    }

    /// Signals the background WebSocket loop to stop and awaits its termination.
    pub async fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for TrafficMonitor {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.join_handle.take() {
            handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::time::Duration;

    use futures_util::SinkExt;
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;
    use tokio_tungstenite::accept_async;
    use tokio_tungstenite::tungstenite::Message;

    use super::*;

    #[test]
    fn test_traffic_parser_maps_clash_api_json_to_node_ids() {
        let raw = r#"{
            "downloadTotal": 9428,
            "uploadTotal": 1564,
            "connections": [
                {
                    "id": "conn-1",
                    "metadata": {
                        "network": "tcp",
                        "type": "tun",
                        "destinationIP": "104.26.13.205",
                        "destinationPort": "443",
                        "host": "api.ipify.org",
                        "process": "chrome.exe",
                        "processPath": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
                    },
                    "upload": 1200,
                    "download": 8400,
                    "chains": ["vpn-karing"]
                },
                {
                    "id": "conn-2",
                    "metadata": {
                        "network": "udp",
                        "destinationIP": "1.1.1.1",
                        "destinationPort": 443,
                        "host": "",
                        "process": "",
                        "processPath": "C:\\Program Files\\Mozilla Firefox\\firefox.exe"
                    },
                    "upload": 300,
                    "download": 900,
                    "chains": ["iface-wi-fi"]
                },
                {
                    "id": "conn-3",
                    "metadata": {
                        "network": "udp",
                        "destinationIP": "192.168.1.1",
                        "destinationPort": "53",
                        "host": "",
                        "process": "svchost.exe",
                        "processPath": ""
                    },
                    "upload": 64,
                    "download": 128,
                    "chains": ["direct"]
                }
            ]
        }"#;

        let mut map = HashMap::new();
        map.insert("vpn-karing".to_string(), "vpn-1".to_string());
        map.insert("iface-wi-fi".to_string(), "if-wifi".to_string());

        let parsed = parse_clash_connections_json(raw, &map).expect("valid clash payload");
        assert_eq!(parsed.len(), 3);

        assert_eq!(
            parsed[0],
            LiveConnection {
                id: "conn-1".to_string(),
                process_name: "chrome.exe".to_string(),
                destination: "api.ipify.org:443".to_string(),
                network: "tcp".to_string(),
                outbound_tag: "vpn-karing".to_string(),
                node_id: Some("vpn-1".to_string()),
                upload_bytes: 1200,
                download_bytes: 8400,
            }
        );

        assert_eq!(
            parsed[1],
            LiveConnection {
                id: "conn-2".to_string(),
                process_name: "firefox.exe".to_string(),
                destination: "1.1.1.1:443".to_string(),
                network: "udp".to_string(),
                outbound_tag: "iface-wi-fi".to_string(),
                node_id: Some("if-wifi".to_string()),
                upload_bytes: 300,
                download_bytes: 900,
            }
        );

        assert_eq!(
            parsed[2],
            LiveConnection {
                id: "conn-3".to_string(),
                process_name: "svchost.exe".to_string(),
                destination: "192.168.1.1:53".to_string(),
                network: "udp".to_string(),
                outbound_tag: "direct".to_string(),
                node_id: None,
                upload_bytes: 64,
                download_bytes: 128,
            }
        );

        let empty = parse_clash_connections_json(r#"{"connections": null}"#, &map)
            .expect("null connections list should parse as empty");
        assert!(empty.is_empty());

        assert!(parse_clash_connections_json("{not json", &map).is_err());
    }

    #[test]
    fn test_connection_ring_buffer_caps_at_200_and_updates_existing_ids() {
        let mut ring = ConnectionRingBuffer::default();
        let batch_a: Vec<LiveConnection> = (0..150)
            .map(|i| LiveConnection {
                id: format!("c-{i}"),
                process_name: "app.exe".to_string(),
                destination: format!("example.com:{i}"),
                network: "tcp".to_string(),
                outbound_tag: "vpn-karing".to_string(),
                node_id: Some("vpn-1".to_string()),
                upload_bytes: 10,
                download_bytes: 20,
            })
            .collect();
        let out_a = ring.push_snapshot(batch_a);
        assert_eq!(out_a.len(), 150);

        let mut batch_b: Vec<LiveConnection> = (150..250)
            .map(|i| LiveConnection {
                id: format!("c-{i}"),
                process_name: "app.exe".to_string(),
                destination: format!("example.com:{i}"),
                network: "tcp".to_string(),
                outbound_tag: "vpn-karing".to_string(),
                node_id: Some("vpn-1".to_string()),
                upload_bytes: 10,
                download_bytes: 20,
            })
            .collect();
        batch_b.push(LiveConnection {
            id: "c-0".to_string(),
            process_name: "app.exe".to_string(),
            destination: "example.com:0".to_string(),
            network: "tcp".to_string(),
            outbound_tag: "vpn-karing".to_string(),
            node_id: Some("vpn-1".to_string()),
            upload_bytes: 999,
            download_bytes: 2000,
        });

        let out_b = ring.push_snapshot(batch_b);
        assert_eq!(out_b.len(), MAX_LIVE_CONNECTIONS);
        let updated_c0 = out_b.iter().find(|c| c.id == "c-0").expect("c-0 updated");
        assert_eq!(updated_c0.upload_bytes, 999);
        assert_eq!(updated_c0.download_bytes, 2000);
        assert!(out_b.iter().all(|c| c.id != "c-1"));
    }

    #[tokio::test]
    async fn test_traffic_monitor_streams_real_websocket_frames() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local tcp listener");
        let port = listener.local_addr().expect("local addr").port();

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept ws client");
            let mut ws = accept_async(stream).await.expect("ws handshake");
            let payload = r#"{
                "connections": [
                    {
                        "id": "ws-1",
                        "metadata": {
                            "network": "tcp",
                            "destinationIP": "93.184.216.34",
                            "destinationPort": "443",
                            "host": "example.org",
                            "process": "chrome.exe"
                        },
                        "upload": 512,
                        "download": 2048,
                        "chains": ["vpn-karing"]
                    }
                ]
            }"#;
            ws.send(Message::Text(payload.to_string()))
                .await
                .expect("send ws payload");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let (tx, mut rx) = broadcast::channel(16);
        let mut map = HashMap::new();
        map.insert("vpn-karing".to_string(), "vpn-1".to_string());

        let mut monitor = TrafficMonitor::spawn(port, map, tx);

        let event = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("receive event before timeout")
            .expect("broadcast event");

        match event {
            RuntimeEvent::TrafficUpdated(conns) => {
                assert_eq!(conns.len(), 1);
                assert_eq!(conns[0].id, "ws-1");
                assert_eq!(conns[0].node_id.as_deref(), Some("vpn-1"));
                assert_eq!(conns[0].destination, "example.org:443");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        monitor.stop().await;
        server_task.await.expect("server task completes");
    }
}
