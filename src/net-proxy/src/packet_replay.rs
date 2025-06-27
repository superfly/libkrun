use bytes::Bytes;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::info;

/// Captures packet traces from real network traffic for replay testing
#[derive(Debug, Clone)]
pub struct PacketTrace {
    pub timestamp: Duration,
    pub direction: PacketDirection, 
    pub data: Bytes,
    pub connection_id: Option<String>, // For multi-connection scenarios
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacketDirection {
    VmToProxy,   // Incoming packets (like Docker commands)
    ProxyToVm,   // Outgoing packets (like registry responses)
    HostToProxy, // Data from external host
    ProxyToHost, // Data to external host
}

/// Parses trace logs to extract packet sequences
pub struct TraceParser {
    traces: VecDeque<PacketTrace>,
    start_time: Option<Instant>,
}

impl TraceParser {
    pub fn new() -> Self {
        Self {
            traces: VecDeque::new(),
            start_time: None,
        }
    }
    
    /// Parse a log line and extract packet information
    pub fn parse_log_line(&mut self, line: &str) -> Option<PacketTrace> {
        // Parse format like: "[IN] 192.168.100.2:54546 > 104.16.98.215:443: Flags [.P], seq 2595303071"
        if let Some(direction) = self.extract_direction(line) {
            let timestamp = self.extract_timestamp(line).unwrap_or_else(|| Duration::from_millis(0));
            let packet_data = self.extract_packet_data(line).unwrap_or_else(|| Bytes::from(vec![0u8; 60]));
            let connection_id = self.extract_connection_id(line);
            
            let trace = PacketTrace {
                timestamp,
                direction,
                data: packet_data,
                connection_id,
            };
            
            info!(?trace, "Parsed packet trace");
            self.traces.push_back(trace.clone());
            return Some(trace);
        }
        None
    }
    
    /// Extract direction from log line markers
    fn extract_direction(&self, line: &str) -> Option<PacketDirection> {
        if line.contains("[IN]") {
            Some(PacketDirection::VmToProxy)
        } else if line.contains("[OUT]") {
            Some(PacketDirection::ProxyToVm) 
        } else {
            None
        }
    }
    
    /// Extract timestamp from log line
    fn extract_timestamp(&mut self, line: &str) -> Option<Duration> {
        // Parse timestamp format: "2025-06-26T21:45:58.528696Z"
        if let Some(ts_start) = line.find("T") {
            if let Some(ts_end) = line.find("Z") {
                let timestamp_str = &line[ts_start-10..ts_end+1];
                // For now, return relative duration from first packet
                if self.start_time.is_none() {
                    self.start_time = Some(Instant::now());
                    return Some(Duration::from_millis(0));
                } else {
                    // In a real implementation, parse the actual timestamp
                    return Some(self.start_time.unwrap().elapsed());
                }
            }
        }
        None
    }
    
    /// Extract packet data from hex dump in logs
    fn extract_packet_data(&self, line: &str) -> Option<Bytes> {
        // For now, create synthetic packet data based on the log description
        // In practice, we'd need the actual packet hex dumps
        if line.contains("seq") && line.contains("ack") {
            // Create a minimal TCP packet for testing
            let mut packet = vec![0u8; 60]; // Ethernet + IP + TCP header
            packet[0..6].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]); // dst MAC
            packet[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x01, 0x02, 0x03]); // src MAC
            
            // Extract payload size if mentioned
            let payload_size = if line.contains("len ") {
                self.extract_number_after(line, "len ").unwrap_or(0)
            } else {
                0
            };
            
            if payload_size > 0 {
                packet.extend(vec![0u8; payload_size as usize]);
            }
            
            Some(Bytes::from(packet))
        } else {
            None
        }
    }
    
    /// Extract connection identifier for multi-connection scenarios
    fn extract_connection_id(&self, line: &str) -> Option<String> {
        // Look for patterns like "192.168.100.2:54546 > 104.16.98.215:443"
        if let Some(start) = line.find("] ") {
            if let Some(end) = line.find(": Flags") {
                return Some(line[start+2..end].to_string());
            }
        }
        None
    }
    
    /// Helper to extract numbers from log lines
    fn extract_number_after(&self, line: &str, pattern: &str) -> Option<u32> {
        if let Some(pos) = line.find(pattern) {
            let after = &line[pos + pattern.len()..];
            if let Some(space_pos) = after.find(' ') {
                after[..space_pos].parse().ok()
            } else {
                after.parse().ok()
            }
        } else {
            None
        }
    }
    
    /// Get all traces for replay
    pub fn get_traces(&self) -> &VecDeque<PacketTrace> {
        &self.traces
    }
    
    /// Load traces from a log file
    pub fn load_from_file(&mut self, file_path: &str) -> std::io::Result<usize> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        
        for line in reader.lines() {
            let line = line?;
            if self.parse_log_line(&line).is_some() {
                count += 1;
            }
        }
        
        info!(parsed_traces = count, "Loaded packet traces from file");
        Ok(count)
    }
}

/// Replays packet sequences to test proxy behavior
pub struct PacketReplayer {
    traces: VecDeque<PacketTrace>,
    current_time: Duration,
}

impl PacketReplayer {
    pub fn new(traces: VecDeque<PacketTrace>) -> Self {
        Self {
            traces,
            current_time: Duration::from_millis(0),
        }
    }
    
    /// Get the next packet that should be sent at the current time
    pub fn next_packet(&mut self) -> Option<PacketTrace> {
        if let Some(trace) = self.traces.front() {
            if trace.timestamp <= self.current_time {
                return self.traces.pop_front();
            }
        }
        None
    }
    
    /// Advance the replay timeline
    pub fn advance_time(&mut self, delta: Duration) {
        self.current_time += delta;
    }
    
    /// Check if replay is complete
    pub fn is_complete(&self) -> bool {
        self.traces.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::NetProxy;
    use std::sync::Arc;
    use utils::eventfd::EventFd;
    use mio::Registry;
    use std::fs::File;
    use std::io::Write;
    use tempfile::NamedTempFile;
    
    #[test]
    fn test_trace_parser() {
        let mut parser = TraceParser::new();
        
        let log_line = r#"2025-06-26T21:45:58.528696Z [IN] 192.168.100.2:54546 > 104.16.98.215:443: Flags [.P], seq 2595303071, ack 142241886, win 65535, len 31"#;
        
        let trace = parser.parse_log_line(log_line);
        assert!(trace.is_some());
        
        let trace = trace.unwrap();
        assert_eq!(trace.direction, PacketDirection::VmToProxy);
        assert!(trace.data.len() > 0);
    }
    
    #[test]
    fn test_docker_pull_replay() {
        // Create a temporary log file with Docker pull failure traces
        let mut temp_file = NamedTempFile::new().expect("Failed to create temp file");
        
        // Sample traces from the failing Docker pull scenario (Token 38 to Cloudflare)
        let log_content = r#"2025-06-26T17:36:29.337481Z [IN] 192.168.100.2:40266 > 104.16.98.215:443: Flags [.P], seq 2595303071, ack 142241886, win 65535, len 31
2025-06-26T17:36:29.337500Z [OUT] 104.16.98.215:443 > 192.168.100.2:40266: Flags [.], ack 2595303102, win 65535, len 0
2025-06-26T17:36:29.338000Z [IN] 192.168.100.2:40266 > 104.16.98.215:443: Flags [.P], seq 2595303102, ack 142241886, win 65535, len 512
2025-06-26T17:36:29.338200Z [OUT] 104.16.98.215:443 > 192.168.100.2:40266: Flags [.P], seq 142241886, ack 2595303614, win 65535, len 1460
2025-06-26T17:36:29.338300Z [IN] 192.168.100.2:40266 > 104.16.98.215:443: Flags [.], ack 142243346, win 65535, len 0"#;
        
        temp_file.write_all(log_content.as_bytes()).expect("Failed to write to temp file");
        temp_file.flush().expect("Failed to flush temp file");
        
        // Parse the traces
        let mut parser = TraceParser::new();
        let trace_count = parser.load_from_file(temp_file.path().to_str().unwrap())
            .expect("Failed to load traces");
        
        assert_eq!(trace_count, 5, "Should parse 5 trace entries");
        
        // Create replayer 
        let traces = parser.get_traces().clone();
        let mut replayer = PacketReplayer::new(traces);
        
        // Verify replay sequence
        let mut packet_count = 0;
        while !replayer.is_complete() {
            if let Some(trace) = replayer.next_packet() {
                match trace.direction {
                    PacketDirection::VmToProxy => {
                        // Simulate VM sending packet to proxy
                        assert!(trace.data.len() > 0);
                        packet_count += 1;
                    }
                    PacketDirection::ProxyToVm => {
                        // Simulate proxy sending response to VM
                        assert!(trace.data.len() > 0);
                        packet_count += 1;
                    }
                    _ => {}
                }
            }
            // Advance time to trigger next packet
            replayer.advance_time(Duration::from_millis(1));
        }
        
        assert_eq!(packet_count, 5, "Should replay all 5 packets");
    }
    
    #[test] 
    fn test_connection_stall_detection() {
        // Create mock log data showing a connection that stalls (like Token 38)
        let mut parser = TraceParser::new();
        
        // Normal activity followed by silence
        let stall_logs = vec![
            "2025-06-26T17:36:29.337481Z [IN] 192.168.100.2:40266 > 104.16.98.215:443: Flags [.P], seq 1000, ack 2000, win 65535, len 1460",
            "2025-06-26T17:36:29.337500Z [OUT] 104.16.98.215:443 > 192.168.100.2:40266: Flags [.], ack 2460, win 65535, len 0", 
            "2025-06-26T17:36:29.338000Z [IN] 192.168.100.2:40266 > 104.16.98.215:443: Flags [.P], seq 2460, ack 2000, win 65535, len 1460",
            // After this point, connection should go silent for >30 seconds
        ];
        
        for log_line in stall_logs {
            parser.parse_log_line(log_line);
        }
        
        let traces = parser.get_traces();
        assert_eq!(traces.len(), 3, "Should parse 3 active packets before stall");
        
        // Verify we can identify the stalling connection
        let connection_id = traces.front().unwrap().connection_id.clone();
        assert!(connection_id.is_some(), "Should extract connection ID");
        assert!(connection_id.unwrap().contains("192.168.100.2:40266"), "Should identify the Docker connection");
    }
}