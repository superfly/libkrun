//! Example: Userspace NAT proxy using smoltcp.
//!
//! This example demonstrates how to implement a custom async network backend
//! for libkrun using smoltcp as the TCP/IP stack. It enables network access
//! for VMs without requiring tap/tun interfaces.
//!
//! # Architecture
//!
//! ```text
//! Guest App
//!     | TCP/UDP
//!     v
//! Guest Kernel (virtio-net)
//!     | Ethernet frames
//!     v
//! AsyncNetWorker (virtio queues)
//!     | borrowed &[u8] (zero-copy)
//!     v
//! SmoltcpProxyBackend
//!     |-- smoltcp (TCP/IP stack)
//!     `-- Host connections (tokio tasks)
//!           |
//!           v
//!      Real network
//! ```

mod backend;
mod device;
mod handler;
mod handlers;
mod util;

use clap::Parser;
use krun::{VirtioNetBackend, NET_ALL_FEATURES};
use smoltcp::wire::{EthernetAddress, Ipv4Address, Ipv6Address};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// Re-export commonly used types
pub use backend::{SmoltcpProxyConfig, SmoltcpProxyFactory};
pub use handler::{
    DeferredFlowDecision, FlowChannels, HandlerError, HandlerResult, IcmpInfo, PacketContext,
    PacketHandler, PacketVerdict, TcpInfo, TransportProtocol, UdpInfo,
};
pub use handlers::{
    Cidr, DeferredEchoHandler, EchoHandler, FirewallConfig, FirewallHandler, PortBitmap,
};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "examples/rootfs_debian")]
    rootfs: String,

    /// Unix socket listener mapping (format: /path/to/socket:vm_port)
    /// Example: --unix-listener /tmp/vm.sock:8080
    #[arg(long = "unix-listener", value_name = "PATH:PORT")]
    unix_listeners: Vec<String>,

    command: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE),
        )
        .with(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let mut builder = krun::Builder::new();

    builder.set_root(&cli.rootfs);

    builder.vm_config(2, 1024);

    let mut command = cli.command.clone();

    let (exec_path, args) = if command.is_empty() {
        ("/usr/bin/bash".to_string(), None)
    } else {
        (
            command.remove(0),
            if command.is_empty() {
                None
            } else {
                Some(command.join(" "))
            },
        )
    };

    println!("using exec path: {exec_path} and args {:?}", args);

    builder.exec_path(exec_path);
    if let Some(args) = args {
        builder.args(args);
    }

    // Parse Unix socket listeners from CLI
    let mut unix_listeners = HashMap::new();
    for listener_spec in &cli.unix_listeners {
        // Format: /path/to/socket:port
        if let Some((path, port_str)) = listener_spec.rsplit_once(':') {
            match port_str.parse::<u16>() {
                Ok(port) => {
                    println!("Adding Unix socket listener: {} -> VM port {}", path, port);
                    unix_listeners.insert(port, PathBuf::from(path));
                }
                Err(e) => {
                    eprintln!("Invalid port in '{}': {}", listener_spec, e);
                }
            }
        } else {
            eprintln!(
                "Invalid listener format '{}', expected /path:port",
                listener_spec
            );
        }
    }

    builder.add_net_device(
        VirtioNetBackend::CustomAsyncFactory(Box::new(SmoltcpProxyFactory::new(
            SmoltcpProxyConfig {
                vm_mac: EthernetAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x00]),
                vm_ip: Ipv4Address::new(192, 168, 100, 2),
                vm_ip6: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
                gateway_mac: EthernetAddress([0x02, 0x00, 0x00, 0x01, 0x02, 0x03]),
                gateway_ip: Ipv4Address::new(192, 168, 100, 1),
                gateway_ip6: Ipv6Address::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
                unix_listeners,
                handlers: vec![
                    Arc::new(EchoHandler::new(12345)),
                    // Deferred echo: accepts after 500ms delay (port 12346)
                    Arc::new(DeferredEchoHandler::accepting(12346, 500)),
                    // Deferred reject: rejects after 500ms delay (port 12347)
                    Arc::new(DeferredEchoHandler::rejecting(12347, 500)),
                    Arc::new(FirewallHandler::new(FirewallConfig::allow_all())),
                ],
            },
        ))),
        [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00],
        NET_ALL_FEATURES,
    );

    let ctx = builder.build().expect("failed to build VM");

    println!("entering krun vm");
    let ctx_result = ctx.run();

    info!("VM is done, res: {ctx_result:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use device::ProxyDevice;
    use smoltcp::phy::Device;

    #[test]
    fn test_proxy_device_checksum_capabilities() {
        let device = ProxyDevice::new();
        let caps = device.capabilities();

        assert!(
            !caps.checksum.tcp.rx(),
            "TCP RX checksum validation should be disabled"
        );
        assert!(
            caps.checksum.tcp.tx(),
            "TCP TX checksum filling should be enabled"
        );
    }
}
