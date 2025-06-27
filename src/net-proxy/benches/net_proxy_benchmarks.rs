use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use bytes::{Bytes, BytesMut};
use net_proxy::simple_proxy::*;
use mio::{Poll, Token};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use utils::eventfd::EventFd;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpPacket, TcpFlags};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet; // Add this trait import

// Re-export the internal functions we need for benchmarking
pub use net_proxy::simple_proxy::{NetProxy, build_tcp_packet, build_udp_packet};

// Define NatKey type locally since it's private
type NatKey = (IpAddr, u16, IpAddr, u16);

/// Helper to create realistic test packets for benchmarking
fn create_test_tcp_packet(size: usize) -> Bytes {
    let nat_key = (
        IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2)),
        12345u16,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        443u16,
    );
    
    let payload = vec![0u8; size];
    build_tcp_packet(
        &mut BytesMut::new(),
        nat_key,
        1000,
        2000,
        Some(&payload),
        Some(TcpFlags::ACK | TcpFlags::PSH),
        65535,
    )
}

fn create_test_udp_packet(size: usize) -> Bytes {
    let nat_key = (
        IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2)),
        53u16,
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        53u16,
    );
    
    let payload = vec![0u8; size];
    build_udp_packet(&mut BytesMut::new(), nat_key, &payload)
}

/// Benchmark packet construction performance
fn bench_packet_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_construction");
    
    // Test different payload sizes: 64B, 512B, 1460B (near MTU)
    for size in [64, 512, 1460].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("tcp_packet", size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(create_test_tcp_packet(size));
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("udp_packet", size),
            size,
            |b, &size| {
                b.iter(|| {
                    black_box(create_test_udp_packet(size));
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark packet parsing performance
fn bench_packet_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_parsing");
    
    // Pre-create test packets of different sizes
    let tcp_packets: Vec<_> = [64, 512, 1460].iter()
        .map(|&size| (size, create_test_tcp_packet(size)))
        .collect();
    
    let udp_packets: Vec<_> = [64, 512, 1460].iter()
        .map(|&size| (size, create_test_udp_packet(size)))
        .collect();
    
    // Benchmark Ethernet header parsing
    for (size, packet) in &tcp_packets {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("ethernet_parse", size),
            packet,
            |b, packet| {
                b.iter(|| {
                    let eth = black_box(EthernetPacket::new(packet));
                    black_box(eth.map(|e| e.get_ethertype()));
                });
            },
        );
    }
    
    // Benchmark full TCP packet parsing
    for (size, packet) in &tcp_packets {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("tcp_full_parse", size),
            packet,
            |b, packet| {
                b.iter(|| {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                    black_box((
                                        tcp.get_source(),
                                        tcp.get_destination(),
                                        tcp.get_sequence(),
                                        tcp.get_acknowledgement(),
                                        tcp.get_flags(),
                                        tcp.payload().len(),
                                    ));
                                }
                            }
                        }
                    }
                });
            },
        );
    }
    
    // Benchmark UDP packet parsing
    for (size, packet) in &udp_packets {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("udp_full_parse", size),
            packet,
            |b, packet| {
                b.iter(|| {
                    if let Some(eth) = EthernetPacket::new(packet) {
                        if eth.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                                if let Some(udp) = UdpPacket::new(ip.payload()) {
                                    black_box((
                                        udp.get_source(),
                                        udp.get_destination(),
                                        udp.payload().len(),
                                    ));
                                }
                            }
                        }
                    }
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark NAT table operations
fn bench_nat_table_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("nat_table_operations");
    
    // Create different sized NAT tables to test lookup performance
    for table_size in [100, 1000, 10000].iter() {
        // Setup NAT table with many entries
        let mut tcp_nat_table: HashMap<NatKey, Token> = HashMap::new();
        let mut reverse_tcp_nat: HashMap<Token, NatKey> = HashMap::new();
        
        for i in 0..*table_size {
            let nat_key = (
                IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                (40000 + (i % 20000)) as u16,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                443u16,
            );
            let token = Token(i);
            tcp_nat_table.insert(nat_key, token);
            reverse_tcp_nat.insert(token, nat_key);
        }
        
        // Benchmark forward lookup (NAT key -> Token)
        group.bench_with_input(
            BenchmarkId::new("forward_lookup", table_size),
            &tcp_nat_table,
            |b, table| {
                let test_key = (
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    45000u16,
                    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                    443u16,
                );
                b.iter(|| {
                    black_box(table.get(&test_key));
                });
            },
        );
        
        // Benchmark reverse lookup (Token -> NAT key)
        group.bench_with_input(
            BenchmarkId::new("reverse_lookup", table_size),
            &reverse_tcp_nat,
            |b, table| {
                let test_token = Token(500);
                b.iter(|| {
                    black_box(table.get(&test_token));
                });
            },
        );
        
        // Benchmark insertion
        group.bench_with_input(
            BenchmarkId::new("insertion", table_size),
            table_size,
            |b, _| {
                b.iter(|| {
                    let mut table: HashMap<NatKey, Token> = HashMap::new();
                    let nat_key = (
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                        black_box(12345u16),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        443u16,
                    );
                    black_box(table.insert(nat_key, Token(999)));
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark buffer operations
fn bench_buffer_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_operations");
    
    // Test different buffer sizes
    for buffer_size in [10, 100, 1000].iter() {
        let packets: Vec<Bytes> = (0..*buffer_size)
            .map(|_| create_test_tcp_packet(1460))
            .collect();
        
        // Benchmark VecDeque push_back
        group.bench_with_input(
            BenchmarkId::new("vecdeque_push_back", buffer_size),
            &packets,
            |b, packets| {
                b.iter(|| {
                    let mut buffer = std::collections::VecDeque::new();
                    for packet in packets {
                        black_box(buffer.push_back(packet.clone()));
                    }
                    black_box(buffer);
                });
            },
        );
        
        // Benchmark VecDeque pop_front
        group.bench_with_input(
            BenchmarkId::new("vecdeque_pop_front", buffer_size),
            &packets,
            |b, packets| {
                b.iter(|| {
                    let mut buffer: std::collections::VecDeque<Bytes> = packets.iter().cloned().collect();
                    while let Some(packet) = buffer.pop_front() {
                        black_box(packet);
                    }
                });
            },
        );
        
        // Benchmark buffer length checks (common operation)
        group.bench_with_input(
            BenchmarkId::new("buffer_len_check", buffer_size),
            &packets,
            |b, packets| {
                let buffer: std::collections::VecDeque<Bytes> = packets.iter().cloned().collect();
                b.iter(|| {
                    black_box(buffer.len() > 8); // Aggressive backpressure threshold check
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_allocation");
    
    // Benchmark BytesMut allocation and conversion
    for size in [64, 512, 1460].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(
            BenchmarkId::new("bytesmut_alloc", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let mut buf = BytesMut::with_capacity(size);
                    buf.resize(size, 0);
                    black_box(buf.freeze());
                });
            },
        );
        
        group.bench_with_input(
            BenchmarkId::new("vec_alloc", size),
            size,
            |b, &size| {
                b.iter(|| {
                    let vec = vec![0u8; size];
                    black_box(Bytes::from(vec));
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark simulated packet processing pipeline
fn bench_packet_processing_pipeline(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_processing_pipeline");
    group.throughput(Throughput::Elements(1));
    
    // Create test packets
    let tcp_packet = create_test_tcp_packet(1460);
    let udp_packet = create_test_udp_packet(512);
    
    // Benchmark full TCP packet processing pipeline (parse + NAT lookup simulation)
    group.bench_function("tcp_pipeline", |b| {
        let mut nat_table: HashMap<NatKey, Token> = HashMap::new();
        // Pre-populate with some entries
        for i in 0..1000 {
            let nat_key = (
                IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                (40000 + i) as u16,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                443u16,
            );
            nat_table.insert(nat_key, Token(i));
        }
        
        b.iter(|| {
            // Simulate full packet processing pipeline
            if let Some(eth) = EthernetPacket::new(&tcp_packet) {
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                        if let Some(tcp) = TcpPacket::new(ip.payload()) {
                            // Extract connection info (this is what the real proxy does)
                            let nat_key = (
                                IpAddr::V4(ip.get_source()),
                                tcp.get_source(),
                                IpAddr::V4(ip.get_destination()),
                                tcp.get_destination(),
                            );
                            
                            // NAT table lookup
                            let token = nat_table.get(&nat_key);
                            
                            // Simulate some processing
                            black_box((
                                token,
                                tcp.get_sequence(),
                                tcp.get_acknowledgement(),
                                tcp.payload().len(),
                            ));
                        }
                    }
                }
            }
        });
    });
    
    // Benchmark UDP pipeline
    group.bench_function("udp_pipeline", |b| {
        let mut nat_table: HashMap<NatKey, Token> = HashMap::new();
        for i in 0..1000 {
            let nat_key = (
                IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                (40000 + i) as u16,
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                53u16,
            );
            nat_table.insert(nat_key, Token(i));
        }
        
        b.iter(|| {
            if let Some(eth) = EthernetPacket::new(&udp_packet) {
                if eth.get_ethertype() == EtherTypes::Ipv4 {
                    if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                        if let Some(udp) = UdpPacket::new(ip.payload()) {
                            let nat_key = (
                                IpAddr::V4(ip.get_source()),
                                udp.get_source(),
                                IpAddr::V4(ip.get_destination()),
                                udp.get_destination(),
                            );
                            
                            let token = nat_table.get(&nat_key);
                            black_box((token, udp.payload().len()));
                        }
                    }
                }
            }
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_packet_construction,
    bench_packet_parsing,
    bench_nat_table_operations,
    bench_buffer_operations,
    bench_memory_allocation,
    bench_packet_processing_pipeline,
);
criterion_main!(benches);