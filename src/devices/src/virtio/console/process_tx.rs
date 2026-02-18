use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{atomic::AtomicU64, OnceLock};
use std::sync::{Arc, Mutex};
use std::{io, thread};

use vm_memory::{GuestMemory, GuestMemoryError, GuestMemoryMmap, GuestMemoryRegion};

use crate::virtio::console::port_io::PortOutput;
use crate::virtio::{DescriptorChain, InterruptTransport, Queue};

static CONSOLE_TX_DIAG_ENABLED: OnceLock<bool> = OnceLock::new();
static CONSOLE_TX_DIAG_MAX_LOGS: OnceLock<u64> = OnceLock::new();
static CONSOLE_TX_DIAG_EMITTED: AtomicU64 = AtomicU64::new(0);
static CONSOLE_TX_DIAG_SEQ: AtomicU64 = AtomicU64::new(1);

const CONSOLE_TX_DIAG_BASELINE_LOGS: u64 = 8;
const CONSOLE_TX_DIAG_SAMPLE_LIMIT: usize = 64 * 1024;

#[derive(Debug)]
struct TxSliceDiagnostics {
    original_len: usize,
    sampled_len: usize,
    nul_bytes: usize,
    control_bytes: usize,
    high_bytes: usize,
    invalid_utf8_bytes: usize,
    elf_markers: usize,
    hash64: u64,
    head_hex: String,
    tail_hex: String,
}

impl TxSliceDiagnostics {
    fn suspicious(&self) -> bool {
        self.nul_bytes > 0 || self.invalid_utf8_bytes > 0 || self.elf_markers > 0
    }
}

pub(crate) fn process_tx(
    port_id: u32,
    mem: GuestMemoryMmap,
    mut queue: Queue,
    interrupt: InterruptTransport,
    output: Arc<Mutex<Box<dyn PortOutput + Send>>>,
    stop: Arc<AtomicBool>,
) {
    loop {
        let Some(head) = pop_head_blocking(&mut queue, &mem, &interrupt, &stop) else {
            return;
        };

        let head_index = head.index;
        let mut bytes_written = 0;

        for (desc_ordinal, desc) in head.into_iter().readable().enumerate() {
            let desc_len = desc.len as usize;
            match write_desc_to_output(
                desc,
                output.lock().unwrap().as_mut(),
                &interrupt,
                port_id,
                head_index,
                desc_ordinal,
            ) {
                Ok(0) => {
                    break;
                }
                Ok(n) => {
                    assert_eq!(n, desc_len);
                    bytes_written += n;
                }
                Err(e) => {
                    log::error!("Failed to write output: {e}");
                }
            }
        }

        if bytes_written == 0 {
            log::trace!("Tx Add used {bytes_written}");
            queue.undo_pop();
        } else {
            log::trace!("Tx add used {bytes_written}");
            if let Err(e) = queue.add_used(&mem, head_index, bytes_written as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }
        }
    }
}

fn pop_head_blocking<'mem>(
    queue: &mut Queue,
    mem: &'mem GuestMemoryMmap,
    interrupt: &InterruptTransport,
    stop: &AtomicBool,
) -> Option<DescriptorChain<'mem>> {
    loop {
        match queue.pop(mem) {
            Some(descriptor) => break Some(descriptor),
            None => {
                interrupt.signal_used_queue();
                thread::park();
                if stop.load(Ordering::Acquire) {
                    break None;
                }
                log::trace!("tx unparked, queue len {}", queue.len(mem))
            }
        }
    }
}

fn write_desc_to_output(
    desc: DescriptorChain,
    output: &mut (dyn PortOutput + Send),
    interrupt: &InterruptTransport,
    port_id: u32,
    head_index: u16,
    desc_ordinal: usize,
) -> Result<usize, GuestMemoryError> {
    desc.mem
        .try_access(desc.len as usize, desc.addr, |_, len, addr, region| {
            let src = region.get_slice(addr, len).unwrap();
            let diagnostics = if console_tx_diag_enabled() {
                Some(sample_tx_slice_diagnostics(len, &src))
            } else {
                None
            };

            loop {
                log::trace!("Tx {src:?}, write_volatile {len} bytes");
                match output.write_volatile(&src) {
                    // try_access seem to handle partial write for us (we will be invoked again with an offset)
                    Ok(n) => {
                        if let Some(diag) = diagnostics.as_ref() {
                            let post_diag = if diag.suspicious() || n != len {
                                Some(sample_tx_slice_diagnostics(len, &src))
                            } else {
                                None
                            };
                            let post_changed = post_diag
                                .as_ref()
                                .map(|post| post.hash64 != diag.hash64)
                                .unwrap_or(false);
                            let suspicious = diag.suspicious() || n != len || post_changed;
                            if should_emit_console_tx_diag(suspicious) {
                                let tx_diag_seq = next_console_tx_diag_seq();
                                log::warn!(
                                    "console_tx_diag seq={} port_id={} head_index={} desc_ordinal={} desc_len={} written={} sampled_len={} nul_bytes={} invalid_utf8_bytes={} elf_markers={} control_bytes={} high_bytes={} hash64={:016x} head_hex={} tail_hex={} post_changed={} post_nul_bytes={} post_invalid_utf8_bytes={} post_elf_markers={} post_hash64={:016x}",
                                    tx_diag_seq,
                                    port_id,
                                    head_index,
                                    desc_ordinal,
                                    diag.original_len,
                                    n,
                                    diag.sampled_len,
                                    diag.nul_bytes,
                                    diag.invalid_utf8_bytes,
                                    diag.elf_markers,
                                    diag.control_bytes,
                                    diag.high_bytes,
                                    diag.hash64,
                                    diag.head_hex,
                                    diag.tail_hex,
                                    post_changed,
                                    post_diag.as_ref().map(|post| post.nul_bytes).unwrap_or(0),
                                    post_diag
                                        .as_ref()
                                        .map(|post| post.invalid_utf8_bytes)
                                        .unwrap_or(0),
                                    post_diag.as_ref().map(|post| post.elf_markers).unwrap_or(0),
                                    post_diag.as_ref().map(|post| post.hash64).unwrap_or(0),
                                );
                            }
                        }
                        break Ok(n);
                    }
                    // We can't return an error otherwise we would not know how many bytes were processed before WouldBlock
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        log::trace!("Tx wait for output (would block)");
                        interrupt.signal_used_queue();
                        output.wait_until_writable();
                    }
                    Err(e) => break Err(GuestMemoryError::IOError(e)),
                }
            }
        })
}

fn next_console_tx_diag_seq() -> u64 {
    CONSOLE_TX_DIAG_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn console_tx_diag_enabled() -> bool {
    *CONSOLE_TX_DIAG_ENABLED.get_or_init(|| {
        std::env::var("WINDSHEAR_VIRTIO_CONSOLE_TX_DIAGNOSTICS")
            .ok()
            .map(|raw| {
                matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false)
    })
}

fn console_tx_diag_max_logs() -> u64 {
    *CONSOLE_TX_DIAG_MAX_LOGS.get_or_init(|| {
        std::env::var("WINDSHEAR_VIRTIO_CONSOLE_TX_DIAGNOSTICS_MAX_LOGS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .filter(|limit| *limit > 0)
            .unwrap_or(200)
    })
}

fn should_emit_console_tx_diag(suspicious: bool) -> bool {
    if !console_tx_diag_enabled() {
        return false;
    }

    let emitted = CONSOLE_TX_DIAG_EMITTED.load(Ordering::Relaxed);
    if emitted >= console_tx_diag_max_logs() {
        return false;
    }

    if !suspicious && emitted >= CONSOLE_TX_DIAG_BASELINE_LOGS {
        return false;
    }

    CONSOLE_TX_DIAG_EMITTED
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count < console_tx_diag_max_logs()).then_some(count + 1)
        })
        .is_ok()
}

fn sample_tx_slice_diagnostics(len: usize, src: &vm_memory::VolatileSlice) -> TxSliceDiagnostics {
    let sample_len = len.min(CONSOLE_TX_DIAG_SAMPLE_LIMIT);
    let mut sample = vec![0_u8; sample_len];
    let copied = src.copy_to(&mut sample);
    sample.truncate(copied);

    let nul_bytes = sample.iter().filter(|byte| **byte == 0).count();
    let control_bytes = sample
        .iter()
        .filter(|byte| **byte < 0x20 && !matches!(**byte, b'\n' | b'\r' | b'\t'))
        .count();
    let high_bytes = sample.iter().filter(|byte| **byte >= 0x80).count();
    let elf_markers = sample.windows(3).filter(|window| *window == b"ELF").count();

    TxSliceDiagnostics {
        original_len: len,
        sampled_len: sample.len(),
        nul_bytes,
        control_bytes,
        high_bytes,
        invalid_utf8_bytes: invalid_utf8_byte_count(&sample),
        elf_markers,
        hash64: fnv1a64(&sample),
        head_hex: hex_prefix(&sample, 16),
        tail_hex: hex_suffix(&sample, 16),
    }
}

fn invalid_utf8_byte_count(bytes: &[u8]) -> usize {
    let mut invalid = 0_usize;
    let mut offset = 0_usize;

    while offset < bytes.len() {
        match std::str::from_utf8(&bytes[offset..]) {
            Ok(_) => break,
            Err(err) => {
                let valid = err.valid_up_to();
                offset = offset.saturating_add(valid);
                match err.error_len() {
                    Some(error_len) => {
                        invalid = invalid.saturating_add(error_len);
                        offset = offset.saturating_add(error_len);
                    }
                    None => {
                        invalid = invalid.saturating_add(bytes.len().saturating_sub(offset));
                        break;
                    }
                }
            }
        }
    }

    invalid
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3_u64);
    }
    hash
}

fn hex_prefix(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .take(count)
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn hex_suffix(bytes: &[u8], count: usize) -> String {
    let start = bytes.len().saturating_sub(count);
    bytes[start..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
