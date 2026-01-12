use std::{
    ffi::CString,
    io::{Error, ErrorKind},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use bytes::BytesMut;
use clap::{Parser, command};
use devices::virtio::BlockBackend;
use graft::{
    core::{
        LogId, PageIdx, VolumeId,
        page::{PAGESIZE, Page},
    },
    local::{
        fjall_storage::FjallStorage,
        page_store::{FilePageStore, FoyerStore},
    },
    remote::RemoteConfig,
    volume_reader::{VolumeRead, VolumeReader},
    volume_writer::{VolumeWrite, VolumeWriter},
};
use imago::io_buffers::{IoVector, IoVectorMut};
use krun::{krun_add_vsock_port, krun_add_vsock_port2, krun_create_ctx, krun_set_vm_config};
use rustix::io::Errno;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{
    EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};
use vm_memory::VolatileSlice;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(long, default_value = "mygraft")]
    volume_tag: String,

    /// Local storage path
    #[arg(long)]
    local_path: Option<String>,

    /// Remote log ID
    #[arg(long)]
    remote_volume: Option<String>,

    #[arg(long, default_value_t = false)]
    read_only: bool,

    #[arg(long, default_value_t = false)]
    vsock: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (non_blocking, _guard) = tracing_appender::non_blocking(std::io::stdout());
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE),
        )
        .with(EnvFilter::from_default_env())
        .init();

    // tracing_subscriber::fmt()

    //     .with_env_filter(EnvFilter::from_default_env())
    //     .finish()
    //     .init();

    let cli = Cli::parse();

    let ctx_id = {
        // Create the configuration context.
        let ctx_id = krun_create_ctx(Some(
            "/Users/jerome/.cache/sprites/components/firmware/4.9.0-2/libkrunfw.4.dylib",
        ));
        if ctx_id < 0 {
            let err = Errno::from_raw_os_error(-ctx_id);
            return Err(err.into());
        }
        ctx_id as u32
    };

    println!("configuring vm");
    let err = krun_set_vm_config(ctx_id, 2, 1024);
    if err < 0 {
        let err = Errno::from_raw_os_error(-err);
        if err == Errno::INVAL {
            anyhow::bail!("wrong cpu or memory configuration");
        }
        return Err(err.into());
    }
    println!("configured basic vpcus and memory");

    let root =
        CString::new("/Users/jerome/src/github.com/superfly/libkrun/examples/rootfs_debian")?;
    let ret = unsafe { krun::krun_set_root(ctx_id, root.as_ptr()) };
    if ret < 0 {
        let err = Errno::from_raw_os_error(-ret);
        return Err(err.into());
    }
    println!("set root");

    let kernel_cmdline = CString::new(
        "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 rootfstype=virtiofs rw debug no-kvmapf init=/usr/bin/tini -- /usr/bin/bash",
    )?;
    let ret = unsafe { krun::krun_set_kernel_cmdline(ctx_id, kernel_cmdline.as_ptr()) };
    if ret < 0 {
        let err = Errno::from_raw_os_error(-ret);
        return Err(err.into());
    }
    println!("configured kernel cmdline");

    let root = std::env::current_dir().unwrap().join("graft_remote");
    tokio::fs::create_dir_all(&root).await.unwrap();

    let remote = Arc::new(
        graft::remote::Remote::with_config(RemoteConfig::Fs {
            root: root.display().to_string(),
        })
        .unwrap(),
    );

    // let page_store = Arc::new(FilePageStore::new("./page_storage")?);
    let page_store = Arc::new(FoyerStore::new("./page_storage")?);
    let storage = Arc::new(FjallStorage::open_with_page_store(
        "./graft_local",
        page_store,
    )?);

    // tokio::spawn(async move {
    //     let mut interval = tokio::time::interval(Duration::from_secs(5));
    //     loop {
    //         interval.tick().await;
    //         let mem_usage = page_store.memory_cache_usage();
    //         warn!(pages = %page_store.total_page_count(), mem_cache_used = mem_usage.0, mem_cache_cap = mem_usage.1, segments_index_size = %page_store.segment_index_memory_estimate(), "foyer store metrics");
    //     }
    // });
    //

    // let storage = Arc::new(FjallStorage::open("./graft_local")?);

    let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel::<VolumeId>(128);

    let rt = graft::rt::runtime::Runtime::new(
        tokio::runtime::Handle::current(),
        remote.clone(),
        storage.clone(),
        Some((Duration::from_secs(2), sync_tx)),
        // None,
    );

    let mut vol = match rt.tag_get(&cli.volume_tag)? {
        Some(vid) => {
            info!("tag ({}) existed, getting vol {vid:?}", cli.volume_tag);
            let vol = rt.volume_get(&vid)?;

            info!("remote = {}", vol.remote);

            vol
        }
        None => {
            let remote_log_id = match &cli.remote_volume {
                Some(raw_log_id) => Some(raw_log_id.parse()?),
                None => None,
            };
            let vol = rt.volume_open(None, None, remote_log_id).unwrap();
            info!("opened vol: {vol:?}, remote = {}", vol.remote);
            let res = rt.tag_replace(&cli.volume_tag, vol.vid.clone()).unwrap();
            info!("replaced tag for vol: {res:?} => {}", cli.volume_tag);
            vol
        }
    };

    if let Some(raw_log_id) = cli.remote_volume {
        let log_id = raw_log_id.parse()?;
        if log_id != vol.remote {
            info!("mismatched remote, forking");
            vol = rt.volume_open(None, None, Some(log_id))?;
            let res = rt.tag_replace(&cli.volume_tag, vol.vid.clone()).unwrap();
            info!("replaced tag for vol: {res:?} => {}", cli.volume_tag);
        }
    }

    let vid = vol.vid;

    let blk = GraftBlockDevice {
        rt,
        vid,
        tx: Default::default(),
        is_read_only: cli.read_only,
        tokio_handle: tokio::runtime::Handle::current(),
        flush_task: Default::default(),
    };

    let ret = krun::add_custom_disk(ctx_id, "hello".into(), cli.read_only, blk);
    if ret < 0 {
        let err = Errno::from_raw_os_error(-ret);
        return Err(err.into());
    }
    println!("configured custom disk");

    // let exec = CString::new("/bin/sh")?;
    // let ret =
    //     unsafe { krun::krun_set_exec(ctx_id, exec.as_ptr(), std::ptr::null(), std::ptr::null()) };
    // if ret < 0 {
    //     let err = Errno::from_raw_os_error(-ret);
    //     return Err(err.into());
    // }
    // println!("configured exec");

    if cli.vsock {
        _ = tokio::fs::remove_file("./vsock_1234.sock").await;
        let path = CString::new("./vsock_1234.sock")?;
        let ret = unsafe { krun_add_vsock_port2(ctx_id, 1234, path.as_ptr(), true) };
        if ret < 0 {
            let err = Errno::from_raw_os_error(-ret);
            return Err(err.into());
        }
        println!("configured vsock listener");
    }

    tokio::spawn({
        let should_connect = cli.vsock;
        async move {
            while let Some(vid) = sync_rx.recv().await {
                debug!(?vid, "volume changed");
                if should_connect {
                    let mut stream = match UnixStream::connect("./vsock_1234.sock").await {
                        Ok(stream) => stream,
                        Err(e) => {
                            error!(error = %e, "could not connect to vsock");
                            continue;
                        }
                    };
                    let _ = stream.write_all(b"invalidate\n").await;
                    let _ = stream.flush().await;

                    let mut buf = [0u8; 16];
                    let res = stream.read(&mut buf).await;
                    debug!("read: {res:?}, buf: {}", String::from_utf8_lossy(&buf));
                }
            }
        }
    });

    // std::thread::spawn(move || {
    let _ = tokio::task::spawn_blocking(move || {
        println!("entiring krun vm");
        let err = krun::krun_start_enter(ctx_id);
        if err < 0 {
            return Err(Errno::from_raw_os_error(-err).into());
        }
        Ok::<_, Error>(())
    })
    .await?;
    // Ok::<_, Error>(())

    Ok(())
}

enum VolumeTx {
    Read(VolumeReader),
    Write(VolumeWriter),
}

struct GraftBlockDevice {
    rt: graft::rt::runtime::Runtime,
    vid: VolumeId,
    tx: Arc<tokio::sync::Mutex<Option<VolumeTx>>>,
    is_read_only: bool,
    tokio_handle: tokio::runtime::Handle,
    flush_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl BlockBackend for GraftBlockDevice {
    fn nsectors(&self) -> u64 {
        (PAGESIZE.as_u64() * 1024 * 1024) / 512
    }

    fn device_id(&self) -> &[u8] {
        b"mygraft".as_slice()
    }

    fn cache_type(&self) -> devices::virtio::CacheType {
        devices::virtio::CacheType::Writeback
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> std::io::Result<usize> {
        trace!(
            "READ {} at offset {offset}",
            bufs.iter().map(|vol| vol.len()).sum::<usize>()
        );

        if bufs.is_empty() {
            return Ok(0);
        }

        let (mut bufv, _guard) = IoVectorMut::from_volatile_slice(bufs);
        let full_length: usize = bufv
            .len()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        if full_length == 0 {
            return Ok(0);
        }

        let tx = {
            match self.tx.blocking_lock().take() {
                None => VolumeTx::Read(self.rt.volume_reader(self.vid.clone()).unwrap()),
                Some(tx) => match tx {
                    VolumeTx::Read(volume_reader) => {
                        let snapshot = volume_reader.snapshot();
                        if !self.rt.snapshot_is_latest(&self.vid, snapshot).unwrap() {
                            debug!(snapshot = ?snapshot, "snapshot is outdated! refreshing volume reader");
                            let read = self.rt.volume_reader(self.vid.clone()).unwrap();
                            debug!(snapshot = ?read.snapshot(), "new tx, new snapshot");
                            VolumeTx::Read(read)
                        } else {
                            VolumeTx::Read(volume_reader)
                        }
                    }
                    VolumeTx::Write(volume_writer) => VolumeTx::Write(volume_writer),
                },
            }
        };

        let page_size = PAGESIZE.as_u64();
        let start_page = (offset / page_size) as usize;
        let end_offset = offset + full_length as u64;
        let end_page = ((end_offset - 1) / page_size) as usize;

        let mut bytes_read = 0usize;

        for page_num in start_page..=end_page {
            // PageIdx is 1-indexed (cannot be zero)
            let page_idx =
                PageIdx::try_new((page_num + 1) as u32).expect("page idx cannot be zero");

            let page = match &tx {
                VolumeTx::Read(reader) => reader.read_page(page_idx).unwrap(),
                VolumeTx::Write(writer) => writer.read_page(page_idx).unwrap(),
            };
            let page_bytes = page.into_bytes();

            // Calculate the slice of this page we need
            let page_start_offset = page_num as u64 * page_size;
            let page_end_offset = page_start_offset + page_size;

            // Where in the page do we start reading?
            let read_start = if offset > page_start_offset {
                (offset - page_start_offset) as usize
            } else {
                0
            };

            // Where in the page do we stop reading?
            let read_end = if end_offset < page_end_offset {
                (end_offset - page_start_offset) as usize
            } else {
                page_size as usize
            };

            let bytes_to_copy = read_end - read_start;

            // Split off the destination buffer for this chunk
            let (mut chunk, remainder) = bufv.split_at(bytes_to_copy as u64);
            bufv = remainder;

            chunk.copy_from_slice(&page_bytes[read_start..read_end]);
            bytes_read += bytes_to_copy;
        }

        *self.tx.blocking_lock() = Some(tx);

        Ok(bytes_read)
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> std::io::Result<usize> {
        trace!(
            "WRITE {} at offset {offset}",
            bufs.iter().map(|vol| vol.len()).sum::<usize>()
        );

        if self.is_read_only {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "device is read-only, writes are not allowed",
            ));
        }

        if bufs.is_empty() {
            return Ok(0);
        }

        let (mut bufv, _guard) = IoVector::from_volatile_slice(bufs);
        let full_length: usize = bufv
            .len()
            .try_into()
            .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

        if full_length == 0 {
            return Ok(0);
        }

        let mut writer = {
            match self.tx.blocking_lock().take() {
                Some(VolumeTx::Write(writer)) => writer,
                Some(VolumeTx::Read(reader)) => reader.try_into().unwrap(),
                None => self.rt.volume_writer(self.vid.clone()).unwrap(),
            }
        };

        let page_size = PAGESIZE.as_u64();
        let start_page = (offset / page_size) as usize;
        let end_offset = offset + full_length as u64;
        let end_page = ((end_offset - 1) / page_size) as usize;

        let mut bytes_written = 0usize;

        for page_num in start_page..=end_page {
            // PageIdx is 1-indexed (cannot be zero)
            let page_idx =
                PageIdx::try_new((page_num + 1) as u32).expect("page idx cannot be zero");

            trace!(?page_idx, offset, "WRITING PAGE");

            // Calculate the slice of this page we're writing
            let page_start_offset = page_num as u64 * page_size;
            let page_end_offset = page_start_offset + page_size;

            // Where in the page do we start writing?
            let write_start = if offset > page_start_offset {
                (offset - page_start_offset) as usize
            } else {
                0
            };

            // Where in the page do we stop writing?
            let write_end = if end_offset < page_end_offset {
                (end_offset - page_start_offset) as usize
            } else {
                page_size as usize
            };

            let bytes_to_copy = write_end - write_start;
            let is_partial = write_start != 0 || write_end != page_size as usize;

            // Get the page buffer - read-modify-write for partial pages
            let mut page_buf = if is_partial {
                // Read existing page content first
                let existing = writer.read_page(page_idx).unwrap();
                BytesMut::from(existing.into_bytes().as_ref())
            } else {
                // Full page write - will be completely overwritten
                let mut buf = BytesMut::with_capacity(page_size as usize);
                buf.resize(page_size as usize, 0);
                buf
            };

            // Split off the source buffer for this chunk
            let (chunk, remainder) = bufv.split_at(bytes_to_copy as u64);
            bufv = remainder;

            // Copy data into the page buffer
            chunk.copy_into_slice(&mut page_buf[write_start..write_end]);

            // Write the page
            let page = unsafe { Page::from_bytes_unchecked(page_buf.freeze()) };
            writer.write_page(page_idx, page).unwrap();

            bytes_written += bytes_to_copy;
        }

        self.tx.blocking_lock().replace(VolumeTx::Write(writer));

        let prev_flush_task = self
            .flush_task
            .lock()
            .unwrap()
            .replace(self.tokio_handle.spawn({
                let tx = self.tx.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    if let Some(VolumeTx::Write(writer)) = tx.lock().await.take() {
                        debug!("COMMITTED");
                        if let Err(e) = writer.commit() {
                            error!(error = %e, "could not commit (after write idle)");
                        } else {
                            debug!("flushed after idle timeout!");
                        }
                    }
                }
            }));

        if let Some(prev_flush_task) = prev_flush_task {
            prev_flush_task.abort();
        }

        Ok(bytes_written)
    }

    fn flush(&self) -> std::io::Result<()> {
        debug!("FLUSH!");

        if let Some(VolumeTx::Write(writer)) = self.tx.blocking_lock().take() {
            debug!("COMMITTED");
            writer.commit().expect("could not commit");
        }

        if let Some(flush_task) = self.flush_task.lock().unwrap().take() {
            flush_task.abort();
        }

        Ok(())
    }

    fn sync(&self) -> std::io::Result<()> {
        debug!("SYNC!");
        Ok(())
    }
}

impl Drop for GraftBlockDevice {
    fn drop(&mut self) {
        if let Some(VolumeTx::Write(writer)) = self.tx.blocking_lock().take() {
            debug!("COMMITTED ON DROP");
            writer.commit().expect("could not commit");
        }
    }
}

// impl BlockDevice for GraftBlockDevice {
//     fn read(&mut self, offset: u64, length: u32) -> anyhow::Result<Bytes> {
//         trace!("read! offset={offset} len={length}");
//         self.buf.clear();

//         let tx = match self.tx.take() {
//             None => VolumeTx::Read(self.rt.volume_reader(self.vid.clone())?),
//             Some(tx) => tx,
//         };
//         // let reader = self.rt.volume_reader(self.vid.clone())?;

//         // let to_read = plan_pages(offset, length as u64);
//         // trace!("to_read plan len={}", to_read.len());

//         let start = (offset / PAGESIZE.as_u64()) as usize + 1;
//         let count = length as usize / PAGESIZE.as_usize();

//         let range = start..(start + count);

//         for n in range {
//             let page_idx = PageIdx::try_new(n as u32).context("page idx cannot be zero")?;
//             let page = match &tx {
//                 VolumeTx::Read(reader) => reader.read_page(page_idx)?,
//                 VolumeTx::Write(writer) => writer.read_page(page_idx)?,
//             };

//             self.buf.extend_from_slice(page.as_ref());
//         }

//         self.tx = Some(tx);

//         // for read in to_read {
//         //     trace!("to read: {read:?}");
//         //     let page_idx = reader
//         //         .read_page(PageIdx::try_new(read.page_id).context("page idx cannot be zero")?)?;
//         //     let len = read.length as usize;
//         //     let offset = read.offset as usize;
//         //     buf[buf_pos..(buf_pos + len)]
//         //         .copy_from_slice(&page_idx.into_bytes().as_ref()[offset..(offset + len)]);
//         //     buf_pos = buf_pos + len;
//         // }

//         Ok(self.buf.split().freeze())
//     }

//     fn size(&self) -> u64 {
//         PAGESIZE.as_u64() * 1024 * 1024
//     }

//     fn write(&mut self, offset: u64, mut data: BytesMut) -> anyhow::Result<()> {
//         trace!("write! offset={offset} len={}", data.len());

//         let mut writer = match self.tx.take() {
//             Some(VolumeTx::Write(writer)) => writer,
//             Some(VolumeTx::Read(reader)) => reader.try_into()?,
//             None => self.rt.volume_writer(self.vid.clone())?,
//         };

//         // let reader = self.rt.volume_reader(self.vid.clone())?;

//         let start = (offset / PAGESIZE.as_u64()) as usize + 1;
//         let count = data.len() / PAGESIZE.as_usize();

//         let range = start..(start + count);

//         // let mut buf_pos = 0;

//         for n in range {
//             let page_idx = PageIdx::try_new(n as u32).context("page idx cannot be zero")?;
//             let buf = data.split_to(PAGESIZE.as_usize());
//             // let buf = data[buf_pos..(buf_pos + PAGESIZE.as_usize())].to_vec();
//             // buf_pos += buf.len();
//             let page = unsafe { Page::from_bytes_unchecked(buf.freeze()) };
//             writer.write_page(page_idx, page)?;
//         }

//         // for write in to_write {
//         //     // trace!("to write: {write:?}");
//         //     let page_idx = PageIdx::try_new(write.page_id).context("page idx cannot be zero")?;
//         //     let buf = if write.offset != 0 && write.length != PAGESIZE.as_u64() {
//         //         // partial page, first need to pull page...
//         //         warn!(
//         //             "got a partial page write! idx={}, offset={}, len={}",
//         //             write.page_id, write.offset, write.length
//         //         );
//         //         unimplemented!();
//         //         // let page = reader.read_page(page_idx)?;

//         //         // let mut buf = page.into_bytes().to_vec();
//         //         // buf[(write.offset as usize)..(write.length as usize)]
//         //         //     .copy_from_slice(&data[pos..(pos + write.length as usize)]);
//         //         // pos += write.length as usize;
//         //         // buf
//         //     } else {
//         //         // full page
//         //         // trace!("got a full page write! idx={}", write.page_id);
//         //         let buf = data[pos..(pos + PAGESIZE.as_usize())].to_vec();
//         //         pos += PAGESIZE.as_usize();
//         //         buf
//         //     };
//         //     writer.write_page(page_idx, Page::from_buf(buf.as_slice())?)?;
//         // };

//         self.tx = Some(VolumeTx::Write(writer));

//         Ok(())
//     }

//     fn flush(&mut self) -> anyhow::Result<()> {
//         trace!("flushing!");
//         if let Some(VolumeTx::Write(writer)) = self.tx.take() {
//             writer.commit()?;
//         }
//         // self.rt.volume_writer(self.vid.clone())?.commit()?;
//         Ok(())
//     }
// }

#[allow(dead_code)]
struct NullDisk;

impl BlockBackend for NullDisk {
    fn nsectors(&self) -> u64 {
        8 * 1024 * 1024
    }

    fn device_id(&self) -> &[u8] {
        &[0]
    }

    fn cache_type(&self) -> devices::virtio::CacheType {
        devices::virtio::CacheType::Writeback
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], _offset: u64) -> std::io::Result<usize> {
        // println!(
        //     "READ {} at offset {offset}",
        //     bufs.iter().map(|vol| vol.len()).sum::<usize>()
        // );
        if bufs.is_empty() {
            return Ok(0);
        }

        Ok(0)
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], _offset: u64) -> std::io::Result<usize> {
        // println!(
        //     "WRITE {} at offset {offset}",
        //     bufs.iter().map(|vol| vol.len()).sum::<usize>()
        // );
        if bufs.is_empty() {
            return Ok(0);
        }
        Ok(bufs.iter().map(|vol| vol.len()).sum())
    }

    fn flush(&self) -> std::io::Result<()> {
        println!("FLUSH");
        Ok(())
    }

    fn sync(&self) -> std::io::Result<()> {
        println!("SYNC");
        Ok(())
    }
}

// use std::{
//     fs::{OpenOptions, create_dir_all, remove_dir_all},
//     io::{Seek, Write},
//     os::unix::fs::FileExt,
//     path::PathBuf,
//     sync::{
//         atomic::{AtomicUsize, Ordering},
//         mpsc::{self, Sender},
//     },
//     thread,
//     time::{Duration, Instant},
// };

// use rand::Rng;

// struct ReaderStats {
//     worker: i32,
//     total_reads: usize,
//     total_bytes_read: usize,
//     elapsed: Duration,
// }

// const PAGE_SIZE: usize = 16384;
// const NUM_PAGES: usize = (1024 * 1024 * 1024 * 10) / PAGE_SIZE;
// const TOTAL_BYTES: usize = NUM_PAGES * PAGE_SIZE;
// const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

// /// the maximum offset of the file that is safe to read
// /// readers should never read a byte larger than this offset
// static FLUSH_OFFSET: AtomicUsize = AtomicUsize::new(0);

// const READ_TARGET: usize = 1024 * 1024 * 1024; // 1 GB

// fn reader(worker: i32, path: PathBuf, tx: Sender<ReaderStats>) {
//     // Wait for the file to have some data
//     loop {
//         let offset = FLUSH_OFFSET.load(Ordering::SeqCst);
//         if offset >= PAGE_SIZE {
//             break;
//         }
//         thread::sleep(Duration::from_millis(10));
//     }

//     let file = OpenOptions::new()
//         .read(true)
//         .open(&path)
//         .expect("failed to open file for reading");

//     let mut rng = rand::rng();
//     let mut buf = vec![0u8; PAGE_SIZE];
//     let mut total_bytes_read = 0usize;
//     let mut total_reads = 0usize;
//     let start = Instant::now();

//     // Read random pages from the file no larger than the flush offset, until we have
//     // read a total of 1 GB of pages from the file
//     while total_bytes_read < READ_TARGET {
//         let flush_offset = FLUSH_OFFSET.load(Ordering::SeqCst);
//         let max_page = flush_offset / PAGE_SIZE;

//         if max_page == 0 {
//             thread::sleep(Duration::from_millis(1));
//             continue;
//         }

//         let page_idx = rng.random_range(0..max_page);
//         let offset = (page_idx * PAGE_SIZE) as u64;

//         let bytes_read = file.read_at(&mut buf, offset).expect("failed to read");

//         total_bytes_read += bytes_read;
//         total_reads += 1;
//     }

//     let elapsed = start.elapsed();

//     tx.send(ReaderStats {
//         worker,
//         total_reads,
//         total_bytes_read,
//         elapsed,
//     })
//     .expect("failed to send reader stats");
// }

// fn main() -> anyhow::Result<()> {
//     let root = PathBuf::from("./pagestore-data");
//     println!("using pagestore root: {}", root.display());
//     if root.exists() {
//         remove_dir_all(&root)?;
//     }
//     create_dir_all(&root)?;

//     let mut writer = OpenOptions::new()
//         .create_new(true)
//         .write(true)
//         .open(root.join("data"))?;

//     let (tx, rx) = mpsc::channel();
//     let num_readers = 4;

//     let data_path = root.join("data");
//     for i in 0..num_readers {
//         let path = data_path.clone();
//         let tx = tx.clone();
//         thread::spawn(move || reader(i, path, tx));
//     }
//     drop(tx); // Drop original sender so rx will close when all readers finish

//     println!(
//         "writing {} pages ({} bytes each, {} total)",
//         NUM_PAGES,
//         PAGE_SIZE,
//         format_bytes(TOTAL_BYTES)
//     );

//     let write_buf = vec![0u8; PAGE_SIZE];

//     // write to the pagestore
//     let mut last_flush = Instant::now();
//     let mut flush_elapsed = Duration::ZERO;
//     let mut write_elapsed = Duration::ZERO;
//     for _ in 0..NUM_PAGES {
//         let write_start = Instant::now();
//         writer.write_all(&write_buf)?;
//         write_elapsed += write_start.elapsed();

//         if last_flush.elapsed() > FLUSH_INTERVAL {
//             let current_offset = writer.stream_position()? as usize;
//             let flush_start = Instant::now();
//             writer.flush()?;
//             flush_elapsed += flush_start.elapsed();
//             FLUSH_OFFSET.store(current_offset, Ordering::SeqCst);
//             last_flush = Instant::now();
//         }
//     }

//     let flush_start = Instant::now();
//     writer.flush()?;
//     flush_elapsed += flush_start.elapsed();

//     let total_elapsed = write_elapsed + flush_elapsed;

//     let write_throughput = TOTAL_BYTES as f64 / write_elapsed.as_secs_f64();
//     let total_throughput = TOTAL_BYTES as f64 / total_elapsed.as_secs_f64();

//     println!("\n--- Write Results ---");
//     println!("write time:  {:?}", write_elapsed);
//     println!("flush time:  {:?}", flush_elapsed);
//     println!("total time:  {:?}", total_elapsed);
//     println!(
//         "write throughput: {}/s",
//         format_bytes(write_throughput as usize)
//     );
//     println!(
//         "total throughput: {}/s",
//         format_bytes(total_throughput as usize)
//     );

//     // Collect and print reader stats
//     println!("\n--- Read Results ---");
//     let mut stats: Vec<ReaderStats> = rx.iter().collect();
//     stats.sort_by_key(|s| s.worker);

//     for stat in &stats {
//         let throughput = stat.total_bytes_read as f64 / stat.elapsed.as_secs_f64();
//         println!(
//             "reader {}: {} reads, {} in {:?} ({}/s)",
//             stat.worker,
//             stat.total_reads,
//             format_bytes(stat.total_bytes_read),
//             stat.elapsed,
//             format_bytes(throughput as usize)
//         );
//     }

//     let total_read_bytes: usize = stats.iter().map(|s| s.total_bytes_read).sum();
//     let total_reads: usize = stats.iter().map(|s| s.total_reads).sum();
//     let avg_elapsed = stats.iter().map(|s| s.elapsed).sum::<Duration>() / stats.len() as u32;
//     let combined_throughput = total_read_bytes as f64 / avg_elapsed.as_secs_f64();

//     println!(
//         "total: {} reads, {} ({}/s combined)",
//         total_reads,
//         format_bytes(total_read_bytes),
//         format_bytes(combined_throughput as usize)
//     );

//     Ok(())
// }

// fn format_bytes(bytes: usize) -> String {
//     const KB: usize = 1024;
//     const MB: usize = KB * 1024;
//     const GB: usize = MB * 1024;

//     if bytes >= GB {
//         format!("{:.2} GB", bytes as f64 / GB as f64)
//     } else if bytes >= MB {
//         format!("{:.2} MB", bytes as f64 / MB as f64)
//     } else if bytes >= KB {
//         format!("{:.2} KB", bytes as f64 / KB as f64)
//     } else {
//         format!("{} B", bytes)
//     }
// }
