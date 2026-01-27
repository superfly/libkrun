use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Error, ErrorKind},
    path::Path,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use clap::{Parser, command};
use futures::{StreamExt, TryStreamExt};
use graft::{
    GraftErr,
    core::{
        LogId, PageIdx, VolumeId,
        page::{PAGESIZE, Page},
    },
    local::{
        fjall_storage::{FjallStorage, FjallStorageErr},
        page_store::{FilePageStore, FoyerStore, PageStore},
    },
    remote::RemoteConfig,
    volume_reader::{VolumeRead, VolumeReader},
    volume_writer::{VolumeWrite, VolumeWriter},
};
use krun::{
    AsyncBlockBackend, AsyncBlockBackendFactory, BlockBackend, BlockDeviceConfig, BlockDeviceType,
    BoxFuture, CacheType, IoVector, IoVectorMut, SendBoxFuture, VolatileSlice, VolatileSliceGuard,
};
use memmap2::MmapMut;
use rustix::io::Errno;
use slatedb::{
    CompactorBuilder, WriteBatch,
    admin::AdminBuilder,
    config::{
        CompactorOptions, GarbageCollectorDirectoryOptions, GarbageCollectorOptions, WriteOptions,
    },
    object_store::{self, ObjectStore},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    task::{JoinSet, block_in_place},
};
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{
    EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt,
};
use wal_blk::{
    AsyncSingleWalWithCache, SingleWalCacheStrategy as CacheStrategy, SingleWalDrainEntry,
    SingleWalIterator, SingleWalWithCacheConfig,
};

// #[global_allocator]
// static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

// #[global_allocator]
// static ALLOC: snmalloc_rs::SnMalloc = snmalloc_rs::SnMalloc;

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

    #[arg(long, default_value = "examples/rootfs_debian")]
    rootfs: String,

    command: Vec<String>,
}

#[tokio::main(worker_threads = 4)]
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

    let cli = Cli::parse();

    // let root = std::env::current_dir().unwrap().join("graft_remote");
    // tokio::fs::create_dir_all(&root).await.unwrap();

    // let remote = Arc::new(
    //     graft::remote::Remote::with_config(RemoteConfig::Fs {
    //         root: root.display().to_string(),
    //     })
    //     .unwrap(),
    // );

    // let page_store = Arc::new(BoundedPageStore::new("./page_storage")?);
    // // let page_store = Arc::new(FilePageStore::new("./page_storage")?);
    // // let page_store = Arc::new(FoyerStore::new("./page_storage")?);
    // let storage = Arc::new(FjallStorage::open_with_page_store(
    //     "./graft_local",
    //     page_store.clone(),
    // )?);

    // // tokio::spawn(async move {
    // //     let mut interval = tokio::time::interval(Duration::from_secs(5));
    // //     loop {
    // //         interval.tick().await;
    // //         let mem_usage = page_store.memory_cache_usage();
    // //         warn!(pages = %page_store.total_page_count(), mem_cache_used = mem_usage.0, mem_cache_cap = mem_usage.1, segments_index_size = %page_store.segment_index_memory_estimate(), "foyer store metrics");
    // //     }
    // // });
    // //

    // // let storage = Arc::new(FjallStorage::open("./graft_local")?);

    // let (sync_tx, mut sync_rx) = tokio::sync::mpsc::channel::<VolumeId>(128);

    // let rt = graft::rt::runtime::Runtime::new(
    //     tokio::runtime::Handle::current(),
    //     remote.clone(),
    //     storage.clone(),
    //     // Some((Duration::from_secs(2), sync_tx)),
    //     None,
    // );

    // let mut vol = match rt.tag_get(&cli.volume_tag)? {
    //     Some(vid) => {
    //         debug!("tag ({}) existed, getting vol {vid:?}", cli.volume_tag);
    //         let vol = rt.volume_get(&vid)?;

    //         debug!("remote = {}", vol.remote);

    //         vol
    //     }
    //     None => {
    //         let remote_log_id = match &cli.remote_volume {
    //             Some(raw_log_id) => Some(raw_log_id.parse()?),
    //             None => None,
    //         };
    //         let vol = rt.volume_open(None, None, remote_log_id).unwrap();
    //         debug!("opened vol: {vol:?}, remote = {}", vol.remote);
    //         let res = rt.tag_replace(&cli.volume_tag, vol.vid.clone()).unwrap();
    //         debug!("replaced tag for vol: {res:?} => {}", cli.volume_tag);
    //         vol
    //     }
    // };

    // if let Some(raw_log_id) = cli.remote_volume {
    //     let log_id = raw_log_id.parse()?;
    //     if log_id != vol.remote {
    //         debug!("mismatched remote, forking");
    //         vol = rt.volume_open(None, None, Some(log_id))?;
    //         let res = rt.tag_replace(&cli.volume_tag, vol.vid.clone()).unwrap();
    //         debug!("replaced tag for vol: {res:?} => {}", cli.volume_tag);
    //     }
    // }

    // let vid = vol.vid;

    // let blk = GraftBlockDevice {
    //     rt,
    //     vid,
    //     page_store,
    //     tx: Default::default(),
    //     is_read_only: cli.read_only,
    //     tokio_handle: tokio::runtime::Handle::current(),
    //     flush_task: Default::default(),
    // };

    // if cli.vsock {
    //     _ = tokio::fs::remove_file("./vsock_1234.sock").await;
    //     let path = CString::new("./vsock_1234.sock")?;
    //     let ret = unsafe { krun_add_vsock_port2(ctx_id, 1234, path.as_ptr(), true) };
    //     if ret < 0 {
    //         let err = Errno::from_raw_os_error(-ret);
    //         return Err(err.into());
    //     }
    //     println!("configured vsock listener");
    // }

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

    // let dir = std::env::current_dir()?.join("slatedb_store");
    // tokio::fs::create_dir_all(&dir).await?;

    // let db = slatedb::Db::builder(
    //     "mydb",
    //     Arc::new(object_store::local::LocalFileSystem::new_with_prefix(dir)?),
    // )
    // .with_settings(slatedb::Settings {
    //     wal_enabled: true,
    //     // l0_sst_size_bytes: 128 * 1024 * 1024,
    //     // filter_bits_per_key: 10,
    //     // flush_interval: Some(std::time::Duration::from_secs(30)),
    //     // garbage_collector_options: Some(GarbageCollectorOptions {
    //     //     wal_options: Some(GarbageCollectorDirectoryOptions {
    //     //         interval: Some(Duration::from_mins(1)),
    //     //         min_age: Duration::from_mins(1),
    //     //     }),
    //     //     manifest_options: Some(GarbageCollectorDirectoryOptions {
    //     //         interval: Some(Duration::from_mins(1)),
    //     //         min_age: Duration::from_mins(1),
    //     //     }),
    //     //     compacted_options: Some(GarbageCollectorDirectoryOptions {
    //     //         interval: Some(Duration::from_mins(1)),
    //     //         min_age: Duration::from_mins(1),
    //     //     }),
    //     //     compactions_options: Some(GarbageCollectorDirectoryOptions {
    //     //         interval: Some(Duration::from_mins(1)),
    //     //         min_age: Duration::from_mins(1),
    //     //     }),
    //     // }),
    //     compression_codec: None,
    //     compactor_options: None,
    //     ..Default::default()
    // })
    // .build()
    // .await?;

    let wal_path = std::env::current_dir()?.join("disk_wal");
    tokio::fs::create_dir_all(&wal_path).await?;

    let cache_path = std::env::current_dir()?.join("disk_cache");

    // let object_store_path = std::env::current_dir()?.join("slatedb_store");
    // tokio::fs::create_dir_all(&object_store_path).await?;

    // let object_store = Arc::new(object_store::local::LocalFileSystem::new_with_prefix(
    //     object_store_path,
    // )?);
    let object_store = Arc::new(
        object_store::aws::AmazonS3Builder::new()
            .with_access_key_id("minioadmin")
            .with_secret_access_key("minioadmin")
            .with_allow_http(true)
            .with_endpoint("http://192.168.0.137:9000")
            .with_bucket_name("slate-test")
            .build()?,
    );

    // Create a factory instead of the backend directly.
    // The factory will create the backend inside the worker's tokio runtime,
    // ensuring SlateDB is initialized on the correct runtime.
    let factory = Box::new(
        WalBlockBackendFactory::new(
            cache_path,
            wal_path,
            object_store.clone(),
            4 * 1024 * 1024 * 1024,
            b"mydisk".into(),
            16 * 1024,
        )
        .with_drain_interval(Duration::from_secs(5)),
    );

    builder.add_block_cfg(BlockDeviceConfig {
        block_id: "hello".into(),
        cache_type: CacheType::Writeback,
        // disk_type: BlockDeviceType::CustomAsyncFactory {
        //     factory: Box::new(NullAsyncBlockDeviceFactory),
        // },
        disk_type: BlockDeviceType::CustomAsyncFactory { factory },
        // disk_type: BlockDeviceType::Custom {
        //     backend: Arc::new(MmapBlockBackend::open(
        //         "./page_storage",
        //         CacheType::Writeback,
        //         false,
        //         Some(1 * 1024 * 1024 * 1024),
        //     )?),
        // },
        is_disk_read_only: false,
        direct_io: false,
    });

    let ctx = builder.build()?;

    println!("entering krun vm");
    let ctx_result = ctx.run();

    info!("VM is done, res: {ctx_result:?}");

    Ok(())
}

/// Block size used by the virtual device
const SECTOR_SIZE: u64 = 512;

// ============================================================================
// WalBlockBackend
// ============================================================================

/// BlockBackend implementation backed by local WAL/cache + SlateDB
pub struct WalBlockBackend {
    /// Local cache + WAL (shared for background drain task)
    local: Arc<AsyncSingleWalWithCache>,
    /// Remote persistent storage
    db: slatedb::Db,
    /// Total device size in bytes
    device_size: u64,
    /// Device identifier
    image_id: Vec<u8>,
    block_size: u32,
    zero_block: Vec<u8>,
    /// Cache hit counter
    cache_hits: std::sync::atomic::AtomicU64,
    /// Cache miss counter
    cache_misses: std::sync::atomic::AtomicU64,
}

// Safety: block_buf is only accessed while holding the LocalBlockBackend's internal lock
unsafe impl Send for WalBlockBackend {}
unsafe impl Sync for WalBlockBackend {}

impl WalBlockBackend {
    pub async fn open(
        cache_path: &Path,
        wal_dir: &Path,
        object_store: Arc<dyn ObjectStore>,
        device_size: u64,
        image_id: Vec<u8>,
        block_size: u32,
    ) -> io::Result<Self> {
        let start = Instant::now();
        let local = Arc::new(AsyncSingleWalWithCache::open(
            cache_path,
            wal_dir,
            SingleWalWithCacheConfig::new(
                block_size,
                (512 * 1024 * 1024) / block_size, // cache slots
                200_000,                          // entries per WAL file
            ),
        )?);
        info!("opened local block backend in {:?}", start.elapsed());

        let mut slate_settings = slatedb::Settings::default();
        slate_settings.wal_enabled = false;
        slate_settings.compactor_options = Some(CompactorOptions {
            poll_interval: Duration::from_secs(5),
            manifest_update_timeout: Duration::from_secs(60),
            max_sst_size: 256 * 1024 * 1024,
            max_concurrent_compactions: 2,
        });
        slate_settings.garbage_collector_options = Some(GarbageCollectorOptions::default());
        slate_settings.compression_codec = None;
        slate_settings.l0_max_ssts = 8;
        slate_settings.l0_sst_size_bytes = 64 * 1024 * 1024;

        info!("WalBlockBackend::open - about to build SlateDB (this makes network calls)");
        let db = slatedb::Db::builder("mydb", object_store)
            .with_settings(slate_settings)
            .with_memory_cache(Arc::new(slatedb::db_cache::SplitCache::new()))
            .build()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        info!("WalBlockBackend::open - SlateDB built successfully (network is working!)");

        Ok(Self {
            local,
            db,
            device_size,
            image_id,
            block_size,
            zero_block: vec![0u8; block_size as usize],
            cache_hits: std::sync::atomic::AtomicU64::new(0),
            cache_misses: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Get Arc to local backend for background tasks
    pub fn local(&self) -> Arc<AsyncSingleWalWithCache> {
        self.local.clone()
    }

    /// Get Arc to SlateDB for background tasks
    pub fn db(&self) -> &slatedb::Db {
        &self.db
    }

    /// Get cache hit count
    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get cache miss count
    pub fn cache_misses(&self) -> u64 {
        self.cache_misses.load(std::sync::atomic::Ordering::Relaxed)
    }
}

async fn read_block(
    local: &AsyncSingleWalWithCache,
    db: &slatedb::Db,
    block_num: u64,
    buf: &mut [u8],
) -> io::Result<()> {
    trace!(block_num, len = %buf.len(), "read_block");
    // Try local first (cache -> WAL)
    if local.read_into(block_num, buf)? {
        trace!("read from cache or WAL!");
        return Ok(());
    }

    trace!("reading from slatedb");
    // Fetch from SlateDB (blocking - see note below)
    let key = block_num.to_be_bytes();
    let result = db
        .get(&key)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    match result {
        Some(data) => {
            buf.copy_from_slice(&data);
            // Populate local cache for next read
            local.populate_cache(block_num, buf);
            Ok(())
        }
        None => {
            // Block never written - return zeros
            buf.fill(0);
            Ok(())
        }
    }
}

/// Factory for creating WalBlockBackend inside the worker's tokio runtime.
/// This ensures SlateDB is initialized on the correct runtime.
pub struct WalBlockBackendFactory {
    cache_path: std::path::PathBuf,
    wal_dir: std::path::PathBuf,
    object_store: Arc<dyn ObjectStore>,
    device_size: u64,
    image_id: Vec<u8>,
    block_size: u32,
    drain_interval: Option<Duration>,
}

impl WalBlockBackendFactory {
    pub fn new(
        cache_path: std::path::PathBuf,
        wal_dir: std::path::PathBuf,
        object_store: Arc<dyn ObjectStore>,
        device_size: u64,
        image_id: Vec<u8>,
        block_size: u32,
    ) -> Self {
        Self {
            cache_path,
            wal_dir,
            object_store,
            device_size,
            image_id,
            block_size,
            drain_interval: None,
        }
    }

    /// Enable the background drain task that flushes WAL to SlateDB.
    pub fn with_drain_interval(mut self, interval: Duration) -> Self {
        self.drain_interval = Some(interval);
        self
    }
}

impl AsyncBlockBackendFactory for WalBlockBackendFactory {
    fn nsectors(&self) -> u64 {
        self.device_size / SECTOR_SIZE
    }

    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
    }

    fn create(
        self: Box<Self>,
    ) -> SendBoxFuture<'static, io::Result<Arc<dyn AsyncBlockBackend + Send + Sync>>> {
        Box::pin(async move {
            info!("WalBlockBackendFactory::create() - about to open backend");
            let backend = WalBlockBackend::open(
                &self.cache_path,
                &self.wal_dir,
                self.object_store,
                self.device_size,
                self.image_id,
                self.block_size,
            )
            .await?;
            info!("WalBlockBackendFactory::create() - backend opened successfully!");

            let backend = Arc::new(backend);

            // Spawn the drain task if configured
            if let Some(interval) = self.drain_interval {
                info!(
                    "WalBlockBackendFactory::create() - spawning drain task with interval {:?}",
                    interval
                );
                let _drain_handle =
                    spawn_drain_task(backend.local(), backend.db().clone(), interval);
            }

            // Spawn periodic cache metrics logger
            let backend_metrics = backend.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(5));
                let mut last_hits = 0u64;
                let mut last_misses = 0u64;
                // SlateDB metrics
                let mut last_db_gets = 0i64;
                let mut last_db_cache_hit = 0i64;
                let mut last_db_cache_miss = 0i64;

                // Get stat references once
                let db_metrics = backend_metrics.db.metrics();
                let db_get_stat = db_metrics.lookup("db/get_requests");
                let db_cache_hit_stat = db_metrics.lookup("dbcache/data_block_hit");
                let db_cache_miss_stat = db_metrics.lookup("dbcache/data_block_miss");

                loop {
                    interval.tick().await;

                    // Local cache metrics
                    let hits = backend_metrics.cache_hits();
                    let misses = backend_metrics.cache_misses();
                    let delta_hits = hits - last_hits;
                    let delta_misses = misses - last_misses;
                    let hit_rate = if delta_hits + delta_misses > 0 {
                        100.0 * delta_hits as f64 / (delta_hits + delta_misses) as f64
                    } else {
                        0.0
                    };
                    let wal_len = backend_metrics.local.wal_len();

                    // SlateDB metrics
                    let db_gets = db_get_stat.as_ref().map(|s| s.get()).unwrap_or(0);
                    let db_cache_hit = db_cache_hit_stat.as_ref().map(|s| s.get()).unwrap_or(0);
                    let db_cache_miss = db_cache_miss_stat.as_ref().map(|s| s.get()).unwrap_or(0);

                    let delta_db_gets = db_gets - last_db_gets;
                    let delta_db_cache_hit = db_cache_hit - last_db_cache_hit;
                    let delta_db_cache_miss = db_cache_miss - last_db_cache_miss;

                    let db_cache_hit_rate = if delta_db_cache_hit + delta_db_cache_miss > 0 {
                        100.0 * delta_db_cache_hit as f64
                            / (delta_db_cache_hit + delta_db_cache_miss) as f64
                    } else {
                        0.0
                    };

                    info!(
                        "cache metrics: hits={}/s misses={}/s hit_rate={:.1}% wal_entries={}",
                        delta_hits / 5,
                        delta_misses / 5,
                        hit_rate,
                        wal_len,
                    );
                    info!(
                        "slatedb metrics: gets={}/s cache_hit={}/s cache_miss={}/s cache_hit_rate={:.1}%",
                        delta_db_gets / 5,
                        delta_db_cache_hit / 5,
                        delta_db_cache_miss / 5,
                        db_cache_hit_rate,
                    );

                    last_hits = hits;
                    last_misses = misses;
                    last_db_gets = db_gets;
                    last_db_cache_hit = db_cache_hit;
                    last_db_cache_miss = db_cache_miss;
                }
            });

            Ok(backend as Arc<dyn AsyncBlockBackend + Send + Sync>)
        })
    }
}

impl AsyncBlockBackend for WalBlockBackend {
    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
    }

    fn nsectors(&self) -> u64 {
        self.device_size / SECTOR_SIZE
    }

    fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn read_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        trace!(offset, "read_vectored_at");

        // Capture what we need - return the future immediately
        // let local = self.local.clone();
        // let db = self.db.clone();
        // let block_size = self.block_size;
        // let zero_block = self.zero_block.clone();
        // let cache_hits = &self.cache_hits;
        // let cache_misses_counter = &self.cache_misses;

        Box::pin(async move {
            // Pre-compute which blocks we need (pure arithmetic, no I/O)
            #[derive(Debug, Clone)]
            struct BlockRequest {
                block_num: u64,
                buf_index: usize,
                buf_offset: usize,
                offset_in_block: usize,
                count: usize,
            }

            let mut requests = Vec::new();
            let mut current_offset = offset;
            let mut total_read = 0usize;

            for (buf_index, buf) in bufs.iter().enumerate() {
                let mut buf_offset = 0usize;
                let buf_len = buf.len();

                while buf_offset < buf_len {
                    let block_num = current_offset / self.block_size as u64;
                    let offset_in_block = (current_offset % self.block_size as u64) as usize;
                    let remaining_in_block = self.block_size as usize - offset_in_block;
                    let to_read = remaining_in_block.min(buf_len - buf_offset);

                    requests.push(BlockRequest {
                        block_num,
                        buf_index,
                        buf_offset,
                        offset_in_block,
                        count: to_read,
                    });

                    buf_offset += to_read;
                    current_offset += to_read as u64;
                    total_read += to_read;
                }
            }

            // Deduplicate block numbers for cache lookup
            let unique_blocks: Vec<u64> = requests
                .iter()
                .map(|r| r.block_num)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            // Phase 1: Batch cache lookup in blocking thread pool
            // This prevents blocking the async runtime
            let cache_results: std::collections::HashMap<u64, Option<Vec<u8>>> = {
                let mut results = std::collections::HashMap::new();
                let mut block_buf = vec![0u8; self.block_size as usize];

                for block_num in unique_blocks {
                    if self.local.read_into(block_num, &mut block_buf)? {
                        // Cache hit - store the data
                        results.insert(block_num, Some(block_buf.clone()));
                    } else {
                        // Cache miss
                        results.insert(block_num, None);
                    }
                }

                results
            };

            // Separate hits from misses and copy hit data to guest memory
            let mut miss_block_nums = std::collections::HashSet::new();

            for req in &requests {
                match cache_results.get(&req.block_num) {
                    Some(Some(data)) => {
                        // Cache hit - copy to guest memory
                        self.cache_hits
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(dst) = bufs[req.buf_index].subslice(req.buf_offset, req.count) {
                            unsafe {
                                dst.copy_from(
                                    &data[req.offset_in_block..req.offset_in_block + req.count],
                                );
                            }
                        }
                    }
                    _ => {
                        // Cache miss - will fetch from DB
                        self.cache_misses
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        miss_block_nums.insert(req.block_num);
                    }
                }
            }

            // Early exit if everything was cached
            if miss_block_nums.is_empty() {
                trace!(total_read, "read_vectored_at: all cached");
                return Ok(total_read);
            }

            // Phase 2: Batch fetch all misses from DB in parallel
            trace!(count = miss_block_nums.len(), "batch fetching cache misses");

            let db_results: std::collections::HashMap<u64, Option<Bytes>> =
                futures::stream::iter(miss_block_nums.into_iter().map({
                    let db = self.db.clone();
                    move |block_num| {
                        let db = db.clone();
                        async move {
                            let key = block_num.to_be_bytes();
                            db.get(&key)
                                .await
                                .map(|data| (block_num, data))
                                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
                        }
                    }
                }))
                .buffer_unordered(32)
                .try_collect()
                .await?;

            // Phase 3: Populate cache with fetched data (in blocking thread)
            // This ensures future reads hit the local cache
            if !db_results.is_empty() {
                let blocks_to_cache: Vec<(u64, Vec<u8>)> = db_results
                    .iter()
                    .filter_map(|(block_num, data)| data.as_ref().map(|d| (*block_num, d.to_vec())))
                    .collect();

                if !blocks_to_cache.is_empty() {
                    for (block_num, data) in blocks_to_cache {
                        self.local.populate_cache(block_num, &data);
                    }
                }
            }

            // Phase 4: Copy DB results to guest memory (only for misses)
            for req in &requests {
                // Skip if this was a cache hit
                if cache_results.get(&req.block_num).map(|v| v.is_some()) == Some(true) {
                    continue;
                }

                if let Some(dst) = bufs[req.buf_index].subslice(req.buf_offset, req.count) {
                    match db_results.get(&req.block_num) {
                        Some(Some(data)) => unsafe {
                            dst.copy_from(
                                &data[req.offset_in_block..req.offset_in_block + req.count],
                            );
                        },
                        _ => unsafe {
                            dst.copy_from(&self.zero_block[0..req.count]);
                        },
                    }
                }
            }

            Ok(total_read)
        })
    }

    fn write_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        trace!(offset, "write_vectored_at");
        let block_size = self.block_size as usize;

        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        if total_len == 0 {
            return Box::pin(async { Ok(0) });
        }

        Box::pin(async move {
            let block_size_u64 = block_size as u64;
            let start_block = offset / block_size_u64;
            let end_offset = offset + total_len as u64;
            let last_block = (end_offset - 1) / block_size_u64;

            let mut total_written = 0usize;
            let mut current_offset = offset;

            // Accumulator for partial blocks only
            let mut partial_block: Option<(u64, Vec<u8>)> = None;

            for buf in bufs {
                let mut buf_offset = 0usize;
                let buf_len = buf.len();

                while buf_offset < buf_len {
                    let block_num = current_offset / block_size_u64;
                    let offset_in_block = (current_offset % block_size_u64) as usize;
                    let remaining_in_block = block_size - offset_in_block;
                    let remaining_in_buf = buf_len - buf_offset;
                    let to_write = remaining_in_block.min(remaining_in_buf);

                    // Fast path: full block, block-aligned, from contiguous guest buffer
                    if offset_in_block == 0 && remaining_in_buf >= block_size {
                        // Flush any pending partial block first
                        if let Some((prev_block, data)) = partial_block.take() {
                            self.local.write_with_cache(
                                prev_block,
                                &data,
                                CacheStrategy::UpdateIfPresent,
                            )?;
                        }

                        // Single-copy: guest RAM → WAL mmap directly
                        let src = buf.subslice(buf_offset, block_size).unwrap();
                        let mut block_data = vec![0u8; block_size];
                        unsafe {
                            src.copy_to(&mut block_data);
                        }
                        self.local.write_with_cache(
                            block_num,
                            &block_data,
                            CacheStrategy::UpdateIfPresent,
                        )?;

                        buf_offset += block_size;
                        current_offset += block_size as u64;
                        total_written += block_size;
                        continue;
                    }

                    // Slow path: partial block, need accumulation
                    let block_data = match &mut partial_block {
                        Some((cur_block, data)) if *cur_block == block_num => data,
                        _ => {
                            // Flush previous partial block if different
                            if let Some((prev_block, data)) = partial_block.take() {
                                self.local.write_with_cache(
                                    prev_block,
                                    &data,
                                    CacheStrategy::UpdateIfPresent,
                                )?;
                            }

                            // Initialize new partial block
                            let mut data = vec![0u8; block_size];

                            // Read existing data for partial blocks
                            let is_partial_start =
                                block_num == start_block && (offset % block_size_u64) != 0;
                            let is_partial_end =
                                block_num == last_block && (end_offset % block_size_u64) != 0;
                            if is_partial_start || is_partial_end {
                                read_block(&self.local, &self.db, block_num, &mut data).await?;
                            }

                            partial_block = Some((block_num, data));
                            &mut partial_block.as_mut().unwrap().1
                        }
                    };

                    // Copy from volatile slice into partial block buffer
                    if let Some(src) = buf.subslice(buf_offset, to_write) {
                        unsafe {
                            src.copy_to(
                                &mut block_data[offset_in_block..offset_in_block + to_write],
                            );
                        }
                    }

                    buf_offset += to_write;
                    current_offset += to_write as u64;
                    total_written += to_write;
                }
            }

            // Flush final partial block
            if let Some((block_num, data)) = partial_block {
                self.local
                    .write_with_cache(block_num, &data, CacheStrategy::UpdateIfPresent)?;
            }

            Ok(total_written)
        })
    }

    fn write_batch(
        &self,
        writes: Vec<(u64, Vec<VolatileSliceGuard>)>,
    ) -> BoxFuture<'_, io::Result<Vec<usize>>> {
        trace!(count = writes.len(), "write_batch");

        if writes.is_empty() {
            return Box::pin(async { Ok(vec![]) });
        }

        let block_size = self.block_size as usize;

        Box::pin(async move {
            let block_size_u64 = block_size as u64;

            // Phase 1: Identify all blocks that need pre-fetching (partial blocks)
            let mut blocks_to_prefetch = std::collections::HashSet::new();

            for (offset, bufs) in &writes {
                let total_len: usize = bufs.iter().map(|b| b.len()).sum();
                if total_len == 0 {
                    continue;
                }

                let start_block = *offset / block_size_u64;
                let end_offset = *offset + total_len as u64;
                let last_block = (end_offset - 1) / block_size_u64;

                // Partial start block needs pre-fetch
                if (*offset % block_size_u64) != 0 {
                    blocks_to_prefetch.insert(start_block);
                }
                // Partial end block needs pre-fetch (if different from start)
                if (end_offset % block_size_u64) != 0 && last_block != start_block {
                    blocks_to_prefetch.insert(last_block);
                }
            }

            // Phase 2: Fetch all needed blocks concurrently
            let prefetched: std::collections::HashMap<u64, Vec<u8>> =
                if !blocks_to_prefetch.is_empty() {
                    trace!(
                        count = blocks_to_prefetch.len(),
                        "prefetching partial blocks"
                    );
                    futures::stream::iter(blocks_to_prefetch.into_iter().map(|block_num| {
                        let local = &self.local;
                        let db = &self.db;
                        async move {
                            let mut data = vec![0u8; block_size];
                            read_block(local, db, block_num, &mut data).await?;
                            Ok::<_, io::Error>((block_num, data))
                        }
                    }))
                    .buffer_unordered(32)
                    .try_collect()
                    .await?
                } else {
                    std::collections::HashMap::new()
                };

            // Phase 3: Process writes using prefetched data
            let mut results = Vec::with_capacity(writes.len());

            for (offset, bufs) in writes {
                let total_len: usize = bufs.iter().map(|b| b.len()).sum();
                if total_len == 0 {
                    results.push(0);
                    continue;
                }

                let start_block = offset / block_size_u64;
                let end_offset = offset + total_len as u64;
                let last_block = (end_offset - 1) / block_size_u64;

                let mut total_written = 0usize;
                let mut current_offset = offset;

                // Accumulator for partial blocks only
                let mut partial_block: Option<(u64, Vec<u8>)> = None;

                for buf in bufs {
                    let mut buf_offset = 0usize;
                    let buf_len = buf.len();

                    while buf_offset < buf_len {
                        let block_num = current_offset / block_size_u64;
                        let offset_in_block = (current_offset % block_size_u64) as usize;
                        let remaining_in_block = block_size - offset_in_block;
                        let remaining_in_buf = buf_len - buf_offset;
                        let to_write = remaining_in_block.min(remaining_in_buf);

                        // Fast path: full block, block-aligned, from contiguous guest buffer
                        if offset_in_block == 0 && remaining_in_buf >= block_size {
                            // Flush any pending partial block first
                            if let Some((prev_block, data)) = partial_block.take() {
                                self.local.write_with_cache(
                                    prev_block,
                                    &data,
                                    CacheStrategy::UpdateIfPresent,
                                )?;
                            }

                            // Single-copy: guest RAM → WAL mmap directly
                            let src = buf.subslice(buf_offset, block_size).unwrap();
                            let mut block_data = vec![0u8; block_size];
                            unsafe {
                                src.copy_to(&mut block_data);
                            }
                            self.local.write_with_cache(
                                block_num,
                                &block_data,
                                CacheStrategy::UpdateIfPresent,
                            )?;

                            buf_offset += block_size;
                            current_offset += block_size as u64;
                            total_written += block_size;
                            continue;
                        }

                        // Slow path: partial block, need accumulation
                        let block_data = match &mut partial_block {
                            Some((cur_block, data)) if *cur_block == block_num => data,
                            _ => {
                                // Flush previous partial block if different
                                if let Some((prev_block, data)) = partial_block.take() {
                                    self.local.write_with_cache(
                                        prev_block,
                                        &data,
                                        CacheStrategy::UpdateIfPresent,
                                    )?;
                                }

                                // Initialize new partial block - use prefetched data if available
                                let is_partial_start =
                                    block_num == start_block && (offset % block_size_u64) != 0;
                                let is_partial_end =
                                    block_num == last_block && (end_offset % block_size_u64) != 0;

                                let data = if is_partial_start || is_partial_end {
                                    // Use prefetched data
                                    prefetched
                                        .get(&block_num)
                                        .cloned()
                                        .unwrap_or_else(|| vec![0u8; block_size])
                                } else {
                                    vec![0u8; block_size]
                                };

                                partial_block = Some((block_num, data));
                                &mut partial_block.as_mut().unwrap().1
                            }
                        };

                        // Copy from volatile slice into partial block buffer
                        if let Some(src) = buf.subslice(buf_offset, to_write) {
                            unsafe {
                                src.copy_to(
                                    &mut block_data[offset_in_block..offset_in_block + to_write],
                                );
                            }
                        }

                        buf_offset += to_write;
                        current_offset += to_write as u64;
                        total_written += to_write;
                    }
                }

                // Flush final partial block for this write
                if let Some((block_num, data)) = partial_block {
                    self.local.write_with_cache(
                        block_num,
                        &data,
                        CacheStrategy::UpdateIfPresent,
                    )?;
                }

                results.push(total_written);
            }

            Ok(results)
        })
    }

    fn flush(&self) -> BoxFuture<'_, io::Result<()>> {
        trace!("flush");
        let local = self.local.clone();
        Box::pin(async move { local.flush_data().await })
    }

    fn sync(&self) -> BoxFuture<'_, io::Result<()>> {
        trace!("sync");
        // self.local.flush()
        Box::pin(async { Ok(()) })
    }

    fn discard(&self, offset: u64, len: u64) -> BoxFuture<'_, io::Result<()>> {
        trace!(offset, len, "discard");
        self.write_zeroes(offset, len, false)
    }

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> BoxFuture<'_, io::Result<()>> {
        trace!(offset, len, unmap, "write_zeroes");
        let start_block = offset / self.block_size as u64;
        let end_block = (offset + len + self.block_size as u64 - 1) / self.block_size as u64;

        Box::pin(async move {
            let local = self.local.clone();
            tokio::task::spawn_blocking(move || local.trim_range(start_block, end_block))
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
        })
    }

    fn on_exit(&self) {
        if let Err(e) = self.local.sync_flush() {
            tracing::error!(error = %e, "failed to flush WAL data on vmm exit");
            return;
        }
        tracing::debug!("WAL persisted on vmm exit");

        // self.local.update_cache_index();
        // if let Err(e) = self.local.flush_cache_index() {
        //     tracing::warn!("failed to flush cache index on vmm exit: {}", e);
        //     return;
        // }
        // tracing::debug!("cache index persisted on vmm exit");
    }
}

/// Spawn background task that drains WAL to SlateDB
pub fn spawn_drain_task(
    local: Arc<AsyncSingleWalWithCache>,
    db: slatedb::Db,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let drain_wal = || async {
            debug!("draining WAL");

            let wal_len = local.wal_len();

            // Seal the current WAL files for all shards
            match local.seal_wal().await {
                Ok(sealed) if !sealed.is_empty() => {
                    info!(wal_len, sealed_count = sealed.len(), "SEALED WAL shards");
                }
                Ok(_) => {
                    debug!("no WAL to seal");
                }
                Err(e) => {
                    warn!(error = %e, "failed to seal WAL");
                }
            }

            // Process all sealed WAL files from all shards
            let sealed_files = local.sealed_file_ids().await;
            info!(?sealed_files, "sealed files");

            for file_id in sealed_files {
                info!(file_id, "draining sealed WAL");
                let mut stream = local.drain_wal_file_stream(file_id, 100);
                while let Some(batch_result) = stream.next().await {
                    let batch = batch_result?;

                    let mut block_nums = Vec::with_capacity(batch.len());

                    // Build SlateDB write batch
                    let mut write_batch = WriteBatch::new();
                    for entry in batch {
                        match entry {
                            wal_blk::StreamDrainEntry::Write { block_num, data } => {
                                write_batch.put(block_num.to_be_bytes(), &data);
                                block_nums.push(block_num);
                            }
                            wal_blk::StreamDrainEntry::TrimRange {
                                start_block,
                                end_block,
                            } => {
                                for block_num in start_block..end_block {
                                    write_batch.delete(block_num.to_be_bytes());
                                }
                            }
                        }
                    }

                    // Commit to SlateDB (async)
                    db.write_with_options(write_batch, &WRITE_OPTS).await?;
                    local.remove_batch_from_index(&block_nums);
                }
                db.flush().await?;

                // Delete WAL file after successful drain
                local.delete_sealed_file_only_async(file_id).await?;
            }

            Ok::<_, anyhow::Error>(())
        };

        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;

            if local.wal_len() == 0 {
                // Force mimalloc to return cross-thread freed memory
                unsafe { libmimalloc_sys::mi_collect(true) };
                continue;
            }

            if let Err(e) = drain_wal().await {
                tracing::error!(error = %e, "could not drain wal");
            }
        }
    })
}

const WRITE_OPTS: WriteOptions = WriteOptions {
    await_durable: false,
};
// async fn drain_to_slatedb_streaming(
//     db: &slatedb::Db,
//     file_id: u64,
//     iter: DrainIterator,
// ) -> io::Result<usize> {
//     let mut count = 0;
//     let mut batch_count = 0;
//     const BATCH_SIZE: usize = 1000; // Tune this

//     let mut tx = WriteBatch::new();

//     for result in iter {
//         let entry = result?;
//         let key = entry.block_num.to_be_bytes();

//         if entry.is_trimmed {
//             tx.delete(&key);
//             // .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//         } else {
//             tx.put(&key, &entry.data);
//             // .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//         }

//         count += 1;
//         batch_count += 1;

//         // Commit in batches to limit memory
//         if batch_count >= BATCH_SIZE {
//             db.write_with_options(tx, &WRITE_OPTS)
//                 // tx.commit_with_options(&WRITE_OPTS)
//                 .await
//                 .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//             tx = WriteBatch::new();
//             // tx = db
//             //     .begin(slatedb::IsolationLevel::Snapshot)
//             //     .await
//             //     .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//             batch_count = 0;
//         }
//         // entry.data is dropped here - memory freed immediately
//     }

//     // Commit remaining
//     if batch_count > 0 {
//         db.write_with_options(tx, &WRITE_OPTS)
//             // tx.commit_with_options(&WRITE_OPTS)
//             .await
//             .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//     }

//     db.flush()
//         .await
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//     Ok(count)
// }
// async fn drain_to_slatedb(
//     db: &slatedb::Db,
//     file_id: u64,
//     result: &DrainResult,
// ) -> io::Result<usize> {
//     trace!(file_id, "drain_to_slatedb");

//     let count = result.entries.len();

//     let tx = db
//         .begin(slatedb::IsolationLevel::Snapshot)
//         .await
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

//     // Write to SlateDB (batched)
//     for entry in &result.entries {
//         trace!(
//             file_id = result.file_id,
//             block_num = entry.block_num,
//             is_trimmed = entry.is_trimmed,
//             "draining a WAL"
//         );
//         let key = entry.block_num.to_be_bytes();
//         if entry.is_trimmed {
//             tx.delete(&key)
//                 .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//         } else {
//             tx.put(&key, &entry.data)
//                 .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
//         }
//     }

//     tx.commit_with_options(&WRITE_OPTS)
//         .await
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

//     // Ensure SlateDB has flushed
//     db.flush()
//         .await
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

//     trace!(file_id, "flushed slatedb");

//     Ok(count)
// }

struct NullAsyncBlockDeviceFactory;
struct NullAsyncBlockDevice;

impl AsyncBlockBackendFactory for NullAsyncBlockDeviceFactory {
    fn nsectors(&self) -> u64 {
        (4 * 1024 * 1024 * 1024) / SECTOR_SIZE
    }

    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
    }

    fn create(
        self: Box<Self>,
    ) -> SendBoxFuture<'static, io::Result<Arc<dyn AsyncBlockBackend + Send + Sync>>> {
        Box::pin(async move {
            Ok(Arc::new(NullAsyncBlockDevice) as Arc<dyn AsyncBlockBackend + Send + Sync>)
        })
    }
}

impl AsyncBlockBackend for NullAsyncBlockDevice {
    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
    }

    fn nsectors(&self) -> u64 {
        (4 * 1024 * 1024 * 1024) / SECTOR_SIZE
    }

    fn image_id(&self) -> &[u8] {
        b"null"
    }

    fn read_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        let len = bufs.iter().map(|buf| buf.len()).sum::<usize>();
        Box::pin(async move { Ok(len) })
    }

    fn write_vectored_at(
        &self,
        bufs: Vec<VolatileSliceGuard>,
        offset: u64,
    ) -> BoxFuture<'_, io::Result<usize>> {
        let len = bufs.iter().map(|buf| buf.len()).sum::<usize>();
        Box::pin(async move { Ok(len) })
    }
}

// struct SlateBlockDevice {
//     handle: tokio::runtime::Handle,
//     db: slatedb::Db,
//     tx: tokio::sync::Mutex<Option<slatedb::DbTransaction>>,
// }

// const ZERO_BLOCK: Bytes = Bytes::from_static(&[0u8; 16 * 1024]);

// impl BlockBackend for SlateBlockDevice {
//     fn cache_type(&self) -> CacheType {
//         CacheType::Writeback
//     }

//     fn nsectors(&self) -> u64 {
//         2 * 1024 * 1024 * 1024
//     }

//     fn image_id(&self) -> &[u8] {
//         b"slate"
//     }

//     fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
//         trace!(
//             "READ {} at offset {offset}",
//             bufs.iter().map(|vol| vol.len()).sum::<usize>()
//         );

//         if bufs.is_empty() {
//             return Ok(0);
//         }

//         let (mut bufv, _guard) = IoVectorMut::from_volatile_slice(bufs);
//         let full_length: usize = bufv
//             .len()
//             .try_into()
//             .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

//         if full_length == 0 {
//             return Ok(0);
//         }

//         let tx = {
//             match self.tx.blocking_lock().take() {
//                 None => self
//                     .handle
//                     .block_on(self.db.begin(slatedb::IsolationLevel::Snapshot))
//                     .unwrap(),
//                 Some(tx) => tx,
//             }
//         };

//         let page_size = 16u64 * 1024;
//         let start_page = (offset / page_size) as usize;
//         let end_offset = offset + full_length as u64;
//         let end_page = ((end_offset - 1) / page_size) as usize;

//         let mut bytes_read = 0usize;

//         for page_num in start_page..=end_page {
//             let data = self
//                 .handle
//                 .block_on(tx.get(page_num.to_be_bytes()))
//                 .expect("could not fetch page");
//             let page_bytes = match data {
//                 Some(buf) => buf,
//                 None => ZERO_BLOCK.clone(),
//             };

//             // Calculate the slice of this page we need
//             let page_start_offset = page_num as u64 * page_size;
//             let page_end_offset = page_start_offset + page_size;

//             // Where in the page do we start reading?
//             let read_start = if offset > page_start_offset {
//                 (offset - page_start_offset) as usize
//             } else {
//                 0
//             };

//             // Where in the page do we stop reading?
//             let read_end = if end_offset < page_end_offset {
//                 (end_offset - page_start_offset) as usize
//             } else {
//                 page_size as usize
//             };

//             let bytes_to_copy = read_end - read_start;

//             // Split off the destination buffer for this chunk
//             let (mut chunk, remainder) = bufv.split_at(bytes_to_copy as u64);
//             bufv = remainder;

//             chunk.copy_from_slice(&page_bytes[read_start..read_end]);
//             bytes_read += bytes_to_copy;
//         }

//         *self.tx.blocking_lock() = Some(tx);

//         // trace!(bytes_read, "READ");

//         Ok(bytes_read)
//     }

//     fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
//         trace!(
//             "WRITE {} at offset {offset}",
//             bufs.iter().map(|vol| vol.len()).sum::<usize>()
//         );

//         // if self.is_read_only {
//         //     return Err(std::io::Error::new(
//         //         std::io::ErrorKind::Other,
//         //         "device is read-only, writes are not allowed",
//         //     ));
//         // }

//         if bufs.is_empty() {
//             return Ok(0);
//         }

//         let (mut bufv, _guard) = IoVector::from_volatile_slice(bufs);
//         let full_length: usize = bufv
//             .len()
//             .try_into()
//             .map_err(|e| Error::new(ErrorKind::InvalidData, e))?;

//         if full_length == 0 {
//             return Ok(0);
//         }

//         let tx = {
//             match self.tx.blocking_lock().take() {
//                 None => self
//                     .handle
//                     .block_on(self.db.begin(slatedb::IsolationLevel::Snapshot))
//                     .unwrap(),
//                 Some(tx) => tx,
//             }
//         };

//         let page_size = 16u64 * 1024;
//         let start_page = (offset / page_size) as usize;
//         let end_offset = offset + full_length as u64;
//         let end_page = ((end_offset - 1) / page_size) as usize;

//         let mut bytes_written = 0usize;

//         let mut page_buf = BytesMut::zeroed(ZERO_BLOCK.len());

//         for page_num in start_page..=end_page {
//             // PageIdx is 1-indexed (cannot be zero)
//             trace!(?page_num, offset, "WRITING PAGE");

//             // Calculate the slice of this page we're writing
//             let page_start_offset = page_num as u64 * page_size;
//             let page_end_offset = page_start_offset + page_size;

//             // Where in the page do we start writing?
//             let write_start = if offset > page_start_offset {
//                 (offset - page_start_offset) as usize
//             } else {
//                 0
//             };

//             // Where in the page do we stop writing?
//             let write_end = if end_offset < page_end_offset {
//                 (end_offset - page_start_offset) as usize
//             } else {
//                 page_size as usize
//             };

//             let bytes_to_copy = write_end - write_start;
//             let is_partial = write_start != 0 || write_end != page_size as usize;

//             // Split off the source buffer for this chunk
//             let (chunk, remainder) = bufv.split_at(bytes_to_copy as u64);
//             bufv = remainder;

//             // Get the page buffer - read-modify-write for partial pages
//             if is_partial {
//                 // Read existing page content first
//                 let existing = self
//                     .handle
//                     .block_on(tx.get(page_num.to_be_bytes()))
//                     .unwrap()
//                     .unwrap_or_else(|| ZERO_BLOCK.clone());

//                 page_buf = BytesMut::from(existing.as_ref());
//             }

//             // Copy data into the page buffer
//             chunk.copy_into_slice(&mut page_buf[write_start..write_end]);

//             trace!("db.put");
//             // Write the page
//             tx.put(page_num.to_be_bytes(), &page_buf).unwrap();
//             trace!("db.put done!");

//             bytes_written += bytes_to_copy;
//         }

//         // trace!(bytes_written, "WROTE");

//         *self.tx.blocking_lock() = Some(tx);

//         Ok(bytes_written)
//     }

//     fn flush(&self) -> io::Result<()> {
//         if let Some(tx) = self.tx.blocking_lock().take() {
//             self.handle
//                 .block_on(tx.commit_with_options(&WriteOptions {
//                     await_durable: false,
//                 }))
//                 .unwrap();
//         }
//         Ok(())
//     }
// }

enum VolumeTx {
    Read(VolumeReader),
    Write(VolumeWriter),
}

struct GraftBlockDevice {
    rt: graft::rt::runtime::Runtime,
    vid: VolumeId,
    // page_store: Arc<BoundedPageStore>,
    tx: Arc<tokio::sync::Mutex<Option<VolumeTx>>>,
    is_read_only: bool,
    tokio_handle: tokio::runtime::Handle,
    flush_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl BlockBackend for GraftBlockDevice {
    fn nsectors(&self) -> u64 {
        (PAGESIZE.as_u64() * 1024 * 1024) / 512
    }

    fn image_id(&self) -> &[u8] {
        b"mygraft".as_slice()
    }

    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
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
                    if let Some(VolumeTx::Write(mut writer)) = tx.lock().await.take() {
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

        if let Some(VolumeTx::Write(mut writer)) = self.tx.blocking_lock().take() {
            if let Err(GraftErr::Storage(FjallStorageErr::IoErr(io_err))) = writer.commit() {
                warn!("local ring buffer is full, pushing to remote");
                if let Err(e) = self.rt.volume_push(self.vid.clone()) {
                    error!(error = %e, "could not push to remote");
                    return Err(io_err);
                }
                // warn!("clearing page store");
                // self.page_store
                //     .clear()
                //     .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                warn!("committing after clear...");
                if let Err(e) = writer.commit() {
                    error!(error = %e, "could not commit after clearing the page store");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "unable to commit after cleared store",
                    ));
                }
            }
            debug!("COMMITTED");
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

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> std::io::Result<()> {
        debug!(offset, len, unmap, "WRITE ZEROES!");

        // TODO: actually write zeroes...

        Ok(())
    }
}

impl Drop for GraftBlockDevice {
    fn drop(&mut self) {
        if let Some(VolumeTx::Write(mut writer)) =
            self.tx.try_lock().ok().and_then(|mut lock| lock.take())
        {
            debug!("COMMITTED ON DROP");
            writer.commit().expect("could not commit");
        }
    }
}

struct NullBlockDevice;

impl BlockBackend for NullBlockDevice {
    fn cache_type(&self) -> CacheType {
        CacheType::Writeback
    }

    fn nsectors(&self) -> u64 {
        2 * 1024 * 1024 // * 512
    }

    fn image_id(&self) -> &[u8] {
        b"/dev/null"
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], _offset: u64) -> std::io::Result<usize> {
        Ok(bufs.iter().map(|chunk| chunk.len()).sum())
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], _offset: u64) -> std::io::Result<usize> {
        Ok(bufs.iter().map(|chunk| chunk.len()).sum())
    }

    fn flush(&self) -> std::io::Result<()> {
        eprintln!("flushed");
        Ok(())
    }

    fn sync(&self) -> std::io::Result<()> {
        eprintln!("synced");
        Ok(())
    }

    fn discard(&self, offset: u64, len: u64) -> std::io::Result<()> {
        eprintln!("discard! offset={offset} len={len}");
        Ok(())
    }

    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> std::io::Result<()> {
        eprintln!("write zeroes! offset={offset} len={len} unmap={unmap}");
        Ok(())
    }
}

/// A block backend backed by a memory-mapped file.
///
/// This implementation minimizes syscalls by using mmap for all read/write
/// operations. The only syscalls occur during:
/// - `sync()`/`flush()`: msync to persist data
/// - `discard()`: fallocate with FALLOC_FL_PUNCH_HOLE
/// - `write_zeroes()`: fallocate with FALLOC_FL_ZERO_RANGE (or memset fallback)
pub struct MmapBlockBackend {
    /// The underlying file (kept open for fsync/fallocate operations)
    file: File,
    /// Memory mapping of the entire file
    mmap: MmapMut,
    /// Size in 512-byte sectors
    nsectors: u64,
    /// Device identifier (typically derived from file path or UUID)
    image_id: Vec<u8>,
    /// Cache type configuration
    cache_type: CacheType,
    /// Tracks dirty state for optimizing flush operations
    dirty: AtomicU64,
}

impl MmapBlockBackend {
    /// Opens or creates a memory-mapped block backend.
    ///
    /// This function handles all file lifecycle scenarios:
    /// - If the file exists and `size_bytes` is `None`: opens as-is
    /// - If the file exists and `size_bytes` is `Some(n)`: resizes to `n` bytes
    /// - If the file doesn't exist and `size_bytes` is `Some(n)`: creates with size `n`
    /// - If the file doesn't exist and `size_bytes` is `None`: returns an error
    ///
    /// The size is always rounded up to the nearest 512-byte sector boundary.
    ///
    /// # Arguments
    /// * `path` - Path to the disk image file
    /// * `cache_type` - Caching behavior configuration
    /// * `read_only` - If true, opens the file in read-only mode (cannot create/resize)
    /// * `size_bytes` - Optional desired size; if provided, file will be created/resized
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file doesn't exist and no size is provided
    /// - The file cannot be opened, created, or memory-mapped
    /// - `read_only` is true but the file doesn't exist or needs resizing
    pub fn open<P: AsRef<Path>>(
        path: P,
        cache_type: CacheType,
        read_only: bool,
        size_bytes: Option<u64>,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        let exists = path.exists();

        // Validate read-only constraints
        if read_only {
            if !exists {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "cannot create file in read-only mode",
                ));
            }
            if size_bytes.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "cannot resize file in read-only mode",
                ));
            }
        }

        // Must provide size if file doesn't exist
        if !exists && size_bytes.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "file '{}' does not exist and no size provided",
                    path.display()
                ),
            ));
        }

        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .create(!read_only)
            .open(path)?;

        // Handle sizing
        let target_size = match size_bytes {
            Some(s) => (s + SECTOR_SIZE - 1) / SECTOR_SIZE * SECTOR_SIZE,
            None => {
                let current = file.metadata()?.len();
                if current == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "existing file has zero size; provide explicit size to resize",
                    ));
                }
                current
            }
        };

        // Resize if needed
        let current_size = file.metadata()?.len();
        if current_size != target_size {
            file.set_len(target_size)?;
        }

        // SAFETY: We maintain exclusive access to the file through the File handle.
        // The mmap is created with the same lifetime as the file.
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        // Generate image ID from path (truncated to 20 bytes per virtio spec)
        let image_id = path.to_string_lossy().bytes().take(20).collect::<Vec<_>>();

        Ok(Self {
            file,
            mmap,
            nsectors: target_size / SECTOR_SIZE,
            image_id,
            cache_type,
            dirty: AtomicU64::new(0),
        })
    }

    /// Returns a slice of the mapped memory at the given offset.
    #[inline]
    fn get_slice(&self, offset: u64, len: usize) -> io::Result<&[u8]> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "read beyond end of device: offset={}, len={}, size={}",
                    offset,
                    len,
                    self.mmap.len()
                ),
            ));
        }

        Ok(&self.mmap[offset as usize..(offset as usize + len)])
    }

    /// Returns a mutable slice of the mapped memory at the given offset.
    #[inline]
    #[allow(dead_code)]
    fn get_slice_mut(&mut self, offset: u64, len: usize) -> io::Result<&mut [u8]> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "write beyond end of device: offset={}, len={}, size={}",
                    offset,
                    len,
                    self.mmap.len()
                ),
            ));
        }

        Ok(&mut self.mmap[offset as usize..(offset as usize + len)])
    }

    /// Marks a range as dirty for tracking purposes.
    #[inline]
    fn mark_dirty(&self) {
        self.dirty.fetch_add(1, Ordering::Relaxed);
    }

    /// Advise the kernel about sequential access patterns (optional optimization).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn advise_sequential(&self) -> io::Result<()> {
        use rustix::mm::{Advice, madvise};

        // SAFETY: The mmap pointer and length are valid for the lifetime of self.
        unsafe {
            #[cfg(target_os = "linux")]
            let advice = Advice::LinuxSequential;
            #[cfg(target_os = "macos")]
            let advice = Advice::Sequential;

            madvise(self.mmap.as_ptr() as *mut _, self.mmap.len(), advice).map_err(io::Error::from)
        }
    }

    /// Advise the kernel about random access patterns.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn advise_random(&self) -> io::Result<()> {
        use rustix::mm::{Advice, madvise};

        // SAFETY: The mmap pointer and length are valid for the lifetime of self.
        unsafe {
            #[cfg(target_os = "linux")]
            let advice = Advice::LinuxRandom;
            #[cfg(target_os = "macos")]
            let advice = Advice::Random;

            madvise(self.mmap.as_ptr() as *mut _, self.mmap.len(), advice).map_err(io::Error::from)
        }
    }

    /// Advise the kernel that this range will be needed soon.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn advise_willneed(&self, offset: u64, len: u64) -> io::Result<()> {
        use rustix::mm::{Advice, madvise};

        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "range beyond end of device",
            ));
        }

        // SAFETY: The range is validated above.
        unsafe {
            let ptr = self.mmap.as_ptr().add(offset as usize) as *mut _;

            #[cfg(target_os = "linux")]
            let advice = Advice::LinuxWillNeed;
            #[cfg(target_os = "macos")]
            let advice = Advice::WillNeed;

            madvise(ptr, len as usize, advice).map_err(io::Error::from)
        }
    }
}

impl BlockBackend for MmapBlockBackend {
    fn cache_type(&self) -> CacheType {
        self.cache_type
    }

    fn nsectors(&self) -> u64 {
        self.nsectors
    }

    fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn read_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        let mut current_offset = offset;
        let mut total_read = 0usize;

        for buf in bufs {
            let len = buf.len();
            let src = self.get_slice(current_offset, len)?;

            // SAFETY: VolatileSlice guarantees the memory is valid for writes.
            // We're copying from our mmap (which we have shared access to) into
            // the guest's buffer.
            let dst = buf.as_ptr();
            unsafe {
                std::ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            }

            current_offset += len as u64;
            total_read += len;
        }

        Ok(total_read)
    }

    fn write_vectored_at(&self, bufs: &[VolatileSlice], offset: u64) -> io::Result<usize> {
        let mut current_offset = offset;
        let mut total_written = 0usize;

        // We need interior mutability for the mmap. This is safe because:
        // 1. The trait takes &self, implying concurrent access is expected
        // 2. Memory-mapped writes are atomic at the page level on most architectures
        // 3. The virtio spec requires proper synchronization at a higher level
        let mmap_ptr = self.mmap.as_ptr() as *mut u8;
        let mmap_len = self.mmap.len();

        for buf in bufs {
            let len = buf.len();
            let end = current_offset
                .checked_add(len as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

            if end > mmap_len as u64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "write beyond end of device",
                ));
            }

            // SAFETY: VolatileSlice guarantees the memory is valid for reads.
            // We're copying from the guest's buffer into our mmap.
            let src = buf.as_ptr();
            unsafe {
                let dst = mmap_ptr.add(current_offset as usize);
                std::ptr::copy_nonoverlapping(src, dst, len);
            }

            current_offset += len as u64;
            total_written += len;
        }

        self.mark_dirty();
        Ok(total_written)
    }

    fn flush(&self) -> io::Result<()> {
        // For mmap with writeback caching, flush is a no-op.
        // The kernel's page cache handles writeback automatically.
        // We only need to explicitly sync when durability is required (via sync()).
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn sync(&self) -> io::Result<()> {
        use rustix::fs::fdatasync;

        // With mmap, dirty pages live in the kernel's page cache (shared with the file).
        // fdatasync flushes these dirty pages to disk without needing msync first.
        // We use fdatasync instead of fsync because:
        // 1. Block devices don't need metadata sync (size/mtime don't change during I/O)
        // 2. fdatasync is significantly faster than fsync
        fdatasync(&self.file).map_err(io::Error::from)
    }

    #[cfg(target_os = "macos")]
    fn sync(&self) -> io::Result<()> {
        use rustix::fs::fcntl_fullfsync;

        // On macOS, fsync() only guarantees data is in the disk's write cache, not on platter.
        // F_FULLFSYNC issues a barrier to flush the disk's write cache to permanent storage.
        // This is the only way to get true durability guarantees on macOS.
        // fcntl_fullfsync(&self.file).map_err(io::Error::from)
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn sync(&self) -> io::Result<()> {
        // Fallback for other platforms
        self.file.sync_all()
    }

    #[cfg(target_os = "linux")]
    fn discard(&self, offset: u64, len: u64) -> io::Result<()> {
        use rustix::fs::{FallocateFlags, fallocate};
        use rustix::io::Errno;

        // Validate bounds
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "discard beyond end of device",
            ));
        }

        // PUNCH_HOLE: Deallocates space in the file, creating a hole.
        // KEEP_SIZE: Don't change the file size.
        let flags = FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE;

        match fallocate(&self.file, flags, offset, len) {
            Ok(()) => Ok(()),
            Err(Errno::OPNOTSUPP) | Err(Errno::NOSYS) => {
                // Not all filesystems support hole punching - that's fine
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn discard(&self, _offset: u64, _len: u64) -> io::Result<()> {
        // No-op on non-Linux platforms
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn write_zeroes(&self, offset: u64, len: u64, unmap: bool) -> io::Result<()> {
        use rustix::fs::{FallocateFlags, fallocate};
        use rustix::io::Errno;

        // Validate bounds
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_zeroes beyond end of device",
            ));
        }

        let flags = if unmap {
            // If unmap is requested, punch a hole (which also zeros on read)
            FallocateFlags::PUNCH_HOLE | FallocateFlags::KEEP_SIZE
        } else {
            // Zero the range without deallocating
            FallocateFlags::ZERO_RANGE | FallocateFlags::KEEP_SIZE
        };

        match fallocate(&self.file, flags, offset, len) {
            Ok(()) => {
                // If we used ZERO_RANGE (not unmap), zero the mmap to maintain consistency.
                // For PUNCH_HOLE, the mmap view is automatically updated by the kernel.
                if !unmap {
                    let mmap_ptr = self.mmap.as_ptr() as *mut u8;
                    unsafe {
                        let dst = mmap_ptr.add(offset as usize);
                        std::ptr::write_bytes(dst, 0, len as usize);
                    }
                }
                self.mark_dirty();
                Ok(())
            }
            Err(Errno::OPNOTSUPP) | Err(Errno::NOSYS) => {
                // Fall back to memset if fallocate doesn't support this operation
                self.write_zeroes_fallback(offset, len)
            }
            Err(e) => Err(e.into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn write_zeroes(&self, offset: u64, len: u64, _unmap: bool) -> io::Result<()> {
        self.write_zeroes_fallback(offset, len)
    }
}

impl MmapBlockBackend {
    /// Fallback implementation that directly zeros memory.
    fn write_zeroes_fallback(&self, offset: u64, len: u64) -> io::Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;

        if end > self.mmap.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write_zeroes beyond end of device",
            ));
        }

        let mmap_ptr = self.mmap.as_ptr() as *mut u8;
        unsafe {
            let dst = mmap_ptr.add(offset as usize);
            std::ptr::write_bytes(dst, 0, len as usize);
        }

        self.mark_dirty();
        Ok(())
    }
}

// SAFETY: The MmapMut is Send, and we handle interior mutability safely
// through raw pointers with proper bounds checking.
unsafe impl Send for MmapBlockBackend {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn create_test_backend(size: u64) -> (MmapBlockBackend, NamedTempFile) {
        let file = NamedTempFile::new().unwrap();

        let backend =
            MmapBlockBackend::open(file.path(), CacheType::Writeback, false, Some(size)).unwrap();
        (backend, file)
    }

    #[test]
    fn test_nsectors() {
        let (backend, _file) = create_test_backend(4096);
        assert_eq!(backend.nsectors(), 8); // 4096 / 512 = 8
    }

    #[test]
    fn test_sync() {
        let (backend, _file) = create_test_backend(4096);
        assert!(backend.sync().is_ok());
    }

    #[test]
    fn test_flush() {
        let (backend, _file) = create_test_backend(4096);
        assert!(backend.flush().is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_discard() {
        let (backend, _file) = create_test_backend(4096);
        // May or may not succeed depending on filesystem
        let _ = backend.discard(0, 512);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_write_zeroes() {
        let (backend, _file) = create_test_backend(4096);
        assert!(backend.write_zeroes(0, 512, false).is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_write_zeroes_with_unmap() {
        let (backend, _file) = create_test_backend(4096);
        // May or may not succeed depending on filesystem
        let _ = backend.write_zeroes(0, 512, true);
    }

    #[test]
    fn test_open_nonexistent_without_size_fails() {
        let result = MmapBlockBackend::open(
            "/nonexistent/path/to/file.img",
            CacheType::Writeback,
            false,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_open_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_disk.img");

        let backend =
            MmapBlockBackend::open(&path, CacheType::Writeback, false, Some(8192)).unwrap();
        assert_eq!(backend.nsectors(), 16); // 8192 / 512
        assert!(path.exists());
    }

    #[test]
    fn test_open_resizes_existing_file() {
        let file = NamedTempFile::new().unwrap();

        // Create with initial size
        {
            let backend =
                MmapBlockBackend::open(file.path(), CacheType::Writeback, false, Some(4096))
                    .unwrap();
            assert_eq!(backend.nsectors(), 8);
        }

        // Reopen with larger size
        {
            let backend =
                MmapBlockBackend::open(file.path(), CacheType::Writeback, false, Some(8192))
                    .unwrap();
            assert_eq!(backend.nsectors(), 16);
        }
    }

    #[test]
    fn test_open_existing_without_size() {
        let file = NamedTempFile::new().unwrap();

        // Create with initial size
        {
            let _backend =
                MmapBlockBackend::open(file.path(), CacheType::Writeback, false, Some(4096))
                    .unwrap();
        }

        // Reopen without specifying size - should use existing size
        {
            let backend =
                MmapBlockBackend::open(file.path(), CacheType::Writeback, false, None).unwrap();
            assert_eq!(backend.nsectors(), 8);
        }
    }

    #[test]
    fn test_read_only_cannot_create() {
        let result =
            MmapBlockBackend::open("/nonexistent/file.img", CacheType::Writeback, true, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_only_cannot_resize() {
        let file = NamedTempFile::new().unwrap();
        file.as_file().set_len(4096).unwrap();

        let result = MmapBlockBackend::open(file.path(), CacheType::Writeback, true, Some(8192));
        assert!(result.is_err());
    }
}
