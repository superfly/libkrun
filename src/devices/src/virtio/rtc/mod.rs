mod device;
mod event_handler;

pub use self::defs::uapi::VIRTIO_ID_CLOCK as TYPE_RTC;
pub use self::device::Rtc;

mod defs {
    pub const RTC_DEV_ID: &str = "virtio_rtc";
    pub const NUM_QUEUES: usize = 1;
    pub const QUEUE_SIZES: &[u16] = &[64; NUM_QUEUES];

    pub mod uapi {
        pub const VIRTIO_F_VERSION_1: u32 = 32;
        pub const VIRTIO_ID_CLOCK: u32 = 17;

        // Request types
        pub const VIRTIO_RTC_REQ_READ: u16 = 0x0001;
        pub const VIRTIO_RTC_REQ_READ_CROSS: u16 = 0x0002;
        pub const VIRTIO_RTC_REQ_CFG: u16 = 0x1000;
        pub const VIRTIO_RTC_REQ_CLOCK_CAP: u16 = 0x1001;
        pub const VIRTIO_RTC_REQ_CROSS_CAP: u16 = 0x1002;

        // Status codes
        pub const VIRTIO_RTC_S_OK: u8 = 0;
        #[allow(dead_code)]
        pub const VIRTIO_RTC_S_EOPNOTSUPP: u8 = 2;
        #[allow(dead_code)]
        pub const VIRTIO_RTC_S_ENODEV: u8 = 3;
        pub const VIRTIO_RTC_S_EINVAL: u8 = 4;
        #[allow(dead_code)]
        pub const VIRTIO_RTC_S_EIO: u8 = 5;

        // Clock types
        pub const VIRTIO_RTC_CLOCK_UTC: u16 = 0;
        #[allow(dead_code)]
        pub const VIRTIO_RTC_CLOCK_TAI: u16 = 1;
        #[allow(dead_code)]
        pub const VIRTIO_RTC_CLOCK_MONOTONIC: u16 = 2;

        // Clock flags
        pub const VIRTIO_RTC_FLAG_LEAP_SECOND_INFO: u8 = 1 << 0;

        // Counter types for cross-timestamping (currently disabled)
        #[allow(dead_code)]
        #[cfg(target_arch = "aarch64")]
        pub const VIRTIO_RTC_COUNTER_ARM_VCT: u16 = 0;
        #[allow(dead_code)]
        #[cfg(target_arch = "x86_64")]
        pub const VIRTIO_RTC_COUNTER_X86_TSC: u16 = 1;
    }
}

#[derive(Debug)]
pub enum RtcError {
    /// Failed to create event fd.
    EventFd(std::io::Error),
}

type Result<T> = std::result::Result<T, RtcError>;
