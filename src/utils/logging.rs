#[cfg(feature = "logging")]
use std::io::Write;

#[cfg(feature = "logging")]
pub fn init() {
    dotenv::dotenv().ok();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            let level = record.level();
            let timestamp = buf.timestamp_micros();
            let module = record.module_path().unwrap_or_default();
            let line = record.line().unwrap_or(0);

            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                timestamp,
                level,
                module,
                line,
                record.args()
            )
        })
        .init();
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        #[cfg(feature = "logging")]
        log::error!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        #[cfg(feature = "logging")]
        log::warn!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        #[cfg(feature = "logging")]
        log::info!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        #[cfg(feature = "logging")]
        log::debug!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        #[cfg(feature = "logging")]
        log::trace!($($arg)*)
    };
}

#[macro_export]
macro_rules! log_error_with_context {
    ($e:ident, $fmt:literal $(, $arg:expr)*) => {
        #[cfg(feature = "logging")]
        log::error!(
            concat!($fmt, " - Error: {:?}"),
            $($arg,)*
            $e
        );
        #[cfg(not(feature = "logging"))]
        {
            let _ = $e;
        }
    };
}

#[macro_export]
macro_rules! log_warn_with_context {
    ($e:ident, $fmt:literal $(, $arg:expr)*) => {
        #[cfg(feature = "logging")]
        log::warn!(
            concat!($fmt, " - Error: {:?}"),
            $($arg,)*
            $e
        );
        #[cfg(not(feature = "logging"))]
        {
            let _ = $e;
        }
    };
}

#[macro_export]
macro_rules! log_info_with_context {
    ($e:ident, $fmt:literal $(, $arg:expr)*) => {
        #[cfg(feature = "logging")]
        log::info!(
            concat!($fmt, " - Error: {:?}"),
            $($arg,)*
            $e
        );
        #[cfg(not(feature = "logging"))]
        {
            let _ = $e;
        }
    };
}

#[macro_export]
macro_rules! log_debug_with_context {
    ($e:ident, $fmt:literal $(, $arg:expr)*) => {
        #[cfg(feature = "logging")]
        log::warn!(
            concat!($fmt, " - Error: {:?}"),
            $($arg,)*
            $e
        );
        #[cfg(not(feature = "logging"))]
        {
            let _ = $e;
        }
    };
}

#[macro_export]
macro_rules! log_trace_with_context {
    ($e:ident, $fmt:literal $(, $arg:expr)*) => {
        #[cfg(feature = "logging")]
        log::trace!(
            concat!($fmt, " - Error: {:?}"),
            $($arg,)*
            $e
        );
        #[cfg(not(feature = "logging"))]
        {
            let _ = $e;
        }
    };
}
