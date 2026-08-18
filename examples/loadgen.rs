//! Closed-loop HTTP load generator.
//!
//! This is the harness that actually answers "did throughput change". The
//! microbenchmarks in `benches/hot_path.rs` measure the latency of a code
//! region; throughput at saturation is a different quantity, and a change can
//! improve one while hurting the other - typically by trading per-call work for
//! cross-core contention.
//!
//! It speaks HTTP/1.1 over a socket and knows nothing about the crate, which is
//! the point: the same binary measures any build of the server, including the
//! one on `master`. That is what makes a genuine before/after possible.
//!
//! ```text
//! # baseline
//! git stash && cargo build --release && ./target/release/server-rs /srv/data &
//! cargo run --release --example loadgen -- --target '/get_dir_info?path=big'
//!
//! # candidate
//! git stash pop && cargo build --release && ./target/release/server-rs /srv/data &
//! cargo run --release --example loadgen -- --target '/get_dir_info?path=big'
//! ```
//!
//! Two things to watch, or the numbers are fiction:
//!
//! * If the generator saturates its own CPU first, you are measuring the
//!   generator. Check with `top`; drop `--connections` or pin the two processes
//!   to disjoint cores with `taskset`.
//! * Closed-loop generators under-report the tail once the server is saturated,
//!   because offered load backs off with latency. Compare medians across runs,
//!   and treat the tail as indicative only.

use std::io::ErrorKind;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Latency buckets, one microsecond each. Anything slower lands in the last
/// bucket, which is reported so a saturated run is obvious.
const BUCKETS: usize = 1 << 16;

struct Options {
    address: String,
    target: String,
    connections: usize,
    duration: std::time::Duration,
    warmup: std::time::Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:8080".to_owned(),
            target: "/get_dir_info?path=".to_owned(),
            connections: 64,
            duration: std::time::Duration::from_secs(10),
            warmup: std::time::Duration::from_secs(2),
        }
    }
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = std::env::args().skip(1);

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--address" => options.address = value_for(&flag, &mut args)?,
            "--target" => options.target = value_for(&flag, &mut args)?,
            "--connections" => {
                options.connections = value_for(&flag, &mut args)?.parse().map_err(|_| "bad --connections")?;
            }
            "--duration" => {
                let seconds = value_for(&flag, &mut args)?.parse().map_err(|_| "bad --duration")?;
                options.duration = std::time::Duration::from_secs(seconds);
            }
            "--warmup" => {
                let seconds = value_for(&flag, &mut args)?.parse().map_err(|_| "bad --warmup")?;
                options.warmup = std::time::Duration::from_secs(seconds);
            }
            "--help" | "-h" => return Err(usage()),
            other => return Err(format!("unknown flag {other}\n\n{}", usage())),
        }
    }

    if options.connections == 0 {
        return Err("--connections must be at least 1".to_owned());
    }

    Ok(options)
}

fn value_for(flag: &str, args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

fn usage() -> String {
    "usage: loadgen [--address HOST:PORT] [--target PATH] [--connections N] \
     [--duration SECS] [--warmup SECS]"
        .to_owned()
}

/// One keep-alive connection, with a buffer that carries any bytes of the next
/// response that arrived early.
struct Connection {
    stream: tokio::net::TcpStream,
    buffer: Vec<u8>,
}

impl Connection {
    async fn open(address: &str) -> std::io::Result<Self> {
        let stream = tokio::net::TcpStream::connect(address).await?;

        // Without this, small requests sit in the kernel waiting for a
        // coalescing partner and we would be benchmarking Nagle's algorithm.
        stream.set_nodelay(true)?;

        Ok(Self {
            stream,
            buffer: Vec::with_capacity(64 * 1024),
        })
    }

    /// Send one request and consume its whole response. Returns the response
    /// size in bytes.
    async fn round_trip(&mut self, request: &[u8]) -> std::io::Result<usize> {
        self.stream.write_all(request).await?;

        let head = loop {
            if let Some(position) = find(&self.buffer, b"\r\n\r\n") {
                break position + 4;
            }
            self.fill().await?;
        };

        if !self.buffer.starts_with(b"HTTP/1.1 200") {
            let status = String::from_utf8_lossy(&self.buffer[..head.min(64)]).into_owned();
            return Err(std::io::Error::other(format!("unexpected status: {status}")));
        }

        let length = content_length(&self.buffer[..head])
            .ok_or_else(|| std::io::Error::other("response had no Content-Length"))?;

        let total = head + length;
        while self.buffer.len() < total {
            self.fill().await?;
        }

        self.buffer.drain(..total);

        Ok(total)
    }

    /// Reads straight into `self.buffer`'s own spare capacity - no
    /// intermediate array, so nothing sized to a read chunk sits in this
    /// future's state across the `.await`.
    async fn fill(&mut self) -> std::io::Result<()> {
        let read = self.stream.read_buf(&mut self.buffer).await?;

        if read == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "server closed the connection",
            ));
        }

        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(head: &[u8]) -> Option<usize> {
    const NAME: &[u8] = b"content-length:";

    for line in head.split(|byte| *byte == b'\n') {
        if line.len() > NAME.len() && line[..NAME.len()].eq_ignore_ascii_case(NAME) {
            return std::str::from_utf8(&line[NAME.len()..])
                .ok()?
                .trim()
                .parse()
                .ok();
        }
    }

    None
}

#[derive(Default)]
struct Samples {
    completed: u64,
    bytes: u64,
    errors: u64,
    histogram: Vec<u32>,
}

impl Samples {
    fn new() -> Self {
        Self {
            histogram: vec![0; BUCKETS],
            ..Self::default()
        }
    }

    fn record(&mut self, latency: std::time::Duration, bytes: usize) {
        self.completed += 1;
        self.bytes += u64::try_from(bytes).unwrap_or(0);

        let micros = usize::try_from(latency.as_micros()).unwrap_or(usize::MAX);
        self.histogram[micros.min(BUCKETS - 1)] += 1;
    }

    fn merge(&mut self, other: &Self) {
        self.completed += other.completed;
        self.bytes += other.bytes;
        self.errors += other.errors;

        for (slot, count) in self.histogram.iter_mut().zip(&other.histogram) {
            *slot += *count;
        }
    }

    /// Microseconds below which `fraction` of samples fall.
    fn percentile(&self, fraction: f64) -> usize {
        // `fraction` is always in `[0, 1]`, so the product is non-negative and
        // truncating it towards zero is exactly what a "count below this
        // point" threshold wants. `completed` would need to exceed 2^52
        // requests before `as f64` lost precision - many years of continuous
        // load at any plausible rate.
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation
        )]
        let wanted = (self.completed as f64 * fraction) as u64;

        let mut seen = 0u64;
        for (micros, count) in self.histogram.iter().enumerate() {
            seen += u64::from(*count);
            if seen >= wanted {
                return micros;
            }
        }

        BUCKETS - 1
    }
}

async fn drive(
    address: String,
    request: Vec<u8>,
    record_from: std::time::Instant,
    stop_at: std::time::Instant,
) -> Samples {
    let mut samples = Samples::new();

    let mut connection = match Connection::open(&address).await {
        Ok(connection) => connection,
        Err(e) => {
            eprintln!("connect failed: {e}");
            samples.errors += 1;
            return samples;
        }
    };

    while std::time::Instant::now() < stop_at {
        let started = std::time::Instant::now();

        match connection.round_trip(&request).await {
            Ok(bytes) => {
                // Warmup requests still run; they just are not counted.
                if started >= record_from {
                    samples.record(started.elapsed(), bytes);
                }
            }
            Err(e) => {
                samples.errors += 1;

                if samples.errors <= 3 {
                    eprintln!("request failed: {e}");
                }

                // Reconnect rather than spin on a dead socket.
                match Connection::open(&address).await {
                    Ok(fresh) => connection = fresh,
                    Err(_) => break,
                }
            }
        }
    }

    samples
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };

    let host = options.address.clone();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n",
        options.target
    )
    .into_bytes();

    println!(
        "load: {} connections against http://{}{} for {:?} (after {:?} warmup)",
        options.connections, options.address, options.target, options.duration, options.warmup
    );

    let now = std::time::Instant::now();
    let record_from = now + options.warmup;
    let stop_at = record_from + options.duration;

    let workers: Vec<_> = (0..options.connections)
        .map(|_| {
            tokio::spawn(drive(
                options.address.clone(),
                request.clone(),
                record_from,
                stop_at,
            ))
        })
        .collect();

    let mut total = Samples::new();
    for worker in workers {
        total.merge(&worker.await?);
    }

    report(&total, options.duration);

    Ok(())
}

fn report(samples: &Samples, window: std::time::Duration) {
    let seconds = window.as_secs_f64();

    #[allow(clippy::cast_precision_loss)]
    let requests_per_second = samples.completed as f64 / seconds;
    #[allow(clippy::cast_precision_loss)]
    let megabytes_per_second = samples.bytes as f64 / seconds / (1024.0 * 1024.0);

    println!("\ncompleted     {}", samples.completed);
    println!("errors        {}", samples.errors);
    println!("throughput    {requests_per_second:.0} req/s");
    println!("bandwidth     {megabytes_per_second:.1} MiB/s");
    println!("latency p50   {} us", samples.percentile(0.50));
    println!("latency p90   {} us", samples.percentile(0.90));
    println!("latency p99   {} us", samples.percentile(0.99));
    println!("latency p99.9 {} us", samples.percentile(0.999));

    let overflow = samples.histogram[BUCKETS - 1];
    if overflow > 0 {
        println!("\n{overflow} samples exceeded {BUCKETS} us and are clamped");
    }

    if samples.errors > 0 {
        println!("\nerrors were recorded - the throughput number is not trustworthy");
    }
}
