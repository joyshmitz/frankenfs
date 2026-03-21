//! Symbol exchange transport for multi-host repair.
//!
//! Provides a small versioned, length-prefixed JSON protocol over TCP for
//! requesting and publishing repair symbols between hosts.

use asupersync::Cx;
use asupersync::types::Time;
use ffs_error::{FfsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_TIMEOUT_SECS: u64 = 5;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;
const DEFAULT_ACCEPT_POLL_INTERVAL_MS: u64 = 50;
const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const FRAME_PREFIX_BYTES: usize = 4;

/// Configures symbol exchange transport behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Fallback connect timeout when the `Cx` budget does not carry a tighter deadline.
    pub connect_timeout: Duration,
    /// Fallback read/write timeout when the `Cx` budget does not carry a tighter deadline.
    pub io_timeout: Duration,
    /// Maximum number of connection attempts before failing.
    pub max_retries: u32,
    /// Initial exponential backoff between retries.
    pub initial_backoff: Duration,
    /// Poll interval used by the nonblocking accept loop.
    pub accept_poll_interval: Duration,
    /// Reject frames larger than this many bytes.
    pub max_frame_bytes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            io_timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS),
            accept_poll_interval: Duration::from_millis(DEFAULT_ACCEPT_POLL_INTERVAL_MS),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

/// One transport-level symbol payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireSymbol {
    pub esi: u32,
    pub data: Vec<u8>,
}

impl From<(u32, Vec<u8>)> for WireSymbol {
    fn from((esi, data): (u32, Vec<u8>)) -> Self {
        Self { esi, data }
    }
}

impl From<WireSymbol> for (u32, Vec<u8>) {
    fn from(symbol: WireSymbol) -> Self {
        (symbol.esi, symbol.data)
    }
}

/// Versioned message envelope for forward-compatible framing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub version: u32,
    pub message: T,
}

impl<T> Envelope<T> {
    #[must_use]
    pub const fn new(message: T) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message,
        }
    }
}

/// Requests supported by the symbol exchange protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    GetSymbols {
        group_id: u32,
        generation: u64,
    },
    PutSymbols {
        group_id: u32,
        generation: u64,
        symbols: Vec<WireSymbol>,
    },
}

/// Responses supported by the symbol exchange protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Symbols {
        generation: u64,
        symbols: Vec<WireSymbol>,
    },
    Stored {
        generation: u64,
        symbol_count: u32,
    },
    NotFound,
    Stale {
        current_generation: u64,
    },
    Error {
        detail: String,
    },
}

/// Stored symbol batch for one group generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSymbols {
    pub generation: u64,
    pub symbols: Vec<(u32, Vec<u8>)>,
}

/// Lookup outcome for a `GetSymbols` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupResult {
    Found(StoredSymbols),
    NotFound,
    Stale { current_generation: u64 },
}

/// Store outcome for a `PutSymbols` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreResult {
    Stored { generation: u64, symbol_count: u32 },
    Stale { current_generation: u64 },
}

/// Backend used by the transport server.
pub trait Store: Send + Sync {
    fn get_symbols(&self, cx: &Cx, group_id: u32, min_generation: u64) -> Result<LookupResult>;

    fn put_symbols(
        &self,
        cx: &Cx,
        group_id: u32,
        generation: u64,
        symbols: &[(u32, Vec<u8>)],
    ) -> Result<StoreResult>;
}

impl<T: Store + ?Sized> Store for Arc<T> {
    fn get_symbols(&self, cx: &Cx, group_id: u32, min_generation: u64) -> Result<LookupResult> {
        self.as_ref().get_symbols(cx, group_id, min_generation)
    }

    fn put_symbols(
        &self,
        cx: &Cx,
        group_id: u32,
        generation: u64,
        symbols: &[(u32, Vec<u8>)],
    ) -> Result<StoreResult> {
        self.as_ref().put_symbols(cx, group_id, generation, symbols)
    }
}

/// In-memory symbol store for testing and local loopback verification.
#[derive(Debug, Default)]
pub struct InMemoryStore {
    groups: Mutex<BTreeMap<u32, StoredSymbols>>,
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_groups(&self) -> Result<MutexGuard<'_, BTreeMap<u32, StoredSymbols>>> {
        self.groups
            .lock()
            .map_err(|_| FfsError::RepairFailed("exchange store mutex poisoned".to_owned()))
    }
}

impl Store for InMemoryStore {
    fn get_symbols(&self, cx: &Cx, group_id: u32, min_generation: u64) -> Result<LookupResult> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let groups = self.lock_groups()?;
        let result = match groups.get(&group_id) {
            None => LookupResult::NotFound,
            Some(stored) if stored.generation < min_generation => LookupResult::Stale {
                current_generation: stored.generation,
            },
            Some(stored) => LookupResult::Found(stored.clone()),
        };
        drop(groups);
        Ok(result)
    }

    fn put_symbols(
        &self,
        cx: &Cx,
        group_id: u32,
        generation: u64,
        symbols: &[(u32, Vec<u8>)],
    ) -> Result<StoreResult> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut groups = self.lock_groups()?;
        if let Some(current) = groups.get(&group_id) {
            if current.generation > generation {
                return Ok(StoreResult::Stale {
                    current_generation: current.generation,
                });
            }
        }

        groups.insert(
            group_id,
            StoredSymbols {
                generation,
                symbols: symbols.to_vec(),
            },
        );
        drop(groups);

        Ok(StoreResult::Stored {
            generation,
            symbol_count: u32::try_from(symbols.len())
                .map_err(|_| FfsError::RepairFailed("symbol count does not fit u32".to_owned()))?,
        })
    }
}

/// TCP symbol exchange client.
#[derive(Debug, Clone)]
pub struct Client {
    remote_addr: SocketAddr,
    config: Config,
}

impl Client {
    pub fn new(remote_addr: impl ToSocketAddrs, config: Config) -> Result<Self> {
        let addr = remote_addr
            .to_socket_addrs()
            .map_err(FfsError::from)?
            .next()
            .ok_or_else(|| {
                FfsError::NotFound("no exchange socket addresses resolved".to_owned())
            })?;
        Ok(Self {
            remote_addr: addr,
            config,
        })
    }

    #[must_use]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub fn get_symbols(&self, cx: &Cx, group_id: u32, generation: u64) -> Result<LookupResult> {
        let response = self.exchange(
            cx,
            Request::GetSymbols {
                group_id,
                generation,
            },
        )?;
        lookup_from_response(response)
    }

    pub fn put_symbols(
        &self,
        cx: &Cx,
        group_id: u32,
        generation: u64,
        symbols: &[(u32, Vec<u8>)],
    ) -> Result<StoreResult> {
        let payload = symbols.iter().cloned().map(WireSymbol::from).collect();
        let response = self.exchange(
            cx,
            Request::PutSymbols {
                group_id,
                generation,
                symbols: payload,
            },
        )?;
        store_from_response(response)
    }

    fn exchange(&self, cx: &Cx, request: Request) -> Result<Response> {
        let mut stream = retry_with_backoff(cx, &self.config, |attempt| {
            let timeout = effective_timeout(cx, self.config.connect_timeout)?;
            TcpStream::connect_timeout(&self.remote_addr, timeout).map_err(|err| {
                FfsError::RepairFailed(format!(
                    "exchange connect attempt {} to {} failed: {err}",
                    attempt + 1,
                    self.remote_addr
                ))
            })
        })?;

        configure_stream_timeouts(cx, &mut stream, self.config.io_timeout)?;
        stream.set_nodelay(true).map_err(FfsError::from)?;
        write_envelope(
            cx,
            &mut stream,
            &Envelope::new(request),
            self.config.max_frame_bytes,
        )?;
        let response: Envelope<Response> =
            read_envelope(cx, &mut stream, self.config.max_frame_bytes)?;
        validate_version(response.version)?;
        Ok(response.message)
    }
}

/// TCP symbol exchange server.
#[derive(Debug)]
pub struct Server<S> {
    listener: TcpListener,
    store: S,
    config: Config,
}

impl<S: Store> Server<S> {
    pub fn bind(bind_addr: impl ToSocketAddrs, store: S, config: Config) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr).map_err(FfsError::from)?;
        Self::from_listener(listener, store, config)
    }

    pub fn from_listener(listener: TcpListener, store: S, config: Config) -> Result<Self> {
        listener.set_nonblocking(true).map_err(FfsError::from)?;
        Ok(Self {
            listener,
            store,
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(FfsError::from)
    }

    /// Accept and handle a single connection.
    pub fn serve_once(&self, cx: &Cx) -> Result<()> {
        let (mut stream, peer_addr) = self.accept(cx)?;
        configure_stream_timeouts(cx, &mut stream, self.config.io_timeout)?;
        stream.set_nodelay(true).map_err(FfsError::from)?;
        match self.handle_connection(cx, &mut stream) {
            Ok(()) => Ok(()),
            Err(FfsError::Cancelled) => Err(FfsError::Cancelled),
            Err(err) => {
                warn!(
                    target: "ffs::repair::exchange",
                    peer = %peer_addr,
                    error = %err,
                    "exchange_connection_failed"
                );
                Ok(())
            }
        }
    }

    /// Run until the caller cancels the `Cx`.
    pub fn serve_until_cancelled(&self, cx: &Cx) -> Result<()> {
        loop {
            match self.serve_once(cx) {
                Ok(()) => {}
                Err(FfsError::Cancelled) => return Ok(()),
                Err(err) => return Err(err),
            }
        }
    }

    fn accept(&self, cx: &Cx) -> Result<(TcpStream, SocketAddr)> {
        loop {
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            if budget_expired(cx) {
                return Err(FfsError::Cancelled);
            }

            match self.listener.accept() {
                Ok(pair) => return Ok(pair),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    sleep_with_budget(cx, self.config.accept_poll_interval)?;
                }
                Err(err) => return Err(FfsError::from(err)),
            }
        }
    }

    fn handle_connection(&self, cx: &Cx, stream: &mut TcpStream) -> Result<()> {
        let request: Envelope<Request> = read_envelope(cx, stream, self.config.max_frame_bytes)?;
        let response = match validate_version(request.version) {
            Ok(()) => self.dispatch(cx, request.message),
            Err(err) => Response::Error {
                detail: err.to_string(),
            },
        };
        write_envelope(
            cx,
            stream,
            &Envelope::new(response),
            self.config.max_frame_bytes,
        )
    }

    fn dispatch(&self, cx: &Cx, request: Request) -> Response {
        let outcome = match request {
            Request::GetSymbols {
                group_id,
                generation,
            } => self
                .store
                .get_symbols(cx, group_id, generation)
                .map(response_for_lookup),
            Request::PutSymbols {
                group_id,
                generation,
                symbols,
            } => {
                let tuples = symbols.into_iter().map(Into::into).collect::<Vec<_>>();
                self.store
                    .put_symbols(cx, group_id, generation, &tuples)
                    .map(|result| response_for_store(&result))
            }
        };

        outcome.unwrap_or_else(|err| Response::Error {
            detail: err.to_string(),
        })
    }
}

fn response_for_lookup(result: LookupResult) -> Response {
    match result {
        LookupResult::Found(found) => Response::Symbols {
            generation: found.generation,
            symbols: found.symbols.into_iter().map(WireSymbol::from).collect(),
        },
        LookupResult::NotFound => Response::NotFound,
        LookupResult::Stale { current_generation } => Response::Stale { current_generation },
    }
}

fn response_for_store(result: &StoreResult) -> Response {
    match result {
        StoreResult::Stored {
            generation,
            symbol_count,
        } => Response::Stored {
            generation: *generation,
            symbol_count: *symbol_count,
        },
        StoreResult::Stale { current_generation } => Response::Stale {
            current_generation: *current_generation,
        },
    }
}

fn lookup_from_response(response: Response) -> Result<LookupResult> {
    match response {
        Response::Symbols {
            generation,
            symbols,
        } => Ok(LookupResult::Found(StoredSymbols {
            generation,
            symbols: symbols.into_iter().map(Into::into).collect(),
        })),
        Response::NotFound => Ok(LookupResult::NotFound),
        Response::Stale { current_generation } => Ok(LookupResult::Stale { current_generation }),
        Response::Error { detail } => Err(FfsError::RepairFailed(detail)),
        Response::Stored { .. } => Err(FfsError::RepairFailed(
            "unexpected store response for get_symbols".to_owned(),
        )),
    }
}

fn store_from_response(response: Response) -> Result<StoreResult> {
    match response {
        Response::Stored {
            generation,
            symbol_count,
        } => Ok(StoreResult::Stored {
            generation,
            symbol_count,
        }),
        Response::Stale { current_generation } => Ok(StoreResult::Stale { current_generation }),
        Response::Error { detail } => Err(FfsError::RepairFailed(detail)),
        Response::Symbols { .. } => Err(FfsError::RepairFailed(
            "unexpected symbol response for put_symbols".to_owned(),
        )),
        Response::NotFound => Err(FfsError::RepairFailed(
            "unexpected not_found response for put_symbols".to_owned(),
        )),
    }
}

fn validate_version(version: u32) -> Result<()> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(FfsError::RepairFailed(format!(
            "unsupported exchange protocol version {version}"
        )))
    }
}

fn current_time() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
        });
    Time::from_nanos(nanos)
}

fn budget_expired(cx: &Cx) -> bool {
    cx.budget().is_past_deadline(current_time())
}

fn effective_timeout(cx: &Cx, fallback: Duration) -> Result<Duration> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let budget = cx.budget();
    let now = current_time();
    if budget.is_past_deadline(now) {
        return Err(FfsError::Cancelled);
    }

    let timeout = budget
        .remaining_time(now)
        .map_or(fallback, |remaining| remaining.min(fallback));

    if timeout.is_zero() {
        return Err(FfsError::Cancelled);
    }

    Ok(timeout)
}

fn configure_stream_timeouts(cx: &Cx, stream: &TcpStream, fallback: Duration) -> Result<()> {
    let timeout = effective_timeout(cx, fallback)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(FfsError::from)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(FfsError::from)?;
    Ok(())
}

fn sleep_with_budget(cx: &Cx, fallback: Duration) -> Result<()> {
    let sleep = effective_timeout(cx, fallback)?;
    thread::sleep(sleep);
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}

fn retry_with_backoff<T, F>(cx: &Cx, config: &Config, mut op: F) -> Result<T>
where
    F: FnMut(u32) -> Result<T>,
{
    let attempts = config.max_retries.max(1);
    let mut backoff = config.initial_backoff;
    for attempt in 0..attempts {
        match op(attempt) {
            Ok(value) => return Ok(value),
            Err(err) if attempt + 1 < attempts => {
                sleep_with_budget(cx, backoff)?;
                backoff = backoff.saturating_mul(2);
                let _ = err;
            }
            Err(err) => return Err(err),
        }
    }

    Err(FfsError::RepairFailed(
        "retry loop exited without a result".to_owned(),
    ))
}

fn write_envelope<T: Serialize>(
    cx: &Cx,
    writer: &mut impl Write,
    envelope: &Envelope<T>,
    max_frame_bytes: usize,
) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let payload = serde_json::to_vec(envelope)
        .map_err(|err| FfsError::RepairFailed(format!("exchange serialize failed: {err}")))?;
    if payload.len() > max_frame_bytes {
        return Err(FfsError::RepairFailed(format!(
            "exchange frame exceeds limit: len={} max={max_frame_bytes}",
            payload.len()
        )));
    }

    let len = u32::try_from(payload.len())
        .map_err(|_| FfsError::RepairFailed("exchange frame length does not fit u32".to_owned()))?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(FfsError::from)?;
    writer.write_all(&payload).map_err(FfsError::from)?;
    writer.flush().map_err(FfsError::from)?;
    Ok(())
}

fn read_envelope<T: for<'de> Deserialize<'de>>(
    cx: &Cx,
    reader: &mut impl Read,
    max_frame_bytes: usize,
) -> Result<Envelope<T>> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
    let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
    reader.read_exact(&mut prefix).map_err(FfsError::from)?;
    let payload_len = usize::try_from(u32::from_le_bytes(prefix)).map_err(|_| {
        FfsError::RepairFailed("exchange frame length does not fit usize".to_owned())
    })?;
    if payload_len > max_frame_bytes {
        return Err(FfsError::RepairFailed(format!(
            "exchange frame exceeds limit: len={payload_len} max={max_frame_bytes}"
        )));
    }

    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload).map_err(FfsError::from)?;
    serde_json::from_slice(&payload)
        .map_err(|err| FfsError::RepairFailed(format!("exchange decode failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::{
        Client, Config, Envelope, InMemoryStore, LookupResult, Request, Response, Server, Store,
        StoreResult, StoredSymbols, lookup_from_response, read_envelope, response_for_lookup,
        retry_with_backoff, store_from_response, write_envelope,
    };
    use asupersync::{Budget, Cx};
    use std::io::Cursor;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn deadline_after(duration: Duration) -> Budget {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch");
        let deadline_nanos = now
            .as_nanos()
            .saturating_add(duration.as_nanos())
            .min(u128::from(u64::MAX));
        Budget::new().with_deadline(asupersync::types::Time::from_nanos(
            u64::try_from(deadline_nanos).expect("deadline fits u64"),
        ))
    }

    #[test]
    fn framing_round_trip_preserves_payload() {
        let cx = Cx::for_testing();
        let request = Envelope::new(Request::GetSymbols {
            group_id: 7,
            generation: 42,
        });
        let mut buffer = Cursor::new(Vec::new());
        write_envelope(&cx, &mut buffer, &request, 4096).expect("write frame");

        buffer.set_position(0);
        let decoded: Envelope<Request> = read_envelope(&cx, &mut buffer, 4096).expect("read frame");
        assert_eq!(decoded, request);
    }

    #[test]
    fn response_mapping_round_trip_preserves_symbols() {
        let symbols = vec![(9, vec![1, 2, 3]), (10, vec![4, 5, 6])];
        let lookup = LookupResult::Found(StoredSymbols {
            generation: 8,
            symbols: symbols.clone(),
        });
        let response = response_for_lookup(lookup);
        let decoded = lookup_from_response(response).expect("lookup");
        assert_eq!(
            decoded,
            LookupResult::Found(StoredSymbols {
                generation: 8,
                symbols,
            })
        );
    }

    #[test]
    fn store_mapping_round_trip_preserves_generation() {
        let decoded = store_from_response(Response::Stored {
            generation: 19,
            symbol_count: 4,
        })
        .expect("store result");
        assert_eq!(
            decoded,
            StoreResult::Stored {
                generation: 19,
                symbol_count: 4,
            }
        );
    }

    #[test]
    fn retry_with_backoff_retries_until_success() {
        let cx = Cx::for_testing();
        let config = Config {
            initial_backoff: Duration::from_millis(1),
            max_retries: 4,
            ..Config::default()
        };
        let mut attempts = 0_u32;
        let result = retry_with_backoff(&cx, &config, |_| {
            attempts = attempts.saturating_add(1);
            if attempts < 3 {
                Err(ffs_error::FfsError::RepairFailed("transient".to_owned()))
            } else {
                Ok("ok")
            }
        })
        .expect("eventual success");

        assert_eq!(result, "ok");
        assert_eq!(attempts, 3);
    }

    #[test]
    fn loopback_exchange_e2e() {
        let store = Arc::new(InMemoryStore::new());
        let seed_symbols = vec![(4, vec![0xaa, 0xbb]), (5, vec![0xcc, 0xdd])];
        let seed_cx = Cx::for_testing();
        store
            .put_symbols(&seed_cx, 12, 7, &seed_symbols)
            .expect("seed store");

        let server_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let server_addr = server_listener.local_addr().expect("listener addr");
        let server_store = Arc::clone(&store);

        let server_thread = thread::spawn(move || {
            let server = Server::from_listener(server_listener, server_store, Config::default())
                .expect("server from listener");
            let server_cx = Cx::for_testing_with_budget(deadline_after(Duration::from_secs(2)));
            server.serve_once(&server_cx).expect("serve get");
            server.serve_once(&server_cx).expect("serve put");
        });

        let client = Client::new(server_addr, Config::default()).expect("client");
        let client_cx = Cx::for_testing_with_budget(deadline_after(Duration::from_secs(2)));

        let fetched = client.get_symbols(&client_cx, 12, 7).expect("get loopback");
        assert_eq!(
            fetched,
            LookupResult::Found(StoredSymbols {
                generation: 7,
                symbols: seed_symbols.clone(),
            })
        );

        let pushed_symbols = vec![(6, vec![0x10, 0x20, 0x30])];
        let store_result = client
            .put_symbols(&client_cx, 99, 3, &pushed_symbols)
            .expect("put loopback");
        assert_eq!(
            store_result,
            StoreResult::Stored {
                generation: 3,
                symbol_count: 1,
            }
        );

        server_thread.join().expect("server thread join");

        let verify = store
            .get_symbols(&client_cx, 99, 3)
            .expect("verify loopback store");
        assert_eq!(
            verify,
            LookupResult::Found(StoredSymbols {
                generation: 3,
                symbols: pushed_symbols,
            })
        );
    }

    #[test]
    fn client_respects_expired_deadline_before_connect() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let client = Client::new(addr, Config::default()).expect("client");
        let past_deadline = Budget::new().with_deadline(asupersync::types::Time::ZERO);
        let cx = Cx::for_testing_with_budget(past_deadline);

        let err = client
            .get_symbols(&cx, 1, 1)
            .expect_err("expired deadline should cancel before connect");
        assert!(matches!(err, ffs_error::FfsError::Cancelled));
    }

    #[test]
    fn server_continues_after_malformed_client_connection() {
        let store = Arc::new(InMemoryStore::new());
        let seed_cx = Cx::for_testing();
        store
            .put_symbols(&seed_cx, 7, 3, &[(1, vec![0xaa])])
            .expect("seed store");

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let server_store = Arc::clone(&store);
        let server_thread = thread::spawn(move || {
            let server =
                Server::from_listener(listener, server_store, Config::default()).expect("server");
            let cx = Cx::for_testing_with_budget(deadline_after(Duration::from_secs(2)));
            server
                .serve_until_cancelled(&cx)
                .expect("server should survive malformed client");
        });

        let mut malformed = std::net::TcpStream::connect(addr).expect("connect malformed client");
        malformed
            .write_all(&1_u32.to_le_bytes())
            .expect("write malformed prefix");
        malformed.write_all(b"{").expect("write malformed payload");
        drop(malformed);

        thread::sleep(Duration::from_millis(100));

        let client = Client::new(addr, Config::default()).expect("client");
        let cx = Cx::for_testing_with_budget(deadline_after(Duration::from_secs(2)));
        let fetched = client
            .get_symbols(&cx, 7, 3)
            .expect("server should still answer valid requests");
        assert_eq!(
            fetched,
            LookupResult::Found(StoredSymbols {
                generation: 3,
                symbols: vec![(1, vec![0xaa])],
            })
        );

        server_thread.join().expect("server thread join");
    }
}
