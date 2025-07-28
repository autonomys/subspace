//! Miscellaneous utilities for networking.

pub(crate) mod key_with_distance;
pub mod multihash;
pub mod piece_provider;
pub(crate) mod rate_limiter;

use event_listener_primitives::Bag;
use futures::channel::oneshot;
use futures::channel::oneshot::Canceled;
use futures::future::{Either, FusedFuture};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::future::Future;
use std::ops::Deref;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{io, thread};
use tokio::runtime::Handle;
use tokio::task;
use tracing::{debug, warn};

const NETWORKING_REGISTRY_PREFIX: &str = "subspace";

/// Metrics for Subspace networking
pub struct SubspaceMetrics {
    established_connections: Gauge,
}

impl SubspaceMetrics {
    /// Constructor
    pub fn new(registry: &mut Registry) -> Self {
        let sub_registry = registry.sub_registry_with_prefix(NETWORKING_REGISTRY_PREFIX);

        let gauge = Gauge::default();
        sub_registry.register(
            "established_connections",
            "The current number of established connections",
            gauge.clone(),
        );

        Self {
            established_connections: gauge,
        }
    }

    pub(crate) fn inc_established_connections(&self) {
        self.established_connections.inc();
    }

    pub(crate) fn dec_established_connections(&self) {
        self.established_connections.dec();
    }
}

/// Joins async join handle on drop.
/// This future is fused, and will return `Poll::Pending` if polled after completion.
#[derive(Debug)]
pub struct AsyncJoinOnDrop<T> {
    handle: Option<task::JoinHandle<T>>,
    abort_on_drop: bool,
}

impl<T> Drop for AsyncJoinOnDrop<T> {
    #[inline]
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.abort_on_drop {
                handle.abort();
            }

            if !handle.is_finished() {
                task::block_in_place(move || {
                    let _ = Handle::current().block_on(handle);
                });
            }
        }
    }
}

impl<T> AsyncJoinOnDrop<T> {
    /// Create new instance.
    #[inline]
    pub fn new(handle: task::JoinHandle<T>, abort_on_drop: bool) -> Self {
        Self {
            handle: Some(handle),
            abort_on_drop,
        }
    }
}

impl<T> FusedFuture for AsyncJoinOnDrop<T> {
    fn is_terminated(&self) -> bool {
        self.handle.is_none()
    }
}

impl<T> Future for AsyncJoinOnDrop<T> {
    type Output = Result<T, task::JoinError>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Some(handle) = self.handle.as_mut() {
            let result = Pin::new(handle).poll(cx);
            if result.is_ready() {
                // Drop the handle, because if we poll it again, it will panic.
                self.handle.take();
            }
            result
        } else {
            Poll::Pending
        }
    }
}

/// Joins synchronous join handle on drop
pub(crate) struct JoinOnDrop(Option<thread::JoinHandle<()>>);

impl Drop for JoinOnDrop {
    #[inline]
    fn drop(&mut self) {
        self.0
            .take()
            .expect("Always called exactly once; qed")
            .join()
            .expect("Panic if background thread panicked");
    }
}

impl JoinOnDrop {
    // Create new instance
    #[inline]
    pub(crate) fn new(handle: thread::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Deref for JoinOnDrop {
    type Target = thread::JoinHandle<()>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("Only dropped in Drop impl; qed")
    }
}

/// This test is successful only for global IP addresses and DNS names.
pub(crate) fn is_global_address_or_dns(addr: &Multiaddr) -> bool {
    match addr.iter().next() {
        Some(Protocol::Ip4(ip)) => ip.is_global(),
        Some(Protocol::Ip6(ip)) => ip.is_global(),
        Some(Protocol::Dns(_)) | Some(Protocol::Dns4(_)) | Some(Protocol::Dns6(_)) => true,
        _ => false,
    }
}

/// Convenience alias for peer ID and its multiaddresses.
pub type PeerAddress = (PeerId, Multiaddr);

/// Helper function. Converts multiaddresses to a tuple with peer ID removing the peer Id suffix.
/// It logs incorrect multiaddresses.
pub fn strip_peer_id(addresses: Vec<Multiaddr>) -> Vec<PeerAddress> {
    addresses
        .into_iter()
        .filter_map(|multiaddr| {
            let mut modified_multiaddr = multiaddr.clone();

            let peer_id: Option<PeerId> = modified_multiaddr.pop().and_then(|protocol| {
                if let Protocol::P2p(peer_id) = protocol {
                    Some(peer_id)
                } else {
                    None
                }
            });

            if let Some(peer_id) = peer_id {
                Some((peer_id, modified_multiaddr))
            } else {
                warn!(%multiaddr, "Incorrect multiaddr provided.");

                None
            }
        })
        .collect()
}

pub(crate) type HandlerFn<A> = Arc<dyn Fn(&A) + Send + Sync + 'static>;
pub(crate) type Handler<A> = Bag<HandlerFn<A>, A>;

/// Runs future on a dedicated thread with the specified name, will block on drop until background
/// thread with future is stopped too, ensuring nothing is left in memory
pub fn run_future_in_dedicated_thread<CreateFut, Fut, T>(
    create_future: CreateFut,
    thread_name: String,
) -> io::Result<impl Future<Output = Result<T, Canceled>> + Send>
where
    CreateFut: (FnOnce() -> Fut) + Send + 'static,
    Fut: Future<Output = T> + 'static,
    T: Send + 'static,
{
    let (drop_tx, drop_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel();
    let handle = Handle::current();
    let join_handle = thread::Builder::new().name(thread_name).spawn(move || {
        let _tokio_handle_guard = handle.enter();

        let future = pin!(create_future());

        let result = match handle.block_on(futures::future::select(future, drop_rx)) {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                // Outer future was dropped, nothing left to do
                return;
            }
        };
        if let Err(_error) = result_tx.send(result) {
            debug!(
                thread_name = ?thread::current().name(),
                "Future finished, but receiver was already dropped",
            );
        }
    })?;
    // Ensure thread will not be left hanging forever
    let join_on_drop = JoinOnDrop::new(join_handle);

    Ok(async move {
        let result = result_rx.await;
        drop(drop_tx);
        drop(join_on_drop);
        result
    })
}
