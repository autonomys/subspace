//! Utility module for handling Subspace client notifications.

use parking_lot::Mutex;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};
use std::fmt;
use std::sync::Arc;

// Stream of notifications returned when subscribing.
type NotificationStream<T> = TracingUnboundedReceiver<T>;

// Collection of channel sending endpoints shared with the receiver side so they can register
// themselves.
type SharedNotificationSenders<T> = Arc<Mutex<Vec<TracingUnboundedSender<T>>>>;

/// The sending half of the Subspace notification channel(s).
#[derive(Clone)]
pub(crate) struct SubspaceNotificationSender<T: Clone + Send + Sync + fmt::Debug + 'static> {
    subscribers: SharedNotificationSenders<T>,
}

impl<T: Clone + Send + Sync + fmt::Debug + 'static> SubspaceNotificationSender<T> {
    /// The `subscribers` should be shared with a corresponding `SharedNotificationSenders`.
    fn new(subscribers: SharedNotificationSenders<T>) -> Self {
        Self { subscribers }
    }

    /// Send out a notification to all subscribers.
    pub(crate) fn notify<F>(&self, get_value: F)
    where
        F: FnOnce() -> T,
    {
        let mut subscribers = self.subscribers.lock();

        // do an initial prune on closed subscriptions
        subscribers.retain(|subscriber| !subscriber.is_closed());

        if !subscribers.is_empty() {
            let value = get_value();
            subscribers.retain(|subscriber| subscriber.unbounded_send(value.clone()).is_ok());
        }
    }
}

/// The receiving half of the Subspace notification channel.
#[derive(Clone)]
pub struct SubspaceNotificationStream<T: Clone + Send + Sync + fmt::Debug + 'static> {
    stream_name: &'static str,
    subscribers: SharedNotificationSenders<T>,
}

impl<T: Clone + Send + Sync + fmt::Debug + 'static> SubspaceNotificationStream<T> {
    /// Create a new receiver of notifications.
    ///
    /// The `subscribers` should be shared with a corresponding `SubspaceNotificationSender`.
    fn new(stream_name: &'static str, subscribers: SharedNotificationSenders<T>) -> Self {
        Self {
            stream_name,
            subscribers,
        }
    }

    /// Subscribe to a channel through which notifications are sent.
    pub fn subscribe(&self) -> NotificationStream<T> {
        let (sender, receiver) = tracing_unbounded(self.stream_name, 100);
        self.subscribers.lock().push(sender);
        receiver
    }
}

/// Creates a new pair of receiver and sender of notifications.
pub(crate) fn channel<T>(
    stream_name: &'static str,
) -> (SubspaceNotificationSender<T>, SubspaceNotificationStream<T>)
where
    T: Clone + Send + Sync + fmt::Debug + 'static,
{
    let subscribers = Arc::new(Mutex::new(Vec::new()));
    let receiver = SubspaceNotificationStream::new(stream_name, subscribers.clone());
    let sender = SubspaceNotificationSender::new(subscribers);
    (sender, receiver)
}
