use backoff::ExponentialBackoff;
use backoff::backoff::Backoff;
use libp2p::PeerId;
use schnellru::{ByLength, LruMap};
use std::ops::Add;
use std::time::Instant;

/// Details about temporary ban, used to track lifecycle of retries
#[derive(Debug)]
struct TemporaryBan {
    backoff: ExponentialBackoff,
    next_release: Option<Instant>,
}

impl TemporaryBan {
    /// Create new temporary ban
    fn new(backoff: ExponentialBackoff) -> Self {
        let mut instance = Self {
            backoff,
            next_release: None,
        };
        instance.backoff.reset();
        instance.next_release = instance
            .backoff
            .next_backoff()
            .map(|duration| Instant::now().add(duration));
        instance
    }

    /// Whether ban is currently active and not expired
    fn is_active(&self) -> bool {
        if let Some(next_release) = self.next_release {
            next_release > Instant::now()
        } else {
            true
        }
    }

    /// Extend temporary ban if it expired already expired, do nothing otherwise
    fn try_extend(&mut self) {
        let now = Instant::now();

        if let Some(next_release) = self.next_release {
            if next_release > now {
                // Old ban if still active, no need to extend it
                return;
            }
        } else {
            // Ban is permanent
            return;
        }

        self.next_release = self
            .backoff
            .next_backoff()
            .map(|duration| now.add(duration));
    }
}

/// Collection of temporary bans that help to prevent reaching out to the same peer ID over and
/// over again.
#[derive(Debug)]
pub(crate) struct TemporaryBans {
    backoff: ExponentialBackoff,
    list: LruMap<PeerId, TemporaryBan>,
}

impl TemporaryBans {
    pub(super) fn new(capacity: u32, backoff: ExponentialBackoff) -> Self {
        Self {
            backoff,
            list: LruMap::new(ByLength::new(capacity)),
        }
    }

    /// Checks if peer is currently banned.
    ///
    /// `false` means peer either is not banned at all or previous temporary ban has expired and
    /// new connection attempt is allowed to be made.
    pub(crate) fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.list
            .peek(peer_id)
            .map(TemporaryBan::is_active)
            .unwrap_or_default()
    }

    /// Create temporary ban for peer or extend existing ban
    pub(crate) fn create_or_extend(&mut self, peer_id: &PeerId) {
        if let Some(ban) = self.list.get(peer_id) {
            ban.try_extend();
        } else {
            self.list
                .insert(*peer_id, TemporaryBan::new(self.backoff.clone()));
        }
    }

    /// Remove temporary ban for peer.
    ///
    /// Returns `true` if there was an entry for peer during call.
    pub(crate) fn remove(&mut self, peer_id: &PeerId) -> bool {
        self.list.remove(peer_id).is_some()
    }
}
