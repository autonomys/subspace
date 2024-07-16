//! Metrics for disk piece cache

use crate::farm::PieceCacheId;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::{Registry, Unit};
use std::sync::atomic::{AtomicI64, AtomicU64};

/// Metrics for disk piece cache
#[derive(Debug)]
pub(super) struct DiskPieceCacheMetrics {
    pub(super) contents: Counter<u64, AtomicU64>,
    pub(super) read_piece: Counter<u64, AtomicU64>,
    pub(super) read_piece_index: Counter<u64, AtomicU64>,
    pub(super) write_piece: Counter<u64, AtomicU64>,
    pub(super) capacity_used: Gauge<i64, AtomicI64>,
}

impl DiskPieceCacheMetrics {
    /// Create new instance
    pub(super) fn new(
        registry: &mut Registry,
        cache_id: &PieceCacheId,
        max_num_elements: u32,
    ) -> Self {
        let registry = registry
            .sub_registry_with_prefix("disk_piece_cache")
            .sub_registry_with_label(("cache_id".into(), cache_id.to_string().into()));

        let contents = Counter::default();
        registry.register_with_unit(
            "contents",
            "Contents requests",
            Unit::Other("Requests".to_string()),
            contents.clone(),
        );

        let read_piece = Counter::default();
        registry.register_with_unit(
            "read_piece",
            "Read piece requests",
            Unit::Other("Pieces".to_string()),
            read_piece.clone(),
        );

        let read_piece_index = Counter::default();
        registry.register_with_unit(
            "read_piece_index",
            "Read piece index requests",
            Unit::Other("Requests".to_string()),
            read_piece_index.clone(),
        );

        let write_piece = Counter::default();
        registry.register_with_unit(
            "write_piece",
            "Write piece requests",
            Unit::Other("Pieces".to_string()),
            write_piece.clone(),
        );

        let capacity_total = Gauge::<i64, AtomicI64>::default();
        capacity_total.set(i64::from(max_num_elements));
        registry.register_with_unit(
            "capacity_total",
            "Piece cache capacity total",
            Unit::Other("Pieces".to_string()),
            capacity_total,
        );

        let capacity_used = Gauge::default();
        registry.register_with_unit(
            "capacity_used",
            "Piece cache capacity used",
            Unit::Other("Pieces".to_string()),
            capacity_used.clone(),
        );

        Self {
            contents,
            read_piece,
            read_piece_index,
            write_piece,
            capacity_used,
        }
    }
}
