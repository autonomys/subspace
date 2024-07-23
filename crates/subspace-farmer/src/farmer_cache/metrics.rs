//! Metrics for farmer cache

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::{Registry, Unit};
use std::sync::atomic::{AtomicI64, AtomicU64};

/// Metrics for farmer cache
#[derive(Debug)]
pub(super) struct FarmerCacheMetrics {
    pub(super) cache_get_hit: Counter<u64, AtomicU64>,
    pub(super) cache_get_miss: Counter<u64, AtomicU64>,
    pub(super) cache_get_error: Counter<u64, AtomicU64>,
    pub(super) cache_find_hit: Counter<u64, AtomicU64>,
    pub(super) cache_find_miss: Counter<u64, AtomicU64>,
    pub(super) piece_cache_capacity_total: Gauge<i64, AtomicI64>,
    pub(super) piece_cache_capacity_used: Gauge<i64, AtomicI64>,
}

impl FarmerCacheMetrics {
    /// Create new instance
    pub(super) fn new(registry: &mut Registry) -> Self {
        let registry = registry.sub_registry_with_prefix("farmer_cache");

        let cache_get_hit = Counter::default();
        registry.register_with_unit(
            "cache_get_hit",
            "Cache get hit",
            Unit::Other("Requests".to_string()),
            cache_get_hit.clone(),
        );

        let cache_get_miss = Counter::default();
        registry.register_with_unit(
            "cache_get_miss",
            "Cache get miss",
            Unit::Other("Requests".to_string()),
            cache_get_miss.clone(),
        );

        let cache_get_error = Counter::default();
        registry.register_with_unit(
            "cache_error",
            "Cache get error",
            Unit::Other("Requests".to_string()),
            cache_get_error.clone(),
        );

        let cache_find_hit = Counter::default();
        registry.register_with_unit(
            "cache_find_hit",
            "Cache find hit",
            Unit::Other("Requests".to_string()),
            cache_find_hit.clone(),
        );

        let cache_find_miss = Counter::default();
        registry.register_with_unit(
            "cache_find_miss",
            "Cache find miss",
            Unit::Other("Requests".to_string()),
            cache_find_miss.clone(),
        );

        let piece_cache_capacity_total = Gauge::default();
        registry.register_with_unit(
            "piece_cache_capacity_total",
            "Piece cache capacity total",
            Unit::Other("Pieces".to_string()),
            piece_cache_capacity_total.clone(),
        );

        let piece_cache_capacity_used = Gauge::default();
        registry.register_with_unit(
            "piece_cache_capacity_used",
            "Piece cache capacity used",
            Unit::Other("Pieces".to_string()),
            piece_cache_capacity_used.clone(),
        );

        Self {
            cache_get_hit,
            cache_get_miss,
            cache_get_error,
            cache_find_hit,
            cache_find_miss,
            piece_cache_capacity_total,
            piece_cache_capacity_used,
        }
    }
}
