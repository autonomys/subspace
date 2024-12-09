//! Thread pool managing utilities for plotting purposes

use crate::plotter::gpu::GpuRecordsEncoder;
use event_listener::Event;
use parking_lot::Mutex;
use std::num::{NonZeroUsize, TryFromIntError};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// Wrapper around [`GpuEncoder`] that on `Drop` will return thread pool back into
/// corresponding [`GpuRecordsEncoderManager`].
#[derive(Debug)]
#[must_use]
pub(super) struct GpuRecordsEncoderGuard<GRE> {
    inner: Arc<(Mutex<Vec<GRE>>, Event)>,
    gpu_records_encoder: Option<GRE>,
}

impl<GRE> Deref for GpuRecordsEncoderGuard<GRE> {
    type Target = GRE;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.gpu_records_encoder
            .as_ref()
            .expect("Value exists until `Drop`; qed")
    }
}

impl<GRE> DerefMut for GpuRecordsEncoderGuard<GRE> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.gpu_records_encoder
            .as_mut()
            .expect("Value exists until `Drop`; qed")
    }
}

impl<GRE> Drop for GpuRecordsEncoderGuard<GRE> {
    #[inline]
    fn drop(&mut self) {
        let (mutex, event) = &*self.inner;
        mutex.lock().push(
            self.gpu_records_encoder
                .take()
                .expect("Happens only once in `Drop`; qed"),
        );
        event.notify_additional(1);
    }
}

/// GPU records encoder manager.
///
/// This abstraction wraps a set of GPU records encoders and allows to use them one at a time.
#[derive(Debug)]
pub(super) struct GpuRecordsEncoderManager<GRE> {
    inner: Arc<(Mutex<Vec<GRE>>, Event)>,
    gpu_records_encoders: NonZeroUsize,
}

impl<GRE> Clone for GpuRecordsEncoderManager<GRE> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            gpu_records_encoders: self.gpu_records_encoders,
        }
    }
}

impl<GRE> GpuRecordsEncoderManager<GRE>
where
    GRE: GpuRecordsEncoder,
{
    /// Create new instance.
    ///
    /// Returns an error if empty list of encoders is provided.
    pub(super) fn new(gpu_records_encoders: Vec<GRE>) -> Result<Self, TryFromIntError> {
        let count = gpu_records_encoders.len().try_into()?;

        Ok(Self {
            inner: Arc::new((Mutex::new(gpu_records_encoders), Event::new())),
            gpu_records_encoders: count,
        })
    }

    /// How many gpu records encoders are being managed here
    pub(super) fn gpu_records_encoders(&self) -> NonZeroUsize {
        self.gpu_records_encoders
    }

    /// Get one of inner thread pool pairs, will wait until one is available if needed
    pub(super) async fn get_encoder(&self) -> GpuRecordsEncoderGuard<GRE> {
        let (mutex, event) = &*self.inner;

        let gpu_records_encoder = loop {
            let listener = event.listen();

            if let Some(thread_pool_pair) = mutex.lock().pop() {
                break thread_pool_pair;
            }

            listener.await;
        };

        GpuRecordsEncoderGuard {
            inner: Arc::clone(&self.inner),
            gpu_records_encoder: Some(gpu_records_encoder),
        }
    }
}
