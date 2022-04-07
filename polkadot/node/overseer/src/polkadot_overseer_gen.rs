// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! # Overseer
//!
//! `overseer` implements the Overseer architecture described in the
//! [implementers-guide](https://w3f.github.io/parachain-implementers-guide/node/index.html).
//! For the motivations behind implementing the overseer itself you should
//! check out that guide, documentation in this crate will be mostly discussing
//! technical stuff.
//!
//! An `Overseer` is something that allows spawning/stopping and overseeing
//! asynchronous tasks as well as establishing a well-defined and easy to use
//! protocol that the tasks can use to communicate with each other. It is desired
//! that this protocol is the only way tasks communicate with each other, however
//! at this moment there are no foolproof guards against other ways of communication.
//!
//! The `Overseer` is instantiated with a pre-defined set of `Subsystems` that
//! share the same behavior from `Overseer`'s point of view.
//!
//! ```text
//!                              +-----------------------------+
//!                              |         Overseer            |
//!                              +-----------------------------+
//!
//!             ................|  Overseer "holds" these and uses |..............
//!             .                  them to (re)start things                      .
//!             .                                                                .
//!             .  +-------------------+                +---------------------+  .
//!             .  |   Subsystem1      |                |   Subsystem2        |  .
//!             .  +-------------------+                +---------------------+  .
//!             .           |                                       |            .
//!             ..................................................................
//!                         |                                       |
//!                       start()                                 start()
//!                         V                                       V
//!             ..................| Overseer "runs" these |.......................
//!             .  +--------------------+               +---------------------+  .
//!             .  | SubsystemInstance1 | <-- bidir --> | SubsystemInstance2  |  .
//!             .  +--------------------+               +---------------------+  .
//!             ..................................................................
//! ```

use futures::{
	channel::oneshot,
	future::Future,
	task::{Context, Poll},
};
use std::pin::Pin;

use std::{
	sync::{
		atomic::{self, AtomicUsize},
		Arc,
	},
	time::Duration,
};

use futures_timer::Delay;

/// A wrapping type for messages.
///
/// Includes a counter to synchronize signals with messages,
/// such that no inconsistent message sequences are prevented.
#[derive(Debug)]
pub struct MessagePacket {
	/// Signal level at the point of reception.
	///
	/// Required to assure signals were consumed _before_
	/// consuming messages that are based on the assumption
	/// that a certain signal was assumed.
	pub signals_received: usize,
	/// The message to be sent/consumed.
	pub message: crate::CollationGenerationMessage,
}

/// Watermark to track the received signals.
#[derive(Debug, Default, Clone)]
pub struct SignalsReceived(Arc<AtomicUsize>);

impl SignalsReceived {
	/// Load the current value of received signals.
	pub fn load(&self) -> usize {
		// off by a few is ok
		self.0.load(atomic::Ordering::Relaxed)
	}

	/// Increase the number of signals by one.
	pub fn inc(&self) {
		self.0.fetch_add(1, atomic::Ordering::Acquire);
	}
}

/// An error type that describes faults that may happen
///
/// These are:
///   * Channels being closed
///   * Subsystems dying when they are not expected to
///   * Subsystems not dying when they are told to die
///   * etc.
#[derive(thiserror::Error, Debug)]
#[allow(missing_docs)]
pub enum OverseerError {
	#[error(transparent)]
	NotifyCancellation(#[from] oneshot::Canceled),

	#[error("Failed to {0}")]
	Context(String),

	#[error("Subsystem stalled: {0}")]
	SubsystemStalled(&'static str),
}

/// A running instance of some [`Subsystem`].
///
/// [`Subsystem`]: trait.Subsystem.html
///
/// `M` here is the inner message type, and _not_ the generated `enum AllMessages`.
pub(crate) struct SubsystemInstance {
	/// Send sink for `Signal`s to be sent to a subsystem.
	pub(crate) tx_signal: metered::MeteredSender<crate::OverseerSignal>,
	/// Send sink for `Message`s to be sent to a subsystem.
	pub(crate) tx_bounded: metered::MeteredSender<MessagePacket>,
	/// The number of signals already received.
	/// Required to assure messages and signals
	/// are processed correctly.
	pub(crate) signals_received: usize,
	/// Name of the subsystem instance.
	pub(crate) name: &'static str,
}

/// A message type that a subsystem receives from an overseer.
/// It wraps signals from an overseer and messages that are circulating
/// between subsystems.
///
/// It is generic over over the message type `M` that a particular `Subsystem` may use.
#[derive(Debug)]
pub enum FromOverseer {
	/// Signal from the `Overseer`.
	Signal(crate::OverseerSignal),

	/// Some other `Subsystem`'s message.
	Communication {
		/// Contained message
		msg: crate::CollationGenerationMessage,
	},
}

/// A future that wraps another future with a `Delay` allowing for time-limited futures.
#[pin_project::pin_project]
pub struct Timeout<F: Future> {
	#[pin]
	future: F,
	#[pin]
	delay: Delay,
}

/// Extends `Future` to allow time-limited futures.
pub trait TimeoutExt: Future {
	/// Adds a timeout of `duration` to the given `Future`.
	/// Returns a new `Future`.
	fn timeout(self, duration: Duration) -> Timeout<Self>
	where
		Self: Sized,
	{
		Timeout { future: self, delay: Delay::new(duration) }
	}
}

impl<F> TimeoutExt for F where F: Future {}

impl<F> Future for Timeout<F>
where
	F: Future,
{
	type Output = Option<F::Output>;

	fn poll(self: Pin<&mut Self>, ctx: &mut Context) -> Poll<Self::Output> {
		let this = self.project();

		if this.delay.poll(ctx).is_ready() {
			return Poll::Ready(None)
		}

		if let Poll::Ready(output) = this.future.poll(ctx) {
			return Poll::Ready(Some(output))
		}

		Poll::Pending
	}
}
