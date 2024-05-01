//! NATS client
//!
//! [`NatsClient`] provided here is a wrapper around [`Client`] that provides convenient methods
//! using domain-specific traits.
//!
//! Before reading code, make sure to familiarize yourself with NATS documentation, especially with
//! [subjects](https://docs.nats.io/nats-concepts/subjects) and
//! [Core NATS](https://docs.nats.io/nats-concepts/core-nats) features.
//!
//! Abstractions provided here cover a few use cases:
//! * request/response (for example piece request)
//! * request/stream of responses (for example a stream of plotted sectors of the farmer)
//! * notifications (typically targeting a particular instance of an app) and corresponding subscriptions (for example solution notification)
//! * broadcasts and corresponding subscriptions (for example slot info broadcast)

use async_nats::{
    Client, HeaderMap, HeaderValue, PublishError, RequestError, RequestErrorKind, Subject,
    SubscribeError, Subscriber, ToServerAddrs,
};
use derive_more::{Deref, DerefMut};
use futures::{Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use std::any::type_name;
use std::collections::VecDeque;
use std::fmt;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tracing::warn;
use ulid::Ulid;

// TODO: Replace this with querying of the actual value from the server
/// Approximate max message size (a few more bytes will not hurt), the actual limit is expected to
/// be 2M in NATS
pub const APPROXIMATE_MAX_MESSAGE_SIZE: usize = 2 * 1024 * 1024 * 8 / 10;

/// Generic request with associated response.
///
/// Used for cases where request/response pattern is needed and response contains a single small
/// message. For large messages or multiple messages chunking with [`GenericStreamRequest`] can be
/// used instead.
pub trait GenericRequest: Encode + Decode + fmt::Debug + Send + Sync + 'static {
    /// Request subject with optional `*` in place of application instance to receive the request
    const SUBJECT: &'static str;
    /// Response type that corresponds to this request
    type Response: Encode + Decode + fmt::Debug + Send + Sync + 'static;
}

/// Generic stream request where response is streamed using [`GenericStreamResponses`].
///
/// Used for cases where a large payload that doesn't fit into NATS message needs to be sent or
/// there is a very large number of messages to send. For simple request/response patten
/// [`GenericRequest`] can be used instead.
pub trait GenericStreamRequest: Encode + Decode + fmt::Debug + Send + Sync + 'static {
    /// Request subject with optional `*` in place of application instance to receive the request
    const SUBJECT: &'static str;
    /// Response type that corresponds to this stream request. These responses are send as a stream
    /// of [`GenericStreamResponses`] messages.
    type Response: Encode + Decode + fmt::Debug + Send + Sync + 'static;
}

/// Messages sent in response to [`StreamRequest`].
///
/// Empty list of responses means the end of the stream.
#[derive(Debug, Encode, Decode)]
pub enum GenericStreamResponses<Response> {
    /// Some responses, but the stream didn't end yet
    Continue(VecDeque<Response>),
    /// Remaining responses and this is the end of the stream.
    Last(VecDeque<Response>),
}

impl<Response> From<GenericStreamResponses<Response>> for VecDeque<Response> {
    fn from(value: GenericStreamResponses<Response>) -> Self {
        match value {
            GenericStreamResponses::Continue(responses) => responses,
            GenericStreamResponses::Last(responses) => responses,
        }
    }
}

impl<Response> GenericStreamResponses<Response> {
    fn next(&mut self) -> Option<Response> {
        match self {
            GenericStreamResponses::Continue(responses) => responses.pop_front(),
            GenericStreamResponses::Last(responses) => responses.pop_front(),
        }
    }

    fn is_last(&self) -> bool {
        matches!(self, Self::Last(_))
    }
}

/// Generic stream request that expects a stream of responses.
///
/// Internally it is expected that [`GenericStreamResponses<Request::Response>`] messages will be
/// sent to auto-generated subject specified in `response_subject` field.
#[derive(Debug, Encode, Decode)]
#[non_exhaustive]
pub struct StreamRequest<Request>
where
    Request: GenericStreamRequest,
{
    /// Request
    pub request: Request,
    /// Topic to send a stream of [`GenericStreamResponses<Request::Response>`]s to
    pub response_subject: String,
}

impl<Request> StreamRequest<Request>
where
    Request: GenericStreamRequest,
{
    /// Create new stream request
    pub fn new(request: Request) -> Self {
        Self {
            request,
            response_subject: format!("stream-response.{}", Ulid::new()),
        }
    }
}

/// Stream request error
#[derive(Debug, Error)]
pub enum StreamRequestError {
    /// Subscribe error
    #[error("Subscribe error: {0}")]
    Subscribe(#[from] SubscribeError),
    /// Publish error
    #[error("Publish error: {0}")]
    Publish(#[from] PublishError),
}

/// Wrapper around subscription that transforms [`GenericStreamResponses<Response>`] messages into a
/// normal `Response` stream.
#[derive(Debug, Deref, DerefMut)]
#[pin_project::pin_project]
pub struct StreamResponseSubscriber<Response> {
    #[pin]
    #[deref]
    #[deref_mut]
    subscriber: Subscriber,
    buffered_responses: GenericStreamResponses<Response>,
    _phantom: PhantomData<Response>,
}

impl<Response> Stream for StreamResponseSubscriber<Response>
where
    Response: Decode,
{
    type Item = Response;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(response) = self.buffered_responses.next() {
            return Poll::Ready(Some(response));
        } else if self.buffered_responses.is_last() {
            return Poll::Ready(None);
        }

        let mut projected = self.project();
        match projected.subscriber.poll_next_unpin(cx) {
            Poll::Ready(Some(message)) => {
                match GenericStreamResponses::<Response>::decode(&mut message.payload.as_ref()) {
                    Ok(mut responses) => {
                        if let Some(response) = responses.next() {
                            *projected.buffered_responses = responses;
                            Poll::Ready(Some(response))
                        } else {
                            Poll::Ready(None)
                        }
                    }
                    Err(error) => {
                        warn!(
                            %error,
                            message_type = %type_name::<Response>(),
                            message = %hex::encode(message.payload),
                            "Failed to decode stream response"
                        );

                        Poll::Ready(None)
                    }
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Generic one-off notification
pub trait GenericNotification: Encode + Decode + fmt::Debug + Send + Sync + 'static {
    /// Notification subject with optional `*` in place of application instance receiving the
    /// request
    const SUBJECT: &'static str;
}

/// Generic broadcast message.
///
/// Broadcast messages are sent by an instance to (potentially) an instance-specific subject that
/// any other app can subscribe to. The same broadcast message can also originate from multiple
/// places and be de-duplicated using [`Self::deterministic_message_id`].
pub trait GenericBroadcast: Encode + Decode + fmt::Debug + Send + Sync + 'static {
    /// Broadcast subject with optional `*` in place of application instance sending broadcast
    const SUBJECT: &'static str;

    /// Deterministic message ID that is used for de-duplicating messages broadcast by different
    /// instances
    fn deterministic_message_id(&self) -> Option<HeaderValue> {
        None
    }
}

/// Subscriber wrapper that decodes messages automatically and skips messages that can't be decoded
#[derive(Debug, Deref, DerefMut)]
#[pin_project::pin_project]
pub struct SubscriberWrapper<Message> {
    #[pin]
    #[deref]
    #[deref_mut]
    subscriber: Subscriber,
    _phantom: PhantomData<Message>,
}

impl<Message> Stream for SubscriberWrapper<Message>
where
    Message: Decode,
{
    type Item = Message;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.project().subscriber.poll_next_unpin(cx) {
            Poll::Ready(Some(message)) => match Message::decode(&mut message.payload.as_ref()) {
                Ok(message) => Poll::Ready(Some(message)),
                Err(error) => {
                    warn!(
                        %error,
                        message_type = %type_name::<Message>(),
                        message = %hex::encode(message.payload),
                        "Failed to decode stream message"
                    );

                    Poll::Pending
                }
            },
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// NATS client wrapper that can be used to interact with other Subspace-specific clients
#[derive(Debug, Clone, Deref)]
pub struct NatsClient {
    client: Client,
}

impl From<Client> for NatsClient {
    fn from(client: Client) -> Self {
        Self { client }
    }
}

impl NatsClient {
    /// Create new instance by connecting to specified addresses
    pub async fn new<A: ToServerAddrs>(addrs: A) -> Result<Self, async_nats::Error> {
        Ok(Self {
            client: async_nats::connect(addrs).await?,
        })
    }

    /// Make request and wait for response
    pub async fn request<Request>(
        &self,
        request: &Request,
        instance: Option<&str>,
    ) -> Result<Request::Response, RequestError>
    where
        Request: GenericRequest,
    {
        let subject = if let Some(instance) = instance {
            Subject::from(Request::SUBJECT.replace('*', instance))
        } else {
            Subject::from_static(Request::SUBJECT)
        };
        let message = self
            .client
            .request(subject.clone(), request.encode().into())
            .await?;

        let response =
            Request::Response::decode(&mut message.payload.as_ref()).map_err(|error| {
                warn!(
                    %subject,
                    %error,
                    response_type = %type_name::<Request::Response>(),
                    response = %hex::encode(message.payload),
                    "Response decoding failed"
                );

                RequestErrorKind::Other
            })?;

        Ok(response)
    }

    /// Make request that expects stream response
    pub async fn stream_request<Request>(
        &self,
        request: Request,
        instance: Option<&str>,
    ) -> Result<StreamResponseSubscriber<Request::Response>, StreamRequestError>
    where
        Request: GenericStreamRequest,
    {
        let stream_request = StreamRequest::new(request);

        let subscriber = self
            .client
            .subscribe(stream_request.response_subject.clone())
            .await?;

        let subject = if let Some(instance) = instance {
            Subject::from(Request::SUBJECT.replace('*', instance))
        } else {
            Subject::from_static(Request::SUBJECT)
        };

        self.client
            .publish(subject, stream_request.encode().into())
            .await?;

        Ok(StreamResponseSubscriber {
            subscriber,
            buffered_responses: GenericStreamResponses::Continue(VecDeque::new()),
            _phantom: PhantomData,
        })
    }

    /// Make notification without waiting for response
    pub async fn notification<Notification>(
        &self,
        notification: &Notification,
        instance: Option<&str>,
    ) -> Result<(), PublishError>
    where
        Notification: GenericNotification,
    {
        let subject = if let Some(instance) = instance {
            Subject::from(Notification::SUBJECT.replace('*', instance))
        } else {
            Subject::from_static(Notification::SUBJECT)
        };

        self.client
            .publish(subject, notification.encode().into())
            .await
    }

    /// Send a broadcast message
    pub async fn broadcast<Broadcast>(
        &self,
        message: &Broadcast,
        instance: &str,
    ) -> Result<(), PublishError>
    where
        Broadcast: GenericBroadcast,
    {
        self.client
            .publish_with_headers(
                Broadcast::SUBJECT.replace('*', instance),
                {
                    let mut headers = HeaderMap::new();
                    if let Some(message_id) = message.deterministic_message_id() {
                        headers.insert("Nats-Msg-Id", message_id);
                    }
                    headers
                },
                message.encode().into(),
            )
            .await
    }

    /// Simple subscription that will produce decoded notifications, while skipping messages that
    /// fail to decode
    pub async fn subscribe_to_notifications<Notification>(
        &self,
        instance: Option<&str>,
    ) -> Result<SubscriberWrapper<Notification>, SubscribeError>
    where
        Notification: GenericNotification,
    {
        self.simple_subscribe(if let Some(instance) = instance {
            Subject::from(Notification::SUBJECT.replace('*', instance))
        } else {
            Subject::from_static(Notification::SUBJECT)
        })
        .await
    }

    /// Simple subscription that will produce decoded broadcasts, while skipping messages that
    /// fail to decode
    pub async fn subscribe_to_broadcasts<Broadcast>(
        &self,
        instance: Option<&str>,
    ) -> Result<SubscriberWrapper<Broadcast>, SubscribeError>
    where
        Broadcast: GenericBroadcast,
    {
        self.simple_subscribe(if let Some(instance) = instance {
            Subject::from(Broadcast::SUBJECT.replace('*', instance))
        } else {
            Subject::from_static(Broadcast::SUBJECT)
        })
        .await
    }

    /// Simple subscription that will produce decoded messages, while skipping messages that fail to
    /// decode
    async fn simple_subscribe<Message>(
        &self,
        subject: Subject,
    ) -> Result<SubscriberWrapper<Message>, SubscribeError>
    where
        Message: Decode,
    {
        Ok(SubscriberWrapper {
            subscriber: self.client.subscribe(subject).await?,
            _phantom: PhantomData,
        })
    }
}
