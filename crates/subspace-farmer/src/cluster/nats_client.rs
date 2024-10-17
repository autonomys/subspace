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

use crate::utils::AsyncJoinOnDrop;
use anyhow::anyhow;
use async_nats::{
    Client, ConnectOptions, HeaderMap, HeaderValue, Message, PublishError, RequestError,
    RequestErrorKind, Subject, SubscribeError, Subscriber, ToServerAddrs,
};
use backoff::backoff::Backoff;
use backoff::ExponentialBackoff;
use derive_more::{Deref, DerefMut};
use futures::channel::mpsc;
use futures::stream::FuturesUnordered;
use futures::{select, FutureExt, Stream, StreamExt};
use parity_scale_codec::{Decode, Encode};
use std::any::type_name;
use std::collections::VecDeque;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{fmt, mem};
use thiserror::Error;
use tracing::{debug, error, trace, warn, Instrument};
use ulid::Ulid;

const EXPECTED_MESSAGE_SIZE: usize = 2 * 1024 * 1024;
const ACKNOWLEDGEMENT_TIMEOUT: Duration = Duration::from_mins(1);
/// Requests should time out eventually, but we should set a larger timeout to allow for spikes in
/// load to be absorbed gracefully
const REQUEST_TIMEOUT: Duration = Duration::from_mins(5);

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

/// Generic stream request where response is streamed using [`NatsClient::stream_response`].
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
    Continue {
        /// Monotonically increasing index of responses in a stream
        index: u32,
        /// Individual responses
        responses: VecDeque<Response>,
        /// Subject where to send acknowledgement of received stream response indices, which acts as
        /// a backpressure mechanism
        ack_subject: String,
    },
    /// Remaining responses and this is the end of the stream.
    Last {
        /// Monotonically increasing index of responses in a stream
        index: u32,
        /// Individual responses
        responses: VecDeque<Response>,
    },
}

impl<Response> From<GenericStreamResponses<Response>> for VecDeque<Response> {
    #[inline]
    fn from(value: GenericStreamResponses<Response>) -> Self {
        match value {
            GenericStreamResponses::Continue { responses, .. } => responses,
            GenericStreamResponses::Last { responses, .. } => responses,
        }
    }
}

impl<Response> GenericStreamResponses<Response> {
    fn next(&mut self) -> Option<Response> {
        match self {
            GenericStreamResponses::Continue { responses, .. } => responses.pop_front(),
            GenericStreamResponses::Last { responses, .. } => responses.pop_front(),
        }
    }

    fn index(&self) -> u32 {
        match self {
            GenericStreamResponses::Continue { index, .. } => *index,
            GenericStreamResponses::Last { index, .. } => *index,
        }
    }

    fn ack_subject(&self) -> Option<&str> {
        if let GenericStreamResponses::Continue { ack_subject, .. } = self {
            Some(ack_subject)
        } else {
            None
        }
    }

    fn is_last(&self) -> bool {
        matches!(self, Self::Last { .. })
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
    response_subject: String,
    buffered_responses: Option<GenericStreamResponses<Response>>,
    next_index: u32,
    acknowledgement_sender: mpsc::UnboundedSender<(String, u32)>,
    _background_task: AsyncJoinOnDrop<()>,
    _phantom: PhantomData<Response>,
}

impl<Response> Stream for StreamResponseSubscriber<Response>
where
    Response: Decode,
{
    type Item = Response;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(buffered_responses) = self.buffered_responses.as_mut() {
            if let Some(response) = buffered_responses.next() {
                return Poll::Ready(Some(response));
            } else if buffered_responses.is_last() {
                return Poll::Ready(None);
            }

            self.buffered_responses.take();
            self.next_index += 1;
        }

        let mut projected = self.project();
        match projected.subscriber.poll_next_unpin(cx) {
            Poll::Ready(Some(message)) => {
                match GenericStreamResponses::<Response>::decode(&mut message.payload.as_ref()) {
                    Ok(mut responses) => {
                        if responses.index() != *projected.next_index {
                            warn!(
                                actual_index = %responses.index(),
                                expected_index = %*projected.next_index,
                                message_type = %type_name::<Response>(),
                                response_subject = %projected.response_subject,
                                "Received unexpected response stream index, aborting stream"
                            );

                            return Poll::Ready(None);
                        }

                        if let Some(ack_subject) = responses.ack_subject() {
                            let index = responses.index();
                            let ack_subject = ack_subject.to_string();

                            if let Err(error) = projected
                                .acknowledgement_sender
                                .unbounded_send((ack_subject.clone(), index))
                            {
                                warn!(
                                    %error,
                                    %index,
                                    message_type = %type_name::<Response>(),
                                    response_subject = %projected.response_subject,
                                    %ack_subject,
                                    "Failed to send acknowledgement for stream response"
                                );
                            }
                        }

                        if let Some(response) = responses.next() {
                            *projected.buffered_responses = Some(responses);
                            Poll::Ready(Some(response))
                        } else {
                            Poll::Ready(None)
                        }
                    }
                    Err(error) => {
                        warn!(
                            %error,
                            response_type = %type_name::<Response>(),
                            response_subject = %projected.response_subject,
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

impl<Response> StreamResponseSubscriber<Response> {
    fn new(subscriber: Subscriber, response_subject: String, nats_client: NatsClient) -> Self {
        let (acknowledgement_sender, mut acknowledgement_receiver) =
            mpsc::unbounded::<(String, u32)>();

        let ack_publisher_fut = {
            let response_subject = response_subject.clone();

            async move {
                while let Some((subject, index)) = acknowledgement_receiver.next().await {
                    trace!(
                        %subject,
                        %index,
                        %response_subject,
                        %index,
                        "Sending stream response acknowledgement"
                    );
                    if let Err(error) = nats_client
                        .publish(subject.clone(), index.to_le_bytes().to_vec().into())
                        .await
                    {
                        warn!(
                            %error,
                            %subject,
                            %index,
                            %response_subject,
                            %index,
                            "Failed to send stream response acknowledgement"
                        );
                        return;
                    }
                }
            }
        };
        let background_task =
            AsyncJoinOnDrop::new(tokio::spawn(ack_publisher_fut.in_current_span()), true);

        Self {
            response_subject,
            subscriber,
            buffered_responses: None,
            next_index: 0,
            acknowledgement_sender,
            _background_task: background_task,
            _phantom: PhantomData,
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

#[derive(Debug)]
struct Inner {
    client: Client,
    request_retry_backoff_policy: ExponentialBackoff,
    approximate_max_message_size: usize,
    max_message_size: usize,
}

/// NATS client wrapper that can be used to interact with other Subspace-specific clients
#[derive(Debug, Clone)]
pub struct NatsClient {
    inner: Arc<Inner>,
}

impl Deref for NatsClient {
    type Target = Client;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner.client
    }
}

impl NatsClient {
    /// Create new instance by connecting to specified addresses
    pub async fn new<A: ToServerAddrs>(
        addrs: A,
        request_retry_backoff_policy: ExponentialBackoff,
    ) -> Result<Self, async_nats::Error> {
        let servers = addrs.to_server_addrs()?.collect::<Vec<_>>();
        Self::from_client(
            async_nats::connect_with_options(
                &servers,
                ConnectOptions::default().request_timeout(Some(REQUEST_TIMEOUT)),
            )
            .await?,
            request_retry_backoff_policy,
        )
    }

    /// Create new client from existing NATS instance
    pub fn from_client(
        client: Client,
        request_retry_backoff_policy: ExponentialBackoff,
    ) -> Result<Self, async_nats::Error> {
        let max_payload = client.server_info().max_payload;
        if max_payload < EXPECTED_MESSAGE_SIZE {
            return Err(format!(
                "Max payload {max_payload} is smaller than expected {EXPECTED_MESSAGE_SIZE}, \
                increase it by specifying max_payload = 2MB or higher number in NATS configuration"
            )
            .into());
        }

        let inner = Inner {
            client,
            request_retry_backoff_policy,
            // Allow up to 90%, the rest will be wrapper data structures, etc.
            approximate_max_message_size: max_payload * 9 / 10,
            // Allow up to 90%, the rest will be wrapper data structures, etc.
            max_message_size: max_payload,
        };

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Approximate max message size (a few more bytes will not hurt), the actual limit is expected
    /// to be a bit higher
    pub fn approximate_max_message_size(&self) -> usize {
        self.inner.approximate_max_message_size
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
        let subject = subject_with_instance(Request::SUBJECT, instance);
        let mut maybe_retry_backoff = None;
        let message = loop {
            match self
                .inner
                .client
                .request(subject.clone(), request.encode().into())
                .await
            {
                Ok(message) => {
                    break message;
                }
                Err(error) => {
                    match error.kind() {
                        RequestErrorKind::TimedOut | RequestErrorKind::NoResponders => {
                            // Continue with retries
                        }
                        RequestErrorKind::Other => {
                            return Err(error);
                        }
                    }

                    let retry_backoff = maybe_retry_backoff.get_or_insert_with(|| {
                        let mut retry_backoff = self.inner.request_retry_backoff_policy.clone();
                        retry_backoff.reset();
                        retry_backoff
                    });

                    if let Some(delay) = retry_backoff.next_backoff() {
                        debug!(
                            %subject,
                            %error,
                            request_type = %type_name::<Request>(),
                            ?delay,
                            "Failed to make request, retrying after some delay"
                        );

                        tokio::time::sleep(delay).await;
                        continue;
                    } else {
                        return Err(error);
                    }
                }
            }
        };

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

    /// Responds to requests from the given subject using the provided processing function.
    ///
    /// This will create a subscription on the subject for the given instance (if provided) and
    /// queue group. Incoming messages will be deserialized as the request type `Request` and passed
    /// to the `process` function to produce a response of type `Request::Response`. The response
    /// will then be sent back on the reply subject from the original request.
    ///
    /// Each request is processed in a newly created async tokio task.
    ///
    /// # Arguments
    ///
    /// * `instance` - Optional instance name to use in place of the `*` in the subject
    /// * `group` - The queue group name for the subscription
    /// * `process` - The function to call with the decoded request to produce a response
    pub async fn request_responder<Request, F, OP>(
        &self,
        instance: Option<&str>,
        queue_group: Option<String>,
        process: OP,
    ) -> anyhow::Result<()>
    where
        Request: GenericRequest,
        F: Future<Output = Option<Request::Response>> + Send,
        OP: Fn(Request) -> F + Send + Sync,
    {
        // Initialize with pending future so it never ends
        let mut processing = FuturesUnordered::new();

        let subject = subject_with_instance(Request::SUBJECT, instance);
        let subscription = if let Some(queue_group) = queue_group {
            self.inner
                .client
                .queue_subscribe(subject, queue_group)
                .await
        } else {
            self.inner.client.subscribe(subject).await
        }
        .map_err(|error| {
            anyhow!(
                "Failed to subscribe to {} requests for {instance:?}: {error}",
                type_name::<Request>(),
            )
        })?;

        debug!(
            request_type = %type_name::<Request>(),
            ?subscription,
            "Requests subscription"
        );
        let mut subscription = subscription.fuse();

        loop {
            select! {
                message = subscription.select_next_some() => {
                    // Create background task for concurrent processing
                    processing.push(self.process_request(
                        message,
                        &process,
                    ));
                },
                _ = processing.next() => {
                    // Nothing to do here
                },
                complete => {
                    break;
                }
            }
        }

        Ok(())
    }

    async fn process_request<Request, F, OP>(&self, message: Message, process: OP)
    where
        Request: GenericRequest,
        F: Future<Output = Option<Request::Response>> + Send,
        OP: Fn(Request) -> F + Send + Sync,
    {
        let Some(reply_subject) = message.reply else {
            return;
        };

        let message_payload_size = message.payload.len();
        let request = match Request::decode(&mut message.payload.as_ref()) {
            Ok(request) => {
                // Free allocation early
                drop(message.payload);
                request
            }
            Err(error) => {
                warn!(
                    request_type = %type_name::<Request>(),
                    %error,
                    message = %hex::encode(message.payload),
                    "Failed to decode request"
                );
                return;
            }
        };

        // Avoid printing large messages in logs
        if message_payload_size > 1024 {
            trace!(
                request_type = %type_name::<Request>(),
                %reply_subject,
                "Processing request"
            );
        } else {
            trace!(
                request_type = %type_name::<Request>(),
                ?request,
                %reply_subject,
                "Processing request"
            );
        }

        if let Some(response) = process(request).await
            && let Err(error) = self.publish(reply_subject, response.encode().into()).await
        {
            warn!(
                request_type = %type_name::<Request>(),
                %error,
                "Failed to send response"
            );
        }
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
            .inner
            .client
            .subscribe(stream_request.response_subject.clone())
            .await?;

        let stream_request_subject = subject_with_instance(Request::SUBJECT, instance);
        debug!(
            request_type = %type_name::<Request>(),
            %stream_request_subject,
            ?subscriber,
            "Stream request subscription"
        );

        self.inner
            .client
            .publish(stream_request_subject, stream_request.encode().into())
            .await?;

        Ok(StreamResponseSubscriber::new(
            subscriber,
            stream_request.response_subject,
            self.clone(),
        ))
    }

    /// Helper method to send responses to requests initiated with [`Self::stream_request`]
    pub async fn stream_response<Request, S>(&self, response_subject: String, response_stream: S)
    where
        Request: GenericStreamRequest,
        S: Stream<Item = Request::Response> + Unpin,
    {
        type Response<Request> =
            GenericStreamResponses<<Request as GenericStreamRequest>::Response>;

        let mut response_stream = response_stream.fuse();

        // Pull the first element to measure response size
        let first_element = match response_stream.next().await {
            Some(first_element) => first_element,
            None => {
                if let Err(error) = self
                    .publish(
                        response_subject.clone(),
                        Response::<Request>::Last {
                            index: 0,
                            responses: VecDeque::new(),
                        }
                        .encode()
                        .into(),
                    )
                    .await
                {
                    warn!(
                        %response_subject,
                        %error,
                        request_type = %type_name::<Request>(),
                        response_type = %type_name::<Request::Response>(),
                        "Failed to send stream response"
                    );
                }

                return;
            }
        };
        let max_message_size = self.inner.max_message_size;
        let max_responses_per_message =
            self.approximate_max_message_size() / first_element.encoded_size();

        let ack_subject = format!("stream-response-ack.{}", Ulid::new());
        let mut ack_subscription = match self.subscribe(ack_subject.clone()).await {
            Ok(ack_subscription) => ack_subscription,
            Err(error) => {
                warn!(
                    %response_subject,
                    %error,
                    request_type = %type_name::<Request>(),
                    response_type = %type_name::<Request::Response>(),
                    "Failed to subscribe to ack subject"
                );
                return;
            }
        };
        debug!(
            %response_subject,
            request_type = %type_name::<Request>(),
            response_type = %type_name::<Request::Response>(),
            ?ack_subscription,
            "Ack subscription subscription"
        );
        let mut index = 0;
        // Initialize buffer that will be reused for responses
        let mut buffer = VecDeque::with_capacity(max_responses_per_message);
        buffer.push_back(first_element);
        let mut overflow_buffer = VecDeque::new();

        loop {
            // Try to fill the buffer
            let mut local_response_stream = response_stream
                .by_ref()
                .take(max_responses_per_message - buffer.len());
            if buffer.is_empty() {
                if let Some(element) = local_response_stream.next().await {
                    buffer.push_back(element);
                }
            }
            while let Some(element) = local_response_stream.next().now_or_never().flatten() {
                buffer.push_back(element);
            }

            loop {
                let is_done = response_stream.is_done() && overflow_buffer.is_empty();
                let num_messages = buffer.len();
                let response = if is_done {
                    Response::<Request>::Last {
                        index,
                        responses: buffer,
                    }
                } else {
                    Response::<Request>::Continue {
                        index,
                        responses: buffer,
                        ack_subject: ack_subject.clone(),
                    }
                };
                let encoded_response = response.encode();
                let encoded_response_len = encoded_response.len();
                // When encoded response is too large, remove one of the responses from it and try
                // again
                if encoded_response_len > max_message_size {
                    buffer = response.into();
                    if let Some(element) = buffer.pop_back() {
                        if buffer.is_empty() {
                            error!(
                                ?element,
                                encoded_response_len,
                                max_message_size,
                                "Element was too large to fit into NATS message, this is an \
                                implementation bug"
                            );
                        }
                        overflow_buffer.push_front(element);
                        continue;
                    } else {
                        error!(
                            %response_subject,
                            request_type = %type_name::<Request>(),
                            response_type = %type_name::<Request::Response>(),
                            "Empty response overflown message size, this should never happen"
                        );
                        return;
                    }
                }

                debug!(
                    %response_subject,
                    num_messages,
                    %index,
                    %is_done,
                    "Publishing stream response messages",
                );

                if let Err(error) = self
                    .publish(response_subject.clone(), encoded_response.into())
                    .await
                {
                    warn!(
                        %response_subject,
                        %error,
                        request_type = %type_name::<Request>(),
                        response_type = %type_name::<Request::Response>(),
                        "Failed to send stream response"
                    );
                    return;
                }

                if is_done {
                    return;
                } else {
                    buffer = response.into();
                    buffer.clear();
                    // Fill buffer with any overflown responses that may have been stored
                    buffer.extend(overflow_buffer.drain(..));
                }

                if index >= 1 {
                    // Acknowledgements are received with delay
                    let expected_index = index - 1;

                    trace!(
                        %response_subject,
                        %expected_index,
                        "Waiting for acknowledgement"
                    );
                    match tokio::time::timeout(ACKNOWLEDGEMENT_TIMEOUT, ack_subscription.next())
                        .await
                    {
                        Ok(Some(message)) => {
                            if let Some(received_index) = message
                                .payload
                                .split_at_checked(mem::size_of::<u32>())
                                .map(|(bytes, _)| {
                                    u32::from_le_bytes(
                                        bytes.try_into().expect("Correctly chunked slice; qed"),
                                    )
                                })
                            {
                                debug!(
                                    %response_subject,
                                    %received_index,
                                    "Received acknowledgement"
                                );
                                if received_index != expected_index {
                                    warn!(
                                        %response_subject,
                                        %received_index,
                                        %expected_index,
                                        request_type = %type_name::<Request>(),
                                        response_type = %type_name::<Request::Response>(),
                                        message = %hex::encode(message.payload),
                                        "Unexpected acknowledgement index"
                                    );
                                    return;
                                }
                            } else {
                                warn!(
                                    %response_subject,
                                    request_type = %type_name::<Request>(),
                                    response_type = %type_name::<Request::Response>(),
                                    message = %hex::encode(message.payload),
                                    "Unexpected acknowledgement message"
                                );
                                return;
                            }
                        }
                        Ok(None) => {
                            warn!(
                                %response_subject,
                                request_type = %type_name::<Request>(),
                                response_type = %type_name::<Request::Response>(),
                                "Acknowledgement stream ended unexpectedly"
                            );
                            return;
                        }
                        Err(_error) => {
                            warn!(
                                %response_subject,
                                %expected_index,
                                request_type = %type_name::<Request>(),
                                response_type = %type_name::<Request::Response>(),
                                "Acknowledgement wait timed out"
                            );
                            return;
                        }
                    }
                }

                index += 1;

                // Unless `overflow_buffer` wasn't empty abort inner loop
                if buffer.is_empty() {
                    break;
                }
            }
        }
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
        self.inner
            .client
            .publish(
                subject_with_instance(Notification::SUBJECT, instance),
                notification.encode().into(),
            )
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
        self.inner
            .client
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

    /// Simple subscription that will produce decoded stream requests, while skipping messages that
    /// fail to decode
    pub async fn subscribe_to_stream_requests<Request>(
        &self,
        instance: Option<&str>,
        queue_group: Option<String>,
    ) -> Result<SubscriberWrapper<StreamRequest<Request>>, SubscribeError>
    where
        Request: GenericStreamRequest,
    {
        self.simple_subscribe(Request::SUBJECT, instance, queue_group)
            .await
    }

    /// Simple subscription that will produce decoded notifications, while skipping messages that
    /// fail to decode
    pub async fn subscribe_to_notifications<Notification>(
        &self,
        instance: Option<&str>,
        queue_group: Option<String>,
    ) -> Result<SubscriberWrapper<Notification>, SubscribeError>
    where
        Notification: GenericNotification,
    {
        self.simple_subscribe(Notification::SUBJECT, instance, queue_group)
            .await
    }

    /// Simple subscription that will produce decoded broadcasts, while skipping messages that
    /// fail to decode
    pub async fn subscribe_to_broadcasts<Broadcast>(
        &self,
        instance: Option<&str>,
        queue_group: Option<String>,
    ) -> Result<SubscriberWrapper<Broadcast>, SubscribeError>
    where
        Broadcast: GenericBroadcast,
    {
        self.simple_subscribe(Broadcast::SUBJECT, instance, queue_group)
            .await
    }

    /// Simple subscription that will produce decoded messages, while skipping messages that fail to
    /// decode
    async fn simple_subscribe<Message>(
        &self,
        subject: &'static str,
        instance: Option<&str>,
        queue_group: Option<String>,
    ) -> Result<SubscriberWrapper<Message>, SubscribeError>
    where
        Message: Decode,
    {
        let subscriber = if let Some(queue_group) = queue_group {
            self.inner
                .client
                .queue_subscribe(subject_with_instance(subject, instance), queue_group)
                .await?
        } else {
            self.inner
                .client
                .subscribe(subject_with_instance(subject, instance))
                .await?
        };
        debug!(
            %subject,
            message_type = %type_name::<Message>(),
            ?subscriber,
            "Simple subscription"
        );

        Ok(SubscriberWrapper {
            subscriber,
            _phantom: PhantomData,
        })
    }
}

fn subject_with_instance(subject: &'static str, instance: Option<&str>) -> Subject {
    if let Some(instance) = instance {
        Subject::from(subject.replace('*', instance))
    } else {
        Subject::from_static(subject)
    }
}
