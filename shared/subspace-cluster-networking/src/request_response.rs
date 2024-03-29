use async_trait::async_trait;
use futures::prelude::*;
use libp2p::swarm::StreamProtocol;
use std::io;

/// A request-response codec using that sends bytes without extra encoding.
#[derive(Debug, Copy, Clone)]
pub struct NoCodec {
    /// Maximum allowed size, in bytes, of a request.
    ///
    /// Any request larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_request_size: u64,
    /// Maximum allowed size, in bytes, of a response.
    ///
    /// Any response larger than this value will be declined as a way to avoid allocating too
    /// much memory for it.
    pub max_response_size: u64,
}

impl NoCodec {
    pub fn new(max_request_size: u64, max_response_size: u64) -> Self {
        Self {
            max_request_size,
            max_response_size,
        }
    }
}

#[async_trait]
impl libp2p::request_response::Codec for NoCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();

        let len = io.take(self.max_request_size).read_to_end(&mut vec).await?;

        vec.truncate(len);

        Ok(vec)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut vec = Vec::new();

        let len = io
            .take(self.max_response_size)
            .read_to_end(&mut vec)
            .await?;

        vec.truncate(len);

        Ok(vec)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Vec<u8>,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&response).await
    }
}

#[cfg(test)]
mod tests {
    use super::NoCodec;
    use futures::prelude::*;
    use futures_ringbuf::Endpoint;
    use libp2p::request_response::Codec;
    use libp2p::swarm::StreamProtocol;
    use parity_scale_codec::{Decode, Encode};

    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    struct TestRequest {
        payload: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
    struct TestResponse {
        payload: String,
    }

    #[tokio::test]
    async fn test_codec() {
        let expected_request = b"test_payload".to_vec();
        let expected_response = b"test_payload".to_vec();
        let protocol = StreamProtocol::new("/test_vec/1");
        let mut codec = NoCodec::new(1024, 1024);

        let (mut a, mut b) = Endpoint::pair(124, 124);
        codec
            .write_request(&protocol, &mut a, expected_request.clone())
            .await
            .expect("Should write request");
        a.close().await.unwrap();

        let actual_request = codec
            .read_request(&protocol, &mut b)
            .await
            .expect("Should read request");
        b.close().await.unwrap();

        assert_eq!(actual_request, expected_request);

        let (mut a, mut b) = Endpoint::pair(124, 124);
        codec
            .write_response(&protocol, &mut a, expected_response.clone())
            .await
            .expect("Should write response");
        a.close().await.unwrap();

        let actual_response = codec
            .read_response(&protocol, &mut b)
            .await
            .expect("Should read response");
        b.close().await.unwrap();

        assert_eq!(actual_response, expected_response);
    }
}
