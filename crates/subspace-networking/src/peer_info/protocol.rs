//! This module defines low-level functions for working with inbound and outbound streams.

use crate::peer_info::PeerInfo;
use futures::prelude::*;
use parity_scale_codec::{Decode, Encode};
use std::io;
use std::io::ErrorKind;

/// Send peer-info data to a remote peer.
pub async fn send<S>(mut stream: S, pi: PeerInfo) -> io::Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let send_data = pi.encode();
    let send_len_bytes = (send_data.len() as u32).to_le_bytes();

    stream.write_all(&send_len_bytes).await?;
    stream.write_all(&send_data).await?;
    stream.flush().await?;

    Ok(stream)
}

/// Receive peer-info data from a remote peer.
pub async fn recv<S>(mut stream: S) -> io::Result<(S, PeerInfo)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut rec_len_bytes = [0u8; 4];
    stream.read_exact(&mut rec_len_bytes).await?;
    let rec_len = u32::from_le_bytes(rec_len_bytes) as usize;
    let mut rec_data = vec![0; rec_len];

    stream.read_exact(&mut rec_data).await?;
    let received_peer_info =
        PeerInfo::decode(&mut &*rec_data).map_err(|err| io::Error::new(ErrorKind::Other, err))?;

    Ok((stream, received_peer_info))
}
