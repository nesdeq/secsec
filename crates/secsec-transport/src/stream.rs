//! Generic byte-stream framing for **stdio / SSH mode** (`finaldesign.md` §11). The QUIC framing in
//! [`crate::frame`] is `quinn`-specific (per-op bidi streams); stdio mode multiplexes the §12 wire over
//! a **single** authenticated byte pipe (an SSH subsystem channel: the server's stdin/stdout), so it
//! needs length-prefixed framing over any [`tokio::io::AsyncRead`] / [`AsyncWrite`].
//!
//! The frame format matches [`crate::frame`]: a `le32` length prefix then the payload, with the same
//! `MAX_FRAME_LEN` bound enforced **before allocation** (§19 alloc-bomb guard). The channel binding for
//! stdio is the SSH exchange hash `H` (fed into the transcript via
//! [`crate::auth::SessionTranscript::new_stdio`]); `host_id = BLAKE3(K_S)` where `K_S` is the server
//! host key from the SSH exchange. Acquiring `H`/`K_S` from a live SSH session (via `russh`) is the
//! remaining integration; this module is the transport-agnostic framing it rides on, testable over an
//! in-memory pipe.

use crate::frame::{FrameError, MAX_FRAME_LEN};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// `host_id = BLAKE3(canonical(K_S))` for stdio/SSH mode (§5/§11): the server host key `K_S` extracted
/// from the SSH exchange hash. The QUIC counterpart is `BLAKE3(SPKI)` ([`crate::HostPin::host_id`]).
#[must_use]
pub fn stdio_host_id(k_s: &[u8]) -> [u8; 32] {
    *blake3::hash(k_s).as_bytes()
}

/// Write one length-prefixed frame to a generic async writer: `le32(len) ‖ payload`.
pub async fn write_frame_stream<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let len = payload.len() as u32;
    w.write_all(&len.to_le_bytes())
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    w.write_all(payload)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    w.flush().await.map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(())
}

/// Read one length-prefixed frame from a generic async reader, rejecting any length `> max` **before**
/// allocating (`max ≤ `[`MAX_FRAME_LEN`]; §19 alloc-bomb guard).
pub async fn read_frame_stream<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max || len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| FrameError::Io(e.to_string()))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SessionTranscript;

    #[tokio::test]
    async fn frames_round_trip_over_a_generic_pipe() {
        // tokio::io::duplex is an in-memory bidirectional pipe — stands in for the SSH subsystem
        // stdin/stdout without needing a real SSH session.
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);

        let payloads: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"hello".to_vec(),
            vec![0xABu8; 4096],
            (0..1000u32).flat_map(|n| n.to_le_bytes()).collect(),
        ];

        // writer task sends every frame; reader reads them back in order.
        let to_send = payloads.clone();
        let writer = tokio::spawn(async move {
            for p in &to_send {
                write_frame_stream(&mut a, p).await.unwrap();
            }
        });
        for expected in &payloads {
            let got = read_frame_stream(&mut b, MAX_FRAME_LEN).await.unwrap();
            assert_eq!(&got, expected);
        }
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn read_frame_rejects_oversize_before_alloc() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // hand-write a frame claiming a huge length; read must reject on the count, not allocate.
        let huge = (MAX_FRAME_LEN as u32) + 1;
        tokio::io::AsyncWriteExt::write_all(&mut a, &huge.to_le_bytes())
            .await
            .unwrap();
        assert!(matches!(
            read_frame_stream(&mut b, MAX_FRAME_LEN).await,
            Err(FrameError::TooLarge(_))
        ));
    }

    #[test]
    fn stdio_transcript_binds_the_exchange_hash() {
        // the stdio transcript pre-feeds H, so a different H yields a different transcript even with
        // identical hellos — binding every per-op signature to the SSH session (§11).
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let host_id = stdio_host_id(b"server-host-key-bytes");

        let mut t1 = SessionTranscript::new_stdio(&h1);
        t1.client_hello(1, &[0x01; 32])
            .server_hello(1, &[0x02; 32], &host_id);
        let mut t2 = SessionTranscript::new_stdio(&h2);
        t2.client_hello(1, &[0x01; 32])
            .server_hello(1, &[0x02; 32], &host_id);
        assert_ne!(
            t1.finalize(),
            t2.finalize(),
            "a different SSH exchange hash must change the transcript"
        );

        // and it differs from QUIC mode (no H pre-fed) with the same hellos.
        let mut q = SessionTranscript::new();
        q.client_hello(1, &[0x01; 32])
            .server_hello(1, &[0x02; 32], &host_id);
        assert_ne!(t1.finalize(), q.finalize());
    }
}
