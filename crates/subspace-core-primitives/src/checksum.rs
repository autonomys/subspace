//! Module containing wrapper for SCALE encoding/decoding with checksum

#[cfg(test)]
mod tests;

use crate::Blake3Hash;
use core::mem;
use parity_scale_codec::{Decode, Encode, EncodeLike, Error, Input, Output};

/// Output wrapper for SCALE codec that will write Blake3 checksum at the end of the encoding
struct Blake3ChecksumOutput<'a, O>
where
    O: Output + ?Sized,
{
    output: &'a mut O,
    hasher: blake3::Hasher,
}

impl<'a, O> Drop for Blake3ChecksumOutput<'a, O>
where
    O: Output + ?Sized,
{
    #[inline]
    fn drop(&mut self) {
        // Write checksum at the very end of encoding
        let hash = *self.hasher.finalize().as_bytes();
        hash.encode_to(self.output);
    }
}

impl<'a, O> Output for Blake3ChecksumOutput<'a, O>
where
    O: Output + ?Sized,
{
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.output.write(bytes);
    }
}

impl<'a, O> Blake3ChecksumOutput<'a, O>
where
    O: Output + ?Sized,
{
    fn new(output: &'a mut O) -> Self {
        Self {
            output,
            hasher: blake3::Hasher::new(),
        }
    }
}

/// Input wrapper for SCALE codec that will write Blake3 checksum at the end of the encoding
struct Blake3ChecksumInput<'a, I>
where
    I: Input,
{
    input: &'a mut I,
    hasher: blake3::Hasher,
}

impl<'a, I> Input for Blake3ChecksumInput<'a, I>
where
    I: Input,
{
    #[inline]
    fn remaining_len(&mut self) -> Result<Option<usize>, Error> {
        self.input.remaining_len()
    }

    #[inline]
    fn read(&mut self, into: &mut [u8]) -> Result<(), Error> {
        self.input.read(into)?;
        self.hasher.update(into);
        Ok(())
    }
}

impl<'a, I> Blake3ChecksumInput<'a, I>
where
    I: Input,
{
    fn new(output: &'a mut I) -> Self {
        Self {
            input: output,
            hasher: blake3::Hasher::new(),
        }
    }

    fn finish(self) -> (Blake3Hash, &'a mut I) {
        // Compute checksum at the very end of decoding
        let hash = *self.hasher.finalize().as_bytes();
        (hash.into(), self.input)
    }
}

/// Wrapper data structure that when encoded/decoded will create/check Blake3 checksum
#[derive(Debug, Clone)]
pub struct Blake3Checksummed<T>(pub T);

impl<T> Encode for Blake3Checksummed<T>
where
    T: Encode,
{
    #[inline]
    fn size_hint(&self) -> usize {
        self.0.size_hint() + mem::size_of::<Blake3Hash>()
    }

    #[inline]
    fn encode_to<O>(&self, dest: &mut O)
    where
        O: Output + ?Sized,
    {
        self.0.encode_to(&mut Blake3ChecksumOutput::new(dest));
    }

    #[inline]
    fn encoded_size(&self) -> usize {
        self.0.encoded_size() + mem::size_of::<Blake3Hash>()
    }
}

impl<T> EncodeLike for Blake3Checksummed<T> where T: EncodeLike {}

impl<T> Decode for Blake3Checksummed<T>
where
    T: Decode,
{
    #[inline]
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut input = Blake3ChecksumInput::new(input);
        let data = T::decode(&mut input)?;
        let (actual_hash, input) = input.finish();
        let expected_hash = Blake3Hash::decode(input)?;

        if actual_hash == expected_hash {
            Ok(Self(data))
        } else {
            Err(Error::from("Checksum mismatch"))
        }
    }
}
