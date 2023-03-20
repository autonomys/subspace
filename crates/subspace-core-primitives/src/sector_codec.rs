//! PoR codec that uses polynomial-based systematic erasure coding

#[cfg(test)]
mod tests;

use crate::Scalar;
use alloc::vec::Vec;
use ark_bls12_381::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use num_integer::Roots;
#[cfg(feature = "parallel-decoding")]
use rayon::prelude::*;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
/// Errors that happen when using `SectorCodec`
pub enum SectorCodecError {
    /// Sector size is wrong
    #[cfg_attr(feature = "std", error("Sector size is wrong"))]
    WrongSectorSize,
    /// Input sector size is wrong
    #[cfg_attr(
        feature = "std",
        error("Input sector size is wrong: expected {expected} bytes provided {actual} bytes")
    )]
    WrongInputSectorSize {
        /// Expected sector size configured in constructor
        expected: usize,
        /// Actual sector size provided as input
        actual: usize,
    },
    /// Failed to instantiate domain
    #[cfg_attr(feature = "std", error("Failed to instantiate domain"))]
    FailedToInstantiateDomain,
}

/// PoR codec that uses polynomial-based systematic erasure coding
#[derive(Debug, Copy, Clone)]
pub struct SectorCodec {
    sector_size_in_scalars: usize,
    /// Sector is assumed to be a square grid of scalars, where both sides of the square are of the
    /// following size
    sector_side_size_in_scalars: usize,
}

impl SectorCodec {
    /// Create new instance for sector size (in bytes)
    pub fn new(sector_size: usize) -> Result<Self, SectorCodecError> {
        if sector_size % Scalar::FULL_BYTES != 0 {
            return Err(SectorCodecError::WrongSectorSize);
        }

        let sector_size_in_scalars = sector_size / Scalar::FULL_BYTES;

        if sector_size_in_scalars == 0 || !sector_size_in_scalars.is_power_of_two() {
            return Err(SectorCodecError::WrongSectorSize);
        }

        let sector_side_size_in_scalars = sector_size_in_scalars.sqrt();
        if sector_side_size_in_scalars.pow(2) != sector_size_in_scalars {
            return Err(SectorCodecError::WrongSectorSize);
        }

        Ok(Self {
            sector_size_in_scalars,
            sector_side_size_in_scalars,
        })
    }

    /// Encode sector in place.
    ///
    /// Data layout is expected to be flat pieces one after another, each piece is a column. The
    /// size of the sector should be equal to the global protocol parameters or else encoding will
    /// fail.
    pub fn encode(&self, sector: &mut [Scalar]) -> Result<(), SectorCodecError> {
        if sector.len() != self.sector_size_in_scalars {
            return Err(SectorCodecError::WrongInputSectorSize {
                expected: self.sector_size_in_scalars * Scalar::FULL_BYTES,
                actual: sector.len() * Scalar::FULL_BYTES,
            });
        }

        let Some(domain) = GeneralEvaluationDomain::<Fr>::new(self.sector_side_size_in_scalars) else {
            return Err(SectorCodecError::FailedToInstantiateDomain);
        };

        let mut row = Vec::<Fr>::with_capacity(self.sector_side_size_in_scalars);

        for row_index in 0..self.sector_side_size_in_scalars {
            row.extend(
                sector
                    .iter()
                    .skip(row_index)
                    .step_by(self.sector_side_size_in_scalars)
                    .map(|scalar| scalar.0),
            );

            domain.ifft_in_place(&mut row);
            domain.coset_fft_in_place(&mut row);

            sector
                .iter_mut()
                .skip(row_index)
                .step_by(self.sector_side_size_in_scalars)
                .zip(row.iter())
                .for_each(|(output, input)| *output = Scalar(*input));

            // Clear for next iteration of the loop
            row.clear();
        }

        Ok(())
    }

    /// Decode sector in place.
    ///
    /// Data layout is the same as in encoding.
    pub fn decode(&self, sector: &mut [Scalar]) -> Result<(), SectorCodecError> {
        if sector.len() != self.sector_size_in_scalars {
            return Err(SectorCodecError::WrongInputSectorSize {
                expected: self.sector_size_in_scalars * Scalar::FULL_BYTES,
                actual: sector.len() * Scalar::FULL_BYTES,
            });
        }

        let Some(domain) = GeneralEvaluationDomain::<Fr>::new(self.sector_side_size_in_scalars) else {
            return Err(SectorCodecError::FailedToInstantiateDomain);
        };

        #[cfg(not(feature = "parallel-decoding"))]
        {
            let mut row = Vec::with_capacity(self.sector_side_size_in_scalars);

            for row_index in 0..self.sector_side_size_in_scalars {
                row.extend(
                    sector
                        .iter()
                        .skip(row_index)
                        .step_by(self.sector_side_size_in_scalars)
                        .map(|scalar| scalar.0),
                );

                domain.coset_ifft_in_place(&mut row);
                domain.fft_in_place(&mut row);

                sector
                    .iter_mut()
                    .skip(row_index)
                    .step_by(self.sector_side_size_in_scalars)
                    .zip(row.iter())
                    .for_each(|(output, input)| *output = Scalar(*input));

                // Clear for next iteration of the loop
                row.clear();
            }
        }
        #[cfg(feature = "parallel-decoding")]
        {
            // Transform sector grid from columns to rows
            let mut rows = vec![
                vec![Fr::default(); self.sector_side_size_in_scalars];
                self.sector_side_size_in_scalars
            ];
            for (row_index, row) in rows.iter_mut().enumerate() {
                sector
                    .iter()
                    .skip(row_index)
                    .step_by(self.sector_side_size_in_scalars)
                    .zip(row)
                    .for_each(|(input, output)| *output = input.0);
            }

            // Decode rows in parallel
            rows.par_iter_mut().for_each(|row| {
                domain.coset_ifft_in_place(row);
                domain.fft_in_place(row);
            });

            // Store result back into inout sector
            for (row_index, row) in rows.into_iter().enumerate() {
                sector
                    .iter_mut()
                    .skip(row_index)
                    .step_by(self.sector_side_size_in_scalars)
                    .zip(row)
                    .for_each(|(output, input)| *output = Scalar(input));
            }
        }

        Ok(())
    }
}
