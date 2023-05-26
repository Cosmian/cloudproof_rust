use std::sync::{Arc, Mutex};

use chrono::{DateTime, TimeZone};
use cosmian_crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use rand::{CryptoRng, Rng};
use rand_distr::{num_traits::Float, Distribution, Normal, Standard, StandardNormal, Uniform};

use super::datetime_to_rfc3339;
use crate::{ano_error, core::AnoError};

// Represent the different Noise methods.
pub enum NoiseMethod<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    StandardNormal: Distribution<N>,
{
    Gaussian(Normal<N>),
    Laplace(Laplace<N>),
    Uniform(Uniform<N>),
}

impl<N> NoiseMethod<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    Standard: Distribution<N>,
    StandardNormal: Distribution<N>,
{
    fn sample<R: CryptoRng + Rng + ?Sized>(&self, rng: &mut R) -> N {
        match self {
            Self::Gaussian(distr) => distr.sample(rng),
            Self::Laplace(distr) => distr.sample(rng),
            Self::Uniform(distr) => distr.sample(rng),
        }
    }
}

/// A Laplace distribution, used to generate random numbers following the
/// Laplace distribution.
///
/// # Example
/// ```
/// use cloudproof_anonymization::core::Laplace;
/// use rand::prelude::*;
/// use rand_distr::Distribution;
///
/// let laplace = Laplace::new(0.0, 1.0);
/// let mut rng = thread_rng();
///
/// let v = laplace.sample(&mut rng);
/// ```
pub struct Laplace<N> {
    mean: N,
    beta: N,
}

impl<N: Float> Laplace<N> {
    /// Creates a new Laplace distribution with a given mean and beta parameter.
    ///
    /// # Arguments
    ///
    /// * `mean` - The mean of the Laplace distribution.
    /// * `beta` - The scale parameter of the Laplace distribution.
    pub const fn new(mean: N, beta: N) -> Self {
        Self { mean, beta }
    }
}

impl<N: Float> Distribution<N> for Laplace<N>
where
    Standard: Distribution<N>,
{
    /// Generates a random number following the Laplace distribution.
    ///
    /// # Arguments
    ///
    /// * `rng` - The random number generator used to generate the number.
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> N {
        let p = rng.gen();
        if rng.gen_bool(0.5) {
            self.mean - self.beta * N::ln(N::one() - p)
        } else {
            self.mean + self.beta * N::ln(p)
        }
    }
}

pub struct NoiseGenerator<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    rand_distr::StandardNormal: rand_distr::Distribution<N>,
{
    method: NoiseMethod<N>,
    rng: Arc<Mutex<CsRng>>,
}

impl<N> NoiseGenerator<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    Standard: Distribution<N>,
    StandardNormal: Distribution<N>,
{
    /// Instantiate a `NoiseGenerator` using mean and standard deviation.
    ///
    /// # Arguments
    ///
    /// * `method_name` - the noise distribution to use ("Gaussian" or
    ///   "Laplace")
    /// * `mean` - mean of the noise distribution
    /// * `std_dev` - the standard deviation of the noise distribution.
    pub fn new_with_parameters(method_name: &str, mean: N, std_dev: N) -> Result<Self, AnoError> {
        if std_dev.is_zero() || std_dev.is_sign_negative() {
            return Err(ano_error!(
                "Standard Deviation must be greater than 0 to generate noise."
            ));
        }

        // Select the appropriate distribution method
        let method = match method_name {
            "Gaussian" => Ok(NoiseMethod::Gaussian(Normal::new(mean, std_dev)?)),
            "Laplace" => {
                // σ = β * sqrt(2)
                let beta = std_dev / N::from(2).unwrap().sqrt();
                Ok(NoiseMethod::Laplace(Laplace::<N>::new(mean, beta)))
            }
            _ => Err(ano_error!("{method_name} is not a supported distribution.")),
        }?;
        Ok(Self {
            method,
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        })
    }

    /// Instantiate a `NoiseGenerator` with bound constraints.
    ///
    /// # Arguments
    ///
    /// * `method_name`: The noise distribution to use ("Uniform", "Gaussian",
    ///   or "Laplace").
    /// * `min_bound`: The lower bound of the range of possible generated noise
    ///   values.
    /// * `max_bound`: The upper bound of the range of possible generated noise
    ///   values.
    pub fn new_with_bounds(
        method_name: &str,
        min_bound: N,
        max_bound: N,
    ) -> Result<Self, AnoError> {
        if min_bound >= max_bound {
            return Err(ano_error!("Min bound must be inferior to Max bound."));
        }

        // Select the appropriate distribution method
        let method = match method_name {
            "Gaussian" => {
                let mean = (max_bound + min_bound) / N::from(2).unwrap();
                // 5σ => 99.99994% of values will be in the bounds
                let std_dev = (mean - min_bound) / N::from(5).unwrap();
                Ok(NoiseMethod::Gaussian(Normal::new(mean, std_dev)?))
            }
            "Laplace" => {
                let mean = (max_bound + min_bound) / N::from(2).unwrap();
                // confidence interval at 1-a: μ ± β * ln(1/a)
                let beta = (mean - min_bound) / -N::ln(N::from(0.00005).unwrap());
                Ok(NoiseMethod::Laplace(Laplace::<N>::new(mean, beta)))
            }
            "Uniform" => Ok(NoiseMethod::Uniform(Uniform::new(min_bound, max_bound))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self {
            method,
            rng: Arc::new(Mutex::new(CsRng::from_entropy())),
        })
    }

    /// Adds noise generated from a chosen distribution to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - A single float value to which noise will be added.
    ///
    /// # Returns
    ///
    /// Original data with added noise
    pub fn apply_on_float(&mut self, data: N) -> N {
        // Sample noise
        let noise = {
            let mut rng = self.rng.lock().expect("failed locking the RNG.");
            self.method.sample(&mut *rng)
        };
        // Add noise to the raw data
        data + noise
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of floats to add noise to.
    /// * `factors`: Factors to scale the noise with, one for each data point.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_floats(&mut self, data: &[N], factors: &[N]) -> Vec<N> {
        // Sample noise once
        let noise = {
            let mut rng = self.rng.lock().expect("failed locking the RNG.");
            self.method.sample(&mut *rng)
        };

        // Add noise to the raw data, scaled by the corresponding factor
        data.iter()
            .zip(factors.iter())
            .map(|(val, factor)| noise.mul_add(*factor, *val))
            .collect()
    }
}

impl NoiseGenerator<f64> {
    /// Adds noise generated from a chosen distribution to the input data.
    ///
    /// # Arguments
    ///
    /// * `data` - A single int value to which noise will be added.
    ///
    /// # Returns
    ///
    /// Original data with added noise
    pub fn apply_on_int(&mut self, data: i64) -> i64 {
        let res = self.apply_on_float(data as f64);
        res.round() as i64
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of ints to add noise to.
    /// * `factors`: Factors to scale the noise with.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_ints(&mut self, data: &[i64], factors: &[f64]) -> Vec<i64> {
        let input_floats: Vec<f64> = data.iter().map(|val: &i64| *val as f64).collect();
        self.apply_correlated_noise_on_floats(&input_floats, factors)
            .iter()
            .map(|val| val.round() as i64)
            .collect()
    }

    /// Applies the selected noise method on a given date string.
    ///
    /// # Arguments
    ///
    /// * `date_str` -  - A date string in the RFC3339 format.
    ///
    /// # Returns
    ///
    ///  The resulting noisy date string
    pub fn apply_on_date(&mut self, date_str: &str) -> Result<String, AnoError> {
        let date = DateTime::parse_from_rfc3339(date_str)?;
        let tz = date.timezone();
        let date_unix = date.timestamp();
        let noisy_date_unix = self.apply_on_int(date_unix);
        datetime_to_rfc3339(tz.timestamp_opt(noisy_date_unix, 0), date_str)
    }

    /// Applies correlated noise to a vector of data.
    /// The noise is sampled once and then applied to each data point, scaled by
    /// a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: List of dates string to add noise to.
    /// * `factors`: Factors to scale the noise with.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise_on_dates(
        &mut self,
        data: &[&str],
        factors: &[f64],
    ) -> Result<Vec<String>, AnoError> {
        let (mut timestamps, mut timezones) = (
            Vec::with_capacity(data.len()),
            Vec::with_capacity(data.len()),
        );
        for date_str in data.iter() {
            match DateTime::parse_from_rfc3339(date_str) {
                Ok(date) => {
                    timestamps.push(date.timestamp());
                    timezones.push(date.timezone());
                }
                Err(e) => return Err(e.into()),
            }
        }

        self.apply_correlated_noise_on_ints(&timestamps, factors)
            .into_iter()
            .enumerate()
            .map(|(i, val)| datetime_to_rfc3339(timezones[i].timestamp_opt(val, 0), data[i]))
            .collect()
    }
}
