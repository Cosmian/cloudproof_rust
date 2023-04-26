use chrono::{DateTime, TimeZone, Utc};
use cosmian_crypto_core::CsRng;
use rand::{Rng, SeedableRng};
use rand_distr::{num_traits::Float, Distribution, Normal, Standard, StandardNormal, Uniform};

use crate::{ano_error, core::AnoError};

// Represent the different Noise methods.
pub enum NoiseMethod<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    rand_distr::StandardNormal: rand_distr::Distribution<N>,
{
    Gaussian(Normal<N>),
    Laplace(Laplace<N>),
    Uniform(Uniform<N>),
}

/// Laplace Distribution
pub struct Laplace<N> {
    mean: N,
    beta: N,
}

impl<N: Float> Laplace<N> {
    pub fn new(mean: N, beta: N) -> Self {
        Self { mean, beta }
    }
}

impl<N: Float> Distribution<N> for Laplace<N>
where
    Standard: Distribution<N>,
{
    // A function to generate samples of the Laplace Noise.
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
    ///   "Laplace").
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
            "Laplace" => Ok(NoiseMethod::Laplace(Laplace::<N>::new(mean, std_dev))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self { method })
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
            "Gaussian" => Ok(NoiseMethod::Gaussian(Normal::new(
                (max_bound + min_bound) / N::from(2).unwrap(),
                // 5 sigma => 99.99994% of values will be in the bounds
                (max_bound - min_bound) / N::from(5).unwrap(),
            )?)),
            "Laplace" => Ok(NoiseMethod::Laplace(Laplace::<N>::new(
                (max_bound + min_bound) / N::from(2).unwrap(),
                // 10 sigma => 99.99995% of values will be in the bounds
                N::from(10).unwrap() / (max_bound - min_bound),
            ))),
            "Uniform" => Ok(NoiseMethod::Uniform(Uniform::new(min_bound, max_bound))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self { method })
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
    pub fn apply_on_float(&self, data: N) -> Result<N, AnoError> {
        let mut rng = CsRng::from_entropy();

        // Sample noise
        let noise = match &self.method {
            NoiseMethod::Gaussian(distr) => distr.sample(&mut rng),
            NoiseMethod::Laplace(distr) => distr.sample(&mut rng),
            NoiseMethod::Uniform(distr) => distr.sample(&mut rng),
        };
        // Add noise to the raw data
        Ok(data + noise)
    }

    /// Applies correlated noise to a vector of data, based on precomputed
    /// factors. The noise is sampled once and then applied to each data
    /// point, scaled by a corresponding factor.
    ///
    /// # Arguments
    ///
    /// * `data`: Data to add noise to.
    /// * `factors`: Factors to scale the noise with, one for each data point.
    ///
    /// # Returns
    ///
    /// A vector containing the original data with added noise
    pub fn apply_correlated_noise(&self, data: &[N], factors: &[N]) -> Result<Vec<N>, AnoError> {
        let mut rng = CsRng::from_entropy();

        // Sample noise once
        let noise = match &self.method {
            NoiseMethod::Gaussian(distr) => distr.sample(&mut rng),
            NoiseMethod::Laplace(distr) => distr.sample(&mut rng),
            NoiseMethod::Uniform(distr) => distr.sample(&mut rng),
        };

        // Add noise to the raw data, scaled by the corresponding factor
        Ok(data
            .iter()
            .zip(factors.iter())
            .map(|(val, factor)| noise.mul_add(*factor, *val))
            .collect())
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
    pub fn apply_on_int(&self, data: i64) -> Result<i64, AnoError> {
        let res = self.apply_on_float(data as f64)?;
        Ok(res.round() as i64)
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
    pub fn apply_on_date(&self, date_str: &str) -> Result<String, AnoError> {
        let date_unix = DateTime::parse_from_rfc3339(date_str)?
            .with_timezone(&Utc)
            .timestamp();
        let noisy_date_unix = self.apply_on_int(date_unix)?;
        match Utc.timestamp_opt(noisy_date_unix, 0) {
            chrono::LocalResult::None => {
                Err(ano_error!("Could not apply noise on date `{}`.", date_str))
            }
            chrono::LocalResult::Single(date) => Ok(date.to_rfc3339()),
            chrono::LocalResult::Ambiguous(_, _) => Err(ano_error!(
                "Applying noise on date `{}` lead to ambiguous result.",
                date_str
            )),
        }
    }
}
