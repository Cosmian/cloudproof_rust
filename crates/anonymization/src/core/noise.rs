use chrono::{DateTime, TimeZone, Utc};
use cosmian_crypto_core::CsRng;
use rand::{Rng, SeedableRng};
use rand_distr::{num_traits::Float, Distribution, Normal, Standard, StandardNormal, Uniform};

use crate::{ano_error, core::AnoError};

pub enum NoiseMethod<N>
where
    N: Float + rand_distr::uniform::SampleUniform,
    rand_distr::StandardNormal: rand_distr::Distribution<N>,
{
    Gaussian(Normal<N>),
    Laplace(Laplace<N>),
    Uniform(Uniform<N>),
}

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
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> N {
        let p = rng.gen();
        if rng.gen_bool(0.5) {
            self.mean + -self.beta * N::ln(N::one() - p)
        } else {
            self.mean + self.beta * N::ln(p)
        }
    }
}

pub fn date_precision(time_unit: &str) -> Result<f64, AnoError> {
    match time_unit {
        "Second" => Ok(1.0),
        "Minute" => Ok(60.0),
        "Hour" => Ok(3600.0),
        "Day" => Ok(86400.0),
        "Month" => Ok(2_628_000.0),
        "Year" => Ok(31_536_000.0),
        _ => Err(ano_error!("Unknown time unit {}", time_unit)),
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
    pub fn new_with_parameters(method_name: &str, mean: N, std_dev: N) -> Result<Self, AnoError> {
        if std_dev.is_zero() || std_dev.is_sign_negative() {
            return Err(ano_error!(
                "Standard Deviation must be greater than 0 to generate noise."
            ));
        }

        let method = match method_name {
            "Gaussian" => Ok(NoiseMethod::Gaussian(Normal::new(mean, std_dev)?)),
            "Laplace" => Ok(NoiseMethod::Laplace(Laplace::<N>::new(mean, std_dev))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self { method })
    }

    pub fn new_date_with_parameters(
        method_name: &str,
        mean: N,
        std_dev: N,
        date_unit: &str,
    ) -> Result<Self, AnoError> {
        let scaled_std_dev = std_dev * N::from(date_precision(date_unit)?).unwrap();
        Self::new_with_parameters(method_name, mean, scaled_std_dev)
    }

    pub fn new_with_bounds(
        method_name: &str,
        min_bound: N,
        max_bound: N,
    ) -> Result<Self, AnoError> {
        if min_bound >= max_bound {
            return Err(ano_error!("Min bound must be inferior to Max bound."));
        }

        let method = match method_name {
            "Gaussian" => Ok(NoiseMethod::Gaussian(Normal::new(
                (max_bound + min_bound) / N::from(2).unwrap(),
                (max_bound - min_bound) / N::from(5).unwrap(),
            )?)),
            "Laplace" => Ok(NoiseMethod::Laplace(Laplace::<N>::new(
                (max_bound + min_bound) / N::from(2).unwrap(),
                (max_bound - min_bound) / N::from(10).unwrap(),
            ))),
            "Uniform" => Ok(NoiseMethod::Uniform(Uniform::new(min_bound, max_bound))),
            _ => Err(ano_error!("No supported distribution {}.", method_name)),
        }?;
        Ok(Self { method })
    }

    pub fn apply_on_float(&self, data: N) -> Result<N, AnoError> {
        let mut rng = CsRng::from_entropy();

        // Sample noise once with std_deviation = 1
        let noise = match &self.method {
            NoiseMethod::Gaussian(distr) => distr.sample(&mut rng),
            NoiseMethod::Laplace(distr) => distr.sample(&mut rng),
            NoiseMethod::Uniform(distr) => distr.sample(&mut rng),
        };
        // Add noise to the raw data
        Ok(data + noise)
    }

    pub fn apply_correlated_noise(&self, data: &[N], factors: &[N]) -> Result<Vec<N>, AnoError> {
        let mut rng = CsRng::from_entropy();

        // Sample noise once with std_deviation = 1
        let noise = match &self.method {
            NoiseMethod::Gaussian(distr) => distr.sample(&mut rng),
            NoiseMethod::Laplace(distr) => distr.sample(&mut rng),
            NoiseMethod::Uniform(distr) => distr.sample(&mut rng),
        };
        // Add noise to the raw data
        Ok(data
            .iter()
            .zip(factors.iter())
            .map(|(val, factor)| noise.mul_add(*factor, *val))
            .collect())
    }
}
impl NoiseGenerator<f64> {
    pub fn apply_on_int(&self, data: i64) -> Result<i64, AnoError> {
        let res = self.apply_on_float(data as f64)?;
        Ok(res.round() as i64)
    }

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
