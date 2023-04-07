use chrono::{DateTime, TimeZone, Utc};
use cosmian_crypto_core::CsRng;
use rand::{Rng, SeedableRng};
use rand_distr::{num_traits::Float, Distribution, Standard, StandardNormal};

use crate::{ano_error, core::AnoError};

pub enum NoiseMethod<N: Float> {
    Gaussian(StandardNormal),
    Laplace(Laplace<N>),
}

impl<N: Float> NoiseMethod<N> {
    #[must_use]
    pub fn new_gaussian() -> Self {
        // Gaussian(0, 1)
        Self::Gaussian(StandardNormal)
    }

    #[must_use]
    pub fn new_laplace() -> Self {
        // Laplace(0, 1)
        Self::Laplace(Laplace::<N>::new(N::one()))
    }
}

pub struct Laplace<N> {
    beta: N,
}

impl<N: Float> Laplace<N> {
    pub fn new(beta: N) -> Self {
        Self { beta }
    }
}

impl<N: Float> Distribution<N> for Laplace<N>
where
    Standard: Distribution<N>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> N {
        let p = rng.gen();
        if rng.gen_bool(0.5) {
            -self.beta * N::ln(N::one() - p)
        } else {
            self.beta * N::ln(p)
        }
    }
}

pub struct NoiseGenerator<N>
where
    N: Float,
{
    method: NoiseMethod<N>,
    standard_deviation: N,
}

impl<N> NoiseGenerator<N>
where
    N: Float,
    Standard: Distribution<N>,
    StandardNormal: Distribution<N>,
{
    pub fn new(method: NoiseMethod<N>, standard_deviation: N) -> Result<Self, AnoError> {
        if standard_deviation.is_zero() || standard_deviation.is_sign_negative() {
            return Err(ano_error!(
                "Standard Deviation must be greater than 0 to generate noise."
            ));
        }

        Ok(Self {
            method,
            standard_deviation,
        })
    }

    pub fn apply_on_float(
        &self,
        data: N,
        lower_bound_opt: Option<N>,
        upper_bound_opt: Option<N>,
    ) -> Result<N, AnoError> {
        let mut rng = CsRng::from_entropy();

        // Sample noise once with std_deviation = 1
        let noise = match &self.method {
            NoiseMethod::Gaussian(distr) => distr.sample(&mut rng),
            NoiseMethod::Laplace(distr) => distr.sample(&mut rng),
        };
        // And scale by the desired std deviation
        let mut standard_deviation = self.standard_deviation;

        // Check that the output is in the bounds
        let mut valid_output = false;
        while !valid_output {
            valid_output = true;
            let noisy_data = data + standard_deviation * noise;

            if let Some(lower_bound) = lower_bound_opt {
                if noisy_data < lower_bound {
                    valid_output = false;
                }
            }
            if let Some(upper_bound) = upper_bound_opt {
                if noisy_data > upper_bound {
                    valid_output = false;
                }
            }
            // Reduce standard deviation to fit in the bounds
            standard_deviation =
                standard_deviation / <N as rand_distr::num_traits::NumCast>::from(2).unwrap();
        }

        Ok(data + standard_deviation * noise)
    }
}
impl NoiseGenerator<f64> {
    pub fn apply_on_int(
        &self,
        data: i64,
        lower_bound_opt: Option<i64>,
        upper_bound_opt: Option<i64>,
    ) -> Result<i64, AnoError> {
        let res = self.apply_on_float(
            data as f64,
            lower_bound_opt.map(|i| i as f64),
            upper_bound_opt.map(|i| i as f64),
        )?;
        Ok(res.round() as i64)
    }

    pub fn apply_on_date(
        &self,
        date_str: &str,
        lower_bound_opt: Option<&str>,
        upper_bound_opt: Option<&str>,
    ) -> Result<String, AnoError> {
        let date_unix = DateTime::parse_from_rfc3339(date_str)?
            .with_timezone(&Utc)
            .timestamp();
        let lower_bound_date =
            lower_bound_opt.and_then(|date_str| DateTime::parse_from_rfc3339(date_str).ok());
        let upper_bound_date =
            upper_bound_opt.and_then(|date_str| DateTime::parse_from_rfc3339(date_str).ok());

        let noisy_date_unix = self.apply_on_int(
            date_unix,
            lower_bound_date.map(|date| date.with_timezone(&Utc).timestamp()),
            upper_bound_date.map(|date| date.with_timezone(&Utc).timestamp()),
        )?;
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
