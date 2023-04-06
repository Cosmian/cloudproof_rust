use rand::{thread_rng, Rng};
use rand_distr::{num_traits::Float, Distribution, Standard, StandardNormal};

use crate::{ano_error, core::AnoError};

pub enum NoiseMethod<N: Float> {
    Gaussian(StandardNormal),
    Laplace(Laplace<N>),
}

impl<N: Float> NoiseMethod<N> {
    pub fn new_gaussian() -> Self {
        // Gaussian(0, 1)
        Self::Gaussian(StandardNormal)
    }

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
        let mut rng = thread_rng();

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
            standard_deviation = standard_deviation / N::from(2).unwrap();
        }

        Ok(data + standard_deviation * noise)
    }
}
