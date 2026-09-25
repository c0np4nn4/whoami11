use crate::{domain::Params, kzg::PublicSrs, require, Result};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{One, UniformRand, Zero};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
pub fn rng(seed: u64, label: &str) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(b"lrdas-artifact-v1");
    h.update(seed.to_le_bytes());
    h.update(label.as_bytes());
    ChaCha20Rng::from_seed(h.finalize().into())
}
pub fn setup(r: usize, seed: u64) -> Result<PublicSrs> {
    require((2..=16384).contains(&r), "unsupported setup degree")?;
    let mut rng = rng(seed, &format!("setup-degree-{r}"));
    let mut tau = Fr::rand(&mut rng);
    while tau.is_zero() || tau.is_one() {
        tau = Fr::rand(&mut rng);
    }
    let mut power = Fr::one();
    let mut g1 = Vec::with_capacity(r);
    let mut g2 = Vec::with_capacity(r + 1);
    for i in 0..=r {
        if i < r {
            g1.push((G1Projective::generator() * power).into_affine());
        }
        g2.push((G2Projective::generator() * power).into_affine());
        power *= tau;
    }
    PublicSrs::from_points(r, g1, g2)
}
pub fn message(p: Params, seed: u64) -> Vec<Fr> {
    let mut rng = rng(seed, "message");
    (0..p.k()).map(|_| Fr::rand(&mut rng)).collect()
}

pub fn long_setup(p: Params, seed: u64) -> Result<crate::variants::LongSrs> {
    use ark_ec::scalar_mul::fixed_base::FixedBase;
    use ark_ff::{Field, PrimeField};
    let degree = p.degree();
    require(degree >= p.m() && degree < 1_048_576, "long fixture degree")?;
    let mut rng = rng(
        seed,
        &format!("long-srs-degree-{degree}-r-{}-b-{}", p.r(), p.b()),
    );
    let mut tau = Fr::rand(&mut rng);
    while tau.is_zero() || tau.is_one() {
        tau = Fr::rand(&mut rng);
    }
    let mut powers = Vec::with_capacity(degree + 1);
    let mut power = Fr::one();
    for _ in 0..=degree {
        powers.push(power);
        power *= tau;
    }
    let bits = Fr::MODULUS_BIT_SIZE as usize;
    let window = FixedBase::get_mul_window_size(degree + 1).min(12);
    let table = FixedBase::get_window_table(bits, window, G1Projective::generator());
    let g1 = G1Projective::normalize_batch(&FixedBase::msm::<G1Projective>(
        bits, window, &table, &powers,
    ));
    let g2 = (0..=p.m())
        .map(|i| (G2Projective::generator() * powers[i]).into_affine())
        .collect();
    let shift_r =
        (G2Projective::generator() * tau.pow([(degree - p.r() + 1) as u64])).into_affine();
    let shift_b = if p.b() > 0 {
        Some((G2Projective::generator() * tau.pow([(degree - p.b() + 1) as u64])).into_affine())
    } else {
        None
    };
    crate::variants::LongSrs::from_points(p, g1, g2, shift_r, shift_b)
}
