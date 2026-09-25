//! Deterministic research fixtures. Publicly reproducible tau is NOT a trusted setup.
//! Tau is generated and dropped here; protocol functions receive public points only.
use crate::{domain::Params, kzg::PublicSrs, require, Result};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{One, UniformRand, Zero};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
/// Domain-separated deterministic RNG, with a reproducible ChaCha20 algorithm.
pub fn rng(seed: u64, label: &str) -> ChaCha20Rng {
    let mut h = Sha256::new();
    h.update(b"lrdas-artifact-v1");
    h.update(seed.to_le_bytes());
    h.update(label.as_bytes());
    ChaCha20Rng::from_seed(h.finalize().into())
}
/// Dedicated SRS experiment fixture; r is included in seed separation.
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
/// Uniform random coefficient message, including residual message coordinates v.
pub fn message(p: Params, seed: u64) -> Vec<Fr> {
    let mut rng = rng(seed, "message");
    (0..p.k()).map(|_| Fr::rand(&mut rng)).collect()
}
