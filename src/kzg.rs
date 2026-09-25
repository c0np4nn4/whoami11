use crate::{bytes, decode, polynomial as poly, require, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct PublicSrs {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    id: [u8; 32],
}
impl PublicSrs {
    pub fn from_points(r: usize, g1: Vec<G1Affine>, g2: Vec<G2Affine>) -> Result<Self> {
        require(
            (2..=16384).contains(&r) && g1.len() == r && g2.len() == r + 1,
            "SRS lengths",
        )?;
        require(
            g1.iter().all(|p| {
                p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero()
            }),
            "invalid G1 SRS",
        )?;
        require(
            g2.iter().all(|p| {
                p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve() && !p.is_zero()
            }),
            "invalid G2 SRS",
        )?;
        require(
            g1[0] == G1Affine::generator() && g2[0] == G2Affine::generator(),
            "SRS generators",
        )?;
        let mut h = Sha256::new();
        for p in &g1 {
            h.update(bytes(p)?);
        }
        for p in &g2 {
            h.update(bytes(p)?);
        }
        Ok(Self {
            g1,
            g2,
            id: h.finalize().into(),
        })
    }
    pub fn r(&self) -> usize {
        self.g1.len()
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    pub fn g1(&self) -> &[G1Affine] {
        &self.g1
    }
    pub fn g2(&self) -> &[G2Affine] {
        &self.g2
    }
    pub fn commit(&self, p: &[Fr]) -> Result<G1Affine> {
        require(p.len() <= self.r(), "polynomial exceeds dedicated SRS")?;
        Ok(G1Projective::msm_unchecked(&self.g1[..p.len()], p).into_affine())
    }
    pub fn commit_g2(&self, p: &[Fr]) -> Result<G2Affine> {
        require(p.len() <= self.g2.len(), "G2 polynomial exceeds SRS")?;
        Ok(G2Projective::msm_unchecked(&self.g2[..p.len()], p).into_affine())
    }
    pub fn open(&self, p: &[Fr], xs: &[Fr]) -> Result<Opening> {
        require(
            p.len() <= self.r() && !xs.is_empty() && xs.len() <= self.r(),
            "opening dimensions",
        )?;
        let z = poly::vanishing(xs)?;
        let values: Vec<_> = xs.iter().map(|x| poly::evaluate(p, *x)).collect();
        let proof = if xs.len() == self.r() {
            G1Affine::zero()
        } else if xs.len() == 1 {
            self.commit(&poly::divide_linear(p, xs[0]).0)?
        } else {
            let i = poly::interpolate(xs, &values)?;
            let mut numerator = p.to_vec();
            numerator.resize(p.len().max(i.len()), Fr::zero());
            for (v, c) in numerator.iter_mut().zip(i) {
                *v -= c;
            }
            self.commit(&poly::divide_exact(&numerator, &z)?)?
        };
        Ok(Opening { values, proof })
    }
    pub fn verify(&self, c: G1Affine, xs: &[Fr], opening: &Opening) -> Result<()> {
        require(
            !xs.is_empty() && xs.len() <= self.r() && xs.len() == opening.values.len(),
            "verify lengths",
        )?;
        require(
            c.is_on_curve()
                && c.is_in_correct_subgroup_assuming_on_curve()
                && opening.proof.is_on_curve()
                && opening.proof.is_in_correct_subgroup_assuming_on_curve(),
            "invalid commitment/proof point",
        )?;
        let z = poly::vanishing(xs)?;
        let i = if xs.len() == 1 {
            vec![opening.values[0]]
        } else {
            poly::interpolate(xs, &opening.values)?
        };
        let ci = self.commit(&i)?;
        if xs.len() == self.r() {
            require(
                opening.proof.is_zero() && ci == c,
                "full-group commitment mismatch",
            )
        } else {
            let lhs = (c.into_group() - ci).into_affine();
            let zg = self.commit_g2(&z)?;
            require(
                pairing_product(lhs, self.g2[0], opening.proof, zg),
                "invalid KZG opening",
            )
        }
    }
}
#[derive(Clone, Debug)]
pub struct Opening {
    pub values: Vec<Fr>,
    pub proof: G1Affine,
}
impl Opening {
    pub fn to_bytes(&self, r: usize) -> Result<Vec<u8>> {
        require(
            !self.values.is_empty() && self.values.len() <= r,
            "response length",
        )?;
        let mut out = Vec::new();
        for v in &self.values {
            out.extend(bytes(v)?);
        }
        if self.values.len() < r {
            out.extend(bytes(&self.proof)?);
        } else {
            require(self.proof.is_zero(), "full-group proof must be identity")?;
        }
        Ok(out)
    }
    pub fn from_bytes(raw: &[u8], t: usize, r: usize) -> Result<Self> {
        require(t > 0 && t <= r && r <= 16384, "response dimensions")?;
        let size = t * 32 + if t < r { 48 } else { 0 };
        require(raw.len() == size, "response byte length")?;
        let values = raw[..t * 32]
            .chunks_exact(32)
            .map(decode)
            .collect::<Result<Vec<_>>>()?;
        let proof = if t < r {
            decode(&raw[t * 32..])?
        } else {
            G1Affine::zero()
        };
        Ok(Self { values, proof })
    }
}
pub fn pairing_product(a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine) -> bool {
    Bls12_381::multi_pairing([a, (-c.into_group()).into_affine()], [b, d])
        .0
        .is_one()
}
pub fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine> {
    require(bases.len() == scalars.len(), "MSM length mismatch")?;
    Ok(G1Projective::msm_unchecked(bases, scalars).into_affine())
}
pub fn decode_srs(r: usize, g1: &[u8], g2: &[u8]) -> Result<PublicSrs> {
    require((2..=16384).contains(&r), "SRS bound")?;
    require(
        g1.len() == r * 48 && g2.len() == (r + 1) * 96,
        "SRS byte length",
    )?;
    PublicSrs::from_points(
        r,
        g1.chunks_exact(48).map(decode).collect::<Result<_>>()?,
        g2.chunks_exact(96).map(decode).collect::<Result<_>>()?,
    )
}
