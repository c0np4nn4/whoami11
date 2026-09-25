//! Profile A KZG, including local multipoint openings and degree-bounded residuals.
use crate::{bytes, decode, polynomial as poly, require, Result};
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{One, Zero};
use sha2::{Digest, Sha256};

/// Public dedicated SRS: exactly r G1 and r+1 G2 powers, without tau.
#[derive(Clone)]
pub struct PublicSrs {
    g1: Vec<G1Affine>,
    g2: Vec<G2Affine>,
    id: [u8; 32],
}
impl PublicSrs {
    /// Load a trusted dedicated SRS of the expected size. This checks encodings and
    /// group membership, not a setup ceremony or consistency of every power.
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
    /// Coefficient bound.
    pub fn r(&self) -> usize {
        self.g1.len()
    }
    /// SRS identity used to bind caches and serialized headers.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
    /// Public G1 powers.
    pub fn g1(&self) -> &[G1Affine] {
        &self.g1
    }
    /// Public G2 powers.
    pub fn g2(&self) -> &[G2Affine] {
        &self.g2
    }
    /// Commit to coefficients of degree <r using real variable-base MSM.
    pub fn commit(&self, p: &[Fr]) -> Result<G1Affine> {
        require(p.len() <= self.r(), "polynomial exceeds dedicated SRS")?;
        Ok(G1Projective::msm_unchecked(&self.g1[..p.len()], p).into_affine())
    }
    /// Form a G2 polynomial commitment (degree at most r).
    pub fn commit_g2(&self, p: &[Fr]) -> Result<G2Affine> {
        require(p.len() <= self.g2.len(), "G2 polynomial exceeds SRS")?;
        Ok(G2Projective::msm_unchecked(&self.g2[..p.len()], p).into_affine())
    }
    /// Open 1..r distinct points of a local polynomial; the full-group proof is identity.
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
    /// Independently verify one opening. No aggregation of unrelated equations.
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
/// One local multipoint proof; values are not trusted until verification.
#[derive(Clone, Debug)]
pub struct Opening {
    /// Claimed field values, in the caller's query order.
    pub values: Vec<Fr>,
    /// G1 quotient commitment (identity for t=r).
    pub proof: G1Affine,
}
impl Opening {
    /// Fixed-size compressed response payload. Full-group proofs are omitted.
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
    /// Decode exactly t field elements and the proof, validating canonical points.
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
/// One two-term pairing product with one final exponentiation.
pub fn pairing_product(a: G1Affine, b: G2Affine, c: G1Affine, d: G2Affine) -> bool {
    Bls12_381::multi_pairing([a, (-c.into_group()).into_affine()], [b, d])
        .0
        .is_one()
}
/// Checked variable-base MSM of exactly matching input lengths.
pub fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine> {
    require(bases.len() == scalars.len(), "MSM length mismatch")?;
    Ok(G1Projective::msm_unchecked(bases, scalars).into_affine())
}
/// Decode an SRS payload without trusting vector length prefixes.
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
